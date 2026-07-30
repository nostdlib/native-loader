# native-loader

Native (C) shellcode loader for Windows, consumed by the
[C2 dashboard](https://github.com/nostdlib/C2) the same way
[`nostdlib/android-loader`](https://github.com/nostdlib/android-loader) is.

A small `loader.exe` / `loader.dll` that downloads position-independent shellcode
from a URL and executes it in-process via `VirtualAlloc` + `CreateThread`.
Download is over **WinHTTP** (TLS 1.2, redirects followed — handles GitHub
release → S3 302s). C2 never compiles it; artifacts are built here in CI and
downloaded at C2 build time.

## Build

```sh
cmake -A x64 -B build-x64 -DCMAKE_BUILD_TYPE=Release && cmake --build build-x64 --config Release
cmake -A Win32 -B build-x86 -DCMAKE_BUILD_TYPE=Release && cmake --build build-x86 --config Release
```

Requires the Visual Studio C++ toolchain (MSVC). `/MT` (static CRT) is set so the
binary has no `vcruntime140.dll` dependency. CI does this automatically — see
[.github/workflows/release.yml](.github/workflows/release.yml).

## Release asset contract

Each release publishes exactly these assets, which C2 downloads into
`wwwroot/loaders/windows-native/`:

| Asset | Variant | Arch |
|-------|---------|------|
| `loader-x64.exe` | GUI exe (no console) | x86_64 |
| `loader-x86.exe` | GUI exe (no console) | i386 |
| `loader-x64.dll` | DLL (`DllMain` spawns loader) | x86_64 |
| `loader-x86.dll` | DLL (`DllMain` spawns loader) | i386 |

The rolling build target is the **`preview`** tag.

## The URL placeholder contract

`src/loader.c` declares `static char g_url[256] = "SHELLCODE_URL_PLACEHOLDER";`
(C zero-fills the remaining 231 bytes). The C2 binder locates the 25-byte ASCII
marker, zeroes the whole 256-byte slot, and writes the operator's shellcode URL
(UTF-8) into it. **Do not change the marker text or the 256-byte size** without
updating the shared `LoaderUrlPatcher` in C2.

At runtime the loader fetches `windows-x86_64.bin` or `windows-i386.bin` from the
[nostdlib/Position-Independent-Agent](https://github.com/nostdlib/Position-Independent-Agent)
release matching its own architecture.

## Related
- [nostdlib/android-loader](https://github.com/nostdlib/android-loader) — the Android counterpart (identical patch contract).
- [nostdlib/C2](https://github.com/nostdlib/C2) — the dashboard that consumes this.
