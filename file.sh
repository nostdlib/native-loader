          x86_64-w64-mingw32-gcc -c -O2 -ffreestanding -nostdlib -fno-stack-protector \
                -fno-asynchronous-unwind-tables -fno-unwind-tables \
                -e _start stub/stub.c -o stub.o

x86_64-w64-mingw32-objdump -r stub.o || true

          mkdir -p dist
          x86_64-w64-mingw32-ld -T stub/stub.ld --entry=_start -o stub.pe stub.o
          x86_64-w64-mingw32-objcopy -O binary stub.pe dist/stub-x64.bin