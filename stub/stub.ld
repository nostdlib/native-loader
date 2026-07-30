/* Linker script: place .text (entry first), .rdata, .data contiguously from VA 0
 * so objcopy -O binary produces a valid position-independent flat blob. */
ENTRY(_start)

SECTIONS
{
    . = 0;
    .text  : { *(.text.start) *(.text) *(.text.*) }
    .rdata : { *(.rdata) *(.rdata.*) *(.rodata) *(.rodata.*) }
    .data  : { *(.data) *(.data.*) }
    /DISCARD/ : { *(.pdata) *(.xdata) *(.rsrc) *(.reloc) *(.idata) *(.edata) *(.bss) *(.drectve) *(.comment) *(.note*) }
}
