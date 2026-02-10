ENTRY(_start)

SECTIONS {
  . = 0x401000;

  .text : {
    *(.text*)
  } :text
}

PHDRS {
  text PT_LOAD FLAGS(7);  /* R + X */
}
