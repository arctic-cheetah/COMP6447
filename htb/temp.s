global  _start

section .text
_start:
    mov   al, 0
    mov   bl, 1
    xchg  al, bl
