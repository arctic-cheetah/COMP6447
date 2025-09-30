global _start

section .data
    message db "Hello HTB Academy!"
    length equ $-message

section .text
_start:
    mov rax, 0x00000000000a6f6c6c6548 ;Hello in le
    push rax  ;Push string onto stack
    mov rax, 1
    mov rdi, 1
    mov rsi, rsp  ;We NEED THE POINTER to str
    mov rdx, 5
    syscall

    ;End program
    mov rax, 60
    mov rdi, 0
    syscall

    0x4B435546