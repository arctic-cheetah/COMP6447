global  _start
extern  printf

section .data
    outFormat db  "It's %s", 0x0a, 0x00
    message db "Aligned!", 0x0a

section .text
_start:
    call print          ; print string
    call Exit           ; Exit the program

print:
    sub rsp, 8 ; Align the stack to 16 bytes, we actually need to subtract 8 to do so!
    push rax
    push rbx
    mov rdi, outFormat  ; set 1st argument (Print Format)
    mov rsi, message    ; set 2nd argument (message)
    call printf         ; printf(outFormat, message)
    pop rbx
    pop rax
    add rsp, 8 ; restore stack
    ret

Exit:
    mov rax, 60
    mov rdi, 0
    syscall