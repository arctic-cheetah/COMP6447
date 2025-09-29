global _start

section .text
_start:
    
    ; ; open(fd=1000, 'O_RDONLY')
    ; mov al, 2          ; open syscall number
    ; mov rdi, rsp        ; move pointer to filename
    ; xor rsi, rsi        ; set O_RDONLY flag
    ; syscall

    ; read file
    ; lea rsi, [rdi]      ; pointer to opened file
    lea rsi, [rsp]
    mov rdi, 1000       ; set fd to 1000
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

