BITS 64
global _start
_start:
; read(fd=1000, char *buff, 1024) 
    xor     eax, eax            ; read
    mov     edi, 1000           ; set fd = 1000
    sub     rsp, 0x400          ; read into buffer, size = 1024
    mov     rsi, rsp            ; move buffer into second arg
    mov     edx, 0x400          ; 0x400 = 1024
    syscall                     ; rax = n
; write(1, buf, nread)
    mov     edx, eax            ;
    mov     edi, 1              ; stdout
    mov     eax, 1              ; write
    syscall
; exit(0) WE NEED THIS
    xor     edi, edi
    mov     eax, 60             ; exit
    syscall
