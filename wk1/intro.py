from pwn import *
from pathlib import Path
import re

PROGRAM_PATH = (Path(__file__).parent / "intro").resolve().__str__()

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

io.recvuntil(delims="{")
bytesGot: str = io.recvuntil(delims="}", drop=True).decode(encoding="ascii").strip()
io.recvlines(2)


# Flush the remainder of the uselss junk
print("____________________________________")

print(f"Hex value received: {bytesGot}")
toIntVal = int(bytesGot, 16)
print(f"The int value is: {toIntVal}")

print(f"Sending value as str: {toIntVal}")
io.sendline(str(toIntVal).encode("ascii"))
val: list[str] = io.recvlinesS(4)
# print(val)

print("____________________________________")
match = re.search(r"0x\d+", val[-1])
numToSubtract = int(match.group(0), 16)
print(f"Hex value received to subtract: {match.group(0)}")
print(f"The int value is: {numToSubtract}")

diff = toIntVal - numToSubtract
print(f"The difference {toIntVal} - {numToSubtract} = {diff}")

print(f"Sending difference as str: {hex(diff)}")
io.sendline(hex(diff).encode("ascii"))

print("____________________________________")
val: list[str] = io.recvlinesS(2)
# print(val)
match = re.search(r"0x\d+", val[-1])
num = int(match.group(0), 16)
print(f"Hex value received to convert to little endian: 0x1337")


le_bytes = p16(num, "little")
# le_hex = "0x" + enhex(le_bytes)
print(f"Sending the number 0x1337 in little endian bytes {le_bytes}")
io.sendline(le_bytes)

print("____________________________________")
val: list[str] = io.recvlinesS(3)
io.recvline()
le_addr = val[-1]
print(f"Received address to convert to int: {le_addr}")
# print(val)

numConvert = u32(le_addr, "little")
print(f"Hex value received to convert to int: {numConvert}")
print(f"Sending number: {numConvert}")
io.sendline(str(numConvert).encode("ascii"))

print("____________________________________")
val: list[str] = io.recvlinesS(3)
# print(val)
io.recvline()

print(f"number: {numConvert}")
print(f"Sending as number as hex: {hex(numConvert)}")
io.sendline(hex(numConvert).encode("ascii"))

print("____________________________________")
val: list[str] = io.recvlinesS(2)
match = re.findall(r"\d+", val[-1])
print(f"Received numbers: {match[0]} + {match[1]}")

num1 = int(match[0])
num2 = int(match[1])
theSum = num1 + num2
print(f"The sum is: {match[0]+match[1]}")
print(f"Sending sum: {match[0]+match[1]}")
io.sendline(str(theSum).encode("ascii"))

print("____________________________________")
val: list[str] = io.recvlinesS(3)
# print(val)
# res = io.recvregex(rb"0x\d+")
res = io.recvline_regex(rb"0x[0-9a-fA-F]+")
# print(res)

match = re.search("0x[0-9a-fA-F]+", res.decode("ascii"))
print(f"Received addr: {match[0]}")
convertedDEADBEEF = int(match[0], 16)
print(f"In decimal the addr is: {convertedDEADBEEF}")
print(f"Sending sum: {convertedDEADBEEF}")

io.sendline(str(convertedDEADBEEF).encode("ascii"))

print("____________________________________")
val = io.recvuntil("Now send me these bytes as decimal: ")
# print(val)

bytesReceived = io.recvline(keepends=False)
print(f"Bytes received is: {bytesReceived}")
bytesToDecimal = u64(bytesReceived)

print(f"Bytes converted is: {bytesToDecimal}")
print(f"Sending the number: {bytesToDecimal}")

io.sendline(str(bytesToDecimal).encode("ascii"))
print("____________________________________")


val = io.recvlines(3)
print(val)
io.interactive()
