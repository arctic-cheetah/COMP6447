from pwn import *
from pathlib import Path
import re

# FullPath
PROGRAM_PATH = (Path(__file__).parent / "too-slow").resolve().__str__()


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


io = start()

# Discard the fkin taunting statement
res = io.recvline()
print(res)

print("____________________________________")

for i in range(0, 10):
    res = io.recvuntil(delims="=").decode("ascii")
    print(res)
    match = re.findall(r"\d+", res)
    # print(f"Received numbers: {match[0]} + {match[1]}")
    num1 = int(match[0])
    num2 = int(match[1])
    ans = num1 + num2
    print(f"{match[0]} + {match[1]} = {ans}")
    io.sendline(str(ans).encode("ascii"))

    res = io.recvline().decode("ascii")
    print(res)

res = io.recvline().decode("ascii")
print(res)

io.interactive()
# endStr = "Well done! Enjoy your Shell! Flag is at /flag"
