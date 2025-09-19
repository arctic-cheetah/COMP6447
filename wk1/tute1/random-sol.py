from pwn import *
import re

# LOL original file name causes name space conflict
# Rename file random to random-num
exe = "./random-num"
context.log_file = "info"


p1 = process(exe)
p2 = process(exe)

p1.recvline()
p1.sendline(b"A")

p2.recvline()


# numGot = p1.recvregex(r"\d+", capture=True)
res = p1.recvlinesS(numlines=1)
numGot = re.search(r"\d+", res[0]).group(0)
print(f"The number recieved from process 1 is: {numGot}")
p2.sendline(str(numGot).encode("ascii"))

res = p2.recvline(timeout=1)
print(res)


p2.interactive()
