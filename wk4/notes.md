## FTX

 checksec ftx
[*] '/home/k-730/COMP6447/wk4/ftx/ftx'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No

main() -> run_game()

TODO:
ooooo, there is a win function :D

## Formatrix

└─$ checksec formatrix  
[*] '/home/k-730/COMP6447/wk4/formatrix/formatrix'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

Cannot overrwrite the return address (SHSTK) so I need to perform GOT on printf or puts?

Most likely not work

┌──(pythonPackages)─(k-730㉿K730)-[~/COMP6447/wk4/formatrix]
└─$ readelf -r formatrix | grep -i printf
000000403580  000500000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000403590  000800000007 R_X86_64_JUMP_SLO 0000000000000000 sprintf@GLIBC_2.2.5 + 0

Maybe printf?
readelf -r ./vuln | grep -i printf

%1$p → RDX at the call → that’s your &buff (first and only real vararg).

%2$p → RCX snapshot taken by va_start in libc (whatever garbage/leftover the compiler left in RCX).

%3$p → R8 snapshot (again, whatever happened to be in R8).

%4$p → R9 snapshot.

%5$p+ match from callers stack frame (overflow area)

reg_save_area (saved by callee for varargs):
  slot0: RDI = dst           ← named arg (not indexable by %n$)
  slot1: RSI = fmt           ← named arg (not indexable by %n$)
  slot2: RDX = 1st vararg    ← %1$...
  slot3: RCX = 2nd vararg    ← %2$...
  slot4: R8  = 3rd vararg    ← %3$...
  slot5: R9  = 4th vararg    ← %4$...

overflow_arg_area (stack in the CALLER at call time):
  [rsp]   = return address into caller          ← %5$...
  [rsp+8] = (often caller’s saved RBP)          ← %6$...
  [rsp+16]= next 8-byte word in caller frame    ← %7$...
  [rsp+24]= next …                               ← %8$..

rbp-0x200 => buf
rbp-0x600 => s

## meme

 checksec meme
[*] '/home/k-730/COMP6447/wk4/meme/meme'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

string to compare: 2tRiViAl
Need to make sure

## Tetris

checksec tetris
[*] '/home/k-730/COMP6447/wk4/tetris/tetris'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

    Stack is executable so we just have to run shellcode to spawn shell here
    Address of name_buff is leaked.
    write shellcode into leaked buffer
    Use this name_buff address to run shellcode
    jump to memory

00:0000│ rsp 0x7ffd3a1203f0 ◂— 0
... ↓        4 skipped
05:0028│-008 0x7ffd3a120418 ◂— 0xa0055bcf0101309
06:0030│ rbp 0x7ffd3a120420 —▸ 0x7ffd3a120450 —▸ 0x7ffd3a1204d0 ◂— 1
07:0038│+008 0x7ffd3a120428 —▸ 0x55bcf01013cf (loop+90) ◂— jmp loop+359

00:0000│ rax rcx rsp 0x7ffd3a1203f0 ◂— 0x732f6e69622fbb48
01:0008│-028         0x7ffd3a1203f8 ◂— 0xd23148f631480068 /*'h'*/
02:0010│-020         0x7ffd3a120400 ◂— 0x530000003bc0c748
03:0018│-018         0x7ffd3a120408 ◂— 0x909090050fe78948
04:0020│-010         0x7ffd3a120410 ◂— 0x9090909090909090
05:0028│-008         0x7ffd3a120418 ◂— 0x9090909090909090
06:0030│ rbp         0x7ffd3a120420 —▸ 0x7ffd3a1203f0 ◂— 0x732f6e69622fbb48
07:0038│+008         0x7ffd3a120428 —▸ 0x55bcf010000a ◂— 0x3000000000000
