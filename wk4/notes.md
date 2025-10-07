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

Cannot overrwrite the return address (SHSTK) so I need to perform GOT on printf

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
