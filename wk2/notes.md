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
