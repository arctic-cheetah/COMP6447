#!/usr/bin/env python3
from pathlib import Path
import sys
import re


def main():
    in_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path("/home/leopard/COMP6447/htb/test.txt")
    )
    data = in_path.read_text(encoding="latin-1", errors="ignore")
    hexstr = re.sub(r"[^0-9a-fA-F]", "", data)  # keep only hex chars

    if len(hexstr) % 2 != 0:
        raise ValueError(f"Odd number of hex digits: {len(hexstr)}")

    b = bytes.fromhex(hexstr)

    # Print as ISO-8859-1 to preserve 1:1 byte->char mapping
    print(b.decode("latin-1"))

    # Also write outputs next to the input file


if __name__ == "__main__":
    main()
