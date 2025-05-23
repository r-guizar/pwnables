# DOESNT WORK, JUST USED GDB TO FIND THE STRING
from pwn import *

s = ssh('blukat', "pwnable.kr", port=2222, password='guest')

p = s.process('./blukat')

print(p.recvuntil(b'!\n').decode())

payload = b''
payload += b'A' * 100       # fill the buffer
payload += p32(1337)        # overwrite canary
payload += p32()

p.sendline('1'.encode())

print(p.recvall().decode())
