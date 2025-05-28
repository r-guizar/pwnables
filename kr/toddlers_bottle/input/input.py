from pwn import *

arg = ['A' for _ in range (100)]
arg[0] = "./input"
arg[65] = '\x00'
arg[66] = '\x20\x0a\x0d'
arg[67] = '4445'

r0, w0 = os.pipe()
r2, w2 = os.pipe()

p = process(argv=arg, env={'\xde\xad\xbe\xef':'\xca\xfe\xba\xbe'} ,stdin = r0, stderr = r2)

os.write(w0, b"\x00\x0a\x00\xff")
os.write(w2, b"\x00\x0a\x02\xff")

with open('/tmp/\x0a', 'w') as f:
    f.write('\x00\x00\x00\x00')

conn = remote('localhost', 4445)
conn.sendline(b'\xde\xad\xbe\xef')

print(p.recvuntil('Stage 5 clear!\n').decode())
