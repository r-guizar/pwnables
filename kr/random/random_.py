from pwn import *

s = ssh("random", "pwnable.kr", password="guest", port=2222)

p = s.process(executable="./random", argv=["random"])

rand_val = 1804289383

target_val = int("0xdeadbeef", 16)

payload = str(target_val ^ rand_val).encode()

p.sendline(payload)

print(p.recvall())
