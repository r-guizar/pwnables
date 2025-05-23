from pwn import *

p = remote("pwnable.kr", 9007)

total = 0

p.recvuntil(b'\nN=')

n, c = map(int, ''.join(p.recvline().decode().split()).split('C='))
# print(f'n = {n}\nc = {c}')

while total != 100:

    num = 0
    low = 0
    high = n - 1 

    while low <= high and c > 0:

        mid = (low + high) // 2
        send = ' '.join([str(i) for i in range(low, mid + 1)]).encode()
        p.sendline(send)

        num = p.recvline().decode().strip()
        
        weight = int(num)
        
        if weight % 10 == 0:
            low = mid + 1
        else:
            high = mid - 1

        c -= 1

        # print(f'Searched [{low} to {high}]')
        # print(num)

    while c > 0:

        p.sendline("0".encode())
        p.recv(1024)
        c -= 1

    p.sendline(str(low).encode())
    p.recvuntil(b'\nN=')
    n, c = map(int, ''.join(p.recvline().decode().split()).split('C='))
    # print(f'n = {n}\nc = {c}')
    total += 1
    print(total)

print(p.recvall())

p.close()