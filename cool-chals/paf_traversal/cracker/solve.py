from pwn import *

elf = ELF("./cracker_patched")
libc = ELF("./libc.so.6")

context.binary = elf

p = process(stdout=PIPE)
gdb.attach(p)

p.interactive()
