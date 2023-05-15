# Strings
Points: 10
Points I think it should give: 10
easy

Description:
~~~
Strings might be helpful but that's not all...

**Author:** BrokenAppendix#7091
~~~
I have been doing this challenge on and off for a while until today I finally solved it. 

What allowed me to solve it was to realize that the description was complete garbage and I used gdb and dissassembled main. This gave me some sussy hex codes. They were encoded in little endian so here is my code to decode them.

```
nums = [0x0,0x656469,0x737b6b,0x315274,0x73346e,0x54375f,0x212157,0x7d]
  
nums = [int(num).to_bytes(4, 'little') for num in nums]
nums = b''.join(nums)
nums = [chr(num) for num in nums if num != b'\x00']
print(''.join(nums))
```

flag: idek{stR1n4s_7TW!!}
