// gcc -o chal chal.c -fstack-protector-all -pie -fpie -Wl,-z,relro,-z,now
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// constants (not important to you)
#define STR_MALLOC 0x1000
#define PRINT_TIME 10

// ansi escape codes
#define CLEAR_SCREEN "\033[2J\033[H"

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BRIGHT_RED "\033[91m"
#define BRIGHT_GREEN "\033[92m"
#define BRIGHT_YELLOW "\033[93m"

#define BOLD "\033[1m"
#define UNDERLINE "\033[4m"

#define RESET "\033[0m"

// tutorial mode!
char TUTORIAL_MODE = 'Y';

enum state {
    INIT,
    LEAK,
    WRITE
};

enum state current_state = INIT;

void tutorial_print(const char* fmt, ...) {
    char* buf = malloc(STR_MALLOC);
    va_list args;
    va_start(args, fmt);
    if  (TUTORIAL_MODE=='Y') {
        int res = vsnprintf(buf, STR_MALLOC - 1, fmt, args);
        for (int i = 0; i < strlen(buf); i++) {
            putchar(buf[i]);
            usleep(PRINT_TIME * 1000);
        };
    };
    va_end(args);
    free(buf);
}

void pick_mode() {
    printf(CLEAR_SCREEN);
    printf(
            "%s\n%s\n\n%s",
            "Welcome to baby WWW2Exec!",
            "Before we get started, would you like to have a guide/tutorial?",
            "Y/N (uppercase) > "
          );
    char opt = getchar();

    // discard buf
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
    }

    if (opt != 'N' && opt != 'Y') {
        printf(
                "%s%s\n\n%s",
                RED,
                "Invalid option. Defaulting to normal mode.",
                RESET
              );
        TUTORIAL_MODE = 'N';
    }

    if (opt == 'Y') {
        tutorial_print(
                "%s%s\n\n%s",
                GREEN,
                "Tutorial mode chosen! I'll guide you along this challenge.",
                RESET
                );
    }

    if (opt == 'N') {
        printf(
                "%s%s\n\n%s",
                YELLOW,
                "Good luck, you're on your own now.",
                RESET
              );
        TUTORIAL_MODE='N';
    }
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    pick_mode();
    printf(CLEAR_SCREEN);

    char buf[512];

    if (TUTORIAL_MODE == 'Y') {
        tutorial_print(
                "%s%sWelcome to baby WWW2Exec!%s\n\n"

                "This challenge is all about achieving Remote Code Execution (RCE) using a format string vulnerability.\n"
                "Let’s break down what the program is doing — and how you can abuse it.\n\n"

                "Here’s the core issue in the code:\n\n"
                "    fgets(buf, sizeof(buf), stdin);\n"
                "    printf(buf);\n\n"

                "%sDanger!%s Your input is passed directly to printf — classic %sformat string vulnerability%s.\n"
                "This lets you both %sleak%s memory and %swrite%s to arbitrary addresses using format specifiers!\n\n",

                BOLD, BRIGHT_YELLOW, RESET,
                BRIGHT_RED, RESET,
                BRIGHT_YELLOW, RESET,
                BRIGHT_GREEN, RESET, BRIGHT_RED, RESET
                );

        // Leak demo
        char* payloads[] = {
            "%1$p", "%2$p", "%3$p", "%4$p", "%5$p", 
            "%6$p", "%7$p", "%8$p", "%9$p", "%10$p"
        };

        tutorial_print("| %-8s | %-18s |\n", "Input", "Leaked Value");
        tutorial_print("|----------|--------------------|\n");
        for (int i = 0; i < 10; i++) {
            char buffer[64];
            snprintf(buffer, sizeof(buffer), payloads[i]);
            tutorial_print("| %-8s | %-18s |\n", payloads[i], buffer);
        }

        tutorial_print(
                "\nFormat specifiers like %%p let you inspect the stack.\n"
                "Even more powerful: %%n writes the number of printed bytes to a memory address — the key to arbitrary writes!\n\n"

                "Let’s now look at the protections enabled on this binary:\n\n"

                "  %s• Stack Canaries:%s Detect stack-based buffer overflows.\n"
                "    ➤ But format strings avoid overflowing — we write directly to memory using %%n.\n\n"

                "  %s• PIE (Position Independent Executable):%s Randomizes binary load addresses.\n"
                "    ➤ Use format string leaks to reveal addresses and defeat PIE.\n\n"

                "  %s• Full RELRO:%s Makes the GOT read-only to prevent overwriting function pointers.\n"
                "    ➤ With GOT off the table, you can still write to the stack, return addresses, TLS DTORS, or __exit_funcs.\n\n"

                "%sSo how do we build a precise write payload?%s\n\n"
                "Typing out %%n chains manually is painful. Thankfully, %spwntools has your back.%s\n\n"

                "Use %sfmtstr_payload(offset, {addr: value})%s to generate a format string that writes exactly what you want.\n"
                "It even handles writing large values across multiple %%hn or %%n calls if needed.\n\n"
                "Example in Python:\n\n"
                "    from pwn import *\n"
                "    payload = fmtstr_payload(6, {0x40404040: 0xdeadbeef})\n"
                "    sendline(payload)\n\n"
                "Here, pwntools assumes that the 6th stack argument is where your input buffer is on the stack, and it builds a payload to write 0xdeadbeef to 0x40404040.\n\n"

                "How do you find the offset? Spam %%p or %%x until your input shows up, then count how many entries deep it is — that's your offset.\n\n"

                "%sStep-by-step exploitation plan:%s\n\n"
                "  1. %sLeak a stack address%s using %%p — this helps you locate your input buffer and the return address.\n"
                "  2. %sLeak a libc address%s on the stack — useful for calculating libc base.\n"
                "  3. %sCalculate where to write%s — either the return address or a function pointer in __exit_funcs.\n"
                "  4. %sUse fmtstr_payload()%s to build a format string that writes your chosen address (e.g., a one_gadget or ROP chain).\n"
                "  5. %sSend your payload%s — and pop your shell!\n\n"

                "%sYour mission:%s Leak addresses, compute offsets, and write values into memory to hijack execution.\n"
                "Stack ROP chains, DTORS table hijacking, libc gadget jumps — you name it.\n\n"
                "%sGo forth and format the world :)%s\n",

            BRIGHT_GREEN, RESET,
            BRIGHT_GREEN, RESET,
            BRIGHT_GREEN, RESET,

            BOLD, RESET,
            BRIGHT_YELLOW, RESET,
            BRIGHT_GREEN, RESET,
            BOLD, RESET

            BRIGHT_GREEN, RESET
            BRIGHT_GREEN, RESET,
            BRIGHT_GREEN, RESET,
            BRIGHT_GREEN, RESET,
            BRIGHT_GREEN, RESET,
            BRIGHT_GREEN, RESET,
            BOLD, RESET,
            BOLD, RESET
                );

        tutorial_print("Continue? (Y/N) > ");
        char opt = getchar();

        // discard buf
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
        }
        if (opt == 'Y') {
            printf(CLEAR_SCREEN);
            current_state += 1;
        }
    }


    while (1) {
        if (current_state == LEAK) {
            tutorial_print(
                    "\n%s[ LEAK PHASE ]%s\n\n"
                    "The first step is to leak key addresses from memory using format strings like %%p.\n"
                    "You're looking for:\n"
                    "  • Stack addresses (to locate your input buffer)\n"
                    "  • Libc pointers (to calculate the base of libc)\n\n"

                    "%sHow do you find where your input is on the stack?%s\n"
                    "Try a format string like:\n\n"
                    "    %%1$p %%2$p %%3$p %%4$p ...\n\n"
                    "Then look for where your exact input appears in the output.\n"
                    "The number where it shows up is your offset!\n\n"

                    "%sHow to verify and inspect it using pwndbg:%s\n\n"
                    " 1. Run the program in GDB with pwndbg:\n"
                    "      gdb ./chal\n\n"
                    " 2. Set a breakpoint at the vulnerable printf (e.g., after the `printf(buf)` line).\n"
                    "      b *main+X   (replace X with the offset to the call)\n\n"
                    " 3. Run the binary:\n"
                    "      r\n"
                    "      > %%1$p %%2$p %%3$p ...\n\n"
                    " 4. When it breaks, use this to see stack args:\n"
                    "      check the $rsi, $rdx, $rcx, $r8, $r9 registers for the outputs of %%1$p to %%5$p respectively\n"
                    "      x/40gx $rsp      ← shows 40 8-byte values from the stack\n"
                    "      x/s $rsp+OFFSET  ← to read strings or inspect specific locations\n\n"
                    " 5. Use `vmmap` to identify regions like libc, stack, heap, PIE base, etc.\n\n"

                    "Once you've identified:\n"
                    "  ✓ Your input offset (e.g., input is argument #6)\n"
                    "  ✓ A stack pointer \n\n"
                    "  ✓ A libc pointer (e.g., leaked puts@libc)\n\n"
                    "You can use GDB to set a breakpoint at main, and then use `info frame` to get the offset of the return address (saved rip) from your stack pointer\n"
                    "Similarly, you can use the libc base in %svmmap%s to calculate the offset of libc pointer from the libc base\n",

                BRIGHT_YELLOW, RESET,
                BRIGHT_GREEN, RESET,
                BRIGHT_GREEN, RESET,
                BRIGHT_GREEN, RESET,
                BRIGHT_YELLOW, RESET
                    );
        } else if (current_state == WRITE) {
            tutorial_print(
                    "\n%s[ WRITE PHASE ]%s\n\n"
                    "Now that you've leaked enough information, it's time to put your arbitrary write primitive to use.\n\n"

                    "%sRecap of what you should have:%s\n"
                    "  ✓ Stack offset (e.g., your input is at %%6$p)\n"
                    "  ✓ A known writable memory location (e.g., stack return address, TLS DTORS, etc.)\n"
                    "  ✓ libc base (from a leaked libc pointer)\n\n"

                    "%sNow, how do we write what we want, where we want?%s\n"
                    "Use pwntools’ %sfmtstr_payload()%s function!\n\n"

                    "Example:\n"
                    "    from pwn import *\n"
                    "    payload = fmtstr_payload(6, {0x40404040: 0xdeadbeef})\n"
                    "    sendline(payload)\n\n"
                    "This builds a format string that writes 0xdeadbeef to 0x40404040,\n"
                    "assuming your input is at the 6th position on the stack.\n\n"

                    "%sWhere can you write to hijack control flow?%s\n"
                    "  • The saved return address on the stack (classic ROP)\n"
                    "  • __exit_funcs or TLS DTORS (called at exit)\n"
                    "  • Any function pointer that runs later (e.g., fini_array)\n\n"

                    "Let's Begin.\n\n"

                    "Start by creating the ROP chain you wish to write onto the return address: \n"
                    "    from pwn import *\n"
                    "    rop = ROP(libc)\n"
                    "    rop.raw(rop.ret[0])\n"
                    "    rop.system(next(libc.search(b'/bin/sh\\0')))\n\n"

                    "Next, write your ROP chain to the return address: \n"
                    "    payload = fmtstr_payload(stack_offset, {ret: rop.chain()})\n\n"

                    "Example:\n"
                    "    from pwn import *\n"
                    "    payload = fmtstr_payload(6, {0x40404040: 0xdeadbeef})\n"
                    "    sendline(payload)\n\n"

                    "%sBreak it :)%s\n",

                BRIGHT_YELLOW, RESET,
                BRIGHT_GREEN, RESET,
                BRIGHT_YELLOW, RESET,
                BRIGHT_YELLOW, RESET,
                BRIGHT_GREEN, RESET,
                BRIGHT_GREEN, RESET,
                BRIGHT_GREEN, RESET,
                BOLD, RESET
                    );
        }


        printf("> ");
        fgets(buf, sizeof(buf), stdin);
        printf("You said: ");
        printf(buf);
        current_state += 1;

        printf("Exit? (Y/N) ");
        char opt = getchar();

        int c;
        while ((c = getchar()) != '\n' && c != EOF) {}
        if (opt == 'Y') {
            break;
        }
    }

    return 0;
}
