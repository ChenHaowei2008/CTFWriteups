#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

void buf(){
	char max[10];
	read(0, max, 0x300);
}

int main()
{
	char max[6];
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	puts("Welcome to ARM ROP!\n");
	puts("In this guided exercise, you will learn how to pop a shell in an ARM statically-linked binary.");
	puts("In ARM, there are a total of 31 general-purpose 64-bit registers (X0-X30)");
	puts("");
	puts("	X0-X5: Argument registers");
	puts("	X8:    The syscall number");
	puts("	X29:   The stack base pointer");
	puts("	X30:   The return address");
	puts("	sp:    The stack pointer");
	puts("	pc:    The program counter");
	puts("");
	puts("Unlike x86-64, when the ret instruction is executed, instead of popping the return address from the stack into the program counter, the value in the X30 register is popped into the pc instead.");
	puts("This means just having stack control isn't enough to control execution flow!");
	puts("In order to reliably control execution flow when you only have control of the stack, you must have gadgets that actually pop values from sp into X30.");
	puts("For example:");
	puts("");
	puts("0x0000000000427454: str x0, [x1]; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x40; ret; ");
	puts("");
	puts("This stores the value of x0 into the address in x1, pops two values from sp+0x10 into x19 and x20 respectively, and then pops two values from sp into x29 and x30 before adding 0x40 to the sp register.");
	puts("");
	puts("Notice that keeping track of what offsets are added to sp at the end are very important!");
	puts("Say we wish to return to main() after our gadget:");
	puts("");
	puts("Hence, we will have to keep the following stack layout at sp:");
	puts("");
	puts("[sp]:        NULL, main()");
	puts("[sp + 0x10]: value of x19, x20");
	puts("[sp + 0x40]: <stack frame of main>");
	puts("");
	puts("Sometimes, we can't just to just rely on ret gadgets to do what we want!");
	puts("Gadgets are scarce, so we have to be creative!");
	puts("Gadgets that end with br <reg> will jump to the address in <reg> independent of sp");
	puts("For example:");
	puts("");
	puts("0x00000000004307d8: ldp x0, x1, [sp, #0x20]; ldr x16, [sp, #8]; ldr w7, [sp, #4]; ldr w6, [sp, #0x38]; add sp, sp, #0xe0; br x16; ");
	puts("");
	puts("However, in order to control execution flow, we will need to control x16 here, particularly during the ldr instruction at:");
	puts("");
	puts("ldr x16, [sp, #8]");
	puts("");
	puts("The stack layout to use this would have to look like:");
	puts("");
	puts("[sp]");
	puts("[sp + 4]:    NULL");
	puts("[sp + 8]:	   next gadget");
	puts("[sp + 0x20]: values of x0, x1");
	puts("[sp + 0xe0]: <stack frame of the next gadget>");
	puts("");
	puts("That's all! Now, try to pop a shell with the following gadgets: ");
	puts("");
	puts("0x0000000000427094: str x0, [x1]; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x40; ret; ");
	puts("0x0000000000430418: ldp x0, x1, [sp, #0x20]; ldr x16, [sp, #8]; ldr w7, [sp, #4]; ldr w6, [sp, #0x38]; add sp, sp, #0xe0; br x16; ");
	puts("0x0000000000442990: mov x8, x6; svc #0; ret; ");
	puts("0x000000000041112c: mov x2, #0; mov x3, #8; mov x8, #0x87; svc #0; ldp x29, x30, [sp], #0x20; ret; ");
	puts("");
	puts("Good luck!");
	buf();
	return 0;
}

