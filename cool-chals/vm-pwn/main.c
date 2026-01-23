#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define NUM_REGS 10
#define MAX_PROG 0x1000
#define STACK_SIZE 0x1000
#define MEM_SIZE 0x1000

#define REG(i) (vm->regs[i])

enum {
	R0,
	R1,
	R2,
	R3,
	R4,
	R5,
	R6,
	R7,
	SP,
	BP
};

typedef enum {
	SYS_READ,
	SYS_WRITE
} Syscall;

typedef enum {
	OP_HALT,
	OP_MOV,
	OP_LOADI,
	OP_LOAD, 
	OP_STORE,
	OP_ADD,
	OP_SUB,
	OP_MUL,
	OP_DIV,
	OP_PRINT,
	OP_JMP,
	OP_CALL,
	OP_RET,
	OP_SYSCALL,
	OP_ENTER,
	OP_LEAVE,
	OP_POP,
	OP_PUSH,
} Opcode;

typedef struct {
	Opcode op;
	int a;
	int b;
} Instruction;

struct {
	long regs[NUM_REGS];
	Instruction program[MAX_PROG];
	long pc;
} CPU; // god im terrible at ts

typedef struct {
	long regs[NUM_REGS];
	Instruction program[MAX_PROG];
	long pc;

	long *memory;

	long stack[STACK_SIZE];
} VM;

static bool overlaps(void *p1, size_t s1, void *p2, size_t s2) {
    char *a1 = p1, *a2 = p2;
    return (a1 < a2 + s2) && (a2 < a1 + s1);
}

int handle_read(VM *vm, int fd, char* buf, size_t size) {
    if (overlaps(buf, size, vm, sizeof(CPU))) {
        printf("Error: writing into protected VM memory\n");
        return -1;
    }

    return read(fd, buf, size);
}

int handle_write(VM *vm, int fd, char* buf, size_t size) {
    if (overlaps(buf, size, vm, sizeof(CPU))) {
        printf("Error: writing into protected VM memory\n");
        return -1;
    }

    return write(fd, buf, size);
}

void handle_syscall(VM *vm, Instruction instr) {
	switch (REG(R7)) {
		case SYS_READ: 
			REG(R7) = handle_read(vm, REG(R0), (char*)REG(R1), (size_t)REG(R2));
			break;
		case SYS_WRITE:
			REG(R7) = handle_write(vm, REG(R0), (char*)REG(R1), (size_t)REG(R2));
			break;
		default: 
			printf("Unknown syscall %d\n", REG(R7));
			return;
	}
}

void handle_call(VM *vm, Instruction instr) {
	if (REG(SP) + 1 >= STACK_SIZE) {
		printf("Error: stack overflow\n");
		return;
	}
	vm->stack[REG(SP)++] = vm->pc;
	vm->pc = instr.a;
}

void handle_ret(VM *vm) {
	if (REG(SP) <= 0) {
		printf("Error: stack underflow\n");
		return;
	}
	vm->pc = vm->stack[--REG(SP)];
}

void handle_leave(VM *vm) {
	REG(SP) = REG(BP);
	REG(BP) = vm->stack[--REG(SP)];
}

void handle_enter(VM *vm) {
	if (REG(SP) + 2 >= STACK_SIZE) {
		printf("Error: stack overflow\n");
		return;
	}
	vm->stack[REG(SP)++] = REG(BP);
	REG(BP) = REG(SP);
}

void run(VM *vm) {
	while (1) {
		Instruction instr = vm->program[vm->pc++];
		int addr = 0;

		switch (instr.op) {
			case OP_HALT: return;
			case OP_MOV: vm->regs[instr.a] = vm->regs[instr.b]; break;
			case OP_LOADI: vm->regs[instr.a] = instr.b; break;
			case OP_ADD: vm->regs[instr.a] = vm->regs[instr.a] + instr.b; break;
			case OP_SUB: vm->regs[instr.a] = vm->regs[instr.a] - instr.b; break;
			case OP_MUL: vm->regs[instr.a] = vm->regs[instr.a] * instr.b; break;
			case OP_DIV: vm->regs[instr.a] = vm->regs[instr.a] / instr.b; break;
			case OP_PRINT: printf("R%d = 0x%x\n", instr.a, vm->regs[instr.a]); break;
			case OP_JMP: vm->pc = instr.a; break;
			case OP_CALL: 
				handle_call(vm, instr);
				break;
			case OP_RET:
				handle_ret(vm);
				break;
			case OP_LOAD:
				addr = vm->regs[instr.b];
				if (addr < 0 || addr >= MEM_SIZE) {
					printf("Error: invalid memory read at %d\n", addr);
					return;
				}
				REG(instr.a) = vm->memory[addr];
				break;
			case OP_STORE:
				addr = REG(instr.a);
				if (addr < 0 || addr >= MEM_SIZE) {
					printf("Error: invalid memory read at %d\n", addr);
					return;
				}
				vm->memory[addr] = REG(instr.b);
				break;
			case OP_SYSCALL:
				handle_syscall(vm, instr);
				break;
			case OP_ENTER:
				handle_enter(vm);
				break;
			case OP_LEAVE:
				handle_leave(vm);
				break;
			case OP_PUSH:
				vm->stack[REG(SP)++] = REG(instr.a);
				break;
			case OP_POP:
				REG(instr.a) = vm->stack[--REG(SP)];
				break;
			default:
				printf("Unknown opcode %d\n", instr.op);
				return;
		}
	}
}

int main() {

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

	VM *vm = mmap((void*)0x10000, 0x100000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(vm, 0, sizeof(*vm));
	memset(vm->program, 0xff, sizeof(vm->program));

	if (vm == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	vm->memory = malloc(MEM_SIZE);
	if (vm->memory == NULL) {
		perror("malloc");
		return 1;
	}
	printf("stack: %p\n", &vm->stack);

	Instruction prog[] = {
		{OP_ENTER},
		{OP_PRINT, SP, 0},
		{OP_CALL, 7, 0},
		{OP_PRINT, SP, 0},
		{OP_PRINT, BP, 0},
		{OP_HALT},
		{0xFF},
		{OP_ENTER},
		{OP_ADD, SP, 16},
		{OP_MOV, R6, SP},
		{OP_ADD, R6, (int)((char*)&vm->stack - 0x10)},
		{OP_MOV, R1, R6},
		{OP_LOADI, R0, 0},
		{OP_LOADI, R2, 0x1000},
		{OP_LOADI, R7, SYS_READ},
		{OP_PRINT, R0, 0},
		{OP_PRINT, R1, 0},
		{OP_PRINT, R2, 0},
		{OP_PRINT, SP, 0},
		{OP_PRINT, BP, 0},
		{OP_SYSCALL, 0, 0},
		{OP_LEAVE},
		{OP_RET}
	};

	for (int i = 0; i < sizeof(prog)/sizeof(Instruction); i++) {
		vm->program[i] = prog[i];
	}

	run(vm);
	return 0;
}
