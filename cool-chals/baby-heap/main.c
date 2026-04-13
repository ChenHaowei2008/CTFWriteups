#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void menu() {
	printf(
		"1. allocate\n"
		"2. free\n"
		"3. read\n"
		"4. edit\n"
	);
}

static int get_int(const char* prompt) {
	int num;
	printf("%s", prompt);
	fflush(stdout);
	scanf("%d*c", &num);
	return num;
}

void alloc_chunk(char **chunks) {
	int idx = get_int("idx: ");
	if (idx < 0 || idx >= 2) _exit(1);
	char* chunk = (char*)malloc(0x18);
	printf("contents: ");
	fflush(stdout);
	read(0, chunk, 0x18);
	chunks[idx] = chunk;
}

void free_chunk(char **chunks) {
	int idx = get_int("idx: ");
	if (idx < 0 || idx > 1) {
		printf("wrong index\n");
		_exit(1);
	}
	free(chunks[idx]);
}

void print_xor_system(char *chunk) {
    int eqs[8][8] = {
        {1,1,0,0,0,0,0,0}, 
        {0,1,1,0,0,0,0,0}, 
        {0,0,1,1,0,0,0,0}, 
        {0,0,0,1,1,0,0,0}, 
        {0,0,0,0,1,1,0,0}, 
        {0,0,0,0,0,1,1,0}, 
        {0,0,0,0,0,0,1,1}, 
        {1,0,0,0,0,0,0,1}  
    };

    printf("XOR system for this chunk:\n");
    for (int i = 0; i < 8; i++) {
        unsigned char xor_val = 0;
        printf("Equation %d: ", i);
        for (int j = 0; j < 8; j++) {
            if (eqs[i][j]) {
                xor_val ^= chunk[j];
                printf("c%d ", j);
            }
        }
        printf("= 0x%02x\n", xor_val);
    }
}

void read_chunk(char **chunks) {
    int idx = get_int("idx: ");
    if (idx < 0 || idx >= 2) _exit(1);

    print_xor_system(chunks[idx]);  
}

void edit_chunk(char **chunks) {
	int idx = get_int("idx: ");
	if (idx < 0 || idx > 1) _exit(1);
	printf("content: ");
	fflush(stdout);
	read(0, chunks[idx], 0x18);
}

int main() {
	setbuf(stdin, NULL);
	int choice = 0;
	char *chunks[2] = {0};

	char *test = malloc(0x18);
	char *buf = malloc(0x400);
	setvbuf(stdout, buf, _IOLBF, 0x400);
	int count = 0;

	while (1) {
		menu();
		choice = get_int(">> ");
		switch (choice) {
			case 1: alloc_chunk(chunks); break;
			case 2: free_chunk(chunks); break;
			case 3: {
				if (count == 0)
					read_chunk(chunks); 
				count++;
				break;
			}
			case 4: edit_chunk(chunks); break;
			default: break;
		}
	}
}
