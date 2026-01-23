#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

size_t sizes[0x10];

const char menu_str[] = 
	"1. create\n"
	"2. delete\n"
	"3. edit\n"
	"4. beer\n"
	">> ";

void beer(void) {
	static const char* banner = "there's only one beer left";
	puts(banner);
}

void menu(void) {
	write(1, menu_str, strlen(menu_str));
}

void create(char **chunks) {
	int idx;
	size_t size;
	write(1, "idx: ", 5);
	scanf("%d", &idx);

	if (idx < 0 || idx >= 0x10)
		_exit(1);

	write(1, "size: ", 6);
	scanf("%zu", &size);

	if (size > 0x90)
		_exit(1);

	chunks[idx] = (char*)malloc(size);
	sizes[idx] = size;
}

void delete(char **chunks) {
	int idx;
	write(1, "idx: ", 5);
	scanf("%d", &idx);

	if (idx < 0 || idx >= 0x10)
		_exit(1);

	free(chunks[idx]);
}

void edit(char **chunks) {
	int idx;
	write(1, "idx: ", 5);
	scanf("%d", &idx);

	if (idx < 0 || idx >= 0x10)
		_exit(1);

	write(1, "data: ", 6);
	read(0, chunks[idx], sizes[idx]);
}

int main() {
	int beers = 0;
	int choice;
	char **chunks;

	setbuf(stdout, NULL);
	setbuf(stdin, NULL);

	chunks = calloc(sizeof(char *), 0x10);
	printf("chunks: %p\n", chunks);
	while (1) {
		menu();
		scanf("%d", &choice);

		switch (choice) {
			case 1: create(chunks); break;
			case 2: delete(chunks); break;
			case 3: edit(chunks); break;
			case 4: {
				if (beers > 0)
					continue;
				beer();
				beers++;

			} 
		}
	}
}
