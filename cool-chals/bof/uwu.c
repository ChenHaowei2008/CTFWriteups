// gcc uwu.c -o uwu -fno-stack-protector

#include <stdlib.h>
#include <stdio.h>

int main() {
    setbuf(stdout, NULL);
    char buffer[100];
    int canary = 0x1337; 

    printf("Cat is at: %p\n", main);

    puts("Can I haz buffer overflow?");
    fgets(buffer, 1000, stdin); // :O

    if (canary == 0x1337) {
        puts("No you can haz no buffer overflow :<");
    }

}

void overflow() {
    puts("Yes you can haz buffer overflow! :3");

    char flag[100];    
    FILE *f = fopen("flag.txt", "r");
    
    fgets(flag, 100, f);
    fclose(f);

    printf("%s", flag);

}

