#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct _IO_FILE_plus
{
  FILE file;
  void *vtable;
};

struct Log {
    char name[0x100];
    struct _IO_FILE_plus fp;
    int open;
};

struct Log *global_log;

void menu() {
    puts("1. Create log");
    puts("2. Write entry");
    puts("3. Change name");
    puts("4. Show log");
    puts("5. Free log");
    puts("6. Exit");
    printf("> ");
}

void create_log() {
    global_log = malloc(sizeof(struct Log));
    printf("Log: %p\n", global_log);
    memset(global_log, 0, sizeof(struct Log));
    FILE *tmp = tmpfile();
    memcpy(&global_log->fp, tmp, sizeof(struct _IO_FILE_plus));
    strcpy(global_log->name, "journal");
    global_log->open = 1;
    puts("Log created.");
}

void show_entry() {
    if (!global_log) {
        puts("No log.");
        return;
    }
    printf("Entry: ");
    char buf[0x100];
    memset(buf, 0, sizeof(buf));
    fgets(buf, 0x100, &global_log->fp.file);
    printf("%s", buf);
    return;
}

void write_entry() {
    if (!global_log || !global_log->open) {
        puts("No log.");
        return;
    }
    char buf[128];
    printf("Entry: ");
    read(0, buf, 128);
}

void free_log() {
    if (!global_log) {
        puts("No log.");
        return;
    }
    fflush(&global_log->fp.file);
    global_log = NULL;
    puts("Log freed.");
}

void change_name() {
    if (!global_log) {
        puts("No log.");
        return;
    }
    printf("Name: ");
    read(0, global_log->name, sizeof(struct Log));
    puts("Name changed.");
    return;
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
    int choice;
    while (1) {
        menu();
        if (scanf("%d%*c", &choice) != 1) break;
        switch (choice) {
            case 1: create_log(); break;
            case 2: write_entry(); break;
            case 3: change_name(); break;
            case 4: show_entry(); break;
            case 5: free_log(); break;
            case 6: exit(0);
            default: puts("Invalid."); break;
        }
    }
}
