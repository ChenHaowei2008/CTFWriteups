#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sched.h>

#include <string.h>

int main()
{
    alarm(0x1a);
    size_t size = 4096;

    void *ptr = mmap(NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    if (ptr == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    printf("Memory mapped at %p\n", ptr);
    pid_t pid = getpid();
    printf("PID: %d\n", pid);
    *(char *)ptr = 0x41;
    while (*(char *)ptr == 0x41)
    {
        usleep(100000);
    }
    char buf[0x100];
    int fd = open("./flag", O_RDONLY);
    read(fd, buf, 0x100);
    memcpy(ptr, buf, 0x30);
    sleep(10);
}
