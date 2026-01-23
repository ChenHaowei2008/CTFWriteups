
// gcc -o chall chall.c -fno-stack-protector -no-pie -z relro -Wno-implicit-function-declaration -lseccomp
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <seccomp.h>
#include <unistd.h>

void cleanUp()
{
    char buf[0x150] = {0};
    // oneLastShot
    fgets(buf, 0x160, stdin);
    return;
}

void taunt()
{
    pid_t pid = fork();
    if (pid == 0)
    {
        execl("./test", "test", (char *)NULL);
        perror("execl failed");
    }
}

void seccomp_()
{
    int rc;
    scmp_filter_ctx ctx;
    char *boohoo = ":(";
    char *stra = "Load Failed %s\n";
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
    {
        perror("seccomp_init");
        exit(1);
    }

    int blocked_syscalls[] = {
        SCMP_SYS(pread64),
        SCMP_SYS(readv),
        SCMP_SYS(execve),
        SCMP_SYS(readlink),
        SCMP_SYS(readahead),
        SCMP_SYS(readlinkat),
        SCMP_SYS(preadv),
        SCMP_SYS(openat),
        SCMP_SYS(openat2),
        SCMP_SYS(open),
        SCMP_SYS(creat),
        SCMP_SYS(sendfile),
        SCMP_SYS(fork),
        SCMP_SYS(execveat),
        SCMP_SYS(sendfile),
        SCMP_SYS(preadv2),
    };

    for (size_t i = 0; i < sizeof(blocked_syscalls) / sizeof(blocked_syscalls[0]); i++)
    {
        rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, blocked_syscalls[i], 0);
        if (rc < 0)
        {
            fprintf(stderr, "Failed to block syscall %d\n", blocked_syscalls[i]);
            seccomp_release(ctx);
            exit(1);
        }
    }
    rc = seccomp_load(ctx);
    if (rc < 0)
    {
        perror("seccomp_load");
        fprintf(stderr, stra, boohoo);
        seccomp_release(ctx);
        cleanUp();
    }

    seccomp_release(ctx);
}

int main()
{
    char buf[0x100];
    char s[] = "Have you heard of 'Don't Tap the Glass'?\n";
    int n = 10;
    taunt();
    seccomp_();
    memset(s, (short)n, n);
    fgets(buf, 0x150, stdin);
    return 0;
}
