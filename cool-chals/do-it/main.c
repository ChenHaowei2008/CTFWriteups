//  gcc -g -o main main.c -fstack-protector-all -no-pie

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ull unsigned long long

void gift() {
  __asm__("pop %rdi; ret");
}

int main(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  char buf[0x20];
  printf("read > ");
  read(0, buf, 0x100);
  
  // let's do it!
  int a;
  int b;
  printf("idx of destination > ");
  scanf("%d", &a);
  printf("idx of source > ");
  scanf("%d", &b);
  memcpy((ull*)(buf)+a, (ull*)(buf)+b, 8);
  puts("did it!");

  return 0;
}
