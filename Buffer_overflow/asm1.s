.section .data
string:
  .ascii "/bin/bash"

.section .text
.globl _start

_start:
  jmp main

address:
  lea string, %esi
  xor %eax, %eax
  movb %al, 9(%esi)
  mov %esi, %ecx
  mov %eax, 14(%esi)
  mov $11, %al
  int $0x80

main:
  call address
  .string "/bin/bash"
