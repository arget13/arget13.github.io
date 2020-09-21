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
{% highlight C %}
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
