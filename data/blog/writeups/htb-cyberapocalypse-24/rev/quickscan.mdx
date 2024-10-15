---
title: HTB - Cyber Apocalypse 2024 - Rev - Quickscan
date: '2024-03-14'
tags: ['rev', 'htb', 'cyber-apocalypse', 'angr']
draft: false
summary: Utilizing angr to analyze a binary's runtime stack and extract a value.
---

## Challenge Description

![alt text](/static/writeups/htb-cyberapocalypse/image-1.png)

## Solution

Quickscan was a medium reversing challenge that simply had a docker instance through which, we'd get a binary, and all that we had to do, was send the data that binary had to the remote instance. We had to do this, for 128 binaries, in 120 seconds. The task is pretty simple.

> After talking to [72Ghoul](https://medium.com/@hexamine22), he used only pwntools to solve this. (Guess I love to make things more complex.)

So, let's see the first binary that is given to us when we connect to the remote host:

![alt text](/static/writeups/htb-cyberapocalypse/image-2.png)

Okay, so the binary given to us is base64-encoded, we'll write a simple pwntools script that'll be the basis of this:

```py:solve.py
#!/usr/bin/env python3

from pwn import *

io = remote("94.237.62.237", 57611)

io.recvuntil(b"ELF:  ")
elf = io.recvline()
write("first", base64.b64decode(elf))
```

Now, this will write the raw data to a file called `"first"`, let's analyze this:

![alt text](/static/writeups/htb-cyberapocalypse/image-3.png)

Running this in GDB, we can see that a value is generated and stored on the stack at runtime. So, we can see that the task at hand is pretty simple. One thing to keep in mind is, all of the binaries had `syscall` instruction, and were invoking `exit` syscall to exit. So, using `angr`, we can continue our execution until we reach the `exit` syscall, and simple get `rsp`, `rsp+8` and `rsp+16` values. I wrote a simple function to do this for me using `angr`:

```py:solve.py
def get_stack_value(filename="test.elf"):
    proj = angr.Project(filename, auto_load_libs=False)
    initial_state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(initial_state)
    simgr.explore(find=lambda s: s.history.jumpkind.startswith('Ijk_Sys'))
    final_state = simgr.found[0]
    stack_vals = [
        final_state.memory.load(final_state.regs.sp, final_state.arch.bits // 8),
        final_state.memory.load(final_state.regs.sp+8, final_state.arch.bits // 8),
        final_state.memory.load(final_state.regs.sp+16, final_state.arch.bits // 8)
    ]
    stack_value = ""
    for i in range(len(stack_vals)):
        stack_value += hex(final_state.solver.eval(stack_vals[i], cast_to=int))[2:].rjust(16, "0")
    return stack_value
```

Now, this function will firstly create an angr project, based on the file name that is passed to the function, default would be `test.elf`. Then, it would run the simulation manager until it gets `Ijk_Sys`, which is `syscall` instruction. When it reaches that state, then what i'm simply doing is the first 3 values stored on the stack using the stack pointer, i.e. `rsp`, `rsp+8` and `rsp+16`. Then the for loop is simply converting each value to hexadecimal and ensuring that in each case, the value is of `8-bytes`.

This was the crux of the challenge, and was pretty simple. The entire solve script that I wrote is:

```py:solve.py
#!/usr/bin/env python3

from pwn import *
import angr

def get_stack_value(filename: str = "test.elf") -> str:
    proj = angr.Project(filename, auto_load_libs=False)
    initial_state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(initial_state)
    simgr.explore(find=lambda s: s.history.jumpkind.startswith('Ijk_Sys'))
    final_state = simgr.found[0]
    stack_vals = [
        final_state.memory.load(final_state.regs.sp, final_state.arch.bits // 8),
        final_state.memory.load(final_state.regs.sp+8, final_state.arch.bits // 8),
        final_state.memory.load(final_state.regs.sp+16, final_state.arch.bits // 8)
    ]
    stack_value = ""
    for i in range(len(stack_vals)):
        stack_value += hex(final_state.solver.eval(stack_vals[i], cast_to=int))[2:].rjust(16, "0")
    return stack_value

def get_elf(filename: str = "test.elf") -> None:
    io.recvuntil(b"ELF:  ")
    data = io.recvline()
    raw_elf = base64.b64decode(data)
    write(filename, raw_elf)

io = remote("94.237.62.237", 57611)

get_elf()
io.recvuntil(b"Expected bytes: ")
send_bytes = io.recvline()[:-1]
info(f"Expected bytes: {send_bytes}")
io.sendlineafter(b"Bytes? ", send_bytes)

for i in range(128):
    get_elf()
    stack = get_stack_value()
    info(f"Extracted from stack: {stack}")
    io.sendlineafter(b"Bytes? ", stack.encode())

io.interactive()
```

This script took around 100 seconds to complete analysis of all 128-binaries, and at the end, we got the flag:

![alt text](/static/writeups/htb-cyberapocalypse/image-4.png)

I had angr on my learning-list for quite some time now and this challenge actually helped me get a better understanding of this, overall; a good fun challenge.
