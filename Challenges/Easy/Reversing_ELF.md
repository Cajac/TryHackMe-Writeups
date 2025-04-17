# Reversing ELF

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Room for beginner Reverse Engineering CTF players
```

Room link: [https://tryhackme.com/r/room/reverselfiles](https://tryhackme.com/r/room/reverselfiles)

## Solution

### Crackme1

We begin by checking the file type with `file`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ file crackme1          
crackme1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=672f525a7ad3c33f190c060c09b11e9ffd007f34, not stripped
```

We have a 64-bit [ELF file](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format).

Let's run it and see what happens?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ chmod +x crackme1                                      

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme1          
flag{<REDACTED>}
```

Ah, I gave us the flag directly.

### Crackme2

This time we have a 32-bit ELF file

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ file crackme2
crackme2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b799eb348f3df15f6b08b3c37f8feb269a60aba7, not stripped
```

Again we run it to get more information

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ chmod +x crackme2

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme2 
Usage: ./crackme2 password
         
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme2 test
Access denied.
```

We need a password.

Let's check for possible passwords with `strings`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ strings -n 8 crackme2
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
__libc_start_main
/usr/local/lib:$ORIGIN
__gmon_start__
GLIBC_2.0
Usage: %s password
super_secret_password
Access denied.
Access granted.
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.9) 5.4.0 20160609
<---snip--->
```

The password is likely `super_secret_password`.

We verify it by inputting the password to the program

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme2 super_secret_password
Access granted.
flag{<REDACTED>}
```

Yes, the password was correct!

### Crackme3

We have another 32-bit ELF file

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ file crackme3
crackme3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=4cf7250afb50109f0f1a01cc543fbf5ba6204a73, stripped
```

Next, we run it to get more information

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ chmod +x crackme3               

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme3                      
Usage: ./crackme3 PASSWORD
```

We need another password.

Let's check for possible passwords with `strings`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ strings -n 8 crackme3
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
__libc_start_main
GLIBC_2.0
Usage: %s PASSWORD
malloc failed
ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==
Correct password!
Come on, even my aunt Mildred got this one!
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
GCC: (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3
<---snip--->
```

The long string ending with two equal signs looks like a [base64 encoded](https://en.wikipedia.org/wiki/Base64) string.

Let's try to decode it

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ echo 'ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==' | base64 -d
f0r_<REDACTED>_7h1ng5  
```

Finally, we verify the password

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme3 f0r_<REDACTED>_7h1ng5                          
Correct password!
```

### Crackme4

Now we have a 64-bit ELF file again

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ file crackme4 
crackme4: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=862ee37793af334043b423ba50ec91cfa132260a, not stripped
```

As usual we execute for further information

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ chmod +x crackme4

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme4                                               
Usage : ./crackme4 password
This time the string is hidden and we used strcmp
```

Since the program is dynamically linked we can see the call to `strcmp` with `ltrace`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ltrace ./crackme4 fake
__libc_start_main(0x400716, 2, 0x7fffaf3ee878, 0x400760 <unfinished ...>
strcmp("my_<REDACTED>_pwd", "fake")                                                                              = 7
printf("password "%s" not OK\n", "fake"password "fake" not OK
)                                                                          = 23
+++ exited (status 0) +++
```

The password seems to be `my_<REDACTED>_pwd`.

Let's verify it

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme4 my_<REDACTED>_pwd
password OK
```

### Crackme5

First, we run the program to see how it behaves

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ chmod +x crackme5

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme5                   
Enter your input:
this_is_a_test
Always dig deeper
```

Let's open the file in [Ghidra](https://ghidra-sre.org/) and decompile it.  
Import the file in Ghidra and analyze it with the default settings.  
Double-click on the `main` function to show the decompiled version of it.

```C
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined local_58 [32];
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined local_35;
  undefined local_34;
  undefined local_33;
  undefined local_32;
  undefined local_31;
  undefined local_30;
  undefined local_2f;
  undefined local_2e;
  undefined local_2d;
  undefined local_2c;
  undefined local_2b;
  undefined local_2a;
  undefined local_29;
  undefined local_28;
  undefined local_27;
  undefined local_26;
  undefined local_25;
  undefined local_24;
  undefined local_23;
  undefined local_22;
  undefined local_21;
  undefined local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 0x4f;
  local_37 = 0x66;
  local_36 = 100;
  local_35 = 0x6c;
  local_34 = 0x44;
  local_33 = 0x53;
  local_32 = 0x41;
  local_31 = 0x7c;
  local_30 = 0x33;
  local_2f = 0x74;
  local_2e = 0x58;
  local_2d = 0x62;
  local_2c = 0x33;
  local_2b = 0x32;
  local_2a = 0x7e;
  local_29 = 0x58;
  local_28 = 0x33;
  local_27 = 0x74;
  local_26 = 0x58;
  local_25 = 0x40;
  local_24 = 0x73;
  local_23 = 0x58;
  local_22 = 0x60;
  local_21 = 0x34;
  local_20 = 0x74;
  local_1f = 0x58;
  local_1e = 0x74;
  local_1d = 0x7a;
  puts("Enter your input:");
  __isoc99_scanf(&DAT_00400966,local_58);
  iVar1 = strcmp_(local_58,&local_38);
  if (iVar1 == 0) {
    puts("Good game");
  }
  else {
    puts("Always dig deeper");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The string we are looking for is divided up into bytes/chars and is hex-encoded.  
Let's change the hex-values by right-clicking on each of them and show them as `Char` instead

```C
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 'O';
  local_37 = 'f';
  local_36 = 'd';
  local_35 = 'l';
  local_34 = 'D';
  local_33 = 'S';
  local_32 = 'A';
  local_31 = '|';
<---snip--->
```

Much better! Now we can create the password manually from each character.

Alternatively, we can get the password by debugging the program with `gdb` and the [GEF extension](https://hugsy.github.io/gef/)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ gdb-gef -q crackme5
Reading symbols from crackme5...
(No debugging symbols found in crackme5)
Error while writing index for `/mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Reversing_ELF/crackme5': No debugging symbols
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.01ms using Python engine 3.11
gef➤  disass main
Dump of assembler code for function main:
   0x0000000000400773 <+0>:     push   rbp
   0x0000000000400774 <+1>:     mov    rbp,rsp
   0x0000000000400777 <+4>:     sub    rsp,0x70
   0x000000000040077b <+8>:     mov    DWORD PTR [rbp-0x64],edi
   0x000000000040077e <+11>:    mov    QWORD PTR [rbp-0x70],rsi
   0x0000000000400782 <+15>:    mov    rax,QWORD PTR fs:0x28
   0x000000000040078b <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000040078f <+28>:    xor    eax,eax
   0x0000000000400791 <+30>:    mov    BYTE PTR [rbp-0x30],0x4f
   0x0000000000400795 <+34>:    mov    BYTE PTR [rbp-0x2f],0x66
   0x0000000000400799 <+38>:    mov    BYTE PTR [rbp-0x2e],0x64
   0x000000000040079d <+42>:    mov    BYTE PTR [rbp-0x2d],0x6c
   0x00000000004007a1 <+46>:    mov    BYTE PTR [rbp-0x2c],0x44
   0x00000000004007a5 <+50>:    mov    BYTE PTR [rbp-0x2b],0x53
   0x00000000004007a9 <+54>:    mov    BYTE PTR [rbp-0x2a],0x41
   0x00000000004007ad <+58>:    mov    BYTE PTR [rbp-0x29],0x7c
   0x00000000004007b1 <+62>:    mov    BYTE PTR [rbp-0x28],0x33
   0x00000000004007b5 <+66>:    mov    BYTE PTR [rbp-0x27],0x74
   0x00000000004007b9 <+70>:    mov    BYTE PTR [rbp-0x26],0x58
   0x00000000004007bd <+74>:    mov    BYTE PTR [rbp-0x25],0x62
   0x00000000004007c1 <+78>:    mov    BYTE PTR [rbp-0x24],0x33
   0x00000000004007c5 <+82>:    mov    BYTE PTR [rbp-0x23],0x32
   0x00000000004007c9 <+86>:    mov    BYTE PTR [rbp-0x22],0x7e
   0x00000000004007cd <+90>:    mov    BYTE PTR [rbp-0x21],0x58
   0x00000000004007d1 <+94>:    mov    BYTE PTR [rbp-0x20],0x33
   0x00000000004007d5 <+98>:    mov    BYTE PTR [rbp-0x1f],0x74
   0x00000000004007d9 <+102>:   mov    BYTE PTR [rbp-0x1e],0x58
   0x00000000004007dd <+106>:   mov    BYTE PTR [rbp-0x1d],0x40
   0x00000000004007e1 <+110>:   mov    BYTE PTR [rbp-0x1c],0x73
   0x00000000004007e5 <+114>:   mov    BYTE PTR [rbp-0x1b],0x58
   0x00000000004007e9 <+118>:   mov    BYTE PTR [rbp-0x1a],0x60
   0x00000000004007ed <+122>:   mov    BYTE PTR [rbp-0x19],0x34
   0x00000000004007f1 <+126>:   mov    BYTE PTR [rbp-0x18],0x74
   0x00000000004007f5 <+130>:   mov    BYTE PTR [rbp-0x17],0x58
   0x00000000004007f9 <+134>:   mov    BYTE PTR [rbp-0x16],0x74
   0x00000000004007fd <+138>:   mov    BYTE PTR [rbp-0x15],0x7a
   0x0000000000400801 <+142>:   mov    edi,0x400954
   0x0000000000400806 <+147>:   call   0x400570 <puts@plt>
   0x000000000040080b <+152>:   lea    rax,[rbp-0x50]
   0x000000000040080f <+156>:   mov    rsi,rax
   0x0000000000400812 <+159>:   mov    edi,0x400966
   0x0000000000400817 <+164>:   mov    eax,0x0
   0x000000000040081c <+169>:   call   0x4005c0 <__isoc99_scanf@plt>
   0x0000000000400821 <+174>:   lea    rdx,[rbp-0x30]
   0x0000000000400825 <+178>:   lea    rax,[rbp-0x50]
   0x0000000000400829 <+182>:   mov    rsi,rdx
   0x000000000040082c <+185>:   mov    rdi,rax
   0x000000000040082f <+188>:   call   0x4006d6 <strcmp_>
   0x0000000000400834 <+193>:   mov    DWORD PTR [rbp-0x54],eax
   0x0000000000400837 <+196>:   cmp    DWORD PTR [rbp-0x54],0x0
   0x000000000040083b <+200>:   jne    0x400849 <main+214>
   0x000000000040083d <+202>:   mov    edi,0x400969
   0x0000000000400842 <+207>:   call   0x400570 <puts@plt>
   0x0000000000400847 <+212>:   jmp    0x400853 <main+224>
   0x0000000000400849 <+214>:   mov    edi,0x400973
   0x000000000040084e <+219>:   call   0x400570 <puts@plt>
   0x0000000000400853 <+224>:   mov    eax,0x0
   0x0000000000400858 <+229>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x000000000040085c <+233>:   xor    rcx,QWORD PTR fs:0x28
   0x0000000000400865 <+242>:   je     0x40086c <main+249>
   0x0000000000400867 <+244>:   call   0x400590 <__stack_chk_fail@plt>
   0x000000000040086c <+249>:   leave
   0x000000000040086d <+250>:   ret
End of assembler dump.
```

We set a breakpoint at the `strcmp` call and run the program

```text
gef➤  break *main+188
Breakpoint 1 at 0x40082f
gef➤  run
Starting program: /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Reversing_ELF/crackme5 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter your input:
test_pw

Breakpoint 1, 0x000000000040082f in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdcd0  →  0x0077705f74736574 ("test_pw"?)
$rbx   : 0x00007fffffffde38  →  0x00007fffffffe1ab  →  "/mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Reversing_E[...]"
$rcx   : 0x0               
$rdx   : 0x00007fffffffdcf0  →  "Ofdl<REDACTED>tXtz"
$rsp   : 0x00007fffffffdcb0  →  0x00007fffffffde38  →  0x00007fffffffe1ab  →  "/mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Reversing_E[...]"
$rbp   : 0x00007fffffffdd20  →  0x0000000000000001
$rsi   : 0x00007fffffffdcf0  →  "Ofdl<REDACTED>tXtz"
$rdi   : 0x00007fffffffdcd0  →  0x0077705f74736574 ("test_pw"?)
$rip   : 0x000000000040082f  →  <main+188> call 0x4006d6 <strcmp_>
$r8    : 0xa               
$r9    : 0xffffffffffffffff
$r10   : 0x0               
$r11   : 0x0               
$r12   : 0x0               
<---snip--->
```

We can see the password as a string in both the `RDX` and `RSI` registers.

Finally we verify the password

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme5                             
Enter your input:
Ofdl<REDACTED>tXtz
Good game
```

And we were correct!

### Crackme6

As before, we run the program to see what happens

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme6
Usage : ./crackme6 password
Good luck, read the source

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme6 test_pw
password "test_pw" not OK
```

Let's decompile in Ghidra. The `main` function looks like this

```C
undefined8 main(int param_1,undefined8 *param_2)

{
  if (param_1 == 2) {
    compare_pwd(param_2[1]);
  }
  else {
    printf("Usage : %s password\nGood luck, read the source\n",*param_2);
  }
  return 0;
}
```

The `compare_pwd` function looks like this

```C
void compare_pwd(undefined8 param_1)

{
  int iVar1;
  
  iVar1 = my_secure_test(param_1);
  if (iVar1 == 0) {
    puts("password OK");
  }
  else {
    printf("password \"%s\" not OK\n",param_1);
  }
  return;
}
```

And the `my_secure_test` function is decompiled to this

```C
undefined8 my_secure_test(char *param_1)

{
  undefined8 uVar1;
  
  if ((*param_1 == '\0') || (*param_1 != '1')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[1] == '\0') || (param_1[1] != '3')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[2] == '\0') || (param_1[2] != '3')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[3] == '\0') || (param_1[3] != '7')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[4] == '\0') || (param_1[4] != '_')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[5] == '\0') || (param_1[5] != 'p')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[6] == '\0') || (param_1[6] != 'w')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[7] == '\0') || (param_1[7] != 'd')) {
    uVar1 = 0xffffffff;
  }
  else if (param_1[8] == '\0') {
    uVar1 = 0;
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}
```

Here the password is shorter and is again compared character by character.

Let's verify it

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme6 1<REDACTED>d
password OK
```

### Crackme7

As usual, we run the program to get more information

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ chmod +x crackme7

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme7
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 1
What is your name? Cajac
Hello, Cajac!
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 2
Enter first number: 11
Enter second number: 22
11 + 22 = 33
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 3
Goodbye!
```

Nothing really interesting there.

Time to decompile in Ghidra. The `main` function looks like this

```C
undefined4 main(void)

{
  int iVar1;
  undefined4 *puVar2;
  byte bVar3;
  undefined4 local_80 [25];
  int local_1c;
  int local_18;
  int local_14;
  undefined *local_10;
  
  bVar3 = 0;
  local_10 = &stack0x00000004;
  while( true ) {
    while( true ) {
      puts("Menu:\n\n[1] Say hello\n[2] Add numbers\n[3] Quit");
      printf("\n[>] ");
      iVar1 = __isoc99_scanf(&DAT_08048814,&local_14);
      if (iVar1 != 1) {
        puts("Unknown input!");
        return 1;
      }
      if (local_14 != 1) break;
      printf("What is your name? ");
      puVar2 = local_80;
      for (iVar1 = 0x19; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar2 = 0;
        puVar2 = puVar2 + (uint)bVar3 * -2 + 1;
      }
      iVar1 = __isoc99_scanf(&DAT_0804883a,local_80);
      if (iVar1 != 1) {
        puts("Unable to read name!");
        return 1;
      }
      printf("Hello, %s!\n",local_80);
    }
    if (local_14 != 2) {
      if (local_14 == 3) {
        puts("Goodbye!");
      }
      else if (local_14 == 0x7a69) {
        puts("Wow such h4x0r!");
        giveFlag();
      }
      else {
        printf("Unknown choice: %d\n",local_14);
      }
      return 0;
    }
    printf("Enter first number: ");
    iVar1 = __isoc99_scanf(&DAT_08048875,&local_18);
    if (iVar1 != 1) break;
    printf("Enter second number: ");
    iVar1 = __isoc99_scanf(&DAT_08048875,&local_1c);
    if (iVar1 != 1) {
      puts("Unable to read number!");
      return 1;
    }
    printf("%d + %d = %d\n",local_18,local_1c,local_18 + local_1c);
  }
  puts("Unable to read number!");
  return 1;
}
```

This comparison looks interesting

```C
      else if (local_14 == 0x7a69) {
        puts("Wow such h4x0r!");
        giveFlag();
      }
```

The hex-value corresponds to `31337` in decimal.

Let's verify as usual and get the flag

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme7
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 31337
Wow such h4x0r!
flag{<REDACTED>}
```

### Crackme8

As normal, we run the program to get further information

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ chmod +x crackme8

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme8
Usage: ./crackme8 password
         
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme8 1234
Access denied.
```

Let's decompile in Ghidra. `main` looks like this

```C
undefined4 main(int param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  if (param_1 == 2) {
    iVar2 = atoi((char *)param_2[1]);
    if (iVar2 == -0x35010ff3) {
      puts("Access granted.");
      giveFlag();
      uVar1 = 0;
    }
    else {
      puts("Access denied.");
      uVar1 = 1;
    }
  }
  else {
    printf("Usage: %s password\n",*param_2);
    uVar1 = 1;
  }
  return uVar1;
}
```

Pretty straight forward. The hexadecimal number corresponds to `-889262067` in decimal.

We try it

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Reversing_ELF]
└─$ ./crackme8 -889262067
Access granted.
flag{<REDACTED>}
```

And get rewarded with the flag!

For additional information, please see the references below.

## References

- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [Executable and Linkable Format - Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [gdb - Linux manual page](https://man7.org/linux/man-pages/man1/gdb.1.html)
- [GEF (GDB Enhanced Features) - Github](https://github.com/hugsy/gef)
- [GEF (GDB Enhanced Features) - Homepage](https://hugsy.github.io/gef/)
- [Ghidra - Homepage](https://ghidra-sre.org/)
- [ltrace - Linux manual page](https://man7.org/linux/man-pages/man1/ltrace.1.html)
- [Reverse engineering - Wikipedia](https://en.wikipedia.org/wiki/Reverse_engineering)
- [strings - Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [strncmp - Linux manual page](https://man7.org/linux/man-pages/man3/strncmp.3p.html)
