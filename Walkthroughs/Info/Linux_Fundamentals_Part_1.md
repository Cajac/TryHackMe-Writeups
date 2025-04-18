# Linux Fundamentals Part 1

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
OS: Linux
Subscription type: Free
Embark on the journey of learning the fundamentals of Linux. 
Learn to run some of the first essential commands on an interactive terminal.
```

Room link: [https://tryhackme.com/room/linuxfundamentalspart1](https://tryhackme.com/room/linuxfundamentalspart1)

## Solution

### Task 2 - A Bit of Background on Linux

#### What year was the first release of a Linux operating system?

Answer: 1991

### Task 4 - Running Your First few Commands

Useful commands:

- echo
- whoami

#### If we wanted to output the text "TryHackMe", what would our command be?

Hint: The use of double quotes is not necessary because the string does not contain any space.

```bash
tryhackme@linux1:~$ echo TryHackMe
TryHackMe
```

Answer: echo TryHackMe

#### What is the username of who you're logged in as on your deployed Linux machine?

Hint: Run the command `whoami` in the terminal

```bash
tryhackme@linux1:~$ whoami
tryhackme
```

Note that the user name is also visible in the prompt before the `@`-sign

Answer: tryhackme

### Task 5 - Interacting With the Filesystem!

Useful commands:

- cat
- cd
- ls
- pwd

#### On the Linux machine that you deploy, how many folders are there?

```bash
tryhackme@linux1:~$ ls -d */
folder1/  folder2/  folder3/  folder4/
tryhackme@linux1:~$ ls -d */ | wc -l
4
```

Answer: 4

#### Which directory contains a file?

Hint: We've discussed about a certain command that can be used to list contents of directories

```bash
tryhackme@linux1:~$ ls -R *
access.log

folder1:

folder2:

folder3:

folder4:
note.txt
```

Answer: folder4

#### What is the contents of this file?

```bash
tryhackme@linux1:~$ cat folder4/note.txt 
Hello World!
```

Answer: Hello World!

#### Use the cd command to navigate to this file and find out the new current working directory. What is the path?

```bash
tryhackme@linux1:~$ cd folder4/
tryhackme@linux1:~/folder4$ pwd
/home/tryhackme/folder4
```

Answer: /home/tryhackme/folder4

### Task 6 -  Searching for Files

Useful commands:

- find
- grep

#### Use grep on "access.log" to find the flag that has a prefix of "THM". What is the flag?

Note: The "access.log" file is located in the "/home/tryhackme/" directory.

Hint: grep "THM" access.log

```bash
tryhackme@linux1:~/folder4$ cd ..
tryhackme@linux1:~$ grep -oE 'THM{.*}' access.log 
THM{ACCESS}
```

Answer: THM{ACCESS}

### Task 7 - An Introduction to Shell Operators

Useful operators:

- `&`, run commands in the background of your terminal
- `&&`, combine multiple commands together in one line of your terminal
- `>`, redirect output from a command
- `>>`, same as `>` but appends rather than replacing/overwriting

#### If we wanted to run a command in the background, what operator would we want to use?

Answer: &

#### If I wanted to replace the contents of a file named "passwords" with the word "password123", what would my command be?

Hint: `echo <content> > <filename>`

```bash
tryhackme@linux1:~$ echo password123 > passwords
tryhackme@linux1:~$ cat passwords
password123
```

Answer: echo password123 > passwords

#### Now if I wanted to add "tryhackme" to this file named "passwords" but also keep "passwords123", what would my command be

Hint: `echo <content> >> <filename>`

```bash
tryhackme@linux1:~$ echo tryhackme >> passwords
tryhackme@linux1:~$ cat passwords 
password123
tryhackme
```

Answer: echo tryhackme >> passwords

For additional information, please see the references below.

## References

- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [cd - Linux manual page](https://man7.org/linux/man-pages/man1/cd.1p.html)
- [echo - Linux manual page](https://man7.org/linux/man-pages/man1/echo.1.html)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [Linux - Wikipedia](https://en.wikipedia.org/wiki/Linux)
- [ls - Linux manual page](https://man7.org/linux/man-pages/man1/ls.1.html)
- [pwd - Linux manual page](https://man7.org/linux/man-pages/man1/pwd.1.html)
- [wc - Linux manual page](https://man7.org/linux/man-pages/man1/wc.1.html)
- [whoami - Linux manual page](https://man7.org/linux/man-pages/man1/whoami.1.html)
