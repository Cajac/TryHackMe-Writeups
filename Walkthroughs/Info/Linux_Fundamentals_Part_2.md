# Linux Fundamentals Part 2

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
OS: Linux
Subscription type: Premium
Description: Continue your learning Linux journey with part two. You will be learning how to log in to a 
Linux machine using SSH, how to advance your commands, file system interaction.
```

Room link: [https://tryhackme.com/room/linuxfundamentalspart2](https://tryhackme.com/room/linuxfundamentalspart2)

## Solution

### Task 2 - Accessing Your Linux Machine Using SSH (Deploy)

#### I've logged into the Linux Fundamentals Part 2 machine using SSH!

Login to the machine using `ssh` with the credentials `tryhackme:tryhackme`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Info/Linux_Fundamentals_Part_1-3]
└─$ ssh tryhackme@10.10.248.104
The authenticity of host '10.10.248.104 (10.10.248.104)' can't be established.
ED25519 key fingerprint is SHA256:p5icoIi8kJsmDO+nZgedjYvBWn88Lgb5VZ7nj7CaFys.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.248.104' (ED25519) to the list of known hosts.
tryhackme@10.10.248.104's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-1075-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Feb  3 19:38:26 UTC 2025

  System load:  0.37              Processes:             114
  Usage of /:   28.3% of 9.62GB   Users logged in:       0
  Memory usage: 5%                IPv4 address for ens5: 10.10.16.227
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

tryhackme@linux2:~$ 
```

### Task 3 - Introduction to Flags and Switches

Useful commands:

- man

#### Explore the manual page of the ls command

The result of `man ls` is

```bash
LS(1)                                                                                User Commands                                                                                LS(1)

NAME
       ls - list directory contents

SYNOPSIS
       ls [OPTION]... [FILE]...

DESCRIPTION
       List information about the FILEs (the current directory by default).  Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.

       Mandatory arguments to long options are mandatory for short options too.

       -a, --all
              do not ignore entries starting with .

       -A, --almost-all
              do not list implied . and ..

       --author
              with -l, print the author of each file

       -b, --escape
              print C-style escapes for nongraphic characters
<---snip--->
```

#### What directional arrow key would we use to navigate down the manual page?

Answer: down

#### What flag would we use to display the output in a "human-readable" way?

```bash
<---snip--->
       -G, --no-group
              in a long listing, don't print group names

       -h, --human-readable
              with -l and -s, print sizes like 1K 234M 2G etc.

       --si   likewise, but use powers of 1000 not 1024

       -H, --dereference-command-line
              follow symbolic links listed on the command line

<---snip--->
```

Answer: -h

### Task 4 - Filesystem Interaction Continued

Useful commands:

- cp
- file
- mkdir
- mv
- rm
- touch

#### How would you create the file named "newnote"?

Hint: Look at the answer formatting - we're not expecting quotation marks for this

```bash
tryhackme@linux2:~$ touch newnote
tryhackme@linux2:~$ 
```

Answer: touch newnote

#### On the deployable machine, what is the file type of "unknown1" in "tryhackme's" home directory?

```bash
tryhackme@linux2:~$ file unknown1 
unknown1: ASCII text
```

Answer: ASCII text

#### How would we move the file "myfile" to the directory "myfolder"

```bash
tryhackme@linux2:~$ ls
important  myfile  myfolder  newnote  unknown1
tryhackme@linux2:~$ mv myfile myfolder/
tryhackme@linux2:~$ ls
important  myfolder  newnote  unknown1
```

Answer: mv myfile myfolder

#### What are the contents of this file?

```bash
tryhackme@linux2:~$ cat myfolder/myfile 
THM{FILESYSTEM}
```

Answer: THM{FILESYSTEM}

### Task 5 - Permissions 101

Useful commands:

- su

#### On the deployable machine, who is the owner of "important"?

```bash
tryhackme@linux2:~$ ls -l important 
-rw-r--r-- 1 user2 user2 14 May  5  2021 important
```

Answer: user2

#### What would the command be to switch to the user "user2"?

Note: The password is `user2`

```bash
tryhackme@linux2:~$ su user2
Password: 
user2@linux2:/home/tryhackme$ 
```

Answer: su user2

#### Output the contents of "important", what is the flag?

```bash
user2@linux2:/home/tryhackme$ cat important 
THM{SU_USER2}
```

Answer: THM{SU_USER2}

### Task 6 - Common Directories

Common directories:

- `/etc`, short for etcetera, contains configuration and other system files
- `/var`, short for variable data, contains data from services and applications
- `/root`, home folder for the `root` user
- `/tmp`, short for temporary, used to store data that is only needed temporarily

#### What is the directory path that would we expect logs to be stored in?

Answer: /var/log

#### What root directory is similar to how RAM on a computer works?

Hint: The contents of this root directory do not persist after reboot

Answer: /tmp

#### Name the home directory of the root user

Answer: /root

For additional information, please see the references below.

## References

- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [cd - Linux manual page](https://man7.org/linux/man-pages/man1/cd.1p.html)
- [cp - Linux manual page](https://man7.org/linux/man-pages/man1/cp.1.html)
- [echo - Linux manual page](https://man7.org/linux/man-pages/man1/echo.1.html)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [Linux - Wikipedia](https://en.wikipedia.org/wiki/Linux)
- [ls - Linux manual page](https://man7.org/linux/man-pages/man1/ls.1.html)
- [man - Linux manual page](https://man7.org/linux/man-pages/man1/man.1.html)
- [mkdir - Linux manual page](https://man7.org/linux/man-pages/man1/mkdir.1.html)
- [mv - Linux manual page](https://man7.org/linux/man-pages/man1/mv.1.html)
- [pwd - Linux manual page](https://man7.org/linux/man-pages/man1/pwd.1.html)
- [rm - Linux manual page](https://man7.org/linux/man-pages/man1/rm.1.html)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [su - Linux manual page](https://man7.org/linux/man-pages/man1/su.1.html)
- [touch - Linux manual page](https://man7.org/linux/man-pages/man1/touch.1.html)
- [wc - Linux manual page](https://man7.org/linux/man-pages/man1/wc.1.html)
- [whoami - Linux manual page](https://man7.org/linux/man-pages/man1/whoami.1.html)
