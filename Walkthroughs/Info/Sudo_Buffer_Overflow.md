# Sudo Buffer Overflow

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
A tutorial room exploring CVE-2019-18634 in the Unix Sudo Program. Room Two in the SudoVulns Series
```

Room link: [https://tryhackme.com/room/sudovulnsbof](https://tryhackme.com/room/sudovulnsbof)

## Solution

### Task 1: Deploy

To deploy this virtual machine you must be connected to the TryHackMe network using your OpenVPN configuration file. If you don't know how to do this, take a quick look at the [OpenVPN room](https://tryhackme.com/room/openvpn) first.

Once you're connected click the green "**Start Machine**" button to start an instance of the machine, then we can get started!

(Please note that VMs can take a few minutes to boot up fully)

You will be using SSH to log into the machine. On Linux this is done from the terminal, with a command that looks like this:

`ssh -p <port-number> <username>@<remote-machine-ip>`

On Windows you would usually use a piece of software such as [PuTTY](https://putty.org/). You would then login like this:

![PuTTY Configuration](Images/PuTTY_Configuration.png)

Whichever method you're using you will then be asked for a password, which, once entered, will let you execute commands remotely on the machine.

---------------------------------------------------------------------------------------

SSH into that machine you deployed earlier, using **port 4444**.

The credentials are:

**Username**: `tryhackme`
**Password**: `tryhackme`

If you're using Linux, the command will look like this:

`ssh -p 4444 tryhackme@10.66.153.67`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Info/Sudo_Buffer_Overflow]
└─$ export TARGET_IP=10.66.153.67

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Info/Sudo_Buffer_Overflow]
└─$ ssh -p 4444 tryhackme@$TARGET_IP  
The authenticity of host '[10.66.153.67]:4444 ([10.66.153.67]:4444)' can't be established.
ED25519 key fingerprint is SHA256:N7uWsmLfwBGC/fYDW0WAKrZ3MXS/Ksh/moMD5kTc+aM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.66.153.67]:4444' (ED25519) to the list of known hosts.
tryhackme@10.66.153.67's password: 
Last login: Sat Feb  8 05:00:59 2020 from 192.168.1.209
tryhackme@sudo-bof:~$ 
```

### Task 2: Buffer Overflow

**CVE-2019-18634** is, at the time of writing, the latest offering from Joe Vennix - the same guy who brought us the security bypass vulnerability that we used in the Security Bypass room. This one is slightly more technical, using a Buffer Overflow attack to get root permissions. It has been patched, but affects versions of sudo earlier than 1.8.26.

Let's break this down a little bit.

In the [Security Bypass room](https://tryhackme.com/room/sudovulnsbypass) I mentioned briefly that you can add things to the `/etc/sudoers` file in order to give lower-privileged users extra permissions. For this exploit we're more interested in one of the other options available: specifically an option called `pwfeedback`. This option is purely aesthetic, and is usually turned off by default (with the exception of ElementaryOS and Linux Mint - although they will likely now also stop using it). If you have used Linux before then you might have noticed that passwords typed into the terminal usually don't show any output at all; `pwfeedback` makes it so that whenever you type a character, an asterisk is displayed on the screen. Inside the `/etc/sudoers` file it is specified like this:

![sudoers pwfeedback](Images/sudoers_pwfeedback.png)

Here's the catch. When this option is turned on, it's possible to perform a [buffer overflow](https://tryhackme.com/room/bof1) attack on the sudo command. To explain it really simply, when a program accepts input from a user it stores the data in a set size of storage space. A buffer overflow attack is when you enter so much data into the input that it spills out of this storage space and into the next "box," overwriting the data in it. As far as we're concerned, this means if we fill the password box of the sudo command up with a lot of garbage, we can inject our own stuff in at the end. This could mean that we get a shell as root! This exploit works regardless of whether we have any sudo permissions to begin with, unlike in CVE-2019-14287 where we had to have a very specific set of permissions in the first place.

Here's a proof of concept:

![sudo buffer overflow 1](Images/sudo_buffer_overflow_1.png)

In this command we're using the programming language Perl to generate a lot of information which we're then passing into the sudo command as a password using the pipe (`|`) operator. Notice that this doesn't actually give us root permissions -- instead it shows us an error message: `Segmentation fault`, which basically means that we've tried to access some memory that we weren't supposed to be able to access. This proves that a buffer overflow vulnerability exists: now we just need to exploit it!

The particular exploit that we're going to be using was written by Saleem Rashid ([@saleemrash1d](https://twitter.com/saleemrash1d))

This is a program written in C that exploits CVE-2019-18634. In reality BOF attacks are considerably more complicated than in the explanation above, so we're not going to go into a huge amount of detail about what the program is doing exactly, but you can imagine that it's doing the same thing as in the explanation: filling the password field with rubbish information, then overwriting something more important that's in the next "box" with code that gives us a root shell.

I've already uploaded a compiled copy of the code into the VM, so all you need to do is run it. This next section is interesting (and useful if you ever need to use this program for a CTF or other hacking challenge), but not essential for completing the room. This is the process that you would use if you were to download and compile the program for yourself:

![sudo buffer overflow 2](Images/sudo_buffer_overflow_2.png)

1. First you download the program (in this case I used `wget` to do it in the terminal). The source code can be found on [Saleem's github](https://github.com/saleemrashid/sudo-cve-2019-18634), so if you're interested, I would highly recommend reading through the code to see what it does!
2. Next you compile the program. I've used gcc to compile the exploit: `gcc -o <output-file> <source-file>`
3. Notice that there are two files in the directory -- a blue coloured file called `exploit` which is our compiled executable, and a white coloured file called `exploit.c` which is the original source file.
4. You would then upload the file into the target machine and run it:

![sudo buffer overflow 3](Images/sudo_buffer_overflow_3.png)

As I said earlier, I have already done the compilation and upload for you. All you need to do is login to the machine and run the exploit, just to see it working for yourself.

---------------------------------------------------------------------------------------

#### Use the pre-compiled exploit in the VM to get a root shell

```bash
tryhackme@sudo-bof:~$ ls
exploit
tryhackme@sudo-bof:~$ ls -la
total 44
drwxr-xr-x 2 tryhackme tryhackme  4096 Feb  8  2020 .
drwxr-xr-x 5 root      root       4096 Feb  8  2020 ..
-rw------- 1 tryhackme tryhackme    22 Feb  8  2020 .bash_history
-rw-r--r-- 1 tryhackme tryhackme   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 tryhackme tryhackme  3771 Apr  4  2018 .bashrc
-rw-r--r-- 1 tryhackme tryhackme   807 Apr  4  2018 .profile
-rwxr-xr-x 1 root      root      17488 Feb  8  2020 exploit
tryhackme@sudo-bof:~$ file exploit 
-bash: file: command not found
tryhackme@sudo-bof:~$ 
```

#### What is the flag in /root/root.txt?

```bash
tryhackme@sudo-bof:~$ ./exploit 
[sudo] password for tryhackme: 
Sorry, try again.
# id
uid=0(root) gid=0(root) groups=0(root),1000(tryhackme)
# cat /root/root.txt
THM{<REDACTED>}
# 
```

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [CVE-2019-18634 - NIST](https://nvd.nist.gov/vuln/detail/cve-2019-18634)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [sudoers - Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
