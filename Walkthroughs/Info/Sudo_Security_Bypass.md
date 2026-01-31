# Sudo Security Bypass

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
Tags: -
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description: 
A tutorial room exploring CVE-2019-14287 in the Unix Sudo Program. Room One in the SudoVulns Series
```

Room link: [https://tryhackme.com/room/sudovulnsbypass](https://tryhackme.com/room/sudovulnsbypass)

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

SSH into that machine you deployed earlier, using **port 2222**.

The credentials are:

**Username**: `tryhackme`
**Password**: `tryhackme`

If you're using Linux, the command will look like this:

`ssh -p 2222 tryhackme@10.65.186.21`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Info/Sudo_Security_Bypass]
└─$ export TARGET_IP=10.65.186.21 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Info/Sudo_Security_Bypass]
└─$ ssh -p 2222 tryhackme@$TARGET_IP  
The authenticity of host '[10.65.186.21]:2222 ([10.65.186.21]:2222)' can't be established.
ED25519 key fingerprint is SHA256:4bgDOPxI7PFcv5CMfQYEkO7uBqKjLKhd7zZwmE8uwbQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.65.186.21]:2222' (ED25519) to the list of known hosts.
tryhackme@10.65.186.21's password: 
Last login: Fri Feb  7 00:14:41 2020 from 192.168.1.151
tryhackme@sudo-privesc:~$ 
```

### Task 2: Security Bypass

**CVE-2019-14287** is a vulnerability found in the Unix Sudo program by a researcher working for Apple: Joe Vennix. Coincidentally, he also found the vulnerability that we'll be covering in the next room of this series. This exploit has since been fixed, but may still be present in older versions of Sudo (versions < 1.8.28), so it's well worth keeping an eye out for!

For those who might be unfamiliar with it: `sudo` is a command in unix that allows you to execute programs as other users. This usually defaults to the superuser (root), but it's also possible to execute programs as other users by specifying their username or UID. For example, sudo would usually be used like so: `sudo <command>`, but you could manually choose to execute it as another user like this: `sudo -u#<id> <command>`. This means that you would be pretending to be another user when you executed the chosen command, which can give you higher permissions than you might otherwise have had. As an example:

![sudo example 1](Images/sudo_example_1.png)

In this example my user account did not have permission to read the file `/root/root.txt`, so I used sudo to temporarily give myself root privileges, in order to read the file.

Like many commands on Unix systems, sudo can be configured by editing a configuration file on your system. In this case that file is called `/etc/sudoers`. Editing this file directly is not recommended due to its importance to the OS installation, however, you can safely edit it with the command `sudo visudo`, which checks when you're saving to ensure that there are no misconfigurations.

The vulnerability we're interested in for this task occurs in a very particular scenario. Say you have a user who you want to grant extra permissions to. You want to let this user execute a program as if they were any other user, but you don't want to let them execute it as root. You might add this line to the sudoers file:

`<user> ALL=(ALL:!root) NOPASSWD: ALL`

This would let your user execute any command as another user, but would (theoretically) prevent them from executing the command as the superuser/admin/root. In other words, you can pretend to be any user, except from the admin.

Theoretically.

In practice, with vulnerable versions of Sudo you can get around this restriction to execute the programs as root anyway, which is obviously great for privilege escalation!

With the above configuration, using `sudo -u#0 <command>` (the UID of root is always 0) would not work, as we're not allowed to execute commands as root. If we try to execute commands as user 0 we will be given an error. Enter CVE-2019-14287.

Joe Vennix found that if you specify a UID of -1 (or its unsigned equivalent: 4294967295), Sudo would incorrectly read this as being 0 (i.e. root). This means that by specifying a UID of -1 or 4294967295, you can execute a command as root, *despite being explicitly prevented from doing so*. It is worth noting that this will only work if you've been granted non-root sudo permissions for the command, as in the configuration above.

Practically, the application of this is as follows: `sudo -u#-1 <command>`

![sudo example 2](Images/sudo_example_2.png)

---------------------------------------------------------------------------------------

#### What command are you allowed to run with sudo?

Hint: Try using: sudo -l to see your privileges

```bash
tryhackme@sudo-privesc:~$ sudo -l
Matching Defaults entries for tryhackme on sudo-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tryhackme may run the following commands on sudo-privesc:
    (ALL, !root) NOPASSWD: /bin/bash
tryhackme@sudo-privesc:~$ 
```

Answer: `/bin/bash`

#### What is the flag in /root/root.txt?

```bash
tryhackme@sudo-privesc:~$ sudo /bin/bash
[sudo] password for tryhackme: 
Sorry, user tryhackme is not allowed to execute '/bin/bash' as root on sudo-privesc.
tryhackme@sudo-privesc:~$ sudo -u#-1 /bin/bash
root@sudo-privesc:~# id
uid=0(root) gid=1000(tryhackme) groups=1000(tryhackme)
root@sudo-privesc:~# cat /root/root.txt
THM{<REDACTED>}
root@sudo-privesc:~# 
```

**Note** that there should be no space between the `-u` parameter and the `#-1` value.

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [CVE-2019-14287 - NIST](https://nvd.nist.gov/vuln/detail/CVE-2019-14287)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [sudoers - Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
