# Hacking with PowerShell

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Premium
Description: Learn the basics of PowerShell and PowerShell Scripting
```

Room link: [https://tryhackme.com/room/powershell](https://tryhackme.com/room/powershell)

## Solution

### Task 1 - Objectives

Use the AttackBox or connect with `xfreerdp`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Hacking_with_PowerShell]
└─$ xfreerdp /v:10.10.207.81 /cert:ignore /u:Administrator /p:BHN2UVw0Q /h:960 /w:1500 +clipboard 
[19:47:51:998] [106485:106486] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[19:47:51:998] [106485:106486] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
<---snip---> 
```

Then open a PowerShell window.

### Task 2 - What is Powershell?

Powershell is the Windows Scripting Language and shell environment built using the .NET framework.

This also allows Powershell to execute .NET functions directly from its shell. Most Powershell commands,  
called cmdlets, are written in .NET. Unlike other scripting languages and shell environments, the output  
of these cmdlets are objects - making Powershell somewhat object-oriented.

The normal format of a cmdlet is represented using Verb-Noun; for example, the cmdlet to list commands  
is called `Get-Command`.

[Common verbs](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-5.1) to use include:

- Get
- Start
- Stop
- Read
- Write
- New
- Out

#### What is the command to get a new object?

Hint: Combine two of the verbs from the list

Answer: Get-New

### Task 3 - Basic Powershell Commands

The main thing to remember here is that `Get-Command` and `Get-Help` are your best friends!

#### What is the location of the file "interesting-file.txt"

Search for the file recursively on C:\ and ignore errors

```powershell
PS C:\Users\Administrator> Get-ChildItem -Path C:\ -Include "interesting-file.txt" -File -Recurse -ErrorAction SilentlyContinue
PS C:\Users\Administrator> Get-ChildItem -Path C:\ -Include "interesting-file.*" -File -Recurse -ErrorAction SilentlyContinue


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        10/3/2019  11:38 PM             23 interesting-file.txt.txt


PS C:\Users\Administrator>
```

Note the double file extension!

Answer: C:\Program Files

#### Specify the contents of this file

```powershell
PS C:\Users\Administrator> Get-Content "C:\Program Files\interesting-file.txt.txt"
notsointerestingcontent
```

Answer: notsointerestingcontent

#### How many cmdlets are installed on the system(only cmdlets, not functions and aliases)?

Hint: There a few ways you can approach this answer. For example, you can Get-command and pipe it to measure. However,  
we're looking for the syntax that matches this room.  
I.e: `Get-Command | Where-Object -Property CommandType -eq Cmdlet | Measure-Object` Will provide the specific answer  
that this question is looking for

```powershell
PS C:\Users\Administrator> Get-Command -Type Cmdlet | Measure-Object


Count    : 6638
Average  :
Sum      :
Maximum  :
Minimum  :
Property :



PS C:\Users\Administrator> (Get-Command -Type Cmdlet | Measure-Object).count
6638
```

Answer: 6638

#### Get the MD5 hash of interesting-file.txt

```powershell
PS C:\Users\Administrator> Get-FileHash -Algorithm MD5 'C:\Program Files\interesting-file.txt.txt'

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             49A586A2A9456226F8A1B4CEC6FAB329                                       C:\Program Files\interesting-file.txt.txt


PS C:\Users\Administrator> (Get-FileHash -Algorithm MD5 'C:\Program Files\interesting-file.txt.txt').hash
49A586A2A9456226F8A1B4CEC6FAB329
```

Answer: 49A586A2A9456226F8A1B4CEC6FAB329

#### What is the command to get the current working directory?

Answer: Get-Location

#### Does the path "C:\Users\Administrator\Documents\Passwords" Exist (Y/N)?

```powershell
PS C:\Users\Administrator> Get-Location "C:\Users\Administrator\Documents\Passwords"
Get-Location : A positional parameter cannot be found that accepts argument 'C:\Users\Administrator\Documents\Passwords'.
At line:1 char:1
+ Get-Location "C:\Users\Administrator\Documents\Passwords"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (:) [Get-Location], ParameterBindingException
    + FullyQualifiedErrorId : PositionalParameterNotFound,Microsoft.PowerShell.Commands.GetLocationCommand
```

Answer: N

#### What command would you use to make a request to a web server?

Answer: Invoke-WebRequest

#### Base64 decode the file b64.txt on Windows

The file is visible on the Administrator's desktop

```powershell
PS C:\Users\Administrator> Set-Location .\Desktop
PS C:\Users\Administrator\Desktop> $encoded = Get-Content .\b64.txt
PS C:\Users\Administrator\Desktop> [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($encoded))
this is the flag - ihopeyoudidthisonwindows
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
```

Answer: ihopeyoudidthisonwindows

### Task 4 - Enumeration

The first step when you have gained initial access to any machine would be to enumerate.  
We'll be enumerating the following:

- users
- basic networking information
- file permissions
- registry permissions
- scheduled and running tasks
- insecure files

#### How many users are there on the machine?

```powershell
PS C:\Users\Administrator\Desktop> Get-LocalUser

Name           Enabled Description
----           ------- -----------
Administrator  True    Built-in account for administering the computer/domain
DefaultAccount False   A user account managed by the system.
duck           True
duck2          True
Guest          False   Built-in account for guest access to the computer/domain


PS C:\Users\Administrator\Desktop> Get-LocalUser | Measure-Object


Count    : 5
Average  :
Sum      :
Maximum  :
Minimum  :
Property :



PS C:\Users\Administrator\Desktop> (Get-LocalUser | Measure-Object).count
5
```

Answer: 5

#### Which local user does this SID(S-1-5-21-1394777289-3961777894-1791813945-501) belong to?

```powershell
PS C:\Users\Administrator\Desktop> Get-LocalUser | Get-Member


   TypeName: Microsoft.PowerShell.Commands.LocalUser

Name                   MemberType Definition
----                   ---------- ----------
Clone                  Method     Microsoft.PowerShell.Commands.LocalUser Clone()
Equals                 Method     bool Equals(System.Object obj)
GetHashCode            Method     int GetHashCode()
GetType                Method     type GetType()
ToString               Method     string ToString()
AccountExpires         Property   System.Nullable[datetime] AccountExpires {get;set;}
Description            Property   string Description {get;set;}
Enabled                Property   bool Enabled {get;set;}
FullName               Property   string FullName {get;set;}
LastLogon              Property   System.Nullable[datetime] LastLogon {get;set;}
Name                   Property   string Name {get;set;}
ObjectClass            Property   string ObjectClass {get;set;}
PasswordChangeableDate Property   System.Nullable[datetime] PasswordChangeableDate {get;set;}
PasswordExpires        Property   System.Nullable[datetime] PasswordExpires {get;set;}
PasswordLastSet        Property   System.Nullable[datetime] PasswordLastSet {get;set;}
PasswordRequired       Property   bool PasswordRequired {get;set;}
PrincipalSource        Property   System.Nullable[Microsoft.PowerShell.Commands.PrincipalSource] PrincipalSource {get;set;}
SID                    Property   System.Security.Principal.SecurityIdentifier SID {get;set;}
UserMayChangePassword  Property   bool UserMayChangePassword {get;set;}


PS C:\Users\Administrator\Desktop> Get-LocalUser -SID S-1-5-21-1394777289-3961777894-1791813945-501

Name  Enabled Description
----  ------- -----------
Guest False   Built-in account for guest access to the computer/domain

```

Answer: Guest

#### How many users have their password required values set to False?

```powershell
PS C:\Users\Administrator\Desktop> Get-LocalUser | Get-Member


   TypeName: Microsoft.PowerShell.Commands.LocalUser

Name                   MemberType Definition
----                   ---------- ----------
Clone                  Method     Microsoft.PowerShell.Commands.LocalUser Clone()
Equals                 Method     bool Equals(System.Object obj)
GetHashCode            Method     int GetHashCode()
GetType                Method     type GetType()
ToString               Method     string ToString()
AccountExpires         Property   System.Nullable[datetime] AccountExpires {get;set;}
Description            Property   string Description {get;set;}
Enabled                Property   bool Enabled {get;set;}
FullName               Property   string FullName {get;set;}
LastLogon              Property   System.Nullable[datetime] LastLogon {get;set;}
Name                   Property   string Name {get;set;}
ObjectClass            Property   string ObjectClass {get;set;}
PasswordChangeableDate Property   System.Nullable[datetime] PasswordChangeableDate {get;set;}
PasswordExpires        Property   System.Nullable[datetime] PasswordExpires {get;set;}
PasswordLastSet        Property   System.Nullable[datetime] PasswordLastSet {get;set;}
PasswordRequired       Property   bool PasswordRequired {get;set;}
PrincipalSource        Property   System.Nullable[Microsoft.PowerShell.Commands.PrincipalSource] PrincipalSource {get;set;}
SID                    Property   System.Security.Principal.SecurityIdentifier SID {get;set;}
UserMayChangePassword  Property   bool UserMayChangePassword {get;set;}


PS C:\Users\Administrator\Desktop> Get-LocalUser | Select-Object Name, PasswordRequired

Name           PasswordRequired
----           ----------------
Administrator              True
DefaultAccount            False
duck                      False
duck2                     False
Guest                     False

PS C:\Users\Administrator\Desktop> Get-LocalUser | Select-Object Name, PasswordRequired | Where-Object PasswordRequired -EQ $False

Name           PasswordRequired
----           ----------------
DefaultAccount            False
duck                      False
duck2                     False
Guest                     False

PS C:\Users\Administrator\Desktop> Get-LocalUser | Select-Object Name, PasswordRequired | Where-Object PasswordRequired -EQ $False | Measure-Object


Count    : 4
Average  :
Sum      :
Maximum  :
Minimum  :
Property :



PS C:\Users\Administrator\Desktop> (Get-LocalUser | Select-Object Name, PasswordRequired | Where-Object PasswordRequired -EQ $False | Measure-Object).count
4
```

Answer: 4

#### How many local groups exist?

```powershell
PS C:\Users\Administrator\Desktop> Get-LocalGroup | Measure-Object


Count    : 24
Average  :
Sum      :
Maximum  :
Minimum  :
Property :



PS C:\Users\Administrator\Desktop> (Get-LocalGroup | Measure-Object).count
24
```

Answer: 24

#### What command did you use to get the IP address info?

```powershell
PS C:\Users\Administrator\Desktop> Get-NetIPAddress


IPAddress         : fe80::842:cb5:f5f5:30ae%7
InterfaceIndex    : 7
InterfaceAlias    : Local Area Connection* 3
AddressFamily     : IPv6
Type              : Unicast
PrefixLength      : 64
PrefixOrigin      : WellKnown
SuffixOrigin      : Link
AddressState      : Preferred
ValidLifetime     : Infinite ([TimeSpan]::MaxValue)
PreferredLifetime : Infinite ([TimeSpan]::MaxValue)
SkipAsSource      : False
PolicyStore       : ActiveStore

IPAddress         : 2001:0:2851:782c:842:cb5:f5f5:30ae
InterfaceIndex    : 7
InterfaceAlias    : Local Area Connection* 3
AddressFamily     : IPv6
Type              : Unicast
PrefixLength      : 64
PrefixOrigin      : RouterAdvertisement
SuffixOrigin      : Link
AddressState      : Preferred
ValidLifetime     : Infinite ([TimeSpan]::MaxValue)
PreferredLifetime : Infinite ([TimeSpan]::MaxValue)
SkipAsSource      : False
PolicyStore       : ActiveStore

IPAddress         : fe80::b03b:aa7d:5eac:91df%5
InterfaceIndex    : 5
InterfaceAlias    : Ethernet
AddressFamily     : IPv6
Type              : Unicast
PrefixLength      : 64
PrefixOrigin      : WellKnown
SuffixOrigin      : Link
AddressState      : Preferred
ValidLifetime     : Infinite ([TimeSpan]::MaxValue)
PreferredLifetime : Infinite ([TimeSpan]::MaxValue)
SkipAsSource      : False
PolicyStore       : ActiveStore

IPAddress         : fe80::5efe:10.10.207.81%6
InterfaceIndex    : 6
InterfaceAlias    : Reusable ISATAP Interface {90ABCE23-305A-4BDE-AA39-4FFDA7413134}
AddressFamily     : IPv6
Type              : Unicast
PrefixLength      : 128
PrefixOrigin      : WellKnown
SuffixOrigin      : Link
AddressState      : Deprecated
ValidLifetime     : Infinite ([TimeSpan]::MaxValue)
PreferredLifetime : Infinite ([TimeSpan]::MaxValue)
SkipAsSource      : False
PolicyStore       : ActiveStore

IPAddress         : ::1
InterfaceIndex    : 1
InterfaceAlias    : Loopback Pseudo-Interface 1
AddressFamily     : IPv6
Type              : Unicast
PrefixLength      : 128
PrefixOrigin      : WellKnown
SuffixOrigin      : WellKnown
AddressState      : Preferred
ValidLifetime     : Infinite ([TimeSpan]::MaxValue)
PreferredLifetime : Infinite ([TimeSpan]::MaxValue)
SkipAsSource      : False
PolicyStore       : ActiveStore

IPAddress         : 10.10.207.81
InterfaceIndex    : 5
InterfaceAlias    : Ethernet
AddressFamily     : IPv4
Type              : Unicast
PrefixLength      : 16
PrefixOrigin      : Dhcp
SuffixOrigin      : Dhcp
AddressState      : Preferred
ValidLifetime     : 00:32:47
PreferredLifetime : 00:32:47
SkipAsSource      : False
PolicyStore       : ActiveStore

IPAddress         : 127.0.0.1
InterfaceIndex    : 1
InterfaceAlias    : Loopback Pseudo-Interface 1
AddressFamily     : IPv4
Type              : Unicast
PrefixLength      : 8
PrefixOrigin      : WellKnown
SuffixOrigin      : WellKnown
AddressState      : Preferred
ValidLifetime     : Infinite ([TimeSpan]::MaxValue)
PreferredLifetime : Infinite ([TimeSpan]::MaxValue)
SkipAsSource      : False
PolicyStore       : ActiveStore


PS C:\Users\Administrator\Desktop> Get-NetIPAddress | Select-Object IPAddress

IPAddress
---------
fe80::842:cb5:f5f5:30ae%7
2001:0:2851:782c:842:cb5:f5f5:30ae
fe80::b03b:aa7d:5eac:91df%5
fe80::5efe:10.10.207.81%6
::1
10.10.207.81
127.0.0.1
```

Answer: Get-NetIPAddress

#### How many ports are listed as listening?

Hint: Get-NetTCPconnection -State

```powershell
PS C:\Users\Administrator\Desktop> Get-NetTCPconnection -State Listen

LocalAddress                        LocalPort RemoteAddress                       RemotePort State       AppliedSetting OwningProcess
------------                        --------- -------------                       ---------- -----       -------------- -------------
::                                  49677     ::                                  0          Listen                     724
::                                  49668     ::                                  0          Listen                     716
::                                  49667     ::                                  0          Listen                     1664
::                                  49666     ::                                  0          Listen                     1000
::                                  49665     ::                                  0          Listen                     1020
::                                  49664     ::                                  0          Listen                     640
::                                  47001     ::                                  0          Listen                     4
::                                  5985      ::                                  0          Listen                     4
::                                  3389      ::                                  0          Listen                     992
::                                  445       ::                                  0          Listen                     4
::                                  135       ::                                  0          Listen                     832
0.0.0.0                             49677     0.0.0.0                             0          Listen                     724
0.0.0.0                             49668     0.0.0.0                             0          Listen                     716
0.0.0.0                             49667     0.0.0.0                             0          Listen                     1664
0.0.0.0                             49666     0.0.0.0                             0          Listen                     1000
0.0.0.0                             49665     0.0.0.0                             0          Listen                     1020
0.0.0.0                             49664     0.0.0.0                             0          Listen                     640
0.0.0.0                             3389      0.0.0.0                             0          Listen                     992
10.10.207.81                        139       0.0.0.0                             0          Listen                     4
0.0.0.0                             135       0.0.0.0                             0          Listen                     832


PS C:\Users\Administrator\Desktop> Get-NetTCPconnection -State Listen | Measure-Object


Count    : 20
Average  :
Sum      :
Maximum  :
Minimum  :
Property :



PS C:\Users\Administrator\Desktop> (Get-NetTCPconnection -State Listen | Measure-Object).Count
20
```

Answer: 20

#### What is the remote address of the local port listening on port 445?

```powershell
PS C:\Users\Administrator\Desktop> Get-NetTCPconnection -State Listen | Where-Object LocalPort -EQ 445

LocalAddress                        LocalPort RemoteAddress                       RemotePort State       AppliedSetting OwningProcess
------------                        --------- -------------                       ---------- -----       -------------- -------------
::                                  445       ::                                  0          Listen                     4


PS C:\Users\Administrator\Desktop> (Get-NetTCPconnection -State Listen | Where-Object LocalPort -EQ 445).LocalAddress
::
```

Answer: ::

#### How many patches have been applied?

Hint: Get hot-fix | measure

```powershell
PS C:\Users\Administrator\Desktop> Get-HotFix

Source        Description      HotFixID      InstalledBy          InstalledOn
------        -----------      --------      -----------          -----------
EC2AMAZ-5M... Update           KB3176936                          10/18/2016 12:00:00 AM
EC2AMAZ-5M... Update           KB3186568     NT AUTHORITY\SYSTEM  6/15/2017 12:00:00 AM
EC2AMAZ-5M... Update           KB3192137     NT AUTHORITY\SYSTEM  9/12/2016 12:00:00 AM
EC2AMAZ-5M... Update           KB3199209     NT AUTHORITY\SYSTEM  10/18/2016 12:00:00 AM
EC2AMAZ-5M... Update           KB3199986     EC2AMAZ-5M13VM2\A... 11/15/2016 12:00:00 AM
EC2AMAZ-5M... Update           KB4013418     EC2AMAZ-5M13VM2\A... 3/16/2017 12:00:00 AM
EC2AMAZ-5M... Update           KB4023834     EC2AMAZ-5M13VM2\A... 6/15/2017 12:00:00 AM
EC2AMAZ-5M... Update           KB4035631     NT AUTHORITY\SYSTEM  8/9/2017 12:00:00 AM
EC2AMAZ-5M... Update           KB4049065     NT AUTHORITY\SYSTEM  11/17/2017 12:00:00 AM
EC2AMAZ-5M... Update           KB4089510     NT AUTHORITY\SYSTEM  3/24/2018 12:00:00 AM
EC2AMAZ-5M... Update           KB4091664     NT AUTHORITY\SYSTEM  1/10/2019 12:00:00 AM
EC2AMAZ-5M... Update           KB4093137     NT AUTHORITY\SYSTEM  4/11/2018 12:00:00 AM
EC2AMAZ-5M... Update           KB4132216     NT AUTHORITY\SYSTEM  6/13/2018 12:00:00 AM
EC2AMAZ-5M... Security Update  KB4465659     NT AUTHORITY\SYSTEM  11/19/2018 12:00:00 AM
EC2AMAZ-5M... Security Update  KB4485447     NT AUTHORITY\SYSTEM  2/13/2019 12:00:00 AM
EC2AMAZ-5M... Security Update  KB4498947     NT AUTHORITY\SYSTEM  5/15/2019 12:00:00 AM
EC2AMAZ-5M... Security Update  KB4503537     NT AUTHORITY\SYSTEM  6/12/2019 12:00:00 AM
EC2AMAZ-5M... Security Update  KB4509091     NT AUTHORITY\SYSTEM  9/6/2019 12:00:00 AM
EC2AMAZ-5M... Security Update  KB4512574     NT AUTHORITY\SYSTEM  9/11/2019 12:00:00 AM
EC2AMAZ-5M... Security Update  KB4516044     NT AUTHORITY\SYSTEM  9/11/2019 12:00:00 AM


PS C:\Users\Administrator\Desktop> Get-HotFix | Measure-Object


Count    : 20
Average  :
Sum      :
Maximum  :
Minimum  :
Property :



PS C:\Users\Administrator\Desktop> (Get-HotFix | Measure-Object).Count
20
```

Answer: 20

#### When was the patch with ID KB4023834 installed?

```powershell
PS C:\Users\Administrator\Desktop> Get-HotFix -Id KB4023834

Source        Description      HotFixID      InstalledBy          InstalledOn
------        -----------      --------      -----------          -----------
EC2AMAZ-5M... Update           KB4023834     EC2AMAZ-5M13VM2\A... 6/15/2017 12:00:00 AM


PS C:\Users\Administrator\Desktop> (Get-HotFix -Id KB4023834).InstalledOn

Thursday, June 15, 2017 12:00:00 AM
```

Answer: 6/15/2017 12:00:00 AM

#### Find the contents of a backup file

```powershell
PS C:\Users\Administrator\Desktop> Get-ChildItem -Path C:\ -Include "*bak*" -File -Recurse -ErrorAction SilentlyContinue


    Directory: C:\Program Files (x86)\Internet Explorer


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        10/4/2019  12:42 AM             12 passwords.bak.txt


PS C:\Users\Administrator\Desktop> Get-ChildItem -Path C:\ -Include "*bak*" -File -Recurse -ErrorAction SilentlyContinue | Get-Content
backpassflag
PS C:\Users\Administrator\Desktop>
```

Answer: backpassflag

#### Search for all files containing API_KEY

Searching in all files on C: yields quite a lot of "noise" so I only searched in the C:\Users directory

```powershell
PS C:\Users\Administrator\Desktop> Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern API_KEY

C:\Users\Public\Music\config.xml:1:API_KEY=fakekey123
```

Answer: fakekey123

#### What command do you do to list all the running processes?

```powershell
PS C:\Users\Administrator\Desktop> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    123       8    22948      12772       0.20   1776   0 amazon-ssm-agent
    287      17     6520      21212       0.14   4924   2 ApplicationFrameHost
    199      14     4748      19164       4.00   3756   2 conhost
    172      12     3692      16956       0.94   4300   2 conhost
    204      10     1768       3936       0.13    532   0 csrss
    118       8     1320       3612       0.03    600   1 csrss
    209      12     1860       4080       0.63   2792   2 csrss
    316      19    13192      18740       0.09    952   1 dwm
    378      38    24472      63240       0.94   2888   2 dwm
   1372      62    22636      76516       3.45   2196   2 explorer
      0       0        0          4                 0   0 Idle
     71       6      964       4676       0.00   1812   0 LiteAgent
    402      23    10716      42148       0.14   2416   1 LogonUI
    909      20     4448      13100       0.59    724   0 lsass
    154       9     2180       8228       0.00   3708   0 MpCmdRun
    190      13     2948       9396       0.02   3352   0 msdtc
    566      65   133504     111520     276.19   1848   0 MsMpEng
    172      23     3700       9216       0.03   2344   0 NisSrv
    555      37   355384     440316      28.72   1212   2 powershell
    762      45   371028     460368     111.55   3308   2 powershell
    253      11     2124       9964       0.13   2108   2 rdpclip
    289      16     5996      21596       0.17   2100   2 RuntimeBroker
    571      29    11836      22840       0.16   3292   2 SearchUI
    232       8     2752       6364       0.41    716   0 services
    836      33    21788      33976       0.61   3204   2 ShellExperienceHost
    381      14     4008      18728       0.25   2260   2 sihost
     54       2      372       1204       0.13    392   0 smss
    424      22     5488      15296       0.08   1664   0 spoolsv
    566      32    10876      20748       1.20    488   0 svchost
    442      33    10444      18404       0.59    536   0 svchost
    695      21     5904      19572       0.41    796   0 svchost
    577      16     3680       9464       0.69    832   0 svchost
    740      26    60176      83688       2.69    992   0 svchost
   1350      44    18536      31608       2.69   1000   0 svchost
    495      19     9736      17484       0.39   1020   0 svchost
    547      28     7148      16524       0.14   1088   0 svchost
    593      36     7204      19640       0.22   1176   0 svchost
    158       9     1648       6800       0.03   1192   0 svchost
    196      11     1972       7832       0.00   1800   0 svchost
    221      16     5128      16272       0.55   1820   0 svchost
    288      18     4200      19236       0.06   2220   2 svchost
    894       0      124        140      21.14      4   0 System
    692      34    39232      75188      17.28   4588   2 SystemSettings
    210      14     2788      11204       0.03   4208   2 SystemSettingsAdminFlows
    194      11     2336      13048       0.06   3580   2 SystemSettingsBroker
    259      16     3012      14460       0.08   2248   2 taskhostw
    279      19     6444      16584       0.16   3932   2 taskhostw
    144      10     3432       9736      19.34   2128   0 TiWorker
    101       8     1668       6484       0.09   4996   0 TrustedInstaller
     92       8      908       4800       0.09    640   0 wininit
    167       9     2060      12576       0.06    648   1 winlogon
    183       8     1760       7276       0.09   2828   2 winlogon
```

Answer: Get-Process

#### What is the path of the scheduled task called new-sched-task?

```powershell
PS C:\Users\Administrator\Desktop> Get-ScheduledTask -TaskName new-sched-task

TaskPath                                       TaskName                          State
--------                                       --------                          -----
\                                              new-sched-task                    Ready

```

Answer: \

#### Who is the owner of the C:\

```powershell
PS C:\Users\Administrator\Desktop> Get-Acl C:\


    Directory:


Path Owner                       Access
---- -----                       ------
C:\  NT SERVICE\TrustedInstaller CREATOR OWNER Allow  268435456...


PS C:\Users\Administrator\Desktop> (Get-Acl C:\).Owner
NT SERVICE\TrustedInstaller
```

Answer: NT SERVICE\TrustedInstaller

### Task 5 - Basic Scripting Challenge

Sample listening ports script

```powershell
$system_ports = Get-NetTCPConnection -State Listen

$text_port = Get-Content -Path C:\Users\Administrator\Desktop\ports.txt

foreach($port in $text_port){

    if($port -in $system_ports.LocalPort){
        echo $port
     }

}
```

Now that we've seen what a basic script looks like - it's time to write one of your own. The emails folder on  
the Desktop contains copies of the emails John, Martha, and Mary have been sending to each other(and themselves).  
Answer the following questions with regard to these emails.

#### What file contains the password?

```powershell
PS C:\Users\Administrator\Desktop\emails> Get-ChildItem -Path * -Recurse | Select-String -Pattern "password"

john\Doc3.txt:6:I got some errors trying to access my passwords file - is there any way you can help? Here is the output I got
martha\Doc3M.txt:6:I managed to fix the corrupted file to get the output, but the password is buried somewhere in these logs:
martha\Doc3M.txt:106:password is johnisalegend99
```

Answer: Doc3M

#### What is the password?

Answer: johnisalegend99

#### What files contains an HTTPS link?

```powershell
PS C:\Users\Administrator\Desktop\emails> Get-ChildItem -Path * -Recurse | Select-String -Pattern "https"

mary\Doc2Mary.txt:5:https://www.howtoworkwell.rand/
```

Answer: Doc2Mary

### Task 6 -  Intermediate Scripting

Hint: either use raw TCP sockets or Test-NetConnection

#### How many open ports did you find between 130 and 140(inclusive of those two)?

```powershell
PS C:\Users\Administrator\Desktop\emails> Get-NetTCPConnection | Where-Object {($_.State -eq “Listen”) -and ($_.LocalPort -ge 130) -and ($_.LocalPort -le 140)}

LocalAddress                        LocalPort RemoteAddress                       RemotePort State       AppliedSetting OwningProcess
------------                        --------- -------------                       ---------- -----       -------------- -------------
::                                  135       ::                                  0          Listen                     832
10.10.207.81                        139       0.0.0.0                             0          Listen                     4
0.0.0.0                             135       0.0.0.0                             0          Listen                     832
```

I don't agree with the expected correct answer (which is 11). I only find 2 open ports: 135 and 139.  
11 open ports means all of them should be open!?

Answer: 11

For additional information, please see the references below.

## References

- [Approved Verbs for PowerShell Commands](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-5.1)
- [Get-ChildItem - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem?view=powershell-5.1)
- [Get-Command - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-command?view=powershell-5.1)
- [Get-Help - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-help?view=powershell-5.1)
- [PowerShell - Wikipedia](https://en.wikipedia.org/wiki/PowerShell)
- [Select-String - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string?view=powershell-5.1)
