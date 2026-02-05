# Retracted

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
Investigate the case of the missing ransomware.
```

Room link: [https://tryhackme.com/room/retracted](https://tryhackme.com/room/retracted)

## Solution

### Task 1: Introduction

#### A Mother's Plea

"Thanks for coming. I know you are busy with your new job, but I did not know who else to turn to."

"So I downloaded and ran an installer for an antivirus program I needed. After a while, I noticed I could no longer open any of my files. And then I saw that my wallpaper was different and contained a terrifying message telling me to pay if I wanted to get my files back. I panicked and got out of the room to call you. But when I came back, everything was back to normal."

"Except for one message telling me to check my Bitcoin wallet. But I don't even know what a Bitcoin is!"

"Can you help me check if my computer is now fine?"

#### Connecting to the Machine

Start the virtual machine in split-screen view by clicking on the green "**Start Machine**" button on the upper right section of this task. If the VM is not visible, use the blue "**Show Split View**" button at the top-right of the page. Alternatively, you can connect to the VM using the credentials below via "Remote Desktop".

- **Username**: `sophie`
- **Password**: `fluffy19601234!`
- **IP**: `10.67.188.31`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Retracted]
└─$ export TARGET_IP=10.67.188.31

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Retracted]
└─$ xfreerdp /v:$TARGET_IP /cert:ignore /u:sophie /p:'fluffy19601234!' /h:1024 /w:1500 +clipboard 
[17:31:14:350] [3737:3738] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[17:31:14:350] [3737:3738] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
<---snip---->
```

---------------------------------------------------------------------------

### Task 2: The Message

"So, as soon as you finish logging in to the computer, you'll see a file on the desktop addressed to me."

"I have no idea why that message is there and what it means. Maybe you do?"

---------------------------------------------------------------------------

#### What is the full path of the text file containing the "message"?

```bat
C:\Users\Sophie>cd Desktop

C:\Users\Sophie\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Sophie\Desktop

02/05/2026  04:25 PM    <DIR>          .
02/05/2026  04:25 PM    <DIR>          ..
01/08/2024  02:24 PM               407 FILES.lnk
01/08/2024  02:24 PM             4,301 FINAL_FundraisingPlan_2024 - Copy (4).docx
01/08/2024  02:24 PM             4,301 FundraisingPlan_2024 - Copy (2).docx
01/08/2024  02:24 PM             4,301 FundraisingPlan_2024 - Copy (3).docx
01/08/2024  02:24 PM             4,301 FundraisingPlan_2024 - Copy.docx
01/08/2024  02:24 PM             4,301 FundraisingPlan_2024.docx
01/08/2024  02:24 PM             8,255 FundraisingPlan_2024.odt
01/08/2024  02:24 PM             2,398 INTERNET.lnk
01/08/2024  02:24 PM           396,145 LOGO.png
01/08/2024  02:24 PM           119,855 Newsletter_DEC2023 - Copy.pptx
01/08/2024  02:24 PM           119,855 Newsletter_DEC2023.pptx
01/08/2024  02:24 PM           119,855 Newsletter_February2024.pptx
01/08/2024  02:24 PM           119,855 Newsletter_JAN2024 - Copy.pptx
01/08/2024  02:24 PM           119,855 Newsletter_JAN2024.pptx
01/08/2024  02:25 PM                19 SOPHIE.txt
01/08/2024  02:24 PM             4,233 Travel CHECKLIST.docx
01/08/2024  02:24 PM             4,708 VolunteerContacts - 2.xlsx
01/08/2024  02:24 PM             4,708 VolunteerContacts.xlsx
              18 File(s)      1,041,653 bytes
               2 Dir(s)  43,952,619,520 bytes free

C:\Users\Sophie\Desktop>type SOPHIE.txt
Check your bitcoin.
C:\Users\Sophie\Desktop>
```

Answer: `C:\Users\Sophie\Desktop\SOPHIE.txt`

#### What program was used to create the text file?

From an **elevated** PowerShell window, we can check for Sysmon events containing `sophie.txt`

```powershell
PS C:\Windows\system32> $search = "sophie.txt"
PS C:\Windows\system32> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'} | Where-Object { $_.Message.ToLower().Contains($search.ToLower())} | Format-Table -AutoSize -Wrap


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated         Id LevelDisplayName Message
-----------         -- ---------------- -------
1/8/2024 2:25:30 PM  1 Information      Process Create:
                                        RuleName: -
                                        UtcTime: 2024-01-08 14:25:30.749
                                        ProcessGuid: {c5d2b969-05da-659c-2601-000000002701}
                                        ProcessId: 5712
                                        Image: C:\Windows\System32\notepad.exe
                                        FileVersion: 10.0.17763.1697 (WinBuild.160101.0800)
                                        Description: Notepad
                                        Product: Microsoft® Windows® Operating System
                                        Company: Microsoft Corporation
                                        OriginalFileName: NOTEPAD.EXE
                                        CommandLine: "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Sophie\Desktop\SOPHIE.txt
                                        CurrentDirectory: C:\Windows\system32\
                                        User: SHIELDED-FUTURE\Sophie
                                        LogonGuid: {c5d2b969-0264-659c-07a5-050000000000}
                                        LogonId: 0x5A507
                                        TerminalSessionId: 2
                                        IntegrityLevel: Medium
                                        Hashes: MD5=5394096A1CEBF81AF24E993777CAABF4,SHA256=A28438E1388F272A52559536D99D65BA15B1A8288BE1200E249851FDF7EE6C7E,IMPHASH=C8922BE3DCD
                                        FEB5994C9EEE7745DC22E
                                        ParentProcessGuid: {c5d2b969-05d7-659c-2501-000000002701}
                                        ParentProcessId: 64
                                        ParentImage: C:\Windows\System32\OpenWith.exe
                                        ParentCommandLine: C:\Windows\system32\OpenWith.exe -Embedding
                                        ParentUser: SHIELDED-FUTURE\Sophie


PS C:\Windows\system32>
```

This event tell us that notepad.exe was used to **read** the file rather than **create** it, but it's all we have to go on...

Answer: `NOTEPAD.EXE`

#### What is the time of execution of the process that created the text file? Timezone UTC (Format YYYY-MM-DD hh:mm:ss)

Hint: Check the Sysmon Operational Logs and filter for Event ID 11.

From the log event above.

```text
UtcTime: 2024-01-08 14:25:30.749
```

Answer: `2024-01-08 14:25:30`

### Task 3: Something Wrong

"I swear something went wrong with my computer when I ran the installer. Suddenly, my files could not be opened, and the wallpaper changed, telling me to pay."

"Wait, are you telling me that the file I downloaded is a virus? But I downloaded it from Google!"

---------------------------------------------------------------------------

#### What is the filename of this "installer"? (Including the file extension)

We start by checking the downloads folder for any remaining files

```bat
C:\Users\Sophie\download>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Sophie\download

11/19/2025  07:31 PM    <DIR>          .
11/19/2025  07:31 PM    <DIR>          ..
01/08/2024  02:14 PM           755,323 antivirus.exe
01/08/2024  02:24 PM           513,938 decryptor.exe
11/19/2025  07:31 PM        95,881,032 Wireshark-4.6.0-x64.exe
               3 File(s)     97,150,293 bytes
               2 Dir(s)  43,823,054,848 bytes free

C:\Users\Sophie\download>
```

The earliest file is `antivirus.exe` so that ought to be the "installer".

Answer: `antivirus.exe`

#### What is the download location of this installer?

See above.

Answer: `C:\Users\Sophie\download`

#### The installer encrypts files and then adds a file extension to the end of the file name. What is this file extension?

We can check for Sysmon file create events (EID 11) from the `antivirus.exe` program

```powershell
PS C:\Windows\system32> $search = "antivirus.exe"
PS C:\Windows\system32> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';'Id'=11} | Where-Object { $_.Message.ToLower().Contains($search.ToLower())
} | Format-Table -AutoSize -Wrap


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated         Id LevelDisplayName Message
-----------         -- ---------------- -------
1/8/2024 2:15:01 PM 11 Information      File created:
                                        RuleName: -
                                        UtcTime: 2024-01-08 14:15:01.682
                                        ProcessGuid: {c5d2b969-0364-659c-d500-000000002701}
                                        ProcessId: 5992
                                        Image: C:\Users\Sophie\download\antivirus.exe
                                        TargetFilename: C:\Users\Sophie\Desktop\VolunteerContacts.xlsx.dmp
                                        CreationUtcTime: 2024-01-05 02:57:01.210
                                        User: SHIELDED-FUTURE\Sophie
1/8/2024 2:15:01 PM 11 Information      File created:
                                        RuleName: -
                                        UtcTime: 2024-01-08 14:15:01.650
                                        ProcessGuid: {c5d2b969-0364-659c-d500-000000002701}
                                        ProcessId: 5992
                                        Image: C:\Users\Sophie\download\antivirus.exe
                                        TargetFilename: C:\Users\Sophie\Desktop\VolunteerContacts - 2.xlsx.dmp
                                        CreationUtcTime: 2024-01-05 02:57:08.877
                                        User: SHIELDED-FUTURE\Sophie
1/8/2024 2:15:01 PM 11 Information      File created:
                                        RuleName: -
                                        UtcTime: 2024-01-08 14:15:01.635
                                        ProcessGuid: {c5d2b969-0364-659c-d500-000000002701}
                                        ProcessId: 5992
                                        Image: C:\Users\Sophie\download\antivirus.exe
                                        TargetFilename: C:\Users\Sophie\Desktop\Travel CHECKLIST.docx.dmp
                                        CreationUtcTime: 2024-01-05 03:00:30.543
                                        User: SHIELDED-FUTURE\Sophie
1/8/2024 2:15:01 PM 11 Information      File created:
                                        RuleName: -
                                        UtcTime: 2024-01-08 14:15:01.603
                                        ProcessGuid: {c5d2b969-0364-659c-d500-000000002701}
                                        ProcessId: 5992
                                        Image: C:\Users\Sophie\download\antivirus.exe
                                        TargetFilename: C:\Users\Sophie\Desktop\Newsletter_JAN2024.pptx.dmp
                                        CreationUtcTime: 2024-01-05 02:58:15.137
                                        User: SHIELDED-FUTURE\Sophie
<---snip--->
```

An additional `.dmp` extension seems to be added.

Answer: `.dmp`

#### The installer reached out to an IP. What is this IP?

Here we check for network connection (EID 3) in the same manner

```powershell
PS C:\Windows\system32> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';'Id'=3} | Where-Object { $_.Message.ToLower().Contains($search.ToLower())}
 | Format-Table -AutoSize -Wrap


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated         Id LevelDisplayName Message
-----------         -- ---------------- -------
1/8/2024 2:15:02 PM  3 Information      Network connection detected:
                                        RuleName: Usermode
                                        UtcTime: 2024-01-08 14:15:00.821
                                        ProcessGuid: {c5d2b969-0364-659c-d500-000000002701}
                                        ProcessId: 5992
                                        Image: C:\Users\Sophie\download\antivirus.exe
                                        User: SHIELDED-FUTURE\Sophie
                                        Protocol: tcp
                                        Initiated: true
                                        SourceIsIpv6: false
                                        SourceIp: 10.10.235.67
                                        SourceHostname: SHIELDED-FUTURES-012.eu-west-1.compute.internal
                                        SourcePort: 49780
                                        SourcePortName: -
                                        DestinationIsIpv6: false
                                        DestinationIp: 10.10.8.111
                                        DestinationHostname: ip-10-10-8-111.eu-west-1.compute.internal
                                        DestinationPort: 80
                                        DestinationPortName: http


PS C:\Windows\system32>
```

Answer: `10.10.8.111`

### Task 4: Back to Normal

"So what happened to the virus? It does seem to be gone since all my files are back."

---------------------------------------------------------------------------

#### The threat actor logged in via RDP right after the “installer” was downloaded. What is the source IP?

Checking for EID 4624 with Logon type 10 (RDP) in the security log gives us nothing.

Next, we check the Sysmon network connections instead around the specified time

```powershell
PS C:\Windows\system32> $StartTime = Get-Date "2024-01-08 14:15:00"
PS C:\Windows\system32> $EndTime = Get-Date "2024-01-08 14:20:00"
PS C:\Windows\system32> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';'Id'=3;StartTime=$StartTime;EndTime=$EndTime} | Format-Table -AutoSize -Wr
ap


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated         Id LevelDisplayName Message
-----------         -- ---------------- -------
1/8/2024 2:19:46 PM  3 Information      Network connection detected:
                                        RuleName: RDP
                                        UtcTime: 2024-01-08 14:19:44.364
                                        ProcessGuid: {c5d2b969-01e7-659c-1500-000000002701}
                                        ProcessId: 1108
                                        Image: C:\Windows\System32\svchost.exe
                                        User: NT AUTHORITY\NETWORK SERVICE
                                        Protocol: tcp
                                        Initiated: false
                                        SourceIsIpv6: false
                                        SourceIp: 10.11.27.46
                                        SourceHostname: ip-10-11-27-46.eu-west-1.compute.internal
                                        SourcePort: 62336
                                        SourcePortName: -
                                        DestinationIsIpv6: false
                                        DestinationIp: 10.10.235.67
                                        DestinationHostname: SHIELDED-FUTURES-012.eu-west-1.compute.internal
                                        DestinationPort: 3389
                                        DestinationPortName: ms-wbt-server
1/8/2024 2:19:22 PM  3 Information      Network connection detected:
                                        RuleName: RDP
                                        UtcTime: 2024-01-08 14:19:20.300
                                        ProcessGuid: {c5d2b969-01e7-659c-1500-000000002701}
                                        ProcessId: 1108
                                        Image: C:\Windows\System32\svchost.exe
                                        User: NT AUTHORITY\NETWORK SERVICE
                                        Protocol: tcp
                                        Initiated: false
                                        SourceIsIpv6: false
                                        SourceIp: 10.11.27.46
                                        SourceHostname: ip-10-11-27-46.eu-west-1.compute.internal
                                        SourcePort: 62305
                                        SourcePortName: -
                                        DestinationIsIpv6: false
                                        DestinationIp: 10.10.235.67
                                        DestinationHostname: SHIELDED-FUTURES-012.eu-west-1.compute.internal
                                        DestinationPort: 3389
                                        DestinationPortName: ms-wbt-server
<---snip--->
```

Answer: `10.11.27.46`

#### This other person downloaded a file and ran it. When was this file run? Timezone UTC (Format YYYY-MM-DD hh:mm:ss)

This ought to be the `decryptor.exe` file we saw earlier in the downloads folder.

```powershell
PS C:\Windows\system32> $search = "decryptor"
PS C:\Windows\system32> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';'Id'=1} -Oldest | Where-Object { $_.Message.ToLower().Contains($search.ToL
ower())} | Format-Table -AutoSize -Wrap


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated         Id LevelDisplayName Message
-----------         -- ---------------- -------
1/8/2024 2:24:18 PM  1 Information      Process Create:
                                        RuleName: -
                                        UtcTime: 2024-01-08 14:24:18.804
                                        ProcessGuid: {c5d2b969-0592-659c-1f01-000000002701}
                                        ProcessId: 4544
                                        Image: C:\Users\Sophie\download\decryptor.exe
                                        FileVersion: -
                                        Description: -
                                        Product: -
                                        Company: -
                                        OriginalFileName: -
                                        CommandLine: "C:\Users\Sophie\download\decryptor.exe"
                                        CurrentDirectory: C:\Users\Sophie\download\
                                        User: SHIELDED-FUTURE\Sophie
                                        LogonGuid: {c5d2b969-0264-659c-07a5-050000000000}
                                        LogonId: 0x5A507
                                        TerminalSessionId: 2
                                        IntegrityLevel: Medium
                                        Hashes: MD5=360DC0ABA309223907043AC5E276AEBB,SHA256=C6DD0F1AC07DBC817ABD3D394792277AFF9E6D427C492DF5053B7AAE057A64C8,IMPHASH=4A0411EBC46
                                        ED2F391209645A07E464B
                                        ParentProcessGuid: {c5d2b969-0266-659c-9c00-000000002701}
                                        ParentProcessId: 3696
                                        ParentImage: C:\Windows\explorer.exe
                                        ParentCommandLine: C:\Windows\Explorer.EXE
                                        ParentUser: SHIELDED-FUTURE\Sophie


PS C:\Windows\system32>
```

Answer: `2024-01-08 14:24:18`

### Task 5: Doesn't Make Sense

"So you're telling me that someone accessed my computer and changed my files but later undid the changes?"

"That doesn't make any sense. Why infect my machine and clean it afterwards?"

"Can you help me make sense of this?"

Arrange the following events in sequential order from 1 to 7, based on the timeline in which they occurred.

---------------------------------------------------------------------------

#### After seeing the ransomware note, Sophie ran out and reached out to you for help

Answer: `3`

#### Sophie downloaded the malware and ran it

UtcTime: 2024-01-08 14:15:00.688

Answer: `1`

#### After all the files are restored, the intruder left the desktop telling Sophie to check her Bitcoin

Monday, January 8, 2024, 2:25:16 PM

Answer: `6`

#### The intruder realized he infected a charity organization. He then downloaded a decryptor and decrypted all the files

UtcTime: 2024-01-08 14:24:18.804
to
UtcTime: 2024-01-08 14:24:19.573

Answer: `5`

#### The downloaded malware encrypted the files on the computer and showed a ransomware note

UtcTime: 2024-01-08 14:15:00.885
to
UtcTime: 2024-01-08 14:15:01.697

Answer: `2`

#### While Sophie was away, an intruder logged into Sophie's machine via RDP and started looking around

UtcTime: 2024-01-08 14:19:20.300

Answer: `4`

#### Sophie and I arrive on the scene to investigate. At this point, the intruder was gone

Answer: `7`

### Task 6: Conclusion

"Adelle from Finance just called me. She says that someone just donated a huge amount of bitcoin to our charity's account!"

"Could this be our intruder? His malware accidentally infected our systems, found the mistake, and retracted all the changes?"

"Maybe he had a change of heart?"

---------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [Event Viewer - Wikipedia](https://en.wikipedia.org/wiki/Event_Viewer)
- [PowerShell - Wikipedia](https://en.wikipedia.org/wiki/PowerShell)
- [Remote Desktop Protocol - Wikipedia](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol)
- [Sysmon - Homepage](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [xfreerdp - Linux manual page](https://linux.die.net/man/1/xfreerdp)
