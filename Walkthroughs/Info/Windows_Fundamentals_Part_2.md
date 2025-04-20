# Windows Fundamentals 2

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
OS: Windows
Subscription type: Free
In part 2 of the Windows Fundamentals module, discover more about System Configuration, UAC Settings, 
Resource Monitoring, the Windows Registry and more.
```

Room link: [https://tryhackme.com/room/windowsfundamentals2x0x](https://tryhackme.com/room/windowsfundamentals2x0x)

## Solution

### Task 1 - Introduction to Windows

We will continue our journey exploring the Windows operating system.

In Windows Fundamentals 1, we covered the desktop, the file system, user account control, the control panel, settings, and the task manager.

This module will attempt to provide an overview of some other utilities available within the Windows operating system and different methods to access these utilities.

We start by connecting to the machine with `freerdp`. Install it with `sudo apt-get install freerdp2-x11` if needed.  
Alternatively, use the AttackBox.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Info/Windows_Fundamentals_2]
└─$ xfreerdp /v:10.10.31.129 /cert:ignore /u:administrator /p:'letmein123!' /h:960 /w:1500 +clipboard
[11:45:06:547] [48858:48859] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[11:45:06:547] [48858:48859] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
<---snip--->
```

### Task 2 - System Configuration

The System Configuration utility (MSConfig) is for advanced troubleshooting, and its main purpose is to help diagnose startup issues.

Note: You need local administrator rights to open this utility.

The utility has five tabs across the top. Below are the names for each tab.

1. General
2. Boot
3. Services
4. Startup
5. Tools

#### What is the name of the service that lists Systems Internals as the manufacturer?

Check the `Services` tab of `System Configuration`

Answer: PsShutdown

#### Whom is the Windows license registered to?

Launch the `About Windows` Tool

Answer: Windows User

#### What is the command for Windows Troubleshooting?

Check `Windows Troubleshooting` on the `Tools` tab

Answer: C:\Windows\System32\control.exe /name Microsoft.Troubleshooting

#### What command will open the Control Panel? (The answer is the name of .exe, not the full path)

See answer of previous question

Answer: control.exe

### Task 3 - Change UAC Settings

We're continuing with Tools that are available through the System Configuration panel.

User Account Control (UAC) was covered in great detail in Windows Fundamentals 1.

The UAC settings can be changed or even turned off entirely (not recommended).

#### What is the command to open User Account Control Settings? (The answer is the name of the .exe file, not the full path)

Check `Change UAC Settings` on the `Tools` tab

Answer: UserAccountControlSettings.exe

### Task 4 - Computer Management

We're continuing with tools that are available through the System Configuration panel.

The Computer Management (compmgmt) utility has three primary sections: System Tools, Storage, and Services and Applications.

#### What is the command to open Computer Management? (The answer is the name of the .msc file, not the full path)

Answer: compmgmt.msc

#### At what time every day is the GoogleUpdateTaskMachineUA task configured to run?

See `Start Time` of the following output

```text
C:\Users\Administrator>schtasks.exe /query /tn GoogleUpdateTaskMachineUA /v /fo list

Folder: \
HostName:                             THM-WINFUN2
TaskName:                             \GoogleUpdateTaskMachineUA
Next Run Time:                        4/20/2025 4:15:35 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        4/20/2025 3:15:35 AM
Last Result:                          0
Author:                               N/A
Task To Run:                          C:\Program Files (x86)\Google\Update\GoogleUpdate.exe /ua /installsource scheduler
Start In:                             N/A
Comment:                              Keeps your Google software up to date. If this task is disabled or stopped, your Google software will not be kept up to date, meaning security vulnerabilities that may arise cannot be fixed and features may not work. This task uninstalls itself when the
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Daily
Start Time:                           6:15:35 AM
Start Date:                           4/23/2021
End Date:                             N/A
Days:                                 Every 1 day(s)
Months:                               N/A
Repeat: Every:                        1 Hour(s), 0 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              24 Hour(s), 0 Minute(s)
Repeat: Stop If Still Running:        Disabled
```

Answer: 6:15 AM

#### What is the name of the hidden folder that is shared?

```text
C:\Users\Administrator>net view \\localhost
Shared resources at \\localhost



Share name    Type  Used as  Comment

-------------------------------------------------------------------------------
sh4r3dF0Ld3r  Disk
The command completed successfully.
```

Answer: sh4r3dF0Ld3r

### Task 5 - System Information

We're continuing with Tools that are available through the System Configuration panel.

What is the System Information (msinfo32) tool?

Per Microsoft, "*Windows includes a tool called Microsoft System Information (Msinfo32.exe).  This tool gathers information about your computer and displays a comprehensive view of your hardware, system components, and software environment, which you can use to diagnose computer issues.*"

The information in System Summary is divided into three sections:

- Hardware Resources
- Components
- Software Environment

#### What is the command to open System Information? (The answer is the name of the .exe file, not the full path)

Answer: msinfo32.exe

#### What is listed under System Name?

```text
C:\Users\Administrator>hostname
THM-WINFUN2

C:\Users\Administrator>systeminfo.exe | findstr /i name
Host Name:                 THM-WINFUN2
OS Name:                   Microsoft Windows Server 2019 Standard
                                 Connection Name: Ethernet
```

Answer: THM-WINFUN2

#### Under Environment Variables, what is the value for ComSpec?

See `Software Environment` and then `Environment Variables`

Answer: %SystemRoot%\system32\cmd.exe

### Task 6 -  Resource Monitor

We're continuing with Tools that are available through the System Configuration panel.

What is Resource Monitor (resmon)?

Per Microsoft, "*Resource Monitor displays per-process and aggregate CPU, memory, disk, and network usage information, in addition to providing details about which processes are using individual file handles and modules. Advanced filtering allows users to isolate the data related to one or more processes (either applications or services), start, stop, pause, and resume services, and close unresponsive applications from the user interface. It also includes a process analysis feature that can help identify deadlocked processes and file locking conflicts so that the user can attempt to resolve the conflict instead of closing an application and potentially losing data.*"

As some of the other tools mentioned in this room, this utility is geared primarily to advanced users who need to perform advanced troubleshooting on the computer system.

In the Overview tab, Resmon has four sections:

- CPU
- Disk
- Network
- Memory

#### What is the command to open Resource Monitor? (The answer is the name of the .exe file, not the full path)

Answer: resmon.exe

### Task 7 - Command Prompt

We're continuing with Tools that are available through the System Configuration panel.

The command prompt (cmd) can seem daunting at first, but it's really not that bad once you understand how to interact with it.

In early operating systems, the command line was the sole way to interact with the operating system.

#### In System Configuration, what is the full command for Internet Protocol Configuration?

Answer: C:\Windows\System32\cmd.exe /k %windir%\system32\ipconfig.exe

#### For the ipconfig command, how do you show detailed information?

Answer: ipconfig /all

### Task 8 - Settings and the Control Panel

We're continuing with Tools that are available through the System Configuration panel.

The Windows Registry (per Microsoft) is a central hierarchical database used to store information necessary to configure the system for one or more users, applications, and hardware devices.

The registry contains information that Windows continually references during operation, such as:

- Profiles for each user
- Applications installed on the computer and the types of documents that each can create
- Property sheet settings for folders and application icons
- What hardware exists on the system
- The ports that are being used.

Warning: The registry is for advanced computer users. Making changes to the registry can affect normal computer operations.

There are various ways to view/edit the registry. One way is to use the Registry Editor (regedit).

#### What is the command to open the Registry Editor? (The answer is the name of  the .exe file, not the full path)

Hint: Refer to the command in MSConfig

Answer: regedt32.exe

## References

- [Microsoft Windows - Wikipedia](https://en.wikipedia.org/wiki/Microsoft_Windows)
- [User Account Control - Wikipedia](https://en.wikipedia.org/wiki/User_Account_Control)
