# Windows Fundamentals 1

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
OS: Windows
Subscription type: Free
In part 1 of the Windows Fundamentals module, we'll start our journey learning about the Windows desktop, 
the NTFS file system, UAC, the Control Panel, and more.
```

Room link: [https://tryhackme.com/room/windowsfundamentals1xbx](https://tryhackme.com/room/windowsfundamentals1xbx)

## Solution

### Task 1 - Introduction to Windows

This module will attempt to provide a general overview of just a handful of what makes up the Windows OS,  
navigate the user interface, make changes to the system, etc.  The content is aimed at those who wish to  
understand and use the Windows OS on a more comfortable level.

We start by connecting to the machine with `freerdp`. Install it with `sudo apt-get install freerdp2-x11` if needed.  
Alternatively, use the AttackBox.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Info/Windows_Fundamentals_1]
└─$ xfreerdp /v:10.10.88.136 /cert:ignore /u:administrator /p:'letmein123!' /h:960 /w:1500 +clipboard
[10:14:29:729] [4743:4744] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[10:14:29:729] [4743:4744] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
<---snip--->
```

### Task 2 - Windows Editions

The Windows operating system has a long history dating back to 1985, and currently,  it is the dominant operating  
system in both home use and corporate networks. Because of this, Windows has always been targeted by hackers &  
malware writers.

As of October 5th, 2021 - Windows 11 now is the current Windows operating system for end-users.

#### What encryption can you enable on Pro that you can't enable in Home?

Answer: BitLocker

### Task 3 - The Desktop (GUI)

The Windows Desktop, aka the graphical user interface or GUI in short, is the screen that welcomes you once you  
log into a Windows 10 machine.

#### The Desktop

The desktop is where you will have shortcuts to programs, folders, files, etc. These icons will either be well  
organized in folders sorted alphabetically or scattered randomly with no specific organization on the desktop.  
In either case, these items are typically placed on the desktop for quick access.

#### The Start Menu

In previous versions of Windows, the word Start was visible at the bottom left corner of the desktop GUI. In modern  
versions of Windows, such as Windows 10, the word 'Start' doesn't appear anymore, but rather a Windows Logo is shown  
instead. Even though the look of the Start Menu has changed, its overall purpose is the same.

The Start Menu provides access to all the apps/programs, files, utility tools, etc., that are most useful.

Clicking on the Windows logo, the Start Menu will open. The Start Menu is broken up into sections.

#### Which selection will hide/disable the Search box?

Answer: Hidden

#### Which selection will hide/disable the Task View button?

Answer: Show Task View button

#### Besides Clock and Network, what other icon is visible in the Notification Area?

Hint: Try right-clicking the icon

Answer: Action Center

### Task 4 - The File System

The file system used in modern versions of Windows is the New Technology File System or simply NTFS.

Before NTFS, there was FAT16/FAT32 (File Allocation Table) and HPFS (High Performance File System).

NTFS is known as a journaling file system. In case of a failure, the file system can automatically  
repair the folders/files on disk using information stored in a log file. This function is not  
possible with FAT.

NTFS addresses many of the limitations of the previous file systems; such as:

- Supports files larger than 4GB
- Set specific permissions on folders and files
- Folder and file compression
- Encryption (Encryption File System or EFS)

On NTFS volumes, you can set permissions that grant or deny access to files and folders.  
The permissions are:

- Full control
- Modify
- Read & Execute
- List folder contents
- Read
- Write

| Permission | Meaning for Folders | Meaning for Files |
|----|----|----|
|Read|Permits viewing and listing of files and subfolders|Permits viewing or accessing of the file's contents|
|Write|Permits adding of files and subfolders|Permits writing to a file|
|Read & Execute|Permits viewing and listing of files and subfolders as well as executing of files; inherited by files and folders|Permits viewing and accessing of the file's contents as well as executing of the file|
|List Folder Contents|Permits viewing and listing of files and subfolders as well as executing of files; inherited by folders only|N/A|
|Modify|Permits reading and writing of files and subfolders; allows deletion of the folder|Permits reading and writing of the file; allows deletion of the file|
|Full Control|Permits reading, writing, changing, and deleting of files and subfolders|Permits reading, writing, changing and deleting of the file|

Another feature of NTFS is [Alternate Data Streams (ADS)](https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)). Alternate Data Streams (ADS) is a file attribute specific to Windows NTFS.

Every file has at least one data stream ($DATA), and ADS allows files to contain more than one stream of data. Natively Window Explorer doesn't display ADS to the user. There are 3rd party executables that can be used to view this data, but Powershell gives you the ability to view ADS for files.

From a security perspective, malware writers have used ADS to hide data.

#### What is the meaning of NTFS?

Answer: New Technology File System

### Task 5 - The Windows\System32 Folders

The Windows folder (C:\Windows) is traditionally known as the folder which contains the Windows operating system. The folder doesn't have to reside in the C drive necessarily. It can reside in any other drive and technically can reside in a different folder.

This is where environment variables, more specifically system environment variables, come into play. Even though not discussed yet, the system  environment variable for the Windows directory is `%windir%`.

The System32 folder holds the important files that are critical for the operating system.

#### What is the system variable for the Windows folder?

Answer: %windir%

### Task 6 -  User Accounts, Profiles, and Permissions

User accounts can be one of two types on a typical local Windows system: Administrator & Standard User.

The user account type will determine what actions the user can perform on that specific Windows system.

- An Administrator can make changes to the system: add users, delete users, modify groups, modify settings on the system, etc.
- A Standard User can only make changes to folders/files attributed to the user & can't perform system-level changes, such as install programs.

#### What is the name of the other user account?

```text
C:\Users\Administrator>net user

User accounts for \\THM-WINFUN1

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
tryhackmebilly           WDAGUtilityAccount
The command completed successfully.
```

Answer: tryhackmebilly

#### What groups is this user a member of?

```text
C:\Users\Administrator>net user tryhackmebilly
User name                    tryhackmebilly
Full Name                    TRY HACK ME
Comment                      window$Fun1!
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/4/2021 12:55:40 AM
Password expires             Never
Password changeable          5/4/2021 12:55:40 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   6/22/2021 10:20:30 AM

Logon hours allowed          All

Local Group Memberships      *Remote Desktop Users *Users
Global Group memberships     *None
The command completed successfully.
```

Answer: Remote Desktop Users,Users

#### What built-in account is for guest access to the computer?

```text
C:\Users\Administrator>net user guest
User name                    Guest
Full Name
Comment                      Built-in account for guest access to the computer/domain
User's comment
Country/region code          000 (System Default)
Account active               No
Account expires              Never

Password last set            4/20/2025 2:26:41 AM
Password expires             Never
Password changeable          4/20/2025 2:26:41 AM
Password required            No
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Guests
Global Group memberships     *None
The command completed successfully.
```

Answer: Guest

#### What is the account description?

```text
C:\Users\Administrator>net user tryhackmebilly
User name                    tryhackmebilly
Full Name                    TRY HACK ME
Comment                      window$Fun1!
User's comment
<---snip--->
Global Group memberships     *None
The command completed successfully.
```

Answer: window$Fun1!

### Task 7 - User Account Control

The large majority of home users are logged into their Windows systems as local administrators. Remember from the previous task that any user with administrator as the account type can make changes to the system.

A user doesn't need to run with high (elevated) privileges on the system to run tasks that don't require such privileges, such as surfing the Internet, working on a Word document, etc. This elevated privilege increases the risk of system compromise because it makes it easier for malware to infect the system. Consequently, since the user account can make changes to the system, the malware would run in the context of the logged-in user.

To protect the local user with such privileges, Microsoft introduced User Account Control (UAC). This concept was first introduced with the short-lived Windows Vista  and continued with versions of Windows that followed.

Note: UAC (by default) doesn't apply for the built-in local administrator account.

How does UAC work? When a user with an account type of administrator logs into a system, the current session doesn't run with elevated permissions. When an operation requiring higher-level privileges needs to execute, the user will be prompted to confirm if they permit the operation to run.

#### What does UAC mean?

Answer: User Account Control

### Task 8 - Settings and the Control Panel

On a Windows system, the primary locations to make changes are the Settings menu and the Control Panel.

For a long time, the Control Panel has been the go-to location to make system changes, such as adding a printer, uninstall a program, etc.

The Settings menu was introduced in Windows 8, the first Windows operating system catered to touch screen tablets, and is still available in Windows 10. As a matter of fact, the Settings menu is now the primary location a user goes to if they are looking to change the system.

#### In the Control Panel, change the view to Small icons. What is the last setting in the Control Panel view?

Answer: Windows Defender Firewall

### Task 9 - Task Manager

The last subject that will be touched on in this module is the Task Manager.

The Task Manager provides information about the applications and processes currently running on the system.  
Other information is also available, such as how much CPU and RAM are being utilized, which falls under Performance.

#### What is the keyboard shortcut to open Task Manager?

Answer: Ctrl+Shift+Esc

For additional information, please see the references below.

## References

- [File and Folder Permissions - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb727008(v=technet.10))
- [Microsoft Windows - Wikipedia](https://en.wikipedia.org/wiki/Microsoft_Windows)
- [NTFS - Wikipedia](https://en.wikipedia.org/wiki/NTFS)
- [NTFS overview - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview)
- [User Account Control - Wikipedia](https://en.wikipedia.org/wiki/User_Account_Control)
