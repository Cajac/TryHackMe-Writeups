# Windows Command Line

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Learn the essential Windows commands.
```

Room link: [https://tryhackme.com/room/windowscommandline](https://tryhackme.com/room/windowscommandline)

## Solution

### Task 1 - Introduction

Everyone prefers a graphical user interface (GUI) until they master a command-line interface (CLI). There are many reasons for that. One reason is that GUIs are usually intuitive. If someone offers you a GUI interface you are unfamiliar with, you can quickly poke around and discover a non-trivial part. Compare this with dealing with a CLI, i.e., a prompt.

CLI interfaces usually have a learning curve; however, as you master the command line, you will find it faster and more efficient. Consider this trivial example: How many clicks do you need to find your IP address using the graphical desktop? Using the command-line interface, you don’t even need to raise your hands off the keyboard. Let’s say you want to recheck your IP address. You need to issue the same command instead of moving the mouse pointer to every corner of your screen.

There are many other advantages to using a CLI besides speed and efficiency. We will mention a few:

- **Lower resource usage**: CLIs require fewer system resources than graphics-intensive GUIs. In other words, you can run your CLI system on older hardware or systems with limited memory. If you are using cloud computing, your system will require lower resources, which in turn will lower your bill.
- **Automation**: While you can automate GUI tasks, creating a batch file or script with the commands you need to repeat is much easier.
- **Remote management**: CLI makes it very convenient to use SSH to manage a remote system such as a server, router, or an IoT device. This approach works well on slow network speeds and systems with limited resources.

#### Learning Objectives

The purpose of this room is to teach you how to use MS Windows Command Prompt `cmd.exe`, the default command-line interpreter in the Windows environment. We will learn how to use the command line to:

- Display basic system information
- Check and troubleshoot network configuration
- Manage files and folders
- Check running processes

#### Connect

We start by connecting to the machine with `ssh`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Windows_Command_Line]
└─$ ssh user@10.10.198.170               
The authenticity of host '10.10.198.170 (10.10.198.170)' can't be established.
ED25519 key fingerprint is SHA256:WXNrzCBIhI0BbpO2+dlBbLRIlFimN8JzidezgFTQOM8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.198.170' (ED25519) to the list of known hosts.
user@10.10.198.170's password: 


<---snip---> 


Microsoft Windows [Version 10.0.20348.2655]
(c) Microsoft Corporation. All rights reserved.

user@WINSRV2022-CORE C:\Users\user>
```

#### What is the default command line interpreter in the Windows environment?

Answer: cmd.exe

### Task 2 - Basic System Information

Before issuing commands, we should note that we can only issue the commands within the Windows Path.  
You can issue the command `set` to check your path from the command line.

```text
user@WINSRV2022-CORE C:\Users\user>set
ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\user\AppData\Roaming
ChocolateyInstall=C:\ProgramData\chocolatey
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=WINSRV2022-CORE
ComSpec=C:\Windows\system32\cmd.exe
DriverData=C:\Windows\System32\Drivers\DriverData
EC2LAUNCH_TELEMETRY=1
HOME=C:\Users\user
HOMEDRIVE=C:
HOMEPATH=\Users\user
LOCALAPPDATA=C:\Users\user\AppData\Local
LOGNAME=user
NUMBER_OF_PROCESSORS=2
OS=Windows_NT
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\ProgramData\chocolatey\bin;C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\WindowsApps;C:\Users\user\AppData\Local\Microsoft\WindowsApps;
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD
PROCESSOR_LEVEL=23
PROCESSOR_REVISION=0102
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=user@WINSRV2022-CORE $P$G
PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC=C:\Users\Public
SHELL=c:\windows\system32\cmd.exe
SSH_CLIENT=10.14.61.233 45978 22
SSH_CONNECTION=10.14.61.233 45978 10.10.198.170 22
SSH_TTY=windows-pty
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Users\user\AppData\Local\Temp
TERM=xterm-256color
TMP=C:\Users\user\AppData\Local\Temp
USER=user
USERDOMAIN=WORKGROUP
USERNAME=user
USERPROFILE=C:\Users\user
windir=C:\Windows
```

Then let’s use the `ver` command to determine the operating system (OS) version.

```text
user@WINSRV2022-CORE C:\Users\user>ver

Microsoft Windows [Version 10.0.20348.2655]
```

Enough warming up. Let’s discover more in-depth information about the system. We can run the `systeminfo` command to list various information about the system such as OS information, system details, processor and memory.

```text
user@WINSRV2022-CORE C:\Users\user>systeminfo
                                                                              
Host Name:                 WINSRV2022-CORE
OS Name:                   Microsoft Windows Server 2022 Datacenter
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00454-60000-00001-AA763
Original Install Date:     4/23/2024, 7:36:29 PM
System Boot Time:          4/20/2025, 4:41:52 PM
System Manufacturer:       Amazon EC2
System Model:              t3a.micro
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2200 Mhz
BIOS Version:              Amazon EC2 1.0, 10/16/2017
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     980 MB
Available Physical Memory: 321 MB
Virtual Memory: Max Size:  1,300 MB
Virtual Memory: Available: 619 MB
Virtual Memory: In Use:    681 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB5041948
                           [02]: KB5041160
                           [03]: KB5032310
                           [04]: KB5041590
Network Card(s):           1 NIC(s) Installed.
                           [01]: Amazon Elastic Network Adapter
                                 Connection Name: Ethernet
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.198.170
                                 [02]: fe80::7723:1a05:e094:d317
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

Before moving on, it is good to mention a couple of tricks.

First, you can pipe it through `more` if the output is too long. Then, you can view it page after page by pressing the space bar button.

Second, `help` provides help information for a specific command and `cls` clears the Command Prompt screen.

#### What is the OS version of the Windows VM?

```text
user@WINSRV2022-CORE C:\Users\user>ver

Microsoft Windows [Version 10.0.20348.2655]
```

Answer: 10.0.20348.2655

#### What is the hostname of the Windows VM?

```text
user@WINSRV2022-CORE C:\Users\user>hostname
WINSRV2022-CORE
```

Answer: WINSRV2022-CORE

### Task 3 - Network Troubleshooting

Most of us are used to looking up MS Windows network configuration from the GUI interface. The command-line interface provides many networking-related commands to look up your current configuration, check ongoing connections, and troubleshoot networking issues.

#### Network Configuration

You can check your network information using `ipconfig`. The terminal output below shows our IP address, subnet mask, and default gateway.

```text
user@WINSRV2022-CORE C:\Users\user>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::7723:1a05:e094:d317%5
   IPv4 Address. . . . . . . . . . . : 10.10.198.170
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1
```

You can also use `ipconfig /all` for more information about your network configuration.

#### Network Troubleshooting

One common troubleshooting task is checking if the server can access a particular server on the Internet. The command syntax is `ping target_name`. Inspired by ping-pong, we send a specific ICMP packet and listen for a response. If a response is received, we know that we can reach the target and that the target can reach us.

Another valuable tool for troubleshooting is `tracert`, which stands for trace route. The command `tracert target_name` traces the network route traversed to reach the target. Without getting into more details, it expects the routers on the path to notify us if they drop a packet because its time-to-live (TTL) has reached zero.

#### More Networking Commands

One networking command worth knowing is `nslookup`. It looks up a host or domain and returns its IP address. The syntax `nslookup example.com` will look up example.com using the default name server; however, `nslookup example.com 1.1.1.1` will use the name server 1.1.1.1.

The final networking command we will cover in this room is `netstat`. This command displays current network connections and listening ports. A basic `netstat` command with no arguments will show you established connections.

```text
user@WINSRV2022-CORE C:\Users\user>netstat

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    10.10.198.170:22       ip-10-14-61-233:45978  ESTABLISHED

```

If you are curious about the other options, you can run `netstat -h`, where `-h` displays the help page. We opted for the following options:

- `-a` displays all established connections and listening ports
- `-b` shows the program associated with each listening port and established connection
- `-o` reveals the process ID (PID) associated with the connection
- `-n` uses a numerical form for addresses and port numbers

#### Which command can we use to look up the server’s physical address (MAC address)?

Hint: Use ipconfig

```text
user@WINSRV2022-CORE C:\Users\user>ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : WINSRV2022-CORE
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : eu-west-1.compute.internal
                                       eu-west-1.ec2-utilities.amazonaws.com

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : Amazon Elastic Network Adapter
   Physical Address. . . . . . . . . : 02-EA-FC-87-E9-95                    <------ Here!
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::7723:1a05:e094:d317%5(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.10.198.170(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Sunday, April 20, 2025 4:42:29 PM
   Lease Expires . . . . . . . . . . : Sunday, April 20, 2025 6:12:28 PM
   Default Gateway . . . . . . . . . : 10.10.0.1
   DHCP Server . . . . . . . . . . . : 10.10.0.1
   DHCPv6 IAID . . . . . . . . . . . : 84601211
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2D-B9-B7-EF-00-0C-29-FF-E5-C8
   DNS Servers . . . . . . . . . . . : 10.0.0.2
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

Answer: ipconfig /all

#### What is the name of the process listening on port 3389?

```text
user@WINSRV2022-CORE C:\Users\user>netstat -abon               

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       1420
 [sshd.exe]
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       892
  RpcEptMapper
<---snip--->
 [svchost.exe]
  UDP    0.0.0.0:500            *:*                                    504
  IKEEXT
 [svchost.exe]
  UDP    0.0.0.0:3389           *:*                                    988
  TermService
 [svchost.exe]
  UDP    0.0.0.0:4500           *:*                                    504
  IKEEXT
<---snip--->
  UDP    [::]:500               *:*                                    504
  IKEEXT
 [svchost.exe]
  UDP    [::]:3389              *:*                                    988
  TermService
 [svchost.exe]
  UDP    [::]:4500              *:*                                    504
  IKEEXT
<---snip--->
```

Answer: TermService

#### What is the subnet mask?

```text
user@WINSRV2022-CORE C:\Users\user>ipconfig /all                 

Windows IP Configuration

   Host Name . . . . . . . . . . . . : WINSRV2022-CORE
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : eu-west-1.compute.internal
                                       eu-west-1.ec2-utilities.amazonaws.com

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : Amazon Elastic Network Adapter
   Physical Address. . . . . . . . . : 02-EA-FC-87-E9-95
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::7723:1a05:e094:d317%5(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.10.198.170(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.0.0                           <----- Here!
   Lease Obtained. . . . . . . . . . : Sunday, April 20, 2025 4:42:29 PM
   Lease Expires . . . . . . . . . . : Sunday, April 20, 2025 6:12:29 PM
   Default Gateway . . . . . . . . . : 10.10.0.1
   DHCP Server . . . . . . . . . . . : 10.10.0.1
   DHCPv6 IAID . . . . . . . . . . . : 84601211
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2D-B9-B7-EF-00-0C-29-FF-E5-C8
   DNS Servers . . . . . . . . . . . : 10.0.0.2
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

Answer: 255.255.0.0

### Task 4 - File and Disk Management

You have learned to look up basic system information and check the network configuration.  
Now, let’s discover how to browse the directories and move files around.

#### Working With Directories

You can use `cd` without parameters to display the current drive and directory. It is the equivalent of asking the system, where am I?

You can view the child directories using `dir`. Note that you can use the following options with `dir`:

- `dir /a` - Displays hidden and system files as well.
- `dir /s` - Displays files in the current directory and all subdirectories.

You can type `tree` to visually represent the child directories and subdirectories.

To create a directory, use `mkdir directory_name`; `mkdir` stands for make directory.

To delete a directory, use `rmdir directory_name`; `rmdir` stands for remove directory.

#### Working With Files

You are working with the command line. You are curious about the contents of a particular text file. You can easily view text files with the command `type`. This command will dump the contents of the text file on the screen; this is convenient for files that fit within your terminal window. You might want to consider `more` for longer text files. This command will display enough text file contents to fill your terminal window. In other words, for long text files, `more` will display a single page and wait for you to press `Spacebar` to move by one page (flip the page) or `Enter` to move by one line.

The `copy` command allows you to copy files from one location to another. Similarly, you can move files using the `move` command.

Finally, we can delete a file using `del` or `erase`.

#### What are the file’s contents in C:\Treasure\Hunt?

```text
user@WINSRV2022-CORE C:\Users\user>cd C:\Treasure\Hunt   

user@WINSRV2022-CORE C:\Treasure\Hunt>dir
 Volume in drive C has no label.
 Volume Serial Number is 5448-D41F

 Directory of C:\Treasure\Hunt

08/20/2024  01:54 PM    <DIR>          .
08/20/2024  01:54 PM    <DIR>          ..
08/20/2024  01:54 PM                18 flag.txt
               1 File(s)             18 bytes
               2 Dir(s)   9,170,341,888 bytes free

user@WINSRV2022-CORE C:\Treasure\Hunt>type flag.txt

THM{<REDACTED>}
```

Answer: `THM{<REDACTED>}`

### Task 5 - Task and Process Management

You must be familiar with MS Windows Task Manager and might be familiar with killing non-responsive processes. Let’s discover how to achieve a similar functionality using the command line.

We can list the running processes using `tasklist`.

```text
user@WINSRV2022-CORE C:\Treasure\Hunt>tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0         92 K
Registry                        96 Services                   0      9,140 K
smss.exe                       316 Services                   0        220 K
csrss.exe                      440 Services                   0      2,396 K
csrss.exe                      512 Console                    1      1,968 K
winlogon.exe                   564 Console                    1     12,200 K
wininit.exe                    584 Services                   0      1,932 K
services.exe                   652 Services                   0      4,340 K
lsass.exe                      676 Services                   0     10,256 K
svchost.exe                    788 Services                   0      6,684 K
fontdrvhost.exe                812 Console                    1      1,612 K
fontdrvhost.exe                816 Services                   0      1,388 K
svchost.exe                    892 Services                   0      6,432 K
svchost.exe                    988 Services                   0      7,908 K
svchost.exe                    392 Services                   0     12,328 K
svchost.exe                    504 Services                   0     39,608 K
svchost.exe                    372 Services                   0      7,912 K
svchost.exe                   1036 Services                   0     28,504 K
svchost.exe                   1060 Services                   0     15,180 K
svchost.exe                   1320 Services                   0     11,364 K
svchost.exe                   1328 Services                   0     13,416 K
svchost.exe                   1408 Services                   0     18,860 K
sshd.exe                      1420 Services                   0      7,060 K
svchost.exe                   1432 Services                   0      5,688 K
MsMpEng.exe                   1504 Services                   0    194,284 K
svchost.exe                   1648 Services                   0      4,964 K
svchost.exe                   1800 Services                   0      3,396 K
AggregatorHost.exe            2264 Services                   0      2,508 K
LogonUI.exe                   2856 Console                    1     12,704 K
conhost.exe                   2960 Console                    1     16,732 K
NisSrv.exe                    2756 Services                   0     10,632 K
amazon-ssm-agent.exe          2428 Services                   0     17,572 K
msdtc.exe                     2684 Services                   0     11,044 K
sshd.exe                      2436 Services                   0      8,352 K
sshd.exe                      2712 Services                   0      7,972 K
conhost.exe                   1264 Services                   0      5,252 K
cmd.exe                       1368 Services                   0      4,696 K
tasklist.exe                   796 Services                   0      8,784 K
WmiPrvSE.exe                  1576 Services                   0      9,104 K
```

Some filtering is helpful because the output is expected to be very long. You can check all available filters by displaying the help page using `tasklist /?`. Let’s say that we want to search for tasks related to `sshd.exe`, we can do that with the command `tasklist /FI "imagename eq sshd.exe"`. Note that `/FI` is used to set the filter image name equals `sshd.exe`.

```text
user@WINSRV2022-CORE C:\Treasure\Hunt>tasklist /FI "imagename eq sshd.exe"

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
sshd.exe                      1420 Services                   0      7,060 K
sshd.exe                      2436 Services                   0      8,352 K
sshd.exe                      2712 Services                   0      7,972 K
```

With the process ID (PID) known, we can terminate any task using `taskkill /PID target_pid`.  
For example, if we want to kill the process with PID `4567`, we would issue the command `taskkill /PID 4567`.

#### What command would you use to find the running processes related to notepad.exe?

Answer: tasklist /FI "imagename eq notepad.exe"

#### What command can you use to kill the process with PID 1516?

Answer: taskkill /PID 1516

### Task 6 - Conclusion

In this room, we focused on the most practical commands for accessing a networked system over the command line.

We intentionally omitted a few common commands as we didn’t see a real value for including them in a beginner room. We mention them below so that you know that the command line can be used for other tasks.

- `chkdsk`: checks the file system and disk volumes for errors and bad sectors.
- `driverquery`: displays a list of installed device drivers.
- `sfc /scannow`: scans system files for corruption and repairs them if possible.

It is important to remember all the commands covered in the previous tasks; moreover, it is equally important to know that `/?` can be used with most commands to display a help page.

In this room, we used the command `more` in two ways:

- Display text files: `more file.txt`
- Pipe long output to view it page by page: `some_command | more`

Equipped with this knowledge, we now know how to display the help page of a new command and how to display long output one page at a time.

#### The command shutdown /s can shut down a system. What is the command you can use to restart a system?

Hint: shutdown /? | more

Answer: shutdown /r

#### What command can you use to abort a scheduled system shutdown?

Answer: taskkill /PID 1516

For additional information, please see the references below.

## References

- [cd - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cd)
- [cmd.exe - Wikipedia](https://en.wikipedia.org/wiki/Cmd.exe)
- [Command-line interface - Wikipedia](https://en.wikipedia.org/wiki/Command-line_interface)
- [dir - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir)
- [ipconfig - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig)
- [netstat - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat)
- [nslookup - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup)
- [shutdown - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown)
- [systeminfo - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo)
- [taskkill - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill)
- [tasklist - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist)
- [tracert - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracert)
- [tree - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tree)
- [type - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/type)
- [ver - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ver)
