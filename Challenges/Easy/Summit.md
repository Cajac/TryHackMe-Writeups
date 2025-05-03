# Summit

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
OS: N/A
Subscription type: Premium
Description: Can you chase a simulated adversary up the Pyramid of Pain until they finally back down?
```

Room link: [https://tryhackme.com/room/summit](https://tryhackme.com/room/summit)

## Solution

### Objective

After participating in one too many incident response activities, PicoSecure has decided to conduct a threat simulation and detection engineering engagement to bolster its malware detection capabilities. You have been assigned to work with an external penetration tester in an iterative purple-team scenario. The tester will be attempting to execute malware samples on a simulated internal user workstation. At the same time, you will need to configure PicoSecure's security tools to detect and prevent the malware from executing.

Following the **Pyramid of Pain**'s ascending priority of indicators, your objective is to increase the simulated adversaries' cost of operations and chase them away for good. Each level of the pyramid allows you to detect and prevent various indicators of attack.

#### Room Prerequisites

Completing the preceding rooms in the Cyber Defence Frameworks module will be beneficial before venturing into this challenge. Specifically, the following:

- The Pyramid of Pain
- MITRE

#### Connection Details

Please click **Start Machine** to deploy the application, and navigate to `https://10-10-207-156.p.thmlabs.com` once the URL has been populated.

Note: It may take a few minutes to deploy the machine entirely. If you receive a "Bad Gateway" response, wait a few minutes and refresh the page.

### What is the first flag you receive after successfully detecting sample1.exe?

We start by reading the first e-mail titled `Introduction: Penetration Test`

```text
Hey there.

I'm Sphinx, and I will be working with you on conducting threat simulation and detection engineering tests. I will attempt to execute malware samples on a simulated compromised user account to see if PicoSecure's security tools can detect the attacks.

This will be an iterative process; as your detection methods become more sophisticated, I will upgrade my malware samples to increase the difficulty of detection.

I will start with something simple, using "sample1.exe".

Scan this file using the Malware Sandbox tool and review the generated report. Maybe there's a unique way for you to distinguish this file and add a detection rule to block it. Once you manage to do so, I'll be in touch again.

Tip: You can access the various security tools by toggling the side menu (click the menu icon in the top left). You can revert your progress anytime with the "Revert Room" option in the side menu.

-Sphinx
```

Next, we navigate to the `Malware Sandbox` tool, submit `sample1.exe` and get the following report:

```text
General Info - sample1.exe
--------------------------

File Name    sample1.exe
File Size    202.50 KB
File Type    PE32+ executable (GUI) x86-64, for MS Windows
Analysis Date    September 5, 2023
OS    Windows 10x64 v1803
Tags    Trojan.Metasploit.A
MIME    application/x-dosexec
MD5    cbda8ae000aa9cbe7c8b982bae006c2a
SHA1    83d2791ca93e58688598485aa62597c0ebbf7610
SHA256    9c550591a25c6228cb7d74d970d133d75c961ffed2ef7180144859cc09efca8c

Behaviour Analysis
------------------

Malicious
METASPLOIT was detected
    sample1.exe (PID: 2492)

Suspicious
Connects to unusual port
    sample1.exe (PID: 2492)

Info
Reads the machine GUID from the registry
    sample1.exe (PID: 2492)
The process checks LSA protection
    sample1.exe (PID: 2492)
Reads the computer name
    sample1.exe (PID: 2492)
Checks supported languages
    sample1.exe (PID: 2492)
```

Take any of the hashes and add it to the Hash Blockliast under `Manage Hashes`.

Go back to the `Mail` to get the flag in the mail titled `Update: You Blocked Me!`.

Answer: `THM{<REDACTED>}`

### What is the second flag you receive after successfully detecting sample2.exe?

The next quest is in the same mail titled `Update: You Blocked Me!`:

```text
Hey again,

Good work. That detection you added blocked my malware from executing. Since file hashes and digests are unique to each file, they are, by far, the highest confidence indicators out there. You can be sure it's my malware sample the next time you see that hash.

However, by design, that is also one of the significant downfalls of simply relying on hashes for detection mechanisms. Since they are so susceptible to change, I only need to alter a single bit of the file, and the detection rule you added will fail.

In fact, all I did this time was recompile the malware, and I generated a new file hash and executed it without issue. See if you can come up with a new way to detect sample2.exe!

Here's your flag: THM{<REDACTED>}

-Sphinx
```

Next, we navigate to the `Malware Sandbox` tool again, submit `sample2.exe` and get the following report:

```text
General Info - sample2.exe
--------------------------

File Name    sample2.exe
File Size    202.73 KB
File Type    PEXE - PE32+ executable (GUI) x86-64, for MS Windows
Analysis Date    September 5, 2023
OS    Windows 10x64 v1803
Tags    Trojan.Metasploit.A
MIME    application/x-dosexec
MD5    4d661bf605d6b0b15915a533b572a6bd
SHA1    6878976974c27c8547cfc5acc90fb28ad2f0e975
SHA256    d576245e85e6b752b2fdffa43abaab1b2e1383556b0169fd04924d6cebc1cdf9

<---snip--->

Network Activity
----------------

HTTP(S) requests
1

TCP/UDP connections
3

DNS requests
0

Threats
0

HTTP requests

PID    Process       Method         IP                        URL
1927    sample2.exe    GET    154.35.10.113:4444    http://154.35.10.113:4444/uvLk8YI32

Connections

PID     Process                IP          Domain       ASN
1927    sample2.exe    154.35.10.113:4444    -    Intrabuzz Hosting Limited
1927    sample2.exe    40.97.128.3:443    -    Microsoft Corporation
1927    sample2.exe    40.97.128.4:443    -    Microsoft Corporation
```

A connection on port 4444. Could it be Meterpreter? We'd better block the IP 154.35.10.113.

Go to the `Firewall Manager` and `Create Firewall Rule`

```text
Type: Egress
Source IP: Any
Destination IP: 154.35.10.113
Action: Deny
```

Go back to the `Mail` to get the flag in the mail titled `Stumped again... for now!`.

Answer: `THM{<REDACTED>}`

### What is the third flag you receive after successfully detecting sample3.exe?

The next mission is in the same mail titled `Stumped again... for now!`:

```text
Huh.

It seems like you stopped me again. You must have found the IP address to which my malware sample connected. Clever!

This method isn't bulletproof, though, as it's trivial for a motivated adversary to get around it using a new public IP address. I just signed up for a cloud service provider and now have access to many more public IPs!

This time, you'll need to detect sample3.exe another way. I already have my server running from a new IP address and have plenty more backups to failover in case they get blocked!

Good luck. 😈

Here's your flag: THM{<REDACTED>}

-Sphinx
```

As before, we navigate to the `Malware Sandbox` tool again, submit `sample3.exe` and get the following report:

```text
General Info - sample3.exe
--------------------------

File Name    sample3.exe
File Size    207.12 KB
File Type    PEXE - PE32+ executable (GUI) x86-64, for MS Windows
Analysis Date    September 5, 2023
OS    Windows 10x64 v1803
Tags    Trojan.Metasploit.A
MIME    application/x-dosexec
MD5    e31f0c62927d9d5a897b4c45e3c64dbc
SHA1    a92d3de6b1e3ab295f10587ca75f15318cb85a7b
SHA256    acb9b1260bcd08a465f9f300ac463b9b1215c097ebe44610359bb80881fe6a05

<---snip--->

Network Activity
----------------

HTTP(S) requests
2
TCP/UDP connections
4
DNS requests
2
Threats
0

HTTP requests

PID     Process        Method    IP                 URL
1021    sample3.exe    GET    62.123.140.9:1337    http://emudyn.bresonicz.info:1337/kzn293la
1021    sample3.exe    GET    62.123.140.9:80    http://emudyn.bresonicz.info/backdoor.exe

Connections

PID     Process                IP                Domain                     ASN
1021    sample3.exe    40.97.128.4:443    services.microsoft.com    Microsoft Corporation
1021    sample3.exe    62.123.140.9:1337    emudyn.bresonicz.info    XplorIta Cloud Services
1021    sample3.exe    62.123.140.9:80    emudyn.bresonicz.info    XplorIta Cloud Services
2712    backdoor.exe    62.123.140.9:80    emudyn.bresonicz.info    XplorIta Cloud Services

DNS requests

Domain                        IP
services.microsoft.com    40.97.128.4
emudyn.bresonicz.info    62.123.140.9
```

This time we shouldn't block the IP, but the domain (`emudyn.bresonicz.info`).

Go to the `DNS Filter` tool and `Create DNS Rule`:

```text
Rule Name: emudyn.bresonicz.info
Category: Malware
Domain Name: emudyn.bresonicz.info
Action: Deny
```

Go back to the `Mail` to get the flag in the mail titled `RE: Stumped again... for now!`.

Answer: `THM{<REDACTED>}`

### What is the fourth flag you receive after successfully detecting sample4.exe?

The next task is in the same mail titled `RE: Stumped again... for now!`:

```text
Greetings again,

It looks like you were able to block my domain this time because every new IP address I try gets detected. You're causing me a bit of trouble now because I have to purchase and register some new domain names and modify DNS records. Some attackers might get mildly annoyed by this and find a new target, but I'm motivated to continue like many.

This time - blocking hashes, IPs, or domains won't help you. If you want to detect sample4.exe, consider what artifacts (or changes) my malware leaves on the victim's host system.

Good luck.

Here's your flag: THM{<REDACTED>}

-Sphinx
```

As before, we navigate to the `Malware Sandbox` tool again, submit `sample4.exe` and get the following report:

```text
General Info - sample4.exe
--------------------------

File Name    sample4.exe
File Size    219.46 KB
File Type    PEXE - PE32+ executable (GUI) x86-64, for MS Windows
Analysis Date    September 5, 2023
OS    Windows 10x64 v1803
Tags    None
MIME    application/x-dosexec
MD5    5f29ff19d99fe244eaf5835ce01a4631
SHA1    cd12d2328f700ae1ba1296a5f011bfc5a49f456d
SHA256    a80cffb40cea83c1a20973a5b803828e67691f71f3c878edb5a139634d7dd422

<---snip--->

Registry Activity
-----------------

Total events
3
Read events
1
Write events
2
Delete events
0

Modification events

(PID) Process: (3806) sample4.exe    Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
Operation: write    Name: DisableRealtimeMonitoring
Value: 1
(PID) Process: (1928) explorer.exe    Key: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
Operation: write    Name: EnableBalloonTips
Value: 1
(PID) Process: (9876) notepad.exe    Key: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt
Operation: read    Name: Progid
Value: txtfile
```

This time we should detect and block the attempt to disable Defender Antivirus (`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`)

Select `Sigma Rule Builder` and then

1. Create a Sigma Rule for `Sysmon Event Logs`
2. `Registry Modifications`

```text
Registry Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
Registry Name: DisableRealtimeMonitoring
Value: 1
ATT&CK ID: Defense Evasion (TA0005)
```

Go back to the `Mail` to get the flag in the mail titled `New Approach`.

Answer: `THM{<REDACTED>}`

### What is the fifth flag you receive after successfully detecting sample5.exe?

The next quest is in the same mail titled `New Approach`:

```text
Hey.

I'm not sure what you managed to do this time, but you seriously threw a wrench into my malware sample! I spent ages trying to reconfigure my attack tools and methodologies to get around your detection - SUPER ANNOYING!

Having my team develop new techniques used in my adversary tools was a time-consuming effort and a significant cost. It's good that we have a substantial budget for this engagement, but many threat actors would have given up and found a new victim by now.

I finally have sample5.exe for you to detect. Different approach this time. In this sample, all of the "heavy lifting" and instruction occurs on my back-end server, so I can easily change the types of protocols I use and the artifacts I leave on the host. You'll have to find something unique or abnormal about the behaviour of my tool to detect it.

I attached the logs of the outgoing network connections from the last 12 hours on the victim machine. That may help you correlate something.

I don't know what to do if you can stop me at this level.

Here's your flag: THM{<REDACTED>}

-Annoyed Sphinx
```

Included in the e-mail is this `outgoing_connections.log` containing

```text
2023-08-15 09:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 09:23:45 | Source: 10.10.15.12 | Destination: 43.10.65.115 | Port: 443 | Size: 21541 bytes
2023-08-15 09:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 10:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 10:14:21 | Source: 10.10.15.12 | Destination: 87.32.56.124 | Port: 80  | Size: 1204 bytes
2023-08-15 10:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 11:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 11:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 11:45:09 | Source: 10.10.15.12 | Destination: 145.78.90.33 | Port: 443 | Size: 805 bytes
2023-08-15 12:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 12:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 13:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 13:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 13:32:17 | Source: 10.10.15.12 | Destination: 72.15.61.98  | Port: 443 | Size: 26084 bytes
2023-08-15 14:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 14:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 14:55:33 | Source: 10.10.15.12 | Destination: 208.45.72.16 | Port: 443 | Size: 45091 bytes
2023-08-15 15:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 15:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 15:40:10 | Source: 10.10.15.12 | Destination: 101.55.20.79 | Port: 443 | Size: 95021 bytes
2023-08-15 16:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 16:18:55 | Source: 10.10.15.12 | Destination: 194.92.18.10 | Port: 80  | Size: 8004 bytes
2023-08-15 16:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 17:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 17:09:30 | Source: 10.10.15.12 | Destination: 77.23.66.214 | Port: 443 | Size: 9584 bytes
2023-08-15 17:27:42 | Source: 10.10.15.12 | Destination: 156.29.88.77 | Port: 443 | Size: 10293 bytes
2023-08-15 17:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 18:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 18:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 19:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 19:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 20:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 20:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 21:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
```

The packet size of 97 bytes seems repeating every 30 minutes and suspicious. Let's block it!

Select `Sigma Rule Builder` and then

1. Create a Sigma Rule for `Sysmon Event Logs`
2. `Network Connections`

```text
Remote IP: Any
Remote Port: Any
Size: 97
Frequency: 1800
ATT&CK ID: Command and Control (TA0011)
```

Go back to the `Mail` to get the flag in the mail titled `RE: New Approach`.

Answer: `THM{<REDACTED>}`

### What is the final flag you receive from Sphinx?

The final task is in the same mail titled `RE: New Approach`:

```text
Hello again,

You managed to detect sample5.exe ! I'm very impressed. But also very annoyed! Because now, I need to go back to the drawing board and create a brand new tool to do what I need to do. If I can't find another one quickly, this will be another significant investment. Also, I will need to train myself all over again on how to use it!

I can keep this up one or two times, but there's no way I can continue after this. The reward no longer outweighs the cost, and I would instead find an easier target with detection capabilities much lower on the pyramid.

For my last trick, I have sample6.exe. This time, you will need more than artifacts or tool detection to help you. You'll need to focus on something extremely hard for me to change subconsciously - my techniques and procedures.

I've attached the recorded command logs from all my previous samples to understand better what actions I tend to perform on my victims to extract info once I have remote access. Good luck!

Here's your flag: THM{<REDACTED>}

-Very Annoyed Sphinx! 😫
```

Included in the e-mail is this `commands.log` containing

```text
dir c:\ >> %temp%\exfiltr8.log
dir "c:\Documents and Settings" >> %temp%\exfiltr8.log
dir "c:\Program Files\" >> %temp%\exfiltr8.log
dir d:\ >> %temp%\exfiltr8.log
net localgroup administrator >> %temp%\exfiltr8.log
ver >> %temp%\exfiltr8.log
systeminfo >> %temp%\exfiltr8.log
ipconfig /all >> %temp%\exfiltr8.log
netstat -ano >> %temp%\exfiltr8.log
net start >> %temp%\exfiltr8.log
```

A lot of host enumeration getting stored in the file `%temp%\exfiltr8.log`. Let's block it!

Select `Sigma Rule Builder` and then

1. Create a Sigma Rule for `Sysmon Event Logs`
2. `File Creation and Modification`

```text
File Path: %temp%
File Name: exfiltr8.log
ATT&CK ID: Discovery (TA0007)
```

Go back to the `Mail` to get the flag in the mail titled `I'm Giving Up`.

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [ATT&CK - Mitre](https://attack.mitre.org/)
- [Sigma - GitHub](https://github.com/SigmaHQ/sigma)
- [The Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
