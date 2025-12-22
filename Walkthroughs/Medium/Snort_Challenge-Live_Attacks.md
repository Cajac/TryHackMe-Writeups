# Snort Challenge - Live Attacks

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
OS: N/A
Subscription type: Premium
Description: Put your snort skills into practice and defend against a live attack
```

Room link: [https://tryhackme.com/room/snortchallenges2](https://tryhackme.com/room/snortchallenges2)

## Solution

### Task 1 - Introduction

The room invites you to a challenge where you will investigate a series of traffic data and stop malicious activity under two different scenarios. Let's start working with Snort to analyse live and captured traffic.

Before joining this room, we suggest completing the [Snort room](https://tryhackme.com/r/room/snort).

**Note**: There are two VMs attached to this challenge. Each task has dedicated VMs. You don't need SSH or RDP, the room provides a "**Screen Split**" feature.

### Task 2 - Scenario 1 | Brute-Force

Use the attached VM to finish this task.

[+] THE NARRATOR

J&Y Enterprise is one of the top coffee retails in the world. They are known as tech-coffee shops and serve millions of coffee lover tech geeks and IT specialists every day.

They are famous for specific coffee recipes for the IT community and unique names for these products. Their top five recipe names are;  
**WannaWhite**, **ZeroSleep**, **MacDown**, **BerryKeep** and **CryptoY**.

J&Y's latest recipe, "**Shot4J**", attracted great attention at the global coffee festival. J&Y officials promised that the product will hit the stores in the coming months.

The super-secret of this recipe is hidden in a digital safe. Attackers are after this recipe, and J&Y enterprises are having difficulties protecting their digital assets.

Last week, they received multiple attacks and decided to work with you to help them improve their security level and protect their recipe secrets.  

This is your assistant **J.A.V.A. (Just Another Virtual Assistant)**. She is an AI-driven virtual assistant and will help you notice possible anomalies. Hey, wait, something is happening...

[+] J.A.V.A.

Welcome, sir. I am sorry for the interruption. It is an emergency. Somebody is knocking on the door!

[+] YOU

Knocking on the door? What do you mean by "knocking on the door"?

[+] J.A.V.A.

We have a brute-force attack, sir.

[+] THE NARRATOR

This is not a comic book! Would you mind going and checking what's going on! Please...

[+] J.A.V.A.

Sir, you need to observe the traffic with Snort and identify the anomaly first. Then you can create a rule to stop the brute-force attack. GOOD LUCK!

---------------------------------------------------

First of all, start Snort in sniffer mode and try to figure out the attack source, service and port.

Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!

Here are a few points to remember:

- Create the rule and test it with `-A console` mode.
- Use `-A full` mode and the default log path to stop the attack.
- Write the correct rule and run the Snort in IPS `-A full` mode.
- Block the traffic at least for a minute and then the flag file will appear on your desktop.

#### What is the name of the service under attack?

We start by sniffing the traffic with `snort` filtering packets with the SYN flag set

```bash
ubuntu@ip-10-10-120-29:~$ sudo snort -X 'tcp[tcpflags] & tcp-syn != 0'
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Snort BPF option: tcp[tcpflags] & tcp-syn != 0
pcap DAQ configured to passive.
Acquiring network traffic from "eth0".
Decoding Ethernet

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

Commencing packet processing (pid=2562)
WARNING: No preprocessors configured for policy 0.
05/10-08:07:45.887239 10.10.245.36:46672 -> 10.10.140.29:22
TCP TTL:64 TOS:0x0 ID:11387 IpLen:20 DgmLen:60 DF
******S* Seq: 0xBC6FA38E  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 1884581414 0 NOP WS: 7 
0x0000: 02 6D 84 B4 B4 1B 02 67 7A 27 40 23 08 00 45 00  .m.....gz'@#..E.
0x0010: 00 3C 2C 7B 40 00 40 06 78 EB 0A 0A F5 24 0A 0A  .<,{@.@.x....$..
0x0020: 8C 1D B6 50 00 16 BC 6F A3 8E 00 00 00 00 A0 02  ...P...o........
0x0030: F5 07 AB 75 00 00 02 04 23 01 04 02 08 0A 70 54  ...u....#.....pT
0x0040: 6E 26 00 00 00 00 01 03 03 07                    n&........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

05/10-08:07:45.889482 10.10.140.29:22 -> 10.10.245.36:46672
TCP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:60 DF
***A**S* Seq: 0xA63CE073  Ack: 0xBC6FA38F  Win: 0xF4B3  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 4119688844 1884581414 NOP WS: 7 
0x0000: 02 67 7A 27 40 23 02 6D 84 B4 B4 1B 08 00 45 00  .gz'@#.m......E.
0x0010: 00 3C 00 00 40 00 40 06 A5 66 0A 0A 8C 1D 0A 0A  .<..@.@..f......
0x0020: F5 24 00 16 B6 50 A6 3C E0 73 BC 6F A3 8F A0 12  .$...P.<.s.o....
0x0030: F4 B3 95 84 00 00 02 04 23 01 04 02 08 0A F5 8D  ........#.......
0x0040: 76 8C 70 54 6E 26 01 03 03 07                    v.pTn&....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/10-08:07:46.821873 10.10.245.36:46674 -> 10.10.140.29:22
TCP TTL:64 TOS:0x0 ID:56663 IpLen:20 DgmLen:60 DF
******S* Seq: 0x56F88CDA  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 1884584897 0 NOP WS: 7 
0x0000: 02 6D 84 B4 B4 1B 02 67 7A 27 40 23 08 00 45 00  .m.....gz'@#..E.
0x0010: 00 3C DD 57 40 00 40 06 C8 0E 0A 0A F5 24 0A 0A  .<.W@.@......$..
0x0020: 8C 1D B6 52 00 16 56 F8 8C DA 00 00 00 00 A0 02  ...R..V.........
0x0030: F5 07 1A 04 00 00 02 04 23 01 04 02 08 0A 70 54  ........#.....pT
0x0040: 7B C1 00 00 00 00 01 03 03 07                    {.........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

05/10-08:07:46.823404 10.10.140.29:22 -> 10.10.245.36:46674
TCP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:60 DF
***A**S* Seq: 0xF0CE99A3  Ack: 0x56F88CDB  Win: 0xF4B3  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 4119692326 1884584897 NOP WS: 7 
0x0000: 02 67 7A 27 40 23 02 6D 84 B4 B4 1B 08 00 45 00  .gz'@#.m......E.
0x0010: 00 3C 00 00 40 00 40 06 A5 66 0A 0A 8C 1D 0A 0A  .<..@.@..f......
0x0020: F5 24 00 16 B6 52 F0 CE 99 A3 56 F8 8C DB A0 12  .$...R....V.....
0x0030: F4 B3 95 84 00 00 02 04 23 01 04 02 08 0A F5 8D  ........#.......
0x0040: 84 26 70 54 7B C1 01 03 03 07                    .&pT{.....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/10-08:07:47.539686 10.10.245.36:46676 -> 10.10.140.29:22
TCP TTL:64 TOS:0x0 ID:40215 IpLen:20 DgmLen:60 DF
******S* Seq: 0x5C7EBF49  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 1884584927 0 NOP WS: 7 
0x0000: 02 6D 84 B4 B4 1B 02 67 7A 27 40 23 08 00 45 00  .m.....gz'@#..E.
0x0010: 00 3C 9D 17 40 00 40 06 08 4F 0A 0A F5 24 0A 0A  .<..@.@..O...$..
0x0020: 8C 1D B6 54 00 16 5C 7E BF 49 00 00 00 00 A0 02  ...T..\~.I......
0x0030: F5 07 E1 EE 00 00 02 04 23 01 04 02 08 0A 70 54  ........#.....pT
0x0040: 7B DF 00 00 00 00 01 03 03 07                    {.........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

05/10-08:07:47.544521 10.10.140.29:22 -> 10.10.245.36:46676
TCP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:60 DF
***A**S* Seq: 0xE868AD0  Ack: 0x5C7EBF4A  Win: 0xF4B3  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 4119692356 1884584927 NOP WS: 7 
0x0000: 02 67 7A 27 40 23 02 6D 84 B4 B4 1B 08 00 45 00  .gz'@#.m......E.
0x0010: 00 3C 00 00 40 00 40 06 A5 66 0A 0A 8C 1D 0A 0A  .<..@.@..f......
0x0020: F5 24 00 16 B6 54 0E 86 8A D0 5C 7E BF 4A A0 12  .$...T....\~.J..
0x0030: F4 B3 95 84 00 00 02 04 23 01 04 02 08 0A F5 8D  ........#.......
0x0040: 84 44 70 54 7B DF 01 03 03 07                    .DpT{.....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
<---snip--->
```

The traffic is to and from **port 22** so the service under attack ought to be **SSH**.

Answer: `SSH`

#### What is the used protocol/port in the attack?

Answer: `tcp/22`

#### Stop the attack and get the flag (which will appear on your Desktop)

Hint: "IPS mode and Dropping Packets" is covered in the main Snort room TASK-7.

We should drop traffic on port 22 (SSH) to the IP `10.10.140.29.22`.  
Our snort rule looks like this

```bash
ubuntu@ip-10-10-120-29:~$ cat /etc/snort/rules/local.rules
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
drop tcp any any <> 10.10.140.29 22 (msg: "Drop SSH attack on 10.10.140.29"; sid:300001; rev:1;)
```

Now we run Snort again but in IDS-mode

```bash
ubuntu@ip-10-10-120-29:~$ sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full
```

Wait about a minute and the flag appears on the Desktop

Answer: `THM{<REDACTED>}`

### Task 3 - Scenario 2 | Reverse-Shell

Use the attached VM to finish this task.

[+] THE NARRATOR

Good Job! Glad to have you in the team!

[+] J.A.V.A.

Congratulations sir. It is inspiring watching you work.

[+] You

Thanks team. J.A.V.A. can you do a quick scan for me? We haven't investigated the outbound traffic yet.

[+] J.A.V.A.

Yes, sir. Outbound traffic investigation has begun.

[+] THE NARRATOR

The outbound traffic? Why?

[+] YOU

We have stopped some inbound access attempts, so we didn't let the bad guys get in. How about the bad guys who are already inside? Also, no need to mention the insider risks, huh? The dwell time is still around 1-3 months, and I am quite new here, so it is worth checking the outgoing traffic as well.

[+] J.A.V.A.

Sir, persistent outbound traffic is detected. Possibly a reverse shell...

[+] YOU

You got it!

[+] J.A.V.A.

Sir, you need to observe the traffic with Snort and identify the anomaly first. Then you can create a rule to stop the reverse shell. GOOD LUCK!

---------------------------------------------------

First of all, start Snort in sniffer mode and try to figure out the attack source, service and port.

Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!

Here are a few points to remember:

- Create the rule and test it with `-A console` mode.
- Use `-A full` mode and the default log path to stop the attack.
- Write the correct rule and run the Snort in IPS `-A full` mode.
- Block the traffic at least for a minute and then the flag file will appear on your desktop.

#### What is the used protocol/port in the attack?

Like before we start by sniffing the traffic with `snort` filtering packets with the SYN flag set, stopping after 10 packets

```bash
ubuntu@ip-10-10-76-216:~$ sudo snort -X -n 10 'tcp[tcpflags] & tcp-syn != 0'
Exiting after 10 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Snort BPF option: tcp[tcpflags] & tcp-syn != 0
pcap DAQ configured to passive.
Acquiring network traffic from "eth0".
Decoding Ethernet

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

Commencing packet processing (pid=1781)
05/10-08:36:23.724097 10.10.196.55:54126 -> 10.10.144.156:4444
TCP TTL:64 TOS:0x0 ID:57317 IpLen:20 DgmLen:60 DF
******S* Seq: 0x741B6CC5  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 2358289516 0 NOP WS: 7 
0x0000: 02 15 8B 5C 4F EF 02 7C 9A 93 DF DD 08 00 45 00  ...\O..|......E.
0x0010: 00 3C DF E5 40 00 40 06 F1 EE 0A 0A C4 37 0A 0A  .<..@.@......7..
0x0020: 90 9C D3 6E 11 5C 74 1B 6C C5 00 00 00 00 A0 02  ...n.\t.l.......
0x0030: F5 07 69 16 00 00 02 04 23 01 04 02 08 0A 8C 90  ..i.....#.......
0x0040: A4 6C 00 00 00 00 01 03 03 07                    .l........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

05/10-08:36:23.744139 10.10.196.55:54128 -> 10.10.144.156:4444
TCP TTL:64 TOS:0x0 ID:11385 IpLen:20 DgmLen:60 DF
******S* Seq: 0x56C8766D  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 2358293307 0 NOP WS: 7 
0x0000: 02 15 8B 5C 4F EF 02 7C 9A 93 DF DD 08 00 45 00  ...\O..|......E.
0x0010: 00 3C 2C 79 40 00 40 06 A5 5B 0A 0A C4 37 0A 0A  .<,y@.@..[...7..
0x0020: 90 9C D3 70 11 5C 56 C8 76 6D 00 00 00 00 A0 02  ...p.\V.vm......
0x0030: F5 07 69 16 00 00 02 04 23 01 04 02 08 0A 8C 90  ..i.....#.......
0x0040: B3 3B 00 00 00 00 01 03 03 07                    .;........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/10-08:36:23.747450 10.10.144.156:4444 -> 10.10.196.55:54128
TCP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:60 DF
***A**S* Seq: 0x2FE7575C  Ack: 0x56C8766E  Win: 0xF4B3  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 1980461006 2358293307 NOP WS: 7 
0x0000: 02 7C 9A 93 DF DD 02 15 8B 5C 4F EF 08 00 45 00  .|.......\O...E.
0x0010: 00 3C 00 00 40 00 40 06 D1 D4 0A 0A 90 9C 0A 0A  .<..@.@.........
0x0020: C4 37 11 5C D3 70 2F E7 57 5C 56 C8 76 6E A0 12  .7.\.p/.W\V.vn..
0x0030: F4 B3 6E 1A 00 00 02 04 23 01 04 02 08 0A 76 0B  ..n.....#.....v.
0x0040: 6F CE 8C 90 B3 3B 01 03 03 07                    o....;....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

05/10-08:36:23.808406 10.10.196.55:54130 -> 10.10.144.156:4444
TCP TTL:64 TOS:0x0 ID:40771 IpLen:20 DgmLen:60 DF
******S* Seq: 0x71F8B035  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 2358304059 0 NOP WS: 7 
0x0000: 02 15 8B 5C 4F EF 02 7C 9A 93 DF DD 08 00 45 00  ...\O..|......E.
0x0010: 00 3C 9F 43 40 00 40 06 32 91 0A 0A C4 37 0A 0A  .<.C@.@.2....7..
0x0020: 90 9C D3 72 11 5C 71 F8 B0 35 00 00 00 00 A0 02  ...r.\q..5......
0x0030: F5 07 69 16 00 00 02 04 23 01 04 02 08 0A 8C 90  ..i.....#.......
0x0040: DD 3B 00 00 00 00 01 03 03 07                    .;........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

05/10-08:36:23.840538 10.10.196.55:54132 -> 10.10.144.156:4444
TCP TTL:64 TOS:0x0 ID:24452 IpLen:20 DgmLen:60 DF
******S* Seq: 0xE9E2668A  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 2358306812 0 NOP WS: 7 
0x0000: 02 15 8B 5C 4F EF 02 7C 9A 93 DF DD 08 00 45 00  ...\O..|......E.
0x0010: 00 3C 5F 84 40 00 40 06 72 50 0A 0A C4 37 0A 0A  .<_.@.@.rP...7..
0x0020: 90 9C D3 74 11 5C E9 E2 66 8A 00 00 00 00 A0 02  ...t.\..f.......
0x0030: F5 07 69 16 00 00 02 04 23 01 04 02 08 0A 8C 90  ..i.....#.......
0x0040: E7 FC 00 00 00 00 01 03 03 07                    ..........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

05/10-08:36:23.860592 10.10.196.55:54134 -> 10.10.144.156:4444
TCP TTL:64 TOS:0x0 ID:38256 IpLen:20 DgmLen:60 DF
******S* Seq: 0xAB9B9A6B  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 2358308596 0 NOP WS: 7 
0x0000: 02 15 8B 5C 4F EF 02 7C 9A 93 DF DD 08 00 45 00  ...\O..|......E.
0x0010: 00 3C 95 70 40 00 40 06 3C 64 0A 0A C4 37 0A 0A  .<.p@.@.<d...7..
0x0020: 90 9C D3 76 11 5C AB 9B 9A 6B 00 00 00 00 A0 02  ...v.\...k......
0x0030: F5 07 69 16 00 00 02 04 23 01 04 02 08 0A 8C 90  ..i.....#.......
0x0040: EE F4 00 00 00 00 01 03 03 07                    ..........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/10-08:36:23.876684 10.10.144.156:43332 -> 10.10.196.55:4444
TCP TTL:64 TOS:0x0 ID:56963 IpLen:20 DgmLen:60 DF
******S* Seq: 0x64083CA7  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 1980542416 0 NOP WS: 7 
0x0000: 02 7C 9A 93 DF DD 02 15 8B 5C 4F EF 08 00 45 00  .|.......\O...E.
0x0010: 00 3C DE 83 40 00 40 06 F3 50 0A 0A 90 9C 0A 0A  .<..@.@..P......
0x0020: C4 37 A9 44 11 5C 64 08 3C A7 00 00 00 00 A0 02  .7.D.\d.<.......
0x0030: F5 07 4D 96 00 00 02 04 23 01 04 02 08 0A 76 0C  ..M.....#.....v.
0x0040: AD D0 00 00 00 00 01 03 03 07                    ..........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/10-08:36:23.896722 10.10.144.156:43334 -> 10.10.196.55:4444
TCP TTL:64 TOS:0x0 ID:17113 IpLen:20 DgmLen:60 DF
******S* Seq: 0xD41084D8  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 1980574760 0 NOP WS: 7 
0x0000: 02 7C 9A 93 DF DD 02 15 8B 5C 4F EF 08 00 45 00  .|.......\O...E.
0x0010: 00 3C 42 D9 40 00 40 06 8E FB 0A 0A 90 9C 0A 0A  .<B.@.@.........
0x0020: C4 37 A9 46 11 5C D4 10 84 D8 00 00 00 00 A0 02  .7.F.\..........
0x0030: F5 07 17 02 00 00 02 04 23 01 04 02 08 0A 76 0D  ........#.....v.
0x0040: 2C 28 00 00 00 00 01 03 03 07                    ,(........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/10-08:36:23.916778 10.10.144.156:43336 -> 10.10.196.55:4444
TCP TTL:64 TOS:0x0 ID:54026 IpLen:20 DgmLen:60 DF
******S* Seq: 0xB60AFBC9  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 1980575799 0 NOP WS: 7 
0x0000: 02 7C 9A 93 DF DD 02 15 8B 5C 4F EF 08 00 45 00  .|.......\O...E.
0x0010: 00 3C D3 0A 40 00 40 06 FE C9 0A 0A 90 9C 0A 0A  .<..@.@.........
0x0020: C4 37 A9 48 11 5C B6 0A FB C9 00 00 00 00 A0 02  .7.H.\..........
0x0030: F5 07 BA 05 00 00 02 04 23 01 04 02 08 0A 76 0D  ........#.....v.
0x0040: 30 37 00 00 00 00 01 03 03 07                    07........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/10-08:36:23.932847 10.10.144.156:43338 -> 10.10.196.55:4444
TCP TTL:64 TOS:0x0 ID:64531 IpLen:20 DgmLen:60 DF
******S* Seq: 0xBC659459  Ack: 0x0  Win: 0xF507  TcpLen: 40
TCP Options (5) => MSS: 8961 SackOK TS: 1980577135 0 NOP WS: 7 
0x0000: 02 7C 9A 93 DF DD 02 15 8B 5C 4F EF 08 00 45 00  .|.......\O...E.
0x0010: 00 3C FC 13 40 00 40 06 D5 C0 0A 0A 90 9C 0A 0A  .<..@.@.........
0x0020: C4 37 A9 4A 11 5C BC 65 94 59 00 00 00 00 A0 02  .7.J.\.e.Y......
0x0030: F5 07 15 E1 00 00 02 04 23 01 04 02 08 0A 76 0D  ........#.....v.
0x0040: 35 6F 00 00 00 00 01 03 03 07                    5o........

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 1.71499 seconds
Snort processed 10 packets.
Snort ran for 0 days 0 hours 0 minutes 1 seconds
   Pkts/sec:           10
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       786432
  Bytes in mapped regions (hblkhd):      13213696
  Total allocated space (uordblks):      683296
  Total free space (fordblks):           103136
  Topmost releasable block (keepcost):   100064
===============================================================================
Packet I/O Totals:
   Received:           25
   Analyzed:           10 ( 40.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:           15 ( 60.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:           10 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:           10 (100.000%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:            0 (  0.000%)
        TCP:           10 (100.000%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            5 ( 50.000%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:           10
===============================================================================
Snort exiting
ubuntu@ip-10-10-76-216:~$ 
```

The traffic is to TCP-port 4444 on more than one IP.

Answer: `tcp/4444`

#### Which tool is highly associated with this specific port number?

Port 4444 is the default port of Metasploit's Meterpreter.

Answer: `Metasploit`

#### Stop the attack and get the flag (which will appear on your Desktop)

Hint: You can easily drop all the traffic coming to a specific port as a rapid response.

We should drop all traffic on port 4444. Our snort rule looks like this

```bash
ubuntu@ip-10-10-76-216:~$ cat /etc/snort/rules/local.rules
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
drop tcp any any <> any 4444 (msg: "Drop all Meterpreter traffic (TCP-port 4444)"; sid:300002; rev:1;)
```

Now we run Snort again but in IDS-mode

```bash
ubuntu@ip-10-10-120-29:~$ sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full
```

Wait about a minute and the flag appears on the Desktop

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [List of TCP and UDP port numbers - Wikipedia](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)
- [Metasploit - Wikipedia](https://en.wikipedia.org/wiki/Metasploit)
- [pcap-filter - Linux manual page](https://linux.die.net/man/7/pcap-filter)
- [Snort - Documents](https://www.snort.org/documents)
- [Snort - Homepage](https://www.snort.org/)
- [snort - Linux manual page](https://manpages.org/snort/8)
- [Snort 3 Rule Writing Guide - Rule Options](https://docs.snort.org/rules/options/)
