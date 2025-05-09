# Snort

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
OS: N/A
Subscription type: Free
Description: Learn how to use Snort to detect real-time threats, analyse recorded traffic files 
and identify anomalies.
```

Room link: [https://tryhackme.com/room/snort](https://tryhackme.com/room/snort)

## Solution

### Task 1 - Introduction

![Snort Picture 1](Images/Snort_Picture_1.png)

This room expects you to be familiar with basic Linux command-line functionalities like general system navigation and Network fundamentals (ports, protocols and traffic data). The room aims to encourage you to start working with Snort to analyse live and captured traffic.

Before joining this room, we suggest completing the '[Network Fundamentals](https://tryhackme.com/module/network-fundamentals)' module. If you have general knowledge of network basics and Linux fundamentals, you will be ready to begin!  If you feel you need assistance in the Linux command line, you can always refer to our "[Linux Fundamentals](https://tryhackme.com/module/linux-fundamentals)" module.

SNORT is an open-source, rule-based **Network Intrusion Detection and Prevention System** (NIDS/NIPS) . It was developed and still maintained by Martin Roesch, open-source contributors, and the Cisco Talos team.

[The official description](https://www.snort.org/): "*Snort is the foremost Open Source Intrusion Prevention System (IPS) in the world. Snort IPS uses a series of rules that help define malicious network activity and uses those rules to find packets that match against them and generate alerts for users*."

### Task 2 - Interactive Material and VM

#### Interactive material and exercise setup

Deploy the machine attached to this task; it will be visible in the **split-screen** view once it is ready. If you don't see a virtual machine load, click the Show Split View button.

Once the machine had fully started, you will see a folder named "**Task-Exercises**" on the Desktop. Each exercise has an individual folder and files; use them accordingly to the questions.

Everything you need is located under the "**Task-Exercises**" folder.

There are two sub-folders available:

- Config-Sample: Sample configuration and rule files. These files are provided to show what the configuration files look like. Installed Snort instance doesn't use them, so feel free to practice and modify them. Snort's original base files are located under **/etc/snort** folder.

- Exercise-Files: There are separate folders for each task. Each folder contains pcap, log and rule files ready to play with.

#### Traffic Generator

The machine is offline, but there is a script (`traffic-generator.sh`) for you to generate traffic to your snort interface. You will use this script to trigger traffic to the snort interface. Once you run the script, it will ask you to choose the exercise type and then automatically open another terminal to show you the output of the selected action.

Note that each traffic is designed for a specific exercise. Make sure you start the snort instance and wait until to end of the script execution. Don't stop the traffic flood unless you choose the wrong exercise.

Run the "**traffic generator.sh**" file by executing it as sudo.

```bash
user@ubuntu$ sudo ./traffic-generator.sh
```

General desktop overview. Traffic generator script in action.

![Snort Traffic Generator 1](Images/Snort_Traffic_Generator_1.png)

Once you choose an action, the menu disappears and opens a terminal instance to show you the output of the action.

![Snort Traffic Generator 2](Images/Snort_Traffic_Generator_2.png)

#### Navigate to the Task-Exercises folder and run the command "./.easy.sh" and write the output

```bash
ubuntu@ip-10-10-5-141:~$ cd Desktop/Task-Exercises/
ubuntu@ip-10-10-5-141:~/Desktop/Task-Exercises$ ls -la
total 28
drwx------ 5 ubuntu ubuntu 4096 Jan 10  2022 .
drwxr-xr-x 3 ubuntu ubuntu 4096 Jan 10  2022 ..
-rwxrwxr-x 1 ubuntu ubuntu   30 Dec 25  2021 .easy.sh
drwx------ 2 ubuntu ubuntu 4096 Jan  6  2022 .traffic-generator-source
drwx------ 2 ubuntu ubuntu 4096 Jan  6  2022 Config-Sample
drwx------ 7 ubuntu ubuntu 4096 Feb  4  2022 Exercise-Files
-rwxrwxr-x 1 ubuntu ubuntu 1677 Jan 10  2022 traffic-generator.sh
ubuntu@ip-10-10-5-141:~/Desktop/Task-Exercises$ ./.easy.sh 
Too Easy!
ubuntu@ip-10-10-5-141:~/Desktop/Task-Exercises$ 
```

Answer: Too Easy!

### Task 3 - Introduction to IDS/IPS

![Detection vs Prevention](Images/Detection_vs_Prevention.png)

Before diving into Snort and analysing traffic, let's have a brief overview of what an Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) is. It is possible to configure your network infrastructure and use both of them, but before starting to use any of them, let's learn the differences.

#### Intrusion Detection System (IDS)

IDS is a passive monitoring solution for detecting possible malicious activities/patterns, abnormal incidents, and policy violations. It is responsible for generating alerts for each suspicious event.

There are two main types of IDS systems;

- **Network Intrusion Detection System (NIDS)** - NIDS monitors the traffic flow from various areas of the network. The aim is to investigate the traffic on the entire subnet. If a signature is identified, an alert is created.

- **Host-based Intrusion Detection System (HIDS)** - HIDS monitors the traffic flow from a single endpoint device. The aim is to investigate the traffic on a particular device. If a signature is identified, an alert is created.

#### Intrusion Prevention System (IPS)

IPS is an active protecting solution for preventing possible malicious activities/patterns, abnormal incidents, and policy violations. It is responsible for stopping/preventing/terminating the suspicious event as soon as the detection is performed.

There are four main types of IPS systems;

- **Network Intrusion Prevention System (NIPS)** - NIPS monitors the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet. If a signature is identified, the connection is terminated.

- **Behaviour-based Intrusion Prevention System (Network Behaviour Analysis - NBA)** - Behaviour-based systems monitor the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet. If an anomaly is identified, the connection is terminated.

Network Behaviour Analysis System works similar to NIPS. The difference between NIPS and Behaviour-based is that behaviour based systems require a training period (also known as "baselining") to learn the normal traffic and differentiate the malicious traffic and threats. This model provides more efficient results against new and unknown threats.

The system is trained to know the "normal" to detect "abnormal". The training period is crucial to avoid any false positives. In case of any security breach during the training period, the results will be highly problematic. Another critical point is to ensure that the system is well trained to recognise benign activities.

- **Wireless Intrusion Prevention System (WIPS)** - WIPS monitors the traffic flow from of wireless network. The aim is to protect the wireless traffic and stop possible attacks launched from there. If a signature is identified, the connection is terminated.

- **Host-based Intrusion Prevention System (HIPS)** - HIPS actively protects the traffic flow from a single endpoint device. The aim is to investigate the traffic on a particular device. If a signature is identified, the connection is terminated.

HIPS working mechanism is similar to HIDS. The difference between them is that while **HIDS creates alerts** for threats, **HIPS stops the threats by terminating the connection**.

#### Detection/Prevention Techniques

There are three main detection and prevention techniques used in IDS and IPS solutions;

| Technique | Approach |
|----|----|
|**Signature-Based**|This technique relies on rules that identify the specific patterns of the known malicious behaviour. This model helps detect known threats.|
|**Behaviour-Based**|This technique identifies new threats with new patterns that pass through signatures. The model compares the known/normal with unknown/abnormal behaviours. This model helps detect previously unknown or new threats.|
|**Policy-Based**|This technique compares detected activities with system configuration and security policies. This model helps detect policy violations.|

#### Summary

Phew! That was a long ride and lots of information. Let's summarise the overall functions of the IDS and IPS in a nutshell.

- **IDS** can identify threats but require user assistance to stop them.
- **IPS** can identify and block the threats with less user assistance at the detection time.

**Now let's talk about Snort. Here is the rest of the [official description](https://www.snort.org/) of the snort;**

"*Snort can be deployed inline to stop these packets, as well. Snort has three primary uses: As a packet sniffer like tcpdump, as a packet logger — which is useful for network traffic debugging, or it can be used as a full-blown network intrusion prevention system. Snort can be downloaded and configured for personal and business use alike.*"

SNORT is an **open-source**, **rule-based** Network Intrusion Detection and Prevention System (**NIDS/NIPS**). It was developed and still maintained by Martin Roesch, open-source contributors, and the Cisco Talos team.

Capabilities of Snort;

- Live traffic analysis
- Attack and probe detection
- Packet logging
- Protocol analysis
- Real-time alerting
- Modules & plugins
- Pre-processors
- Cross-platform support! (Linux & Windows)

Snort has three main use models;

- **Sniffer Mode** - Read IP packets and prompt them in the console application.
- **Packet Logger Mode** - Log all IP packets (inbound and outbound) that visit the network.
- **NIDS (Network Intrusion Detection System) and NIPS (Network Intrusion Prevention System) Modes** - Log/drop the packets that are deemed as malicious according to the user-defined rules.

#### Which IDS or IPS type can help you stop the threats on a local machine?

Answer: HIPS

#### Which IDS or IPS type can help you detect threats on a local network?

Answer: NIDS

#### Which IDS or IPS type can help you detect the threats on a local machine?

Answer: HIDS

#### Which IDS or IPS type can help you stop the threats on a local network?

Answer: NIPS

#### Which described solution works by detecting anomalies in the network?

Answer: NBA

#### According to the official description of the snort, what kind of NIPS is it?

Answer: full-blown

#### NBA training period is also known as ...

Answer: baselining

### Task 4 - First Interaction with Snort

#### The First Interaction with Snort

First, let's verify snort is installed. The following command will show you the instance version.

```bash
ser@ubuntu$ snort -V

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build XXXXXX) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11
```

Before getting your hands dirty, we should ensure our configuration file is valid.

Here `-T` is used for testing configuration, and `-c` is identifying the configuration file (**snort.conf**).  
Note that it is possible to use an additional configuration file by pointing it with `-c`.

```bash
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -T 

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
... [Output truncated]
        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build XXXX) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

           Rules Engine: SF_SNORT_DETECTION_ENGINE  Version 2.4  
           Preprocessor Object: SF_GTP  Version 1.1  
           Preprocessor Object: SF_SIP  Version 1.1  
           Preprocessor Object: SF_SSH  Version 1.1  
           Preprocessor Object: SF_SMTP  Version 1.1  
           Preprocessor Object: SF_POP  Version 1.0  
           Preprocessor Object: SF_DCERPC2  Version 1.0  
           Preprocessor Object: SF_IMAP  Version 1.0  
           Preprocessor Object: SF_DNP3  Version 1.1  
           Preprocessor Object: SF_SSLPP  Version 1.1  
           Preprocessor Object: SF_MODBUS  Version 1.1  
           Preprocessor Object: SF_SDF  Version 1.1  
           Preprocessor Object: SF_REPUTATION  Version 1.1  
           Preprocessor Object: SF_DNS  Version 1.1  
           Preprocessor Object: SF_FTPTELNET  Version 1.2  
... [Output truncated]
Snort successfully validated the configuration!
Snort exiting
```

Once we use a configuration file, snort got much more power! The configuration file is an all-in-one management file of the snort. Rules, plugins, detection mechanisms, default actions and output settings are identified here. It is possible to have multiple configuration files for different purposes and cases but can only use one at runtime.

Note that every time you start the Snort, it will automatically show the default banner and initial information about your setup. You can prevent this by using the `-q`  parameter.

| Parameter | Description |
|----|----|
|`-V` / `--version`|This parameter provides information about your instance version.|
|`-c`|Identifying the configuration file|
|`-T`|Snort's self-test parameter, you can test your setup with this parameter.|
|`-q`|Quiet mode prevents snort from displaying the default banner and initial information about your setup.|

That was an easy one; let's continue exploring snort modes!

#### Run the Snort instance and check the build number

Hint: `-V` helps you have information on your current build.

```bash
ubuntu@ip-10-10-5-141:~/Desktop/Task-Exercises$ snort -V

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11
```

Answer: 149

#### Test the current instance with "/etc/snort/snort.conf" file and check how many rules are loaded with the current build

Hint: `-c` identifies the configuration file. `-T` activates self-test mode.

```bash
ubuntu@ip-10-10-5-141:~/Desktop/Task-Exercises$ snort -c /etc/snort/snort.conf -T
Running in Test mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
PortVar 'HTTP_PORTS' defined :  [ 80:81 311 383 591 593 901 1220 1414 1741 1830 2301 2381 2809 3037 3128 3702 4343 4848 5250 6988 7000:7001 7144:7145 7510 7777 7779 8000 8008 8014 8028 8080 8085 8088 8090 8118 8123 8180:8181 8243 8280 8300 8800 8888 8899 9000 9060 9080 9090:9091 9443 9999 11371 34443:34444 41080 50002 55555 ]
<---snip--->
WARNING: /etc/snort/rules/community-web-php.rules(474) GID 1 SID 100000934 in rule duplicates previous rule. Ignoring old rule.

4151 Snort rules read
    3477 detection rules
    0 decoder rules
    0 preprocessor rules
3477 Option Chains linked into 271 Chain Headers
0 Dynamic rules
+++++++++++++++++++++++++++++++++++++++++++++++++++
<---snip--->
```

Answer: 4151

#### Test the current instance with "/etc/snort/snortv2.conf" file and check how many rules are loaded with the current build

Hint: Remember, you can have multiple configuration files for different purposes/cases.

```bash
ubuntu@ip-10-10-5-141:~/Desktop/Task-Exercises$ snort -c /etc/snort/snortv2.conf -T
Running in Test mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snortv2.conf"
<---snip--->
+++++++++++++++++++++++++++++++++++++++++++++++++++
Initializing rule chains...
1 Snort rules read
    1 detection rules
    0 decoder rules
    0 preprocessor rules
1 Option Chains linked into 1 Chain Headers
0 Dynamic rules
+++++++++++++++++++++++++++++++++++++++++++++++++++
<---snip--->
```

Answer: 1

### Task 5 - Operation Mode 1: Sniffer Mode

![Snort Picture 2](Images/Snort_Picture_2.png)

#### Let's run Snort in Sniffer Mode

Like tcpdump, Snort has various flags capable of viewing various data about the packet it is ingesting.

Sniffer mode parameters are explained in the table below;

| Parameter | Description |
|----|----|
|`-v`|Verbose. Display the TCP/IP output in the console.|
|`-d`|Display the packet data (payload).|
|`-e`|Display the link-layer (TCP/IP/UDP/ICMP) headers.|
|`-X`|Display the full packet details in HEX.|
|`-i`|This parameter helps to define a specific network interface to listen/sniff. Once you have multiple interfaces, you can choose a specific interface to sniff.|

Let's start using each parameter and see the difference between them. Snort needs active traffic on your interface, so we need to generate traffic to see Snort in action.

To do this, use the **traffic-generator** script (find this in the Task-Exercise folder)

#### Sniffing with parameter "-i"

Start the Snort instance in **verbose** mode (`-v`) and use the **interface** (`-i`) "eth0"; `sudo snort -v -i eth0`

In case you have only one interface, Snort uses it by default. The above example demonstrates to sniff on the interface named "eth0". Once you simulate the parameter `-v`, you will notice it will automatically use the "eth0" interface and prompt it.

#### Sniffing with parameter "-v"

Start the Snort instance in **verbose** mode (`-v`); `sudo snort -v`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start showing the  packets in verbosity mode as follows;

```bash
user@ubuntu$ sudo snort -v
                             
Running in packet dump mode

        --== Initializing Snort ==--
...
Commencing packet processing (pid=64)
12/01-20:10:13.846653 192.168.175.129:34316 -> 192.168.175.2:53
UDP TTL:64 TOS:0x0 ID:23826 IpLen:20 DgmLen:64 DF
Len: 36
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

12/01-20:10:13.846794 192.168.175.129:38655 -> 192.168.175.2:53
UDP TTL:64 TOS:0x0 ID:23827 IpLen:20 DgmLen:64 DF
Len: 36
===============================================================================
Snort exiting
```

As you can see in the given output, verbosity mode provides tcpdump like output information. Once we interrupt the sniffing with `CTRL + C`, it stops and summarises the sniffed packets.

#### Sniffing with parameter "-d"

Start the Snort instance in **dumping packet data mode** (`-d`); `sudo snort -d`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start showing the packets in verbosity mode as follows;

```bash
user@ubuntu$ sudo snort -d
                             
Running in packet dump mode

        --== Initializing Snort ==--
...
Commencing packet processing (pid=67)

12/01-20:45:42.068675 192.168.175.129:37820 -> 192.168.175.2:53
UDP TTL:64 TOS:0x0 ID:53099 IpLen:20 DgmLen:56 DF
Len: 28
99 A5 01 00 00 01 00 00 00 00 00 00 06 67 6F 6F  .............goo
67 6C 65 03 63 6F 6D 00 00 1C 00 01              gle.com.....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
12/01-20:45:42.070742 192.168.175.2:53 -> 192.168.175.129:44947
UDP TTL:128 TOS:0x0 ID:63307 IpLen:20 DgmLen:72
Len: 44
FE 64 81 80 00 01 00 01 00 00 00 00 06 67 6F 6F  .d...........goo
67 6C 65 03 63 6F 6D 00 00 01 00 01 C0 0C 00 01  gle.com.........
00 01 00 00 00 05 00 04 D8 3A CE CE              .........:..

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

As you can see in the given output, packet data payload mode covers the verbose mode and provides more data.

#### Sniffing with parameter "-de"

Start the Snort instance in **dump** (`-d`) and **link-layer header grabbing** (`-e`) mode; `snort -d -e`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start showing the  packets in verbosity mode as follows;

```bash
user@ubuntu$ sudo snort -de
                             
Running in packet dump mode

        --== Initializing Snort ==--
...
Commencing packet processing (pid=70)
12/01-20:55:26.958773 00:0C:29:A5:B7:A2 -> 00:50:56:E1:9B:9D type:0x800 len:0x46
192.168.175.129:47395 -> 192.168.175.2:53 UDP TTL:64 TOS:0x0 ID:64294 IpLen:20 DgmLen:56 DF
Len: 28
6D 9C 01 00 00 01 00 00 00 00 00 00 06 67 6F 6F  m............goo
67 6C 65 03 63 6F 6D 00 00 01 00 01              gle.com.....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
12/01-20:55:26.965226 00:50:56:E1:9B:9D -> 00:0C:29:A5:B7:A2 type:0x800 len:0x56
192.168.175.2:53 -> 192.168.175.129:47395 UDP TTL:128 TOS:0x0 ID:63346 IpLen:20 DgmLen:72
Len: 44
6D 9C 81 80 00 01 00 01 00 00 00 00 06 67 6F 6F  m............goo
67 6C 65 03 63 6F 6D 00 00 01 00 01 C0 0C 00 01  gle.com.........
00 01 00 00 00 05 00 04 D8 3A D6 8E              .........:..
```

#### Sniffing with parameter "-X"

Start the Snort instance in **full packet dump mode** (`-X`); `sudo snort -X`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start showing the packets in verbosity mode as follows;

```bash
user@ubuntu$ sudo snort -X
                             
Running in packet dump mode

        --== Initializing Snort ==--
...
Commencing packet processing (pid=76)
WARNING: No preprocessors configured for policy 0.
12/01-21:07:56.806121 192.168.175.1:58626 -> 239.255.255.250:1900
UDP TTL:1 TOS:0x0 ID:48861 IpLen:20 DgmLen:196
Len: 168
0x0000: 01 00 5E 7F FF FA 00 50 56 C0 00 08 08 00 45 00  ..^....PV.....E.
0x0010: 00 C4 BE DD 00 00 01 11 9A A7 C0 A8 AF 01 EF FF  ................
0x0020: FF FA E5 02 07 6C 00 B0 85 AE 4D 2D 53 45 41 52  .....l....M-SEAR
0x0030: 43 48 20 2A 20 48 54 54 50 2F 31 2E 31 0D 0A 48  CH * HTTP/1.1..H
0x0040: 4F 53 54 3A 20 32 33 39 2E 32 35 35 2E 32 35 35  OST: 239.255.255
0x0050: 2E 32 35 30 3A 31 39 30 30 0D 0A 4D 41 4E 3A 20  .250:1900..MAN: 
0x0060: 22 73 73 64 70 3A 64 69 73 63 6F 76 65 72 22 0D  "ssdp:discover".
0x0070: 0A 4D 58 3A 20 31 0D 0A 53 54 3A 20 75 72 6E 3A  .MX: 1..ST: urn:
0x0080: 64 69 61 6C 2D 6D 75 6C 74 69 73 63 72 65 65 6E  dial-multiscreen
0x0090: 2D 6F 72 67 3A 73 65 72 76 69 63 65 3A 64 69 61  -org:service:dia
0x00A0: 6C 3A 31 0D 0A 55 53 45 52 2D 41 47 45 4E 54 3A  l:1..USER-AGENT:
0x00B0: 20 43 68 72 6F 6D 69 75 6D 2F 39 35 2E 30 2E 34   Chromium/95.0.4
0x00C0: 36 33 38 2E 36 39 20 57 69 6E 64 6F 77 73 0D 0A  638.69 Windows..
0x00D0: 0D 0A                                            ..

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
12/01-21:07:57.624205 216.58.214.142 -> 192.168.175.129
ICMP TTL:128 TOS:0x0 ID:63394 IpLen:20 DgmLen:84
Type:0  Code:0  ID:15  Seq:1  ECHO REPLY
0x0000: 00 0C 29 A5 B7 A2 00 50 56 E1 9B 9D 08 00 45 00  ..)....PV.....E.
0x0010: 00 54 F7 A2 00 00 80 01 24 13 D8 3A D6 8E C0 A8  .T......$..:....
0x0020: AF 81 00 00 BE B6 00 0F 00 01 2D E4 A7 61 00 00  ..........-..a..
0x0030: 00 00 A4 20 09 00 00 00 00 00 10 11 12 13 14 15  ... ............
0x0040: 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25  .......... !"#$%
0x0050: 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35  &'()*+,-./012345
0x0060: 36 37                                            67

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

Note that you can use the parameters both in combined and separated form as follows;

- snort -v
- snort -vd
- snort -de
- snort -v -d -e
- snort -X

Make sure you understand and practice each parameter with different types of traffic and discover your favourite combination.

### Task 6 - Operation Mode 2: Packet Logger Mode

![Snort Picture 3](Images/Snort_Picture_3.png)

#### Let's run Snort in Logger Mode

You can use Snort as a sniffer and log the sniffed packets via logger mode. You only need to use the packet logger mode parameters, and Snort does the rest to accomplish this.

Packet logger parameters are explained in the table below;

 | Parameter | Description |
 |----|----|
|`-l`|Logger mode, target log and alert output directory. Default output folder is **/var/log/snort**. The default action is to dump as tcpdump format in **/var/log/snort**|
|`-K ASCII`|Log packets in ASCII format.|
|`-r`|Reading option, read the dumped logs in Snort.|
|`-n`|Specify the number of packets that will process/read. Snort will stop after reading the specified number of packets.|

Let's start using each parameter and see the difference between them. Snort needs active traffic on your interface, so we need to generate traffic to see Snort in action.

#### Logfile Ownership

Before generating logs and investigating them, we must remember the Linux file ownership and permissions. No need to deep dive into user types and permissions. The fundamental file ownership rule; **whoever creates a file becomes the owner of the corresponding file**.

Snort needs superuser (root) rights to sniff the traffic, so once you run the snort with the "sudo" command, the "root" account will own the generated log files. Therefore you will need "root" rights to investigate the log files. There are two different approaches to investigate the generated log files;

- **Elevation of privileges** - You can elevate your privileges to examine the files. You can use the "sudo" command to execute your command as a superuser with the following command `sudo command`. You can also elevate the session privileges and switch to the superuser account to examine the generated log files with the following command: `sudo su`

- **Changing the ownership of files/directories** - You can also change the ownership of the file/folder to read it as your user: `sudo chown username file` or `sudo chown username -R directory` The `-R` parameter helps recursively process the files and directories.

#### Logging with parameter "-l"

First, start the Snort instance in packet logger mode; `sudo snort -dev -l .`

Now start ICMP/HTTP traffic with the traffic-generator script.

Once the traffic is generated, Snort will start showing the packets and log them in the target directory. You can configure the default output directory in snort.config file. However, you can use the `-l` parameter to set a target directory. Identifying the default log directory is useful for continuous monitoring operations, and the `-l` parameter is much more useful for testing purposes.

The `-l .` part of the command creates the logs in the current directory. You will need to use this option to have the logs for each exercise in their folder.

```bash
user@ubuntu$ sudo snort -dev -l .
                             
Running in packet logging mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Log directory = /var/log/snort
pcap DAQ configured to passive.
Acquiring network traffic from "ens33".
Decoding Ethernet

        --== Initialization Complete ==--
...
Commencing packet processing (pid=2679)
WARNING: No preprocessors configured for policy 0.
WARNING: No preprocessors configured for policy 0.
```

Now, let's check the generated log file. Note that the log file names will be different in your case.

```bash
user@ubuntu$ ls .
                             
snort.log.1638459842
```

As you can see, it is a single all-in-one log file. It is a binary/tcpdump format log.

#### Logging with parameter "-K ASCII"

Start the Snort instance in packet logger mode; `sudo snort -dev -K ASCII`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, Snort will start showing the  packets in verbosity mode as follows;

```bash
user@ubuntu$ sudo snort -dev -K ASCII -l .
                             
Running in packet logging mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Log directory = /var/log/snort
pcap DAQ configured to passive.
Acquiring network traffic from "ens33".
Decoding Ethernet

        --== Initialization Complete ==--
...
Commencing packet processing (pid=2679)
WARNING: No preprocessors configured for policy 0.
WARNING: No preprocessors configured for policy 0.
```

Now, let's check the generated log file.

```bash
user@ubuntu$ ls .
                             
142.250.187.110  192.168.175.129  snort.log.1638459842
```

The logs created with "-K ASCII" parameter is entirely different. There are two folders with IP address names. Let's look into them.

```bash
user@ubuntu$ ls ./192.168.175.129/
                             
ICMP_ECHO  UDP:36648-53  UDP:40757-53  UDP:47404-53  UDP:50624-123
```

Once we look closer at the created folders, we can see that the logs are in ASCII and categorised format, so it is possible to read them without using a Snort instance.

In a nutshell, ASCII mode provides multiple files in human-readable format, so it is possible to read the logs easily by using a text editor. By contrast with ASCII format, binary format is not human-readable and requires analysis using Snort or an application like tcpdump.

Let's compare the ASCII format with the binary format by opening both of them in a text editor. The difference between the binary log file and the ASCII log file is shown below. (Left side: binary format. Right side: ASCII format).

![Snort Log Format Comparison](Images/Snort_Log_Format_Comparison.png)

#### Reading generated logs with parameter "-r"

Start the Snort instance in packet reader mode; `sudo snort -r`

```bash
user@ubuntu$ sudo snort -r snort.log.1638459842
                             
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1638459842".

        --== Initialization Complete ==--
...
Commencing packet processing (pid=3012)
WARNING: No preprocessors configured for policy 0.
12/02-07:44:03.123225 192.168.175.129 -> 142.250.187.110
ICMP TTL:64 TOS:0x0 ID:41900 IpLen:20 DgmLen:84 DF
Type:8  Code:0  ID:1   Seq:49  ECHO
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
WARNING: No preprocessors configured for policy 0.
12/02-07:44:26.169620 192.168.175.129 -> 142.250.187.110
ICMP TTL:64 TOS:0x0 ID:44765 IpLen:20 DgmLen:84 DF
Type:8  Code:0  ID:1   Seq:72  ECHO
===============================================================================
Packet I/O Totals:
   Received:           51
   Analyzed:           51 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
...
      Total:           51
===============================================================================
Snort exiting
```

Note that Snort can read and handle the binary like output (tcpdump and Wireshark also can handle this log format). However, if you create logs with "-K ASCII" parameter, Snort will not read them. As you can see in the above output, Snort read and displayed the log file just like in the sniffer mode.

Opening log file with tcpdump.

```bash
user@ubuntu$ sudo tcpdump -r snort.log.1638459842 -ntc 10
                             
reading from file snort.log.1638459842, link-type EN10MB (Ethernet)
IP 192.168.175.129 > 142.250.187.110: ICMP echo request, id 1, seq 49, length 64
IP 142.250.187.110 > 192.168.175.129: ICMP echo reply, id 1, seq 49, length 64
IP 192.168.175.129 > 142.250.187.110: ICMP echo request, id 1, seq 50, length 64
IP 142.250.187.110 > 192.168.175.129: ICMP echo reply, id 1, seq 50, length 64
IP 192.168.175.129 > 142.250.187.110: ICMP echo request, id 1, seq 51, length 64
IP 142.250.187.110 > 192.168.175.129: ICMP echo reply, id 1, seq 51, length 64
IP 192.168.175.129 > 142.250.187.110: ICMP echo request, id 1, seq 52, length 64
IP 142.250.187.110 > 192.168.175.129: ICMP echo reply, id 1, seq 52, length 64
IP 192.168.175.1.63096 > 239.255.255.250.1900: UDP, length 173
IP 192.168.175.129 > 142.250.187.110: ICMP echo request, id 1, seq 53, length 64
```

Opening log file with Wireshark.

![Snort Wireshark Example](Images/Snort_Wireshark_Example.png)

`-r` parameter also allows users to filter the binary log files. You can filter the processed log to see specific packets with the `-r` parameter and Berkeley Packet Filters (BPF).

- `sudo snort -r logname.log -X`
- `sudo snort -r logname.log icmp`
- `sudo snort -r logname.log tcp`
- `sudo snort -r logname.log 'udp and port 53'`

The output will be the same as the above, but only packets with the chosen protocol will be shown. Additionally, you can specify the number of processes with the parameter `-n`. The following command will process only the first 10 packets:

- `snort -dvr logname.log -n 10`

Please use the following resources to understand how the BPF works and its use.

- [https://en.wikipedia.org/wiki/Berkeley_Packet_Filter](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)
- [https://biot.com/capstats/bpf.html](https://biot.com/capstats/bpf.html)
- [https://www.tcpdump.org/manpages/tcpdump.1.html](https://www.tcpdump.org/manpages/tcpdump.1.html)

Now, use the attached VM and **navigate to the Task-Exercises/Exercise-Files/TASK-6 folder** to answer the questions!

#### Answer the questions below

Investigate the traffic with the default configuration file with ASCII mode.

`sudo snort -dev -K ASCII -l .`

Execute the traffic generator script and choose "**TASK-6 Exercise**". Wait until the traffic ends, then stop the Snort instance. Now analyse the output summary and answer the question.

`sudo ./traffic-generator.sh`

Now, you should have the logs in the current directory. Navigate to folder "**145.254.160.237**".

#### What is the source port used to connect port 53?

Hint: You can re-generate the traffic if the expected log is not generated. "sudo ls" can help you!  
Check the "Logfile Ownership" part in this task to avoid the "permission denied" error.

```bash
ubuntu@ip-10-10-5-141:~/Desktop/Task-Exercises/Exercise-Files/TASK-6$ cd 145.254.160.237/
bash: cd: 145.254.160.237/: Permission denied
ubuntu@ip-10-10-5-141:~/Desktop/Task-Exercises/Exercise-Files/TASK-6$ sudo su
root@ip-10-10-5-141:/home/ubuntu/Desktop/Task-Exercises/Exercise-Files/TASK-6# cd 145.254.160.237/
root@ip-10-10-5-141:/home/ubuntu/Desktop/Task-Exercises/Exercise-Files/TASK-6/145.254.160.237# ls
TCP:3371-80  TCP:3372-80  UDP:3009-53
root@ip-10-10-5-141:/home/ubuntu/Desktop/Task-Exercises/Exercise-Files/TASK-6/145.254.160.237# cat UDP\:3009-53 
05/08-17:59:54.205946 00:00:01:00:00:00 -> FE:FF:20:00:01:00 type:0x800 len:0x59
145.254.160.237:3009 -> 145.253.2.203:53 UDP TTL:128 TOS:0x0 ID:3913 IpLen:20 DgmLen:75
Len: 47
00 23 01 00 00 01 00 00 00 00 00 00 07 70 61 67  .#...........pag
65 61 64 32 11 67 6F 6F 67 6C 65 73 79 6E 64 69  ead2.googlesyndi
63 61 74 69 6F 6E 03 63 6F 6D 00 00 01 00 01     cation.com.....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

05/08-17:59:55.035344 FE:FF:20:00:01:00 -> 00:00:01:00:00:00 type:0x800 len:0xBC
145.253.2.203:53 -> 145.254.160.237:3009 UDP TTL:249 TOS:0x0 ID:5525 IpLen:20 DgmLen:174 DF
Len: 146
00 23 81 80 00 01 00 04 00 00 00 00 07 70 61 67  .#...........pag
65 61 64 32 11 67 6F 6F 67 6C 65 73 79 6E 64 69  ead2.googlesyndi
63 61 74 69 6F 6E 03 63 6F 6D 00 00 01 00 01 C0  cation.com......
0C 00 05 00 01 00 00 BC C1 00 11 07 70 61 67 65  ............page
61 64 32 06 67 6F 6F 67 6C 65 C0 26 C0 3B 00 05  ad2.google.&.;..
00 01 00 00 00 7A 00 1A 06 70 61 67 65 61 64 06  .....z...pagead.
67 6F 6F 67 6C 65 06 61 6B 61 64 6E 73 03 6E 65  google.akadns.ne
74 00 C0 58 00 01 00 01 00 00 00 7B 00 04 D8 EF  t..X.......{....
3B 68 C0 58 00 01 00 01 00 00 00 7B 00 04 D8 EF  ;h.X.......{....
3B 63                                            ;c

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

root@ip-10-10-5-141:/home/ubuntu/Desktop/Task-Exercises/Exercise-Files/TASK-6/145.254.160.237# 
```

Answer: 3009

#### Use snort.log.1640048004 Read the snort.log file with Snort; what is the IP ID of the 10th packet?

Hints:

- `snort -r snort.log.1640048004 -n 10`
- `-n` helps to analyse the "n" number of packets. You can view the IP with sniffing mode parameters `-v`, `-d`, `-e` or `-X`.

```bash
root@ip-10-10-5-141:/home/ubuntu/Desktop/Task-Exercises/Exercise-Files/TASK-6# snort -r snort.log.1640048004 -n 10
Exiting after 10 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1640048004".

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/13-10:17:09.754737 65.208.228.223:80 -> 145.254.160.237:3372
TCP TTL:47 TOS:0x0 ID:49313 IpLen:20 DgmLen:1420 DF
***A**** Seq: 0x114C6C54  Ack: 0x38AFFFF3  Win: 0x1920  TcpLen: 20
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.344 seconds
Snort processed 10 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:           10
<---snip--->
```

Answer: 49313

#### Read the "snort.log.1640048004" file with Snort; what is the referer of the 4th packet?

Hint: "-X" helps you to display the full packet details.

```bash
root@ip-10-10-5-141:/home/ubuntu/Desktop/Task-Exercises/Exercise-Files/TASK-6# snort -r snort.log.1640048004 -n 4 -X
Exiting after 4 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1640048004".

        --== Initialization Complete ==--
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/13-10:17:08.222534 145.254.160.237:3372 -> 65.208.228.223:80
TCP TTL:128 TOS:0x0 ID:3909 IpLen:20 DgmLen:519 DF
***AP*** Seq: 0x38AFFE14  Ack: 0x114C618C  Win: 0x25BC  TcpLen: 20
0x0000: FE FF 20 00 01 00 00 00 01 00 00 00 08 00 45 00  .. ...........E.
0x0010: 02 07 0F 45 40 00 80 06 90 10 91 FE A0 ED 41 D0  ...E@.........A.
0x0020: E4 DF 0D 2C 00 50 38 AF FE 14 11 4C 61 8C 50 18  ...,.P8....La.P.
0x0030: 25 BC A9 58 00 00 47 45 54 20 2F 64 6F 77 6E 6C  %..X..GET /downl
0x0040: 6F 61 64 2E 68 74 6D 6C 20 48 54 54 50 2F 31 2E  oad.html HTTP/1.
0x0050: 31 0D 0A 48 6F 73 74 3A 20 77 77 77 2E 65 74 68  1..Host: www.eth
0x0060: 65 72 65 61 6C 2E 63 6F 6D 0D 0A 55 73 65 72 2D  ereal.com..User-
0x0070: 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35  Agent: Mozilla/5
0x0080: 2E 30 20 28 57 69 6E 64 6F 77 73 3B 20 55 3B 20  .0 (Windows; U; 
0x0090: 57 69 6E 64 6F 77 73 20 4E 54 20 35 2E 31 3B 20  Windows NT 5.1; 
0x00A0: 65 6E 2D 55 53 3B 20 72 76 3A 31 2E 36 29 20 47  en-US; rv:1.6) G
0x00B0: 65 63 6B 6F 2F 32 30 30 34 30 31 31 33 0D 0A 41  ecko/20040113..A
0x00C0: 63 63 65 70 74 3A 20 74 65 78 74 2F 78 6D 6C 2C  ccept: text/xml,
0x00D0: 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 6D 6C 2C  application/xml,
0x00E0: 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 68 74 6D  application/xhtm
0x00F0: 6C 2B 78 6D 6C 2C 74 65 78 74 2F 68 74 6D 6C 3B  l+xml,text/html;
0x0100: 71 3D 30 2E 39 2C 74 65 78 74 2F 70 6C 61 69 6E  q=0.9,text/plain
0x0110: 3B 71 3D 30 2E 38 2C 69 6D 61 67 65 2F 70 6E 67  ;q=0.8,image/png
0x0120: 2C 69 6D 61 67 65 2F 6A 70 65 67 2C 69 6D 61 67  ,image/jpeg,imag
0x0130: 65 2F 67 69 66 3B 71 3D 30 2E 32 2C 2A 2F 2A 3B  e/gif;q=0.2,*/*;
0x0140: 71 3D 30 2E 31 0D 0A 41 63 63 65 70 74 2D 4C 61  q=0.1..Accept-La
0x0150: 6E 67 75 61 67 65 3A 20 65 6E 2D 75 73 2C 65 6E  nguage: en-us,en
0x0160: 3B 71 3D 30 2E 35 0D 0A 41 63 63 65 70 74 2D 45  ;q=0.5..Accept-E
0x0170: 6E 63 6F 64 69 6E 67 3A 20 67 7A 69 70 2C 64 65  ncoding: gzip,de
0x0180: 66 6C 61 74 65 0D 0A 41 63 63 65 70 74 2D 43 68  flate..Accept-Ch
0x0190: 61 72 73 65 74 3A 20 49 53 4F 2D 38 38 35 39 2D  arset: ISO-8859-
0x01A0: 31 2C 75 74 66 2D 38 3B 71 3D 30 2E 37 2C 2A 3B  1,utf-8;q=0.7,*;
0x01B0: 71 3D 30 2E 37 0D 0A 4B 65 65 70 2D 41 6C 69 76  q=0.7..Keep-Aliv
0x01C0: 65 3A 20 33 30 30 0D 0A 43 6F 6E 6E 65 63 74 69  e: 300..Connecti
0x01D0: 6F 6E 3A 20 6B 65 65 70 2D 61 6C 69 76 65 0D 0A  on: keep-alive..
0x01E0: 52 65 66 65 72 65 72 3A 20 68 74 74 70 3A 2F 2F  Referer: http://
0x01F0: 77 77 77 2E 65 74 68 65 72 65 61 6C 2E 63 6F 6D  www.ethereal.com
0x0200: 2F 64 65 76 65 6C 6F 70 6D 65 6E 74 2E 68 74 6D  /development.htm
0x0210: 6C 0D 0A 0D 0A                                   l....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
<---snip--->
```

Answer: `http://www.ethereal.com/development.html`

#### Read the "snort.log.1640048004" file with Snort; what is the Ack number of the 8th packet?

```bash
root@ip-10-10-5-141:/home/ubuntu/Desktop/Task-Exercises/Exercise-Files/TASK-6# snort -r snort.log.1640048004 -n 8 -X
Exiting after 8 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1640048004".

        --== Initialization Complete ==--
<---snip--->
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/13-10:17:09.123830 65.208.228.223:80 -> 145.254.160.237:3372
TCP TTL:47 TOS:0x0 ID:49312 IpLen:20 DgmLen:1420 DF
***A**** Seq: 0x114C66F0  Ack: 0x38AFFFF3  Win: 0x1920  TcpLen: 20
0x0000: 00 00 01 00 00 00 FE FF 20 00 01 00 08 00 45 00  ........ .....E.
0x0010: 05 8C C0 A0 40 00 2F 06 2C 30 41 D0 E4 DF 91 FE  ....@./.,0A.....
0x0020: A0 ED 00 50 0D 2C 11 4C 66 F0 38 AF FF F3 50 10  ...P.,.Lf.8...P.
0x0030: 19 20 C3 51 00 00 20 20 20 20 20 20 20 20 20 20  . .Q..          
0x0040: 3C 61 20 68 72 65 66 3D 22 73 65 61 72 63 68 2E  <a href="search.
0x0050: 68 74 6D 6C 22 3E 53 65 61 72 63 68 3A 3C 2F 61  html">Search:</a
0x0060: 3E 0A 09 09 20 20 3C 2F 64 69 76 3E 0A 09 20 20  >...  </div>..  
0x0070: 20 20 20 20 20 20 3C 2F 74 64 3E 0A 09 20 20 20        </td>..   
0x0080: 20 20 20 20 20 3C 74 64 3E 0A 09 20 20 20 20 20       <td>..     
0x0090: 20 20 20 20 20 3C 64 69 76 20 63 6C 61 73 73 3D       <div class=
0x00A0: 22 74 6F 70 66 6F 72 6D 74 65 78 74 22 3E 0A 20  "topformtext">. 
0x00B0: 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20                  
0x00C0: 20 3C 69 6E 70 75 74 20 74 79 70 65 3D 22 74 65   <input type="te
0x00D0: 78 74 22 20 73 69 7A 65 3D 22 31 32 22 20 6E 61  xt" size="12" na
0x00E0: 6D 65 3D 22 77 6F 72 64 73 22 3E 0A 09 09 20 20  me="words">...  
0x00F0: 3C 69 6E 70 75 74 20 74 79 70 65 3D 22 68 69 64  <input type="hid
0x0100: 64 65 6E 22 20 6E 61 6D 65 3D 22 63 6F 6E 66 69  den" name="confi
0x0110: 67 22 20 76 61 6C 75 65 3D 22 65 74 68 65 72 65  g" value="ethere
0x0120: 61 6C 22 3E 0A 09 09 20 20 3C 2F 64 69 76 3E 0A  al">...  </div>.
0x0130: 09 20 20 20 20 20 20 20 20 3C 2F 74 64 3E 0A 09  .        </td>..
0x0140: 09 3C 74 64 20 76 61 6C 69 67 6E 3D 22 62 6F 74  .<td valign="bot
0x0150: 74 6F 6D 22 3E 0A 09 09 20 20 3C 69 6E 70 75 74  tom">...  <input
0x0160: 20 74 79 70 65 3D 22 69 6D 61 67 65 22 20 63 6C   type="image" cl
0x0170: 61 73 73 3D 22 67 6F 62 75 74 74 6F 6E 22 20 73  ass="gobutton" s
0x0180: 72 63 3D 22 6D 6D 2F 69 6D 61 67 65 2F 67 6F 2D  rc="mm/image/go-
0x0190: 62 75 74 74 6F 6E 2E 67 69 66 22 3E 0A 09 09 3C  button.gif">...<
0x01A0: 2F 74 64 3E 0A 20 20 20 20 20 20 20 20 20 20 20  /td>.           
0x01B0: 20 20 20 3C 2F 74 72 3E 0A 20 20 20 20 20 20 20     </tr>.       
0x01C0: 20 20 20 20 20 20 20 3C 2F 66 6F 72 6D 3E 0A 3C         </form>.<
0x01D0: 2F 74 61 62 6C 65 3E 0A 09 20 20 3C 2F 64 69 76  /table>..  </div
0x01E0: 3E 0A 20 20 20 20 20 20 20 20 3C 2F 74 64 3E 0A  >.        </td>.
0x01F0: 20 20 20 20 20 20 3C 2F 74 72 3E 0A 20 20 20 20        </tr>.    
0x0200: 3C 2F 74 61 62 6C 65 3E 0A 20 20 20 20 3C 2F 64  </table>.    </d
0x0210: 69 76 3E 0A 3C 64 69 76 20 63 6C 61 73 73 3D 22  iv>.<div class="
0x0220: 73 69 74 65 62 61 72 22 3E 0A 3C 70 3E 0A 20 20  sitebar">.<p>.  
0x0230: 3C 61 20 68 72 65 66 3D 22 2F 22 3E 48 6F 6D 65  <a href="/">Home
0x0240: 3C 2F 61 3E 0A 20 20 3C 73 70 61 6E 20 63 6C 61  </a>.  <span cla
0x0250: 73 73 3D 22 73 69 74 65 62 61 72 73 65 70 22 3E  ss="sitebarsep">
0x0260: 7C 3C 2F 73 70 61 6E 3E 0A 20 20 3C 61 20 68 72  |</span>.  <a hr
0x0270: 65 66 3D 22 69 6E 74 72 6F 64 75 63 74 69 6F 6E  ef="introduction
0x0280: 2E 68 74 6D 6C 22 3E 49 6E 74 72 6F 64 75 63 74  .html">Introduct
0x0290: 69 6F 6E 3C 2F 61 3E 0A 20 20 3C 73 70 61 6E 20  ion</a>.  <span 
0x02A0: 63 6C 61 73 73 3D 22 73 69 74 65 62 61 72 73 65  class="sitebarse
0x02B0: 70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20 20 44 6F  p">|</span>.  Do
0x02C0: 77 6E 6C 6F 61 64 0A 20 20 3C 73 70 61 6E 20 63  wnload.  <span c
0x02D0: 6C 61 73 73 3D 22 73 69 74 65 62 61 72 73 65 70  lass="sitebarsep
0x02E0: 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20 20 3C 61 20  ">|</span>.  <a 
0x02F0: 68 72 65 66 3D 22 64 6F 63 73 2F 22 3E 44 6F 63  href="docs/">Doc
0x0300: 75 6D 65 6E 74 61 74 69 6F 6E 3C 2F 61 3E 0A 20  umentation</a>. 
0x0310: 20 3C 73 70 61 6E 20 63 6C 61 73 73 3D 22 73 69   <span class="si
0x0320: 74 65 62 61 72 73 65 70 22 3E 7C 3C 2F 73 70 61  tebarsep">|</spa
0x0330: 6E 3E 0A 20 20 3C 61 20 68 72 65 66 3D 22 6C 69  n>.  <a href="li
0x0340: 73 74 73 2F 22 3E 4C 69 73 74 73 3C 2F 61 3E 0A  sts/">Lists</a>.
0x0350: 20 20 3C 73 70 61 6E 20 63 6C 61 73 73 3D 22 73    <span class="s
0x0360: 69 74 65 62 61 72 73 65 70 22 3E 7C 3C 2F 73 70  itebarsep">|</sp
0x0370: 61 6E 3E 0A 20 20 3C 61 20 68 72 65 66 3D 22 66  an>.  <a href="f
0x0380: 61 71 2E 68 74 6D 6C 22 3E 46 41 51 3C 2F 61 3E  aq.html">FAQ</a>
0x0390: 0A 20 20 3C 73 70 61 6E 20 63 6C 61 73 73 3D 22  .  <span class="
0x03A0: 73 69 74 65 62 61 72 73 65 70 22 3E 7C 3C 2F 73  sitebarsep">|</s
0x03B0: 70 61 6E 3E 0A 20 20 3C 61 20 68 72 65 66 3D 22  pan>.  <a href="
0x03C0: 64 65 76 65 6C 6F 70 6D 65 6E 74 2E 68 74 6D 6C  development.html
0x03D0: 22 3E 44 65 76 65 6C 6F 70 6D 65 6E 74 3C 2F 61  ">Development</a
0x03E0: 3E 0A 3C 2F 70 3E 0A 3C 2F 64 69 76 3E 0A 3C 64  >.</p>.</div>.<d
0x03F0: 69 76 20 63 6C 61 73 73 3D 22 6E 61 76 62 61 72  iv class="navbar
0x0400: 22 3E 0A 3C 70 3E 0A 20 20 3C 61 20 68 72 65 66  ">.<p>.  <a href
0x0410: 3D 22 23 72 65 6C 65 61 73 65 73 22 3E 4F 66 66  ="#releases">Off
0x0420: 69 63 69 61 6C 20 52 65 6C 65 61 73 65 73 3C 2F  icial Releases</
0x0430: 61 3E 0A 20 20 3C 73 70 61 6E 20 63 6C 61 73 73  a>.  <span class
0x0440: 3D 22 6E 61 76 62 61 72 73 65 70 22 3E 7C 3C 2F  ="navbarsep">|</
0x0450: 73 70 61 6E 3E 0A 20 20 3C 61 20 68 72 65 66 3D  span>.  <a href=
0x0460: 22 23 6F 74 68 65 72 70 6C 61 74 22 3E 4F 74 68  "#otherplat">Oth
0x0470: 65 72 20 50 6C 61 74 66 6F 72 6D 73 3C 2F 61 3E  er Platforms</a>
0x0480: 0A 20 20 3C 73 70 61 6E 20 63 6C 61 73 73 3D 22  .  <span class="
0x0490: 6E 61 76 62 61 72 73 65 70 22 3E 7C 3C 2F 73 70  navbarsep">|</sp
0x04A0: 61 6E 3E 0A 20 20 3C 61 20 68 72 65 66 3D 22 23  an>.  <a href="#
0x04B0: 6F 74 68 65 72 64 6F 77 6E 22 3E 4F 74 68 65 72  otherdown">Other
0x04C0: 20 44 6F 77 6E 6C 6F 61 64 73 3C 2F 61 3E 0A 20   Downloads</a>. 
0x04D0: 20 3C 73 70 61 6E 20 63 6C 61 73 73 3D 22 6E 61   <span class="na
0x04E0: 76 62 61 72 73 65 70 22 3E 7C 3C 2F 73 70 61 6E  vbarsep">|</span
0x04F0: 3E 0A 20 20 3C 61 20 68 72 65 66 3D 22 23 6C 65  >.  <a href="#le
0x0500: 67 61 6C 22 3E 4C 65 67 61 6C 20 4E 6F 74 69 63  gal">Legal Notic
0x0510: 65 73 3C 2F 61 3E 0A 3C 2F 70 3E 0A 3C 2F 64 69  es</a>.</p>.</di
0x0520: 76 3E 0A 3C 21 2D 2D 20 42 65 67 69 6E 20 41 64  v>.<!-- Begin Ad
0x0530: 20 34 36 38 78 36 30 20 2D 2D 3E 0A 3C 64 69 76   468x60 -->.<div
0x0540: 20 63 6C 61 73 73 3D 22 61 64 62 6C 6F 63 6B 22   class="adblock"
0x0550: 3E 0A 3C 73 63 72 69 70 74 20 74 79 70 65 3D 22  >.<script type="
0x0560: 74 65 78 74 2F 6A 61 76 61 73 63 72 69 70 74 22  text/javascript"
0x0570: 3E 3C 21 2D 2D 0A 67 6F 6F 67 6C 65 5F 61 64 5F  ><!--.google_ad_
0x0580: 63 6C 69 65 6E 74 20 3D 20 22 70 75 62 2D 32 33  client = "pub-23
0x0590: 30 39 31 39 31 39 34 38 36 37                    0919194867

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
<---snip--->
```

Answer: 0x38AFFFF3

#### Read the "snort.log.1640048004" file with Snort; what is the number of the "TCP port 80" packets?

Hint: BPF filters will help you to filter the log file. 'tcp and port 80'

```bash
root@ip-10-10-5-141:/home/ubuntu/Desktop/Task-Exercises/Exercise-Files/TASK-6# snort -r snort.log.1640048004 tcp and port 80
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Snort BPF option: tcp and port 80
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1640048004".

        --== Initialization Complete ==--
<---snip--->
===============================================================================
Packet I/O Totals:
   Received:           41
   Analyzed:           41 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
<---snip--->
```

Answer: 41

### Task 7 - Operation Mode 3: IDS/IPS

![Snort Picture 4](Images/Snort_Picture_4.png)

#### Snort in IDS/IPS Mode

Capabilities of Snort are not limited to sniffing and logging the traffic. IDS/IPS mode helps you manage the traffic according to user-defined rules.

**Note that** (N)IDS/IPS mode depends on the rules and configuration. **TASK-10** summarises the essential paths, files and variables. Also, **TASK-3** covers configuration testing. Here, we need to understand the operating logic first, and then we will be going into rules in **TASK-9**.

#### Let's run Snort in IDS/IPS Mode

NIDS mode parameters are explained in the table below;

 | Parameter | Description |
 |----|----|
|`-c`|Defining the configuration file.|
|`-T`|Testing the configuration file.|
|`-N`|Disable logging.|
|`-D`|Background mode.|
|`-A`|Alert modes; **full**: Full alert mode, providing all possible information about the alert. This one also is the **default** mode; once you use `-A` and don't specify any mode, snort uses this mode. **fast**: Fast mode shows the alert message, timestamp, source and destination IP, along with port numbers. **console**: Provides fast style alerts on the console screen. **cmg**: CMG style, basic header details with payload in hex and text format. **none**: Disabling alerting.|

Let's start using each parameter and see the difference between them. Snort needs active traffic on your interface, so we need to generate traffic to see Snort in action. To do this, use the **traffic-generator** script and sniff the traffic.

**Once you start running IDS/IPS mode, you need to use rules**. As we mentioned earlier, we will use a pre-defined ICMP rule as an example. The defined rule will only generate alerts in any direction of ICMP packet activity.

`alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)`

This rule is located in `/etc/snort/rules/local.rules`.

Remember, in this module, we will focus only on the operating modes. The rules are covered in TASK9&10. Snort will create an "alert" file if the traffic flow triggers an alert. One last note; once you start running IPS/IDS mode, the sniffing and logging mode will be semi-passive. However, you can activate the functions using the parameters discussed in previous tasks. (-i, -v, -d, -e, -X, -l, -K ASCII) If you don't remember the purpose of these commands, please revisit TASK4.

#### IDS/IPS mode with parameter "-c and -T"

Start the Snort instance and test the configuration file. `sudo snort -c /etc/snort/snort.conf -T` This command will check your configuration file and prompt it if there is any misconfiguratioın in your current setting. You should be familiar with this command if you covered TASK3. If you don't remember the output of this command, please revisit TASK4.

#### IDS/IPS mode with parameter "-N"

Start the Snort instance and disable logging by running the following command: `sudo snort -c /etc/snort/snort.conf -N`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. This command will disable logging mode. The rest of the other functions will still be available (if activated).

The command-line output will provide the information requested with the parameters. So, if you activate verbosity (`-v`) or full packet dump (`-X`) you will still have the output in the console, but there will be no logs in the log folder.

#### IDS/IPS mode with parameter "-D"

Start the Snort instance in background mode with the following command: `sudo snort -c /etc/snort/snort.conf -D`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start processing the packets and accomplish the given task with additional parameters.

```bash
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -D

Spawning daemon child...
My daemon child 2898 lives...
Daemon parent exiting (0)
```

The command-line output will provide the information requested with the parameters. So, if you activate verbosity (`-v`) or full packet dump (`-X`) with packet logger mode (`-l`) you will still have the logs in the logs folder, but there will be no output in the console.
Once you start the background mode and want to check the corresponding process, you can easily use the "ps" command as shown below;

```bash
user@ubuntu$ ps -ef | grep snort

root        2898    1706  0 05:53 ?        00:00:00 snort -c /etc/snort/snort.conf -D
```

If you want to stop the daemon, you can easily use the "kill" command to stop the process.

```bash
user@ubuntu$ sudo kill -9 2898
```

**Note that** daemon mode is mainly used to automate the Snort. This parameter is mainly used in scripts to start the Snort service in the background. It is not recommended to use this mode unless you have a working knowledge of Snort and stable configuration.

#### IDS/IPS mode with parameter "-A"

Remember that there are several alert modes available in snort;

- **console**: Provides fast style alerts on the console screen.
- **cmg**: Provides basic header details with payload in hex and text format.
- **full**: Full alert mode, providing all possible information about the alert.
- **fast**: Fast mode, shows the alert message, timestamp, source and destination ıp along with port numbers.
- **none**: Disabling alerting.

In this section, only the "**console**" and "**cmg**" parameters provide alert information in the console. It is impossible to identify the difference between the rest of the alert modes via terminal. Differences can be identified by looking at generated logs.

At the end of this section, we will compare the "full", "fast" and "none" modes. Remember that these parameters don't provide console output, so we will continue to identify the differences through log formats.

#### IDS/IPS mode with parameter "-A console"

Console mode provides fast style alerts on the console screen. Start the Snort instance in console alert mode (`-A console`) with the following command `sudo snort -c /etc/snort/snort.conf -A console`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

```bash
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -A console
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
...
Commencing packet processing (pid=3743)
12/12-02:08:27.577495  [**] [1:366:7] ICMP PING *NIX [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-02:08:27.577495  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-02:08:27.577495  [**] [1:384:5] ICMP PING [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-02:08:27.609719  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
^C*** Caught Int-Signal
12/12-02:08:29.595898  [**] [1:366:7] ICMP PING *NIX [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-02:08:29.595898  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-02:08:29.595898  [**] [1:384:5] ICMP PING [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.175.129 -> 142.250.187.110
===============================================================================
Run time for packet processing was 26.25844 seconds
Snort processed 88 packets.
```

#### IDS/IPS mode with parameter "-A cmg"

Cmg mode provides basic header details with payload in hex and text format. Start the Snort instance in cmg alert mode (`-A cmg`) with the following command `sudo snort -c /etc/snort/snort.conf -A cmg`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

```bash
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -A cmg
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
...
Commencing packet processing (pid=3743)
12/12-02:23:56.944351  [**] [1:366:7] ICMP PING *NIX [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-02:23:56.944351 00:0C:29:A5:B7:A2 -> 00:50:56:E1:9B:9D type:0x800 len:0x62
192.168.175.129 -> 142.250.187.110 ICMP TTL:64 TOS:0x0 ID:10393 IpLen:20 DgmLen:84 DF
Type:8  Code:0  ID:4   Seq:1  ECHO
BC CD B5 61 00 00 00 00 CE 68 0E 00 00 00 00 00  ...a.....h......
10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F  ................
20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F   !"#$%&'()*+,-./
30 31 32 33 34 35 36 37                          01234567

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

Let's compare the console and cmg outputs before moving on to other alarm types. As you can see in the given outputs above, **console mode** provides basic header and rule information. **Cmg mode** provides full packet details along with rule information.

#### IDS/IPS mode with parameter "-A fast"

Fast mode provides alert messages, timestamps, and source and destination IP addresses. **Remember, there is no console output in this mode**. Start the Snort instance in fast alert mode (`-A fast`) with the following command `sudo snort -c /etc/snort/snort.conf -A fast`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

```bash
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -A fast
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
...
Commencing packet processing (pid=3743)
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

Let's check the alarm file;

![Snort IDS Mode Fast](Images/Snort_IDS_Mode_Fast.png)

As you can see in the given picture above, fast style alerts contain summary information on the action like direction and alert header.

#### IDS/IPS mode with parameter "-A full"

Full alert mode provides all possible information about the alert. **Remember, there is no console output in this mode**. Start the Snort instance in full alert mode (`-A full`) with the following command `sudo snort -c /etc/snort/snort.conf -A full`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

```bash
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -A full
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
...
Commencing packet processing (pid=3744)
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

Let's check the alarm file;

![Snort IDS Mode Full](Images/Snort_IDS_Mode_Full.png)

 As you can see in the given picture above, full style alerts contain all possible information on the action.

#### IDS/IPS mode with parameter "-A none"

Disable alerting. This mode doesn't create the alert file. However, it still logs the traffic and creates a log file in binary dump format. **Remember, there is no console output in this mode**. Start the Snort instance in none alert mode (`-A none`) with the following command `sudo snort -c /etc/snort/snort.conf -A none`

Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

```bash
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -A none
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
...
Commencing packet processing (pid=3745)
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

Snort only generated the log file, no alert file.

#### IDS/IPS mode: "Using rule file without configuration file"

It is possible to run the Snort only with rules without a configuration file. Running the Snort in this mode will help you test the user-created rules. However, this mode will provide less performance.

```bash
user@ubuntu$ sudo snort -c /etc/snort/rules/local.rules -A console
Running in IDS mode

12/12-12:13:29.167955  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:29.200543  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:30.169785  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:30.201470  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:31.172101  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
^C*** Caught Int-Signal
```

#### IPS mode and dropping packets

Snort IPS mode activated with `-Q --daq afpacket` parameters. You can also activate this mode by editing snort.conf file. However, you don't need to edit snort.conf file in the scope of this room. Review the bonus task or snort manual for further information on daq and advanced configuration settings: `-Q --daq afpacket`

Activate the Data Acquisition (DAQ) modules and use the afpacket module to use snort as an IPS: `-i eth0:eth1`

Identifying interfaces note that Snort IPS require at least two interfaces to work. Now run the traffic-generator script as **sudo** and start **ICMP/HTTP traffic**.

```bash
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console
Running in IPS mode

12/18-07:40:01.527100  [Drop] [**] [1:1000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.131 -> 192.168.175.2
12/18-07:40:01.552811  [Drop] [**] [1:1000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 172.217.169.142 -> 192.168.1.18
12/18-07:40:01.566232  [Drop] [**] [1:1000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.131 -> 192.168.175.2
12/18-07:40:02.517903  [Drop] [**] [1:1000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.1.18 -> 172.217.169.142
12/18-07:40:02.550844  [Drop] [**] [1:1000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 172.217.169.142 -> 192.168.1.18
^C*** Caught Int-Signal
```

As you can see in the picture above, Snort blocked the packets this time. **We used the same rule with a different action (drop/reject)**. Remember, for the scope of this task; our point is the operating mode, not the rule.

#### Answer the questions below

Investigate the traffic with the default configuration file.

`sudo snort -c /etc/snort/snort.conf -A full -l .`

Execute the traffic generator script and choose "**TASK-7 Exercise**". Wait until the traffic stops, then stop the Snort instance. Now analyse the output summary and answer the question.

`sudo ./traffic-generator.sh`

#### What is the number of the detected HTTP GET methods?

Hint: Timing is important, you should start the sniffing before the attack and terminate right after the attack.  
You can read the provided output statistics summary on the console.

```bash
root@ip-10-10-5-141:/home/ubuntu/Desktop/Task-Exercises/Exercise-Files/TASK-7# sudo snort -c /etc/snort/snort.conf -A full -l .
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
<---snip--->
===============================================================================
HTTP Inspect - encodings (Note: stream-reassembled packets included):
    POST methods:                         0         
    GET methods:                          2         
    HTTP Request Headers extracted:       2         
    HTTP Request Cookies extracted:       0         
    Post parameters extracted:            0         
    HTTP response Headers extracted:      3         
    HTTP Response Cookies extracted:      0         
    Unicode:                              0         
    Double unicode:                       0         
    Non-ASCII representable:              0         
    Directory traversals:                 0         
    Extra slashes ("//"):                 1         
    Self-referencing paths ("./"):        0         
    HTTP Response Gzip packets extracted: 1         
    Gzip Compressed Data Processed:       1272.00   
    Gzip Decompressed Data Processed:     3608.00   
    Total packets processed:              1426      
===============================================================================
<---snip--->
```

Answer: 2

### Task 8 - Operation Mode 4: PCAP Investigation

![Snort Picture 5](Images/Snort_Picture_5.png)

#### Let's investigate PCAPs with Snort

Capabilities of Snort are not limited to sniffing, logging and detecting/preventing the threats. PCAP read/investigate mode helps you work with pcap files. Once you have a pcap file and process it with Snort, you will receive default traffic statistics with alerts depending on your ruleset.

Reading a pcap without using any additional parameters we discussed before will only overview the packets and provide statistics about the file. In most cases, this is not very handy. We are investigating the pcap with Snort to benefit from the rules and speed up our investigation process by using the known patterns of threats.

**Note that** we are pretty close to starting to create rules. Therefore, you need to grasp the working mechanism of the Snort, learn the discussed parameters and begin combining the parameters for different purposes.

PCAP mode parameters are explained in the table below;

| Parameter | Description |
|----|----|
|`-r` / `--pcap-single=`|Read a single pcap|
|`--pcap-list=""`|Read pcaps provided in command (space separated).|
|`--pcap-show`|Show pcap name on console during processing.|

#### Investigating single PCAP with parameter "-r"

For test purposes, you can still test the default reading option with pcap by using the following command `snort -r icmp-test.pcap`

Let's investigate the pcap with our configuration file and see what will happen. `sudo snort -c /etc/snort/snort.conf -q -r icmp-test.pcap -A console -n 10`

If you don't remember the purpose of the parameters in the given command, please revisit previous tasks and come back again!

```bash
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -q -r icmp-test.pcap -A console -n 10

12/12-12:13:29.167955  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:29.200543  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:30.169785  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:30.201470  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:31.172101  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:31.204104  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:32.174106  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:32.208683  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:33.176920  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:33.208359  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
```

Our ICMP rule got a hit! As you can see in the given output, snort identified the traffic and prompted the alerts according to our ruleset.

#### Investigating multiple PCAPs with parameter "--pcap-list"

Let's investigate multiple pcaps with our configuration file and see what will happen. `sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console -n 10`

```bash
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console

12/12-12:13:29.167955  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:29.200543  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:30.169785  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:30.201470  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:31.172101  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
...
12/12-12:13:31.204104  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:32.174106  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:32.208683  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:33.176920  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:33.208359  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
```

Our ICMP rule got a hit! As you can see in the given output, snort identified the traffic and prompted the alerts according to our ruleset.

Here is one point to notice: we've processed two pcaps, and there are lots of alerts, so it is impossible to match the alerts with provided pcaps without snort's help. We need to separate the pcap process to identify the source of the alerts.

#### Investigating multiple PCAPs with parameter "--pcap-show"

Let's investigate multiple pcaps, distinguish each one, and see what will happen. `sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console --pcap-show`

```bash
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console --pcap-show 

Reading network traffic from "icmp-test.pcap" with snaplen = 1514
12/12-12:13:29.167955  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:29.200543  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:30.169785  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
...

Reading network traffic from "http2.pcap" with snaplen = 1514
12/12-12:13:35.213176  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
12/12-12:13:36.182950  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 192.168.175.129 -> 142.250.187.110
12/12-12:13:38.223470  [**] [1:10000001:0] ICMP Packet found [**] [Priority: 0] {ICMP} 142.250.187.110 -> 192.168.175.129
...
```

Our ICMP rule got a hit! As you can see in the given output, snort identified the traffic, distinguished each pcap file and prompted the alerts according to our ruleset.

Now, use the attached VM and navigate to the **Task-Exercises/Exercise-Files/TASK-8** folder to answer the questions!

Investigate the mx-1.pcap file with the default configuration file.

`sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap`

#### What is the number of the generated alerts?

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-8$ sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
<---snip--->
===============================================================================
Action Stats:
     Alerts:          170 (147.826%)
     Logged:          170 (147.826%)
     Passed:            0 (  0.000%)
<---snip--->
```

Answer: 170

#### Keep reading the output. How many TCP Segments are Queued?

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-8$ sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap
Running in IDS mode
<---snip--->
===============================================================================
Stream statistics:
            Total sessions: 3
              TCP sessions: 2
              UDP sessions: 1
             ICMP sessions: 0
               IP sessions: 0
                TCP Prunes: 0
                UDP Prunes: 0
               ICMP Prunes: 0
                 IP Prunes: 0
TCP StreamTrackers Created: 2
TCP StreamTrackers Deleted: 2
              TCP Timeouts: 0
              TCP Overlaps: 0
       TCP Segments Queued: 18
     TCP Segments Released: 18
       TCP Rebuilt Packets: 5
<---snip--->
```

Answer: 18

#### Keep reading the output.How many "HTTP response headers" were extracted?

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-8$ sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap
Running in IDS mode
<---snip--->
===============================================================================
HTTP Inspect - encodings (Note: stream-reassembled packets included):
    POST methods:                         0         
    GET methods:                          2         
    HTTP Request Headers extracted:       2         
    HTTP Request Cookies extracted:       0         
    Post parameters extracted:            0         
    HTTP response Headers extracted:      3         
    HTTP Response Cookies extracted:      0         
    Unicode:                              0         
    Double unicode:                       0         
    Non-ASCII representable:              0         
    Directory traversals:                 0         
    Extra slashes ("//"):                 1         
    Self-referencing paths ("./"):        0         
    HTTP Response Gzip packets extracted: 1         
    Gzip Compressed Data Processed:       1272.00   
    Gzip Decompressed Data Processed:     3608.00   
    Total packets processed:              24        
===============================================================================
<---snip--->
```

Answer: 3

Investigate the mx-1.pcap file with the second configuration file.

`sudo snort -c /etc/snort/snortv2.conf -A full -l . -r mx-1.pcap`

#### What is the number of the generated alerts?

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-8$ sudo snort -c /etc/snort/snortv2.conf -A full -l . -r mx-1.pcap
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snortv2.conf"
<---snip--->
===============================================================================
Action Stats:
     Alerts:           68 ( 59.130%)
     Logged:           68 ( 59.130%)
     Passed:            0 (  0.000%)
<---snip--->
```

Answer: 68

Investigate the mx-2.pcap file with the default configuration file.

`sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-2.pcap`

#### What is the number of the generated alerts?

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-8$ sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-2.pcap
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
<---snip--->
===============================================================================
Action Stats:
     Alerts:          340 (147.826%)
     Logged:          340 (147.826%)
     Passed:            0 (  0.000%)
<---snip--->
```

Answer: 340

#### Keep reading the output. What is the number of the detected TCP packets?

Hint: Check for the TCP Port Filter.

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-8$ sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-2.pcap
Running in IDS mode
<---snip--->
===============================================================================
Stream statistics:
            Total sessions: 3
              TCP sessions: 2
<---snip--->
           TCP Port Filter
                  Filtered: 0
                 Inspected: 0
                   Tracked: 82
<---snip--->
```

Answer: 82

Investigate the mx-2.pcap and mx-3.pcap files with the default configuration file.

`sudo snort -c /etc/snort/snort.conf -A full -l . --pcap-list="mx-2.pcap mx-3.pcap"`

#### What is the number of the generated alerts?

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-8$ sudo snort -c /etc/snort/snort.conf -A full -l . --pcap-list="mx-2.pcap mx-3.pcap"
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
<---snip--->
===============================================================================
Action Stats:
     Alerts:         1020 (147.826%)
     Logged:         1020 (147.826%)
     Passed:            0 (  0.000%)
<---snip--->
```

Answer: 1020

### Task 9 - Snort Rule Structure

![Snort Picture 6](Images/Snort_Picture_6.png)

#### Let's Learn Snort Rules

Understanding the Snort rule format is essential for any blue and purple teamer.  The primary structure of the snort rule is shown below;

![Snort_Rule_Layout](Images/Snort_Rule_Layout.png)

Each rule should have a type of action, protocol, source and destination IP, source and destination port and an option. Remember, Snort is in passive mode by default. So most of the time, you will use Snort as an IDS. You will need to start **"inline mode" to turn on IPS mode**. But before you start playing with inline mode, you should be familiar with Snort features and rules.

The Snort rule structure is easy to understand but difficult to produce. You should be familiar with rule options and related details to create efficient rules. It is recommended to practice Snort rules and option details for different use cases.

We will cover the basic rule structure in this room and help you take a step into snort rules. You can always advance your rule creation skills with different rule options by practising different use cases and studying rule option details in depth. We will focus on two actions; "**alert**" for IDS mode and "**reject**" for IPS mode.

Rules cannot be processed without a header. Rule options are "optional" parts. However, it is almost impossible to detect sophisticated attacks without using the rule options.

Action

There are several actions for rules. Make sure you understand the functionality and test it before creating rules for live systems. The most common actions are listed below.

- **alert**: Generate an alert and log the packet.
- **log**: Log the packet.
- **drop**: Block and log the packet.
- **reject**: Block the packet, log it and terminate the packet session.

Protocol

Protocol parameter identifies the type of the protocol that filtered for the rule.

Note that Snort2 supports only four protocols filters in the rules (**IP**, **TCP**, **UDP** and **ICMP**). However, you can detect the application flows using port numbers and options. For instance, if you want to detect FTP traffic, you cannot use the FTP keyword in the protocol field but filter the FTP traffic by investigating TCP traffic on port 21.

#### IP and Port Numbers

These parameters identify the source and destination IP addresses and associated port numbers filtered for the rule.

| Filter Type | Example |
|----|----|
|IP Filtering|`alert icmp 192.168.1.56 any <> any any  (msg: "ICMP Packet From "; sid: 100001; rev:1;)` This rule will create an alert for each ICMP packet originating from the 192.168.1.56 IP address.|
|Filter an IP range|`alert icmp 192.168.1.0/24 any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)` This rule will create an alert for each ICMP packet originating from the 192.168.1.0/24 subnet.|
|Filter multiple IP ranges|`alert icmp [192.168.1.0/24, 10.1.1.0/24] any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)` This rule will create an alert for each ICMP packet originating from the 192.168.1.0/24 and 10.1.1.0/24 subnets.|
|Exclude IP addresses/ranges|"negation operator" is used for excluding specific addresses and ports. Negation operator is indicated with "!" `alert icmp !192.168.1.0/24 any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)`  This rule will create an alert for each ICMP packet not originating from the 192.168.1.0/24 subnet.|
|Port Filtering|`alert tcp any any <> any 21  (msg: "FTP Port 21 Command Activity Detected"; sid: 100001; rev:1;)` This rule will create an alert for each TCP packet sent to port 21.|
|Exclude a specific port|`alert tcp any any <> any !21  (msg: "Traffic Activity Without FTP Port 21 Command Channel"; sid: 100001; rev:1;)` This rule will create an alert for each TCP packet not sent to port 21.|
|Filter a port range (Type 1)|`alert tcp any any <> any 1:1024   (msg: "TCP 1-1024 System Port Activity"; sid: 100001; rev:1;)` This rule will create an alert for each TCP packet sent to ports between 1-1024.|
|Filter a port range (Type 2)|`alert tcp any any <> any :1024   (msg: "TCP 0-1024 System Port Activity"; sid: 100001; rev:1;)` This rule will create an alert for each TCP packet sent to ports less than or equal to 1024.|
|Filter a port range (Type 3)|`alert tcp any any <> any 1025: (msg: "TCP Non-System Port Activity"; sid: 100001; rev:1;)` This rule will create an alert for each TCP packet sent to source port higher than or equal to 1025.|
|Filter a port range (Type 4)|`alert tcp any any <> any [21,23] (msg: "FTP and Telnet Port 21-23 Activity Detected"; sid: 100001; rev:1;)` This rule will create an alert for each TCP packet sent to port 21 and 23.|

#### Direction

The direction operator indicates the traffic flow to be filtered by Snort. The left side of the rule shows the source, and the right side shows the destination.

- `->` Source to destination flow.
- `<>` Bidirectional flow

Note that there is no "<-" operator in Snort.

![Snort_Rule_Layout 2](Images/Snort_Rule_Layout_2.png)

#### There are three main rule options in Snort

- **General Rule Options** - Fundamental rule options for Snort.
- **Payload Rule Options** - Rule options that help to investigate the payload data. These options are helpful to detect specific payload patterns.
- **Non-Payload Rule Options** - Rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.

#### General Rule Options

| Option | Description |
|----|----|
|**Msg**|The message field is a basic prompt and quick identifier of the rule. Once the rule is triggered, the message filed will appear in the console or log. Usually, the message part is a one-liner that summarises the event.|
|**Sid**|Snort rule IDs (SID) come with a pre-defined scope, and each rule must have a SID in a proper format. There are three different scopes for SIDs: **<100**: Reserved rules,  **100-999,999**: Rules came with the build,  **>=1,000,000**: Rules created by user. Briefly, the rules we will create should have sid greater than 100.000.000. Another important point is; SIDs should not overlap, and each id must be unique.|
|**Reference**|Each rule can have additional information or reference to explain the purpose of the rule or threat pattern. That could be a Common Vulnerabilities and Exposures (CVE) id or external information. Having references for the rules will always help analysts during the alert and incident investigation.|
|**Rev**|Snort rules can be modified and updated for performance and efficiency issues. Rev option help analysts to have the revision information of each rule. Therefore, it will be easy to understand rule improvements. Each rule has its unique rev number, and there is no auto-backup feature on the rule history. Analysts should keep the rule history themselves. Rev option is only an indicator of how many times the rule had revisions. alert icmp any any <> any any (msg: "ICMP Packet Found"; sid: 100001; reference:cve,CVE-XXXX; **rev:1;**)|

#### Payload Detection Rule Options

**Content**

Payload data. It matches specific payload data by ASCII, HEX or both. It is possible to use this option multiple times in a single rule. However, the more you create specific pattern match features, the more it takes time to investigate a packet.

Following rules will create an alert for each HTTP packet containing the keyword "GET". This rule option is case sensitive!

- **ASCII mode** - alert tcp any any <> any 80  (msg: "GET Request Found"; **content:"GET";** sid: 100001; rev:1;)
- **HEX mode** - alert tcp any any <> any 80  (msg: "GET Request Found"; **content:"|47 45 54|";** sid: 100001; rev:1;)

**Nocase**

Disabling case sensitivity. Used for enhancing the content searches.

alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; **nocase;** sid: 100001; rev:1;)

**Fast_pattern**

Prioritise content search to speed up the payload search operation. By default, Snort uses the biggest content and evaluates it against the rules. "fast_pattern" option helps you select the initial packet match with the specific value for further investigation. This option **always works case insensitive** and can be used once per rule. Note that **this option is required when using multiple "content" options**.

The following rule has two content options, and the fast_pattern option tells to snort to use the first content option (in this case, "GET") for the initial packet match.

alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; **fast_pattern;** content:"www";  sid:100001; rev:1;)

#### Non-Payload Detection Rule Options

There are rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.

| Option | Description |
|----|----|
|**ID**|Filtering the IP id field. alert tcp any any <> any any (msg: "ID TEST"; **id:123456;** sid: 100001; rev:1;)|
|**Flags**|Filtering the TCP flags. **F** - FIN, **S** - SYN, **R** - RST, **P** - PSH, **A** - ACK, **U** - URG  alert tcp any any <> any any (msg: "FLAG TEST"; **flags:S;**  sid: 100001; rev:1;)|
|**Dsize**|Filtering the packet payload size. Examples: dsize:min<>max, dsize:>100, dsize:<100  alert ip any any <> any any (msg: "SEQ TEST"; **dsize:100<>300;**  sid: 100001; rev:1;)|
|**Sameip**|Filtering the source and destination IP addresses for duplication.  alert ip any any <> any any (msg: "SAME-IP TEST";  **sameip;** sid: 100001; rev:1;)|

Remember, once you create a rule, it is a local rule and should be in your `local.rules` file. This file is located under `/etc/snort/rules/local.rules`. A quick reminder on how to edit your local rules is shown below.

```bash
user@ubuntu$ sudo gedit /etc/snort/rules/local.rules 
```

That is your "local.rules" file.

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-8$ cat /etc/snort/rules/local.rules 
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
```

Note that there are some default rules activated with snort instance. These rules are deactivated to manage your rules and improve your exercise experience. For further information, please refer to the TASK-10 or Snort manual.

By this point, we covered the primary structure of the Snort rules. Understanding and practicing the fundamentals is suggested before creating advanced rules and using additional options.

Wow! We have covered the fundamentals of the Snort rules!  
Now, use the attached VM and navigate to the **Task-Exercises/Exercise-Files/TASK-9** folder to answer the questions!

Note that you can use the following command to create the logs in the current directory: `-l .`

Use "task9.pcap". Write a rule to filter IP ID "35369" and run it against the given pcap file. You may use this command: `snort -c local.rules -A full -l . -r task9.pcap`

#### What is the request name of the detected packet?

Hint: Try to filter different protocols like TCP/UDP/ICMP. id:35369;

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-9$ cat /etc/snort/rules/local.rules 
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any any <> any any (msg: "Magic ID Found in TCP Packet"; id:35369; sid: 100002; rev:1;)
alert udp any any <> any any (msg: "Magic ID Found in UDP Packet"; id:35369; sid: 100003; rev:1;)
alert icmp any any <> any any (msg: "Magic ID Found in ICMP Packet"; id:35369; sid: 100004; rev:1;)

ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-9$ snort -c /etc/snort/rules/local.rules -A full -l . -r task9.pcap
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/rules/local.rules"
Tagged Packet Limit: 256
Log directory = .

+++++++++++++++++++++++++++++++++++++++++++++++++++
Initializing rule chains...
4 Snort rules read
    4 detection rules
<---snip--->
===============================================================================
Action Stats:
     Alerts:          168 (  4.308%)
     Logged:          168 (  4.308%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:         3900 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-9$ cat alert | grep -i magic -A5
[**] [1:100004:1] Magic ID Found in ICMP Packet [**]
[Priority: 0] 
03/03-20:00:32.042975 192.168.121.2 -> 192.168.120.1
ICMP TTL:255 TOS:0x0 ID:35369 IpLen:20 DgmLen:40
Type:13  Code:0  ID: 7  Seq: 6  TIMESTAMP REQUEST
```

Answer: TIMESTAMP REQUEST

Clear the previous alert file and comment out the old rules. Create a rule to filter packets with Syn flag and run it against the given pcap file.

#### What is the number of detected packets?

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-9$ cat /etc/snort/rules/local.rules 
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any any (msg: "SYN Flag Found"; flags:S;  sid: 100005; rev:1;)

ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-9$ sudo snort -q -c /etc/snort/rules/local.rules -A console -r task9.pcap
03/03-20:02:09.464106  [**] [1:100005:1] SYN Flag Found [**] [Priority: 0] {TCP} 2003:51:6012:110::b15:22:60892 -> 2003:51:6012:121::2:22
```

Answer: 1

Clear the previous alert file and comment out the old rules. Write a rule to filter packets with Push-Ack flags and run it against the given pcap file.

#### What is the number of detected packets?

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-9$ cat /etc/snort/rules/local.rules 
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any any (msg: "Push-Ack Flags Found"; flags:PA;  sid: 100006; rev:1;)

ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-9$ sudo snort -c /etc/snort/rules/local.rules -A console -r task9.pcap
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/rules/local.rules"
Tagged Packet Limit: 256
Log directory = /var/log/snort
<---snip--->
===============================================================================
Action Stats:
     Alerts:          216 (  5.538%)
     Logged:          216 (  5.538%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:         3900 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting
```

Answer: 216

Clear the previous alert file and comment out the old rules. Create a rule to filter UDP packets with the same source and destination IP and run it against the given pcap file.

#### What is the number of packets that show the same source and destination address?

```bash
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-9$ cat /etc/snort/rules/local.rules 
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert udp any any <> any any (msg: "UDP Same-IP Found"; sameip; sid: 100007; rev:1;)

ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-9$ sudo snort -q -c /etc/snort/rules/local.rules -A console -r task9.pcap
03/03-19:59:12.666896  [**] [1:100007:1] UDP Same-IP Found [**] [Priority: 0] {UDP} 0.0.0.0:68 -> 255.255.255.255:67
03/03-19:59:12.699148  [**] [1:100007:1] UDP Same-IP Found [**] [Priority: 0] {UDP} 0.0.0.0:68 -> 255.255.255.255:67
03/03-19:59:12.715650  [**] [1:100007:1] UDP Same-IP Found [**] [Priority: 0] {UDP} 0.0.0.0:68 -> 255.255.255.255:67
12/18-21:57:47.200000  [**] [1:100007:1] UDP Same-IP Found [**] [Priority: 0] {UDP} 192.168.0.21:0 -> 192.168.0.21:0
12/18-21:57:47.300000  [**] [1:100007:1] UDP Same-IP Found [**] [Priority: 0] {UDP} 192.168.0.44:4444 -> 192.168.0.44:4444
12/18-21:57:47.400000  [**] [1:100007:1] UDP Same-IP Found [**] [Priority: 0] {UDP} 192.168.0.21:0 -> 192.168.0.21:0
12/18-21:57:47.500000  [**] [1:100007:1] UDP Same-IP Found [**] [Priority: 0] {UDP} 192.168.0.21:0 -> 192.168.0.21:0
ubuntu@ip-10-10-175-69:~/Desktop/Task-Exercises/Exercise-Files/TASK-9$ sudo snort -q -c /etc/snort/rules/local.rules -A console -r task9.pcap | wc -l
7
```

Answer: 7

#### Case Example - An analyst modified an existing rule successfully. Which rule option must the analyst change after the implementation?

Answer: rev

### Task 10 - Snort2 Operation Logic: Points to Remember

#### Points to Remember

Main Components of Snort

- **Packet Decoder** - Packet collector component of Snort. It collects and prepares the packets for pre-processing.
- **Pre-processors** - A component that arranges and modifies the packets for the detection engine.
- **Detection Engine** - The primary component that process, dissect and analyse the packets by applying the rules.
- **Logging and Alerting** - Log and alert generation component.
- **Outputs and Plugins** - Output integration modules (i.e. alerts to syslog/mysql) and additional plugin (rule management detection plugins) support is done with this component.

There are three types of rules available for snort

- **Community Rules** - Free ruleset under the GPLv2. Publicly accessible, no need for registration.
- **Registered Rules** - Free ruleset (requires registration). This ruleset contains subscriber rules with 30 days delay.
- **Subscriber Rules (Paid)** - Paid ruleset (requires subscription). This ruleset is the main ruleset and is updated twice a week (Tuesdays and Thursdays).

You can download and read more on the rules [here](https://www.snort.org/downloads).

**Note**: Once you install Snort2, it automatically creates the required directories and files. However, if you want to use the community or the paid rules, you need to indicate each rule in the **snort.conf** file.

Since it is a long, all-in-one configuration file, editing it without causing misconfiguration is troublesome for some users. That is why Snort has several rule updating modules and integration tools. To sum up, **never replace your configured Snort configuration files**; you must edit your configuration files manually or update your rules with additional tools and modules to not face any fail/crash or lack of feature.

- **snort.conf**: Main configuration file.
- **local.rules**: User-generated rules file.

Let's start with overviewing the main configuration file (snort.conf) `sudo gedit /etc/snort/snort.conf`

#### Navigate to the "Step #1: Set the network variables." section

This section manages the scope of the detection and rule paths.

| TAG NAME | INFO | EXAMPLE |
|----|----|----|
|**HOME_NET**|That is where we are protecting.|'any' OR '192.168.1.1/24'|
|**EXTERNAL_NET**|This field is the external network, so we need to keep it as 'any' or '!$HOME_NET'.|'any' OR '!$HOME_NET'|
|**RULE_PATH**|Hardcoded rule path.|/etc/snort/rules|
|**SO_RULE_PATH**|These rules come with registered and subscriber rules.|$RULE_PATH/so_rules|
|**PREPROC_RULE_PATH**|These rules come with registered and subscriber rules.|$RULE_PATH/plugin_rules|

#### Navigate to the "Step #2: Configure the decoder." section

In this section, you manage the IPS mode of snort. The single-node installation model IPS model works best with "afpacket" mode. You can enable this mode and run Snort in IPS.

| TAG NAME | INFO | EXAMPLE |
|----|----|----|
|**#config daq:**|IPS mode selection.|afpacket|
|**#config daq_mode:**|Activating the inline mode|inline|
|**#config logdir:**|Hardcoded default log path.|/var/logs/snort|

Data Acquisition Modules (DAQ) are specific libraries used for packet I/O, bringing flexibility to process packets. It is possible to select DAQ type and mode for different purposes.

There are six DAQ modules available in Snort;

- **Pcap**: Default mode, known as Sniffer mode.
- **Afpacket**: Inline mode, known as IPS mode.
- **Ipq**: Inline mode on Linux by using Netfilter. It replaces the snort_inline patch.  
- **Nfq**: Inline mode on Linux.
- **Ipfw**: Inline on OpenBSD and FreeBSD by using divert sockets, with the pf and ipfw firewalls.
- **Dump**: Testing mode of inline and normalisation.

The most popular modes are the default (**pcap**) and inline/IPS (**Afpacket**).

#### Navigate to the "Step #6: Configure output plugins" section

This section manages the outputs of the IDS/IPS actions, such as logging and alerting format details. The default action prompts everything in the console application, so configuring this part will help you use the Snort more efficiently.

#### Navigate to the "Step #7: Customise your ruleset" section

| TAG NAME | INFO | EXAMPLE |
|----|----|----|
|`# site specific rules`|Hardcoded local and user-generated rules path.|include $RULE_PATH/local.rules|
|`#include $RULE_PATH/`|Hardcoded default/downloaded rules path.|include $RULE_PATH/rulename|

Note that "#" is commenting operator. **You should uncomment a line to activate it.**

### Task 11 - Conclusion

In this room, we covered Snort, what it is, how it operates, and how to create and use the rules to investigate threats.

- Understanding and practising the fundamentals is crucial before creating advanced rules and using additional options.
- Do not create complex rules at once; try to add options step by step to notice possible syntax errors or any other problem easily.
- Do not reinvent the wheel; use it or modify/enhance it if there is a smooth rule.
- Take a backup of the configuration files before making any change.
- Never delete a rule that works properly. Comment it if you don't need it.
- Test newly created rules before migrating them to production.

Now, we invite you to complete the snort challenge room: [Snort Challenge - Live Attacks](https://tryhackme.com/room/snortchallenges1)

A great way to quickly recall snort rules and commands is to download and refer to the TryHackMe snort cheatsheet.

For additional information, please see the references below.

## References

- [Berkeley Packet Filter - Wikipedia](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)
- [Snort - Documents](https://www.snort.org/documents)
- [Snort - Homepage](https://www.snort.org/)
- [tcpdump - Linux manual page](https://man7.org/linux/man-pages/man1/tcpdump.1.html)
