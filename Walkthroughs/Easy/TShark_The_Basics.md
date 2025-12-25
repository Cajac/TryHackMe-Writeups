# TShark: The Basics

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: Linux
Subscription type: Premium
Description: 
Learn the basics of TShark and take your protocol and PCAP analysis skills a step further.
```

Room link: [https://tryhackme.com/room/tsharkthebasics](https://tryhackme.com/room/tsharkthebasics)

## Solution

### Task 1: Introduction

TShark is an open-source command-line network traffic analyser. It is created by the Wireshark developers and has most of the features of Wireshark. It is commonly used as a command-line version of Wireshark. However, it can also be used like tcpdump. Therefore it is preferred for comprehensive packet assessments.

#### Learning Objectives

- Filtering the traffic with TShark
- Implementing Wireshark filters in TShark
- Expanding and automating packet filtering with TShark

We have prepared a VM with TShark and the necessary files. You can start the machine by pressing the green **Start Machine** button attached to this task. The machine will start in split view. In case it is not opening the split view, you can press the blue **Show Split View** button at the top of the page.

We suggest completing the [Network Fundamentals](https://tryhackme.com/module/network-fundamentals) and [Wireshark](https://tryhackme.com/module/wireshark) modules before starting this room.

---------------------------------------------------------------------------------------

### Task 2: Command-Line Packet Analysis Hints | TShark and Supplemental CLI Tools

#### Command-Line Packet Analysis Hints

TShark is a text-based tool, and it is suitable for data carving, in-depth packet analysis, and automation with scripts. This strength and flexibility come out of the nature of the CLI tools, as the produced/processed data can be pipelined to additional tools. The most common tools used in packet analysis are listed below.

|Tool/Utility|Purpose and Benefit|
|----|----|
|**capinfos**|A program that provides details of a specified capture file. It is suggested to view the summary of the capture file before starting an investigation.|
|**grep**|Helps search plain-text data.|
|**cut**|Helps cut parts of lines from a specified data source.|
|**uniq**|Filters repeated lines/values.|
|**nl**|Views the number of shown lines.|
|**sed**|A stream editor.|
|**awk**|Scripting language that helps pattern search and processing.|

**Note**: Sample usage of these tools is covered in the [Zeek room](https://tryhackme.com/room/zeekbro).

Open the terminal and follow the given instructions. You can follow along with the interactive materials by switching to the following directory.

- `cd Desktop/exercise-files/`

```bash
user@ubuntu$ capinfos demo.pcapng 
File name:           demo.pcapng
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 65535 bytes
Number of packets:   4...
File size:           25 kB
Data size:           25 kB
Capture duration:    30.393704 seconds
First packet time:   2004-05-13 10:17:07.311224
Last packet time:    2004-05-13 10:17:37.704928
Data byte rate:      825 bytes/s
Data bit rate:       6604 bits/s
Average packet size: 583.51 bytes
Average packet rate: 1 packets/s
SHA256:              25a72bdf10339...
RIPEMD160:           6ef5f0c165a1d...
SHA1:                3aac91181c3b7...
Strict time order:   True
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 65535
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 4...
..
```

---------------------------------------------------------------------------------------

Find the task files on the Desktop in the "exercise-files" folder.

View the details of the demo.pcapng file with "capinfos".

#### What is the "RIPEMD160" value?

```bash
ubuntu@ip-10-66-140-173:~$ cd Desktop/exercise-files/
ubuntu@ip-10-66-140-173:~/Desktop/exercise-files$ ls
demo.pcapng
ubuntu@ip-10-66-140-173:~/Desktop/exercise-files$ capinfos demo.pcapng 
File name:           demo.pcapng
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 65535 bytes
Number of packets:   43
File size:           25 kB
Data size:           25 kB
Capture duration:    30.393704 seconds
First packet time:   2004-05-13 10:17:07.311224
Last packet time:    2004-05-13 10:17:37.704928
Data byte rate:      825 bytes/s
Data bit rate:       6604 bits/s
Average packet size: 583.51 bytes
Average packet rate: 1 packets/s
SHA256:              25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d
RIPEMD160:           6ef5f0c165a1db4a3cad3116b0c5bcc0cf6b9ab7
SHA1:                3aac91181c3b7eb34fb7d2b6dd6783f4827fcf07
Strict time order:   True
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 65535
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 43
```

Answer: `6ef5f0c165a1db4a3cad3116b0c5bcc0cf6b9ab7`

### Task 3: TShark Fundamentals I | Main Parameters I

#### Command-Line Interface and Parameters

TShark is a text-based (command-line) tool. Therefore, conducting an in-depth and consecutive analysis of the obtained results is easy. Multiple built-in options are ready to use to help analysts conduct such investigations. However, learning the parameters is essential; you will need the built-in options and associated parameters to keep control of the output and not be flooded with the detailed output of TShark. The most common parameters are explained in the given table below. Note that TShark requires superuser privileges to sniff live traffic and list all available interfaces.

|Parameter|Purpose|
|----|----|
|-h|Display the help page with the most common features.<br>`tshark -h`|
|-v|Show version info.<br>`tshark -v`|
|-D|List available sniffing interfaces.<br>`tshark -D`|
|-i|Choose an interface to capture live traffic.<br>`tshark -i 1`<br>`tshark -i ens55`|
|No Parameter|Sniff the traffic like tcpdump.<br>`tshark`|

Let's view the version info of the TShark instance in the given VM. Open the terminal and follow the given instructions.

```bash
user@ubuntu$ tshark -v                           
TShark (Wireshark) 3 (Git v3. packaged as 3.)

Copyright 1998-2020 Gerald Combs and contributors. License GPLv2+: GNU GPL version 2 or later.
This is free software; see the source for copying conditions.
..
```

#### Sniffing

Sniffing is one of the essential functionalities of TShark. A computer node can have multiple network interfaces that allow the host to communicate and sniff the traffic through the network. Specific interfaces might be associated with particular tasks/jobs. Therefore, the ability to choose a sniffing interface helps users decide and set the proper interface for sniffing.
Let's view the available interfaces in the given VM.

```bash
user@ubuntu$ sudo tshark -D
1. ens5
2. lo (Loopback)
3. any
4. bluetooth-monitor
5. nflog
..
```

Sniffing can be done with and without selecting a specific interface. When a particular interface is selected, TShark uses that interface to sniff the traffic. TShark will use the first available interface when no interface is selected, usually listed as 1 in the terminal. Having no interface argument is an alias for `-i 1`. You can also set different sniffing interfaces by using the parameter `-i`. TShark always echoes the used interface name at the beginning of the sniffing.

```bash
# Sniffing with the default interface.
user@ubuntu$ tshark                           
Capturing on 'ens5'
    1   0.000000 aaa.aaa.aaa.aaa ? bbb.bbb.bbb.bbb TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1 
    2   0.911310 aaa.aaa.aaa.aaa ? bbb.bbb.bbb.bbb TCP 80 ? 3372 [SYN, ACK] Seq=0 Ack=1 Win=5840 Len=0 MSS=1380 SACK_PERM=1 
    3   0.911310 aaa.aaa.aaa.aaa ? bbb.bbb.bbb.bbb TCP 3372 ? 80 [ACK] Seq=1 Ack=1 Win=9660 Len=0 
...
100 packets captured

# Choosing an interface
user@ubuntu$ tshark -i 2
Capturing on 'Loopback: lo'
...
```

---------------------------------------------------------------------------------------

#### What is the installed TShark version in the given VM?

```bash
ubuntu@ip-10-66-140-173:~/Desktop/exercise-files$ tshark -v
TShark (Wireshark) 3.2.3 (Git v3.2.3 packaged as 3.2.3-1)

Copyright 1998-2020 Gerald Combs <gerald@wireshark.org> and contributors.
License GPLv2+: GNU GPL version 2 or later <https://www.gnu.org/licenses/gpl-2.0.html>
This is free software; see the source for copying conditions. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Compiled (64-bit) with libpcap, with POSIX capabilities (Linux), with libnl 3,
with GLib 2.64.2, with zlib 1.2.11, with SMI 0.4.8, with c-ares 1.15.0, with Lua
5.2.4, with GnuTLS 3.6.13 and PKCS #11 support, with Gcrypt 1.8.5, with MIT
Kerberos, with MaxMind DB resolver, with nghttp2 1.40.0, with brotli, with LZ4,
with Zstandard, with Snappy, with libxml2 2.9.10.

Running on Linux 5.15.0-1084-aws, with AMD EPYC 7571 (with SSE4.2), with 1931 MB
of physical memory, with locale C, with libpcap version 1.9.1 (with TPACKET_V3),
with GnuTLS 3.6.13, with Gcrypt 1.8.5, with brotli 1.0.7, with zlib 1.2.11,
binary plugins supported (0 loaded).

Built using gcc 9.3.0.
```

Answer: `3.2.3`

List the available interfaces with TShark.

#### What is the number of available interfaces in the given VM?

Hint: Remember, TShark requires superuser privileges to sniff live traffic and list all available interfaces.

```bash
ubuntu@ip-10-67-162-252:~/Desktop/exercise-files$ sudo tshark -D
Running as user "root" and group "root". This could be dangerous.
1. ens5
2. lo (Loopback)
3. any
4. bluetooth-monitor
5. nflog
6. nfqueue
7. ciscodump (Cisco remote capture)
8. dpauxmon (DisplayPort AUX channel monitor capture)
9. randpkt (Random packet generator)
10. sdjournal (systemd Journal Export)
11. sshdump (SSH remote capture)
12. udpdump (UDP Listener remote capture)
```

Answer: `12`

### Task 4: TShark Fundamentals I | Main Parameters II

#### Command-Line Interface and Parameters II

Let's continue discovering main parameters of TShark.

|Parameter|Purpose|
|----|----|
|-r|Read/input function. Read a capture file.<br>`tshark -r demo.pcapng`|
|-c|Packet count. Stop after capturing a specified number of packets.<br>E.g. stop after capturing/filtering/reading 10 packets.<br>`tshark -c 10`|
|-w|Write/output function. Write the sniffed traffic to a file.<br>`tshark -w sample-capture.pcap`|
|-V|Verbose.<br>Provide detailed information **for each packet**. This option will provide details similar to Wireshark's "Packet Details Pane".<br>`tshark -V`|
|-q|Silent mode.<br>Suspress the packet outputs on the terminal.<br>`tshark -q`|
|-x|Display packet bytes.<br>Show packet details in hex and ASCII dump for each packet.<br>`tshark -x`|

#### Read Capture Files

TShark can also process PCAP files. You can use the `-r` parameter to process the file and investigate the packets. You can limit the number of shown packets using the `-c` parameter.

```bash
user@ubuntu$ tshark -r demo.pcapng
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1 
    2   0.911310 65.208.228.223 ? 145.254.160.237 TCP 80 ? 3372 [SYN, ACK] Seq=0 Ack=1 Win=5840 Len=0 MSS=1380 SACK_PERM=1 
    3   0.911310 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [ACK] Seq=1 Ack=1 Win=9660 Len=0 

..

# Read by count, show only the first 2 packets.
user@ubuntu$ tshark -r demo.pcapng -c 2
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1 
    2   0.911310 65.208.228.223 ? 145.254.160.237 TCP 80 ? 3372 [SYN, ACK] Seq=0 Ack=1 Win=5840 Len=0 MSS=1380 SACK_PERM=1 
```

#### Write Data

TShark can also write the sniffed or filtered packets to a file. You can save the sniffed traffic to a file using the `-w` parameter. This option helps analysts to separate specific packets from the file/traffic and save them for further analysis. It also allows analysts to share only suspicious packets/scope with higher-level investigators.

```bash
# Read the first packet of the demo.pcapng, create write-demo.pcap and save the first packet there.
user@ubuntu$ tshark -r demo.pcapng -c 1 -w write-demo.pcap

# List the contents of the current folder.
user@ubuntu$ ls
demo.pcapng  write-demo.pcap

# Read the write-demo.pcap and show the packet bytes/details.
user@ubuntu$ tshark -r write-demo.pcap 
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1 
```

#### Show Packet Bytes

TShark can show packet details in hex and ASCII format. You can view the dump of the packets by using the `-x` parameter. Once you use this parameter, all packets will be shown in hex and ASCII format. Therefore, it might be hard to spot anomalies at a glance, so using this option after reducing the number of packets will be much more efficient.

```bash
# Read the packets from write-demo.pcap
user@ubuntu$ tshark -r write-demo.pcap 
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1 

# Read the packets from write-demo.pcap and show the packet bytes/details.
user@ubuntu$ tshark -r write-demo.pcap -x
0000  fe ff 20 00 01 00 00 00 01 00 00 00 08 00 45 00   .. ...........E.
0010  00 30 0f 41 40 00 80 06 91 eb 91 fe a0 ed 41 d0   .0.A@.........A.
0020  e4 df 0d 2c 00 50 38 af fe 13 00 00 00 00 70 02   ...,.P8.......p.
0030  22 38 c3 0c 00 00 02 04 05 b4 01 01 04 02         "8............
```

#### Verbosity

Default TShark packet processing and sniffing operations provide a single line of information and exclude verbosity. The default approach makes it easy to follow the number of processed/sniffed packets; however, TShark can also provide verbosity for each packet when instructed. Verbosity is provided similarly to Wireshark's "Packet Details Pane". As verbosity offers a long list of packet details, it is suggested to use that option for specific packets instead of a series of packets.  

```bash
# Default view
user@ubuntu$ tshark -r demo.pcapng -c 1
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1 

# Verbosity
user@ubuntu$ tshark -r demo.pcapng -c 1 -V
Frame 1: 62 bytes on wire (496 bits), 62 bytes captured (496 bits)
...
Ethernet II, Src: 00:00:01:00:00:00, Dst: fe:ff:20:00:01:00
...
Internet Protocol Version 4, Src: 145.254.160.237, Dst: 65.208.228.223
    0100 .... = Version: 4
    .... 0101 = Header Length: 20 bytes (5)
    Total Length: 48
    Identification: 0x0f41 (3905)
    Flags: 0x4000, Don't fragment
    Fragment offset: 0
    Time to live: 128
    Protocol: TCP (6)
    Source: 145.254.160.237
    Destination: 65.208.228.223
Transmission Control Protocol, Src Port: 3372, Dst Port: 80, Seq: 0, Len: 0
 ...
```

Verbosity provides full packet details and makes it difficult to investigate (long and complex terminal output for each packet). However, it is still helpful for in-depth packet analysis and scripting, making TShark stand out. Remember, the best utilisation time of verbosity is after filtering the packets. You can compare the above output with the below screenshot and see the scripting, carving, and correlation opportunities you have!

![TShark CLI vs Wireshark GUI](Images/TShark_CLI_vs_Wireshark_GUI.png)

---------------------------------------------------------------------------------------

Read the "demo.pcapng" file with TShark.

#### What are the assigned TCP flags in the 29th packet?

```bash
ubuntu@ip-10-67-162-252:~/Desktop/exercise-files$ tshark -r demo.pcapng -c 29 | tail -n3
   27   3.955688 216.239.59.99 → 145.254.160.237 HTTP 214 HTTP/1.1 200 OK  (text/html)
   28   3.955688 145.254.160.237 → 216.239.59.99 TCP 54 3371 → 80 [ACK] Seq=722 Ack=1591 Win=8760 Len=0
   29   4.105904 65.208.228.223 → 145.254.160.237 TCP 1434 80 → 3372 [PSH, ACK] Seq=12421 Ack=480 Win=6432 Len=1380 [TCP segment of a reassembled PDU]
```

Answer: `PSH, ACK`

#### What is the "Ack" value of the 25th packet?

```bash
ubuntu@ip-10-67-162-252:~/Desktop/exercise-files$ tshark -r demo.pcapng -c 25 | tail -n3
   23   3.635227 65.208.228.223 → 145.254.160.237 TCP 1434 80 → 3372 [ACK] Seq=11041 Ack=480 Win=6432 Len=1380 [TCP segment of a reassembled PDU]
   24   3.645241 216.239.59.99 → 145.254.160.237 TCP 54 80 → 3371 [ACK] Seq=1 Ack=722 Win=31460 Len=0
   25   3.815486 145.254.160.237 → 65.208.228.223 TCP 54 3372 → 80 [ACK] Seq=480 Ack=12421 Win=9660 Len=0
```

Answer: `12421`

#### What is the "Window size value" of the 9th packet?

```bash
ubuntu@ip-10-67-162-252:~/Desktop/exercise-files$ tshark -r demo.pcapng -c 9 | tail -n3
    7   1.812606 145.254.160.237 → 65.208.228.223 TCP 54 3372 → 80 [ACK] Seq=480 Ack=1381 Win=9660 Len=0
    8   1.812606 65.208.228.223 → 145.254.160.237 TCP 1434 80 → 3372 [ACK] Seq=1381 Ack=480 Win=6432 Len=1380 [TCP segment of a reassembled PDU]
    9   2.012894 145.254.160.237 → 65.208.228.223 TCP 54 3372 → 80 [ACK] Seq=480 Ack=2761 Win=9660 Len=0
```

Answer: `9660`

### Task 5: TShark Fundamentals II | Capture Conditions

#### Capture Condition Parameters

As a network sniffer and packet analyser, TShark can be configured to count packets and stop at a specific point or run in a loop structure. The most common parameters are explained below.

**-a Parameter**

Define capture conditions for a single run/loop. **STOP** after completing the condition. Also known as "Autostop".

**Duration**: Sniff the traffic and stop after X seconds. Create a new file and write output to it.

- `tshark -w test.pcap -a duration:1`

**Filesize**: Define the maximum capture file size. Stop after reaching X file size (KB).

- `tshark -w test.pcap -a filesize:10`

**Files**: Define the maximum number of output files. Stop after X files.

- `tshark -w test.pcap -a filesize:10 -a files:3`

**-b Parameter**

**Ring buffer control options**. Define capture conditions for multiple runs/loops. (**INFINITE LOOP**).

**Duration**: Sniff the traffic for X seconds, create a new file and write output to it.

- `tshark -w test.pcap -b duration:1`

**Filesize**: Define the maximum capture file size. Create a new file and write output to it after reaching filesize X (KB).

- `tshark -w test.pcap -b filesize:10`

- **Files**: Define the maximum number of output files. Rewrite the first/oldest file after creating X files.

- `tshark -w test.pcap -b filesize:10 -b files:3`

Capture condition parameters only work in the "capturing/sniffing" mode. You will receive an error message if you try to read a pcap file and apply the capture condition parameters. The idea is to save the capture files in specific sizes for different purposes during live capturing. If you need to extract sorts of packets from a specific capture file, you will need to use the read&write options discussed in the previous task.

**Hint**: TShark supports combining autostop (`-a`) parameters with ring buffer control parameters (`-b`). You can combine the parameters according to your needs. Use the infinite loop options carefully; remember, you must use at least one autostop parameter to stop the infinite loop.

```bash
# Start sniffing the traffic and stop after 2 seconds, and save the dump into 5 files, each 5kb.

user@ubuntu$ tshark -w autostop-demo.pcap -a duration:2 -a filesize:5 -a files:5
Capturing on 'ens5'
13 

# List the contents of the current folder.
user@ubuntu$ ls
-rw------- 1 ubuntu ubuntu   autostop-demo_..1_2022.pcap
-rw------- 1 ubuntu ubuntu   autostop-demo_..2_2022.pcap
-rw------- 1 ubuntu ubuntu   autostop-demo_..3_2022.pcap
-rw------- 1 ubuntu ubuntu   autostop-demo_..4_2022.pcap
-rw------- 1 ubuntu ubuntu   autostop-demo_..5_2022.pcap
```

---------------------------------------------------------------------------------------

#### Which parameter can help analysts to create a continuous capture dump?

Hint: Ring buffer controls can help analysts to create queries that can run in an infinite loop.

Answer: `-b`

#### Can we combine autostop and ring buffer parameters with TShark? y/n

Answer: `y`

### Task 6: TShark Fundamentals III | Packet Filtering Options: Capture vs. Display Filters

#### Packet Filtering Parameters | Capture & Display Filters

There are two dimensions of packet filtering in TShark; live (capture) and post-capture (display) filtering. These two dimensions can be filtered with two different approaches; using a predefined syntax or Berkeley Packet Filters (BPF). TShark supports both, so you can use Wireshark filters and BPF to filter traffic. As mentioned earlier, TShark is a command-line version of Wireshark, so we will need to use different filters for capturing and filtering packets. A quick recap from the [Wireshark: Packet Operations](https://tryhackme.com/r/room/wiresharkpacketoperations) room:

**Capture Filters**

Live filtering options. The purpose is to **save** only a specific part of the traffic. It is set before capturing traffic and is not changeable during live capture.

**Display Filters**

Post-capture filtering options. The purpose is to investigate packets by **reducing the number of visible packets**, which is changeable during the investigation.

Capture filters are used to have a specific type of traffic in the capture file rather than having everything. Capture filters have limited filtering features, and the purpose is to implement a scope by range, protocol, and direction filtering. This might sound like bulk/raw filtering, but it still provides organised capture files with reasonable file size. The display filters investigate the capture files in-depth without modifying the packet.

|Parameter|Purpose|
|----|----|
|-f|Capture filters. Same as BPF syntax and Wireshark's **capture** filters.|
|-Y|Display filters. Same as Wireshark's **display** filters.|

Check out the [Wireshark: Packet Operations](https://tryhackme.com/room/wiresharkpacketoperations) room (Task 4 & 5) if you want to review the principles of packet filtering.

---------------------------------------------------------------------------------------

#### Which parameter is used to set "Capture Filters"?

Answer: `-f`

#### Which parameter is used to set "Display Filters"?

Answer: `-Y`

### Task 7: TShark Fundamentals IV | Packet Filtering Options: Capture Filters

#### Capture Filters

Wireshark's capture filter syntax is used here. The basic syntax for the Capture/BPF filter is shown below. You can read more on capture filter syntax [here](https://www.wireshark.org/docs/man-pages/pcap-filter.html) and [here](https://gitlab.com/wireshark/wireshark/-/wikis/CaptureFilters#useful-filters). Boolean operators can also be used in both types of filters.

**Traffic Type**

Target match type. You can filter IP addresses, hostnames, IP ranges, and port numbers. Note that if you don't set a qualifier, the "host" qualifier will be used by default.

Options: host | net | port | portrange

Filtering a host

- `tshark -f "host 10.10.10.10"`

Filtering a network range

- `tshark -f "net 10.10.10.0/24"`

Filtering a Port

- `tshark -f "port 80"`

Filtering a port range

- `tshark -f "portrange 80-100"`

**Traffic Direction**

Target direction/flow. Note that if you don't use the direction operator, it will be equal to "either" and cover both directions.

Options: src | dst

Filtering source address

- `tshark -f "src host 10.10.10.10"`

Filtering destination address

- `tshark -f "dst host 10.10.10.10"`

**Traffic Protocol**

Target protocol.

Options: arp | ether | icmp | ip | ip6 | tcp | udp

Filtering TCP

- `tshark -f "tcp"`

Filtering MAC address

- `tshark -f "ether host F8:DB:C5:A2:5D:81"`

You can also filter protocols with IP [Protocol numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml) assigned by IANA.

Filtering IP Protocols 1 (ICMP)

- `tshark -f "ip proto 1"`

We need to create traffic noise to test and simulate capture filters. We will use the "terminator" terminal instance to have a split-screen view in a single terminal. The "terminator" will help you craft and sniff packets using a single terminal interface. Now, run the `terminator` command and follow the instructions using the new terminal instance.

- First, run the given TShark command in Terminal-1 to start sniffing traffic.
- Then, run the given cURL command in Terminal-2 to create network noise.
- View sniffed packets results in Terminal-1.

Terminal 1:

```bash
user@ubuntu$ tshark -f "host 10.10.10.10"
Capturing on 'ens5'
    1 0.000000000 YOUR-IP → 10.10.10.10  TCP 74 36150 → 80 [SYN] Seq=0 Win=62727 Len=0 MSS=8961 SACK_PERM=1 TSval=2045205701 TSecr=0 WS=128
    2 0.003452830  10.10.10.10 → YOUR-IP TCP 74 80 → 36150 [SYN, ACK] Seq=0 Ack=1 Win=62643 Len=0 MSS=8961 SACK_PERM=1 TSval=744450747 TSecr=2045205701 WS=64
    3 0.003487830 YOUR-IP → 10.10.10.10  TCP 66 36150 → 80 [ACK] Seq=1 Ack=1 Win=62848 Len=0 TSval=2045205704 TSecr=744450747
    4 0.003610800 YOUR-IP → 10.10.10.10  HTTP 141 GET / HTTP/1.1
```

Terminal 2:

```bash
user@ubuntu$ curl -v 10.10.10.10
*   Trying 10.10.10.10:80...
* TCP_NODELAY set
* Connected to 10.10.10.10 (10.10.10.10) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.10.10
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Accept-Ranges: bytes
< Content-Length: 1220
< Content-Type: text/html; charset=utf-8
```

**Note**: The 10.10.10.10 host doesn't seem to be available anymore!

Being comfortable with the command line and TShark filters requires time and practice. You can use the below table to practice TShark capture filters.

**Host Filtering**

Capturing traffic to or from a specific host.

Traffic generation with cURL. This command sends a default HTTP query to a specified address.

- `curl tryhackme.com`

TShark capture filter for a host

- `tshark -f "host tryhackme.com"`

**IP Filtering**

Capturing traffic to or from a specific port. We will use the Netcat tool to create noise on specific ports.

Traffic generation with Netcat. Here Netcat is instructed to provide details (verbosity), and timeout is set to 5 seconds.

- `nc 10.10.10.10 4444 -vw 5`

TShark capture filter for specific IP address

- `tshark -f "host 10.10.10.10"`

**Port Filtering**

Capturing traffic to or from a specific port. We will use the Netcat tool to create noise on specific ports.

Traffic generation with Netcat. Here Netcat is instructed to provide details (verbosity), and timeout is set to 5 seconds.

- `nc 10.10.10.10 4444 -vw 5`

TShark capture filter for port 4444

- `tshark -f "port 4444"`

**Protocol Filtering**

Capturing traffic to or from a specific protocol. We will use the Netcat tool to create noise on specific ports.

Traffic generation with Netcat. Here Netcat is instructed to use UDP, provide details (verbosity), and timeout is set to 5 seconds.

- `nc -u 10.10.10.10 4444 -vw 5`

TShark capture filter for

- `tshark -f "udp"`

---------------------------------------------------------------------------------------

#### What is the number of packets with SYN bytes?

Answer: `2`

#### What is the number of packets sent to the IP address "10.10.10.10"?

Answer: `7`

#### What is the number of packets with ACK bytes?

Answer: `8`

### Task 8: TShark Fundamentals V | Packet Filtering Options: Display Filters

#### Display Filters

Wireshark's display filter syntax is used here. You can use the official [Display Filter Reference](https://www.wireshark.org/docs/dfref/) to find the protocol breakdown for filtering. Additionally, you can use Wireshark's build-in "Display Filter Expression" menu to break down protocols for filters. Note that Boolean operators can also be used in both types of filters. Common filtering options are shown in the given table below.

**Note**: Using single quotes for capture filters is recommended to avoid space and bash expansion problems. Once again, you can check the [Wireshark: Packet Operations](https://tryhackme.com/room/wiresharkpacketoperations) room (Task 4 & 5) if you want to review the principles of packet filtering.

**Protocol: IP**

Filtering an IP without specifying a direction.

- `tshark -Y 'ip.addr == 10.10.10.10'`

Filtering a network range

- `tshark -Y 'ip.addr == 10.10.10.0/24'`

Filtering a source IP

- `tshark -Y 'ip.src == 10.10.10.10'`

Filtering a destination IP

- `tshark -Y 'ip.dst == 10.10.10.10'`

**Protocol: TCP**

Filtering HTTP packets

- `tshark -Y 'http'`

Filtering HTTP packets with response code "200"

- `tshark -Y "http.response.code == 200"`

**Protocol: DNS**

Filtering DNS packets

- `tshark -Y 'dns'`

Filtering all DNS "A" packets

- `tshark -Y 'dns.qry.type == 1'`

We will use the "demo.pcapng" to test display filters. Let's see the filters in action!

```bash
user@ubuntu$ tshark -r demo.pcapng -Y 'ip.addr == 145.253.2.203'
13 2.55 145.254.160.237 ? 145.253.2.203 DNS Standard query 0x0023 A ..
17 2.91 145.253.2.203 ? 145.254.160.237 DNS Standard query response 0x0023 A ..
```

The above terminal demonstrates using the "IP filtering" option. TShark filters the packets and provides the output in our terminal. It is worth noting that TShark doesn't count the "total number of filtered packets"; it assigns numbers to packets according to the capture time, but only displays the packets that match our filter.

Look at the above example. There are two matched packets, but the associated numbers don't start from zero or one; "13" and "17" are assigned to these filtered packets. Keeping track of these numbers and calculating the "total number of filtered packets" can be confusing if your filter retrieves more than a handful of packets. Another example is shown below.

```bash
user@ubuntu$ tshark -r demo.pcapng -Y 'http'
  4   0.911 145.254.160.237 ? 65.208.228.223 HTTP GET /download.html HTTP/1.1  
 18   2.984 145.254.160.237 ? 216.239.59.99 HTTP GET /pagead/ads?client... 
 27   3.955 216.239.59.99 ? 145.254.160.237 HTTP HTTP/1.1 200 OK  (text/html) 
 38   4.846 65.208.228.223 ? 145.254.160.237 HTTP/XML HTTP/1.1 200 OK 
```

You can use the `nl` command to get a numbered list of your output. Therefore you can easily calculate the "total number of filtered packets" without being confused with "assigned packet numbers". The usage of the `nl` command is shown below.

```bash
user@ubuntu$ tshark -r demo.pcapng -Y 'http' | nl
1    4  0.911 145.254.160.237 ? 65.208.228.223 HTTP GET /download.html HTTP/1.1  
2   18  2.984 145.254.160.237 ? 216.239.59.99 HTTP GET /pagead/ads?client... 
3   27   3.955 216.239.59.99 ? 145.254.160.237 HTTP HTTP/1.1 200 OK (text/html) 
4   38   4.846 65.208.228.223 ? 145.254.160.237 HTTP/XML HTTP/1.1 200 OK 
```

---------------------------------------------------------------------------------------

Use the "**demo.pcapng**" file to answer the questions.

#### What is the number of packets with a "65.208.228.223" IP address?

```bash
ubuntu@ip-10-66-177-221:~/Desktop/exercise-files$ tshark -r demo.pcapng -Y 'ip.addr == 65.208.228.223' | wc -l
34
```

Answer: `34`

#### What is the number of packets with a "TCP port 3371"?

```bash
ubuntu@ip-10-66-177-221:~/Desktop/exercise-files$ tshark -r demo.pcapng -Y 'tcp.port == 3371' | wc -l
7
```

Answer: `7`

#### What is the number of packets with a "145.254.160.237" IP address as a source address?

```bash
ubuntu@ip-10-66-177-221:~/Desktop/exercise-files$ tshark -r demo.pcapng -Y 'ip.src == 145.254.160.237' | wc -l
20
```

Answer: `20`

**Rerun** the previous query and look at the output.

#### What is the packet number of the "Duplicate" packet?

Hint: Duplicate packets are shown as "TCP/UDP Dup.."

```bash
ubuntu@ip-10-66-177-221:~/Desktop/exercise-files$ tshark -r demo.pcapng -Y 'ip.src == 145.254.160.237'               
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 62 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1
    3   0.911310 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=1 Ack=1 Win=9660 Len=0
    4   0.911310 145.254.160.237 ? 65.208.228.223 HTTP 533 GET /download.html HTTP/1.1 
    7   1.812606 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=1381 Win=9660 Len=0
    9   2.012894 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=2761 Win=9660 Len=0
   12   2.553672 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=5521 Win=9660 Len=0
   13   2.553672 145.254.160.237 ? 145.253.2.203 DNS 89 Standard query 0x0023 A pagead2.googlesyndication.com
   15   2.814046 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=6901 Win=9660 Len=0
   18   2.984291 145.254.160.237 ? 216.239.59.99 HTTP 775 GET /pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020&format=468x60_as&output=html&url=http%3A%2F%2Fwww.ethereal.com%2Fdownload.html&color_bg=FFFFFF&color_text=333333&color_link=000000&color_url=666633&color_border=666633 HTTP/1.1 
   19   3.014334 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=8281 Win=9660 Len=0
   22   3.495025 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=11041 Win=9660 Len=0
   25   3.815486 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=12421 Win=9660 Len=0
   28   3.955688 145.254.160.237 ? 216.239.59.99 TCP 54 3371 ? 80 [ACK] Seq=722 Ack=1591 Win=8760 Len=0
   30   4.216062 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=13801 Win=9660 Len=0
   33   4.356264 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=16561 Win=9660 Len=0
   35   4.496465 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=17941 Win=9660 Len=0
   37   4.776868 145.254.160.237 ? 216.239.59.99 TCP 54 [TCP Dup ACK 28#1] 3371 ? 80 [ACK] Seq=722 Ack=1591 Win=8760 Len=0
   39   5.017214 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=18365 Win=9236 Len=0
   41  17.905747 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [ACK] Seq=480 Ack=18366 Win=9236 Len=0
   42  30.063228 145.254.160.237 ? 65.208.228.223 TCP 54 3372 ? 80 [FIN, ACK] Seq=480 Ack=18366 Win=9236 Len=0
```

Packet number **37** shows a `TCP Dup ACK` info.

Answer: `37`

### Task 9: Conclusion

**Congratulations**! You just finished the TShark: The Basics room. In this room, we covered TShark, what it is, how it operates, and how to use it to investigate traffic captures.

Now, we invite you to complete the [TShark: CLI Wireshark Features](https://tryhackme.com/r/room/tsharkcliwiresharkfeatures) room to boost your CLI packet hunting skills by implementing Wireshark features with TShark.

For additional information, please see the references below.

## References

- [awk - Linux manual page](https://man7.org/linux/man-pages/man1/awk.1p.html)
- [cut - Linux manual page](https://man7.org/linux/man-pages/man1/cut.1.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [nl - Linux manual page](https://man7.org/linux/man-pages/man1/nl.1.html)
- [pcap - Wikipedia](https://en.wikipedia.org/wiki/Pcap)
- [sed - Linux manual page](https://man7.org/linux/man-pages/man1/sed.1.html)
- [tail - Linux manual page](https://man7.org/linux/man-pages/man1/tail.1.html)
- [uniq - Linux manual page](https://man7.org/linux/man-pages/man1/uniq.1.html)
- [Wireshark - capinfos](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [Wireshark - Documentation](https://gitlab.com/wireshark/wireshark/-/wikis/home)
- [Wireshark - Homepage](https://www.wireshark.org/)
- [Wireshark - tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Wireshark - Wikipedia](https://en.wikipedia.org/wiki/Wireshark)
