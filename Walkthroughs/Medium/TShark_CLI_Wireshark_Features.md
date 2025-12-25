# TShark: CLI Wireshark Features

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
Tags: Linux
Subscription type: Premium
Description: 
Take your TShark skills to the next level by implementing Wireshark functionalities in the CLI.
```

Room link: [https://tryhackme.com/room/wiresharktrafficanalysis](https://tryhackme.com/room/wiresharktrafficanalysis)

## Solution

### Task 1: Introduction

In our first room, [TShark: The Basics](https://tryhackme.com/room/tsharkthebasics), we covered the fundamentals of TShark by focusing on how it operates and how to use it to investigate traffic captures. In this room, we will cover advanced features of TShark by focusing on translating Wireshark GUI features to the TShark CLI and investigate events of interest.

To start the VM, press the green **Start Machine** button attached to this task. The machine will start in split view. In case it is not showing up, you can press the blue **Show Split View** button at the top of the page.

The task files for this room are located in the following directory:

- `~/Desktop/exercise-files`

### Task 2: Command-Line Wireshark Features I | Statistics I

#### Command-Line Wireshark Features I | Statistics

At the beginning of this module, we mentioned that TShark is considered a command line version of Wireshark. In addition to sharing the same display filters, TShark can accomplish several features of Wireshark explained below.

Three important points when using Wireshark-like features:

- These options are applied to all packets in scope unless a display filter is provided.
- Most of the commands shown below are CLI versions of the Wireshark features discussed in [Wireshark: Packet Operations](https://tryhackme.com/room/wiresharkpacketoperations) (Task 2).
- TShark explains the parameters used at the beginning of the output line.
  - For example, you will use the `phs` option to view the protocol hierarchy. Once you use this command, the result will start with the "**P**rotocol **H**ierarchy **S**tatistics" header.

**--color Parameter**

- Wireshark-like colourised output.
- `tshark --color`

**-z Parameter**

- Statistics
- There are multiple options available under this parameter. You can view the available filters under this parameter with:
  - `tshark -z help`
- Sample usage.
  - `tshark -z <filter>`
- Each time you filter the statistics, packets are shown first, then the statistics provided. You can suppress packets and focus on the statistics by using the `-q` parameter.

#### Colourised Output

TShark can provide colourised outputs to help analysts speed up the analysis and spot anomalies quickly. If you are more of a Wireshark person and feel the need for a Wireshark-style packet highlighting this option does that. The colour option is activated with the `--color` parameter, as shown below.

![TShark Colourised Output](Images/TShark_Colourised_Output.png)

#### Statistics | Protocol Hierarchy

Protocol hierarchy helps analysts to see the protocols used, frame numbers, and size of packets in a tree view based on packet numbers. As it provides a summary of the capture, it can help analysts decide the focus point for an event of interest. Use the `-z io,phs -q` parameters to view the protocol hierarchy.

```bash
user@ubuntu$ tshark -r demo.pcapng -z io,phs -q
===================================================================
Protocol Hierarchy Statistics
Filter: 

  eth                                    frames:43 bytes:25091
    ip                                   frames:43 bytes:25091
      tcp                                frames:41 bytes:24814
        http                             frames:4 bytes:2000
          data-text-lines                frames:1 bytes:214
            tcp.segments                 frames:1 bytes:214
          xml                            frames:1 bytes:478
            tcp.segments                 frames:1 bytes:478
      udp                                frames:2 bytes:277
        dns                              frames:2 bytes:277
===================================================================
```

After viewing the entire packet tree, you can focus on a specific protocol as shown below. Add the `udp` keyword to the filter to focus on the UDP protocol.

```bash
user@ubuntu$ tshark -r demo.pcapng -z io,phs,udp -q
===================================================================
Protocol Hierarchy Statistics
Filter: udp

  eth                                    frames:2 bytes:277
    ip                                   frames:2 bytes:277
      udp                                frames:2 bytes:277
        dns                              frames:2 bytes:277
===================================================================
```

#### Statistics | Packet Lengths Tree

The packet lengths tree view helps analysts to overview the general distribution of packets by size in a tree view. It allows analysts to detect anomalously big and small packets at a glance! Use the `-z plen,tree -q` parameters to view the packet lengths tree.

```bash
user@ubuntu$ tshark -r demo.pcapng -z plen,tree -q

=========================================================================================================================
Packet Lengths:
Topic / Item       Count     Average       Min val       Max val     Rate (ms)     Percent     Burst rate    Burst start  
-------------------------------------------------------------------------------------------------------------------------
Packet Lengths     43        583.51        54            1484        0.0014        100         0.0400        2.554        
 0-19              0         -             -             -           0.0000        0.00        -             -            
 20-39             0         -             -             -           0.0000        0.00        -             -            
 40-79             22        54.73         54            62          0.0007        51.16       0.0200        0.911        
 80-159            1         89.00         89            89          0.0000        2.33        0.0100        2.554        
 160-319           2         201.00        188           214         0.0001        4.65        0.0100        2.914        
 320-639           2         505.50        478           533         0.0001        4.65        0.0100        0.911        
 640-1279          1         775.00        775           775         0.0000        2.33        0.0100        2.984        
 1280-2559         15        1440.67       1434          1484        0.0005        34.88       0.0200        2.554        
 2560-5119         0         -             -             -           0.0000        0.00        -             -            
 5120 and greater  0         -             -             -           0.0000        0.00        -             -            
-------------------------------------------------------------------------------------------------------------------------
```

#### Statistics | Endpoints

The endpoint statistics view helps analysts to overview the unique endpoints. It also shows the number of packets associated with each endpoint. If you are familiar with Wireshark, you should know that endpoints can be viewed in multiple formats. Similar to Wireshark, TShark supports multiple source filtering options for endpoint identification. Use the `-z endpoints,ip -q` parameters to view IP endpoints. Note that you can choose other available protocols as well.

Filters for the most common viewing options are explained below.

|Filter|Purpose|
|----|----|
|eth|Ethernet addresses|
|ip|IPv4 addresses|
|ipv6|IPv6 addresses|
|tcp|TCP addresses<br>Valid for both IPv4 and IPv6|
|udp|UDP addresses<br>Valid for both IPv4 and IPv6|
|wlan|IEEE 802.11 addresses|

```bash
user@ubuntu$ tshark -r demo.pcapng -z endpoints,ip -q
================================================================================
IPv4 Endpoints
Filter:
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
145.254.160.237               43         25091         20            2323          23           22768   
65.208.228.223                34         20695         18           19344          16            1351   
216.239.59.99                  7          4119          4            3236           3             883   
145.253.2.203                  2           277          1             188           1              89   
================================================================================
```

#### Statistics | Conversations

The conversations view helps analysts to overview the traffic flow between two particular connection points. Similar to endpoint filtering, conversations can be viewed in multiple formats. This filter uses the same parameters as the "Endpoints" option. Use the `-z conv,ip -q` parameters to view IP conversations.

```bash
user@ubuntu$ tshark -r demo.pcapng -z conv,ip -q  
================================================================================
IPv4 Conversations
Filter:
                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration
                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |             65.208.228.223   <-> 145.254.160.237           16      1351      18     19344      34     20695     0.000000000        30.3937
145.254.160.237  <-> 216.239.59.99              4      3236       3       883       7      4119     2.984291000         1.7926
145.253.2.203    <-> 145.254.160.237            1        89       1       188       2       277     2.553672000         0.3605
================================================================================
```

#### Statistics | Expert Info

The expert info view helps analysts to view the automatic comments provided by Wireshark. If you are unfamiliar with the "Wireshark Expert Info", visit task 4 in the [Wireshark: The Basics](https://tryhackme.com/room/wiresharkthebasics) room of the [Wireshark module](https://tryhackme.com/module/wireshark). Use the `-z expert -q` parameters to view the expert information.

```bash
user@ubuntu$ tshark -r demo.pcapng -z expert -q

Notes (3)
=============
   Frequency      Group           Protocol  Summary
           1   Sequence                TCP  This frame is a (suspected) spurious retransmission
           1   Sequence                TCP  This frame is a (suspected) retransmission
           1   Sequence                TCP  Duplicate ACK (#1)

Chats (8)
=============
   Frequency      Group           Protocol  Summary
           1   Sequence                TCP  Connection establish request (SYN): server port 80
           1   Sequence                TCP  Connection establish acknowledge (SYN+ACK): server port 80
           1   Sequence               HTTP  GET /download.html HTTP/1.1\r\n
           1   Sequence               HTTP  GET /pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020
           2   Sequence               HTTP  HTTP/1.1 200 OK\r\n
           2   Sequence                TCP  Connection finish (FIN)
```

----------------------------------------------------------------------

Use the "**write-demo.pcap**" to answer the questions.

#### What is the byte value of the TCP protocol?

Hint: Read the capture file and view the "Protocol Hierarchy" with "-z io,phs -q" parameters.

```bash
ubuntu@ip-10-67-132-77:~/Desktop/exercise-files$ tshark -r write-demo.pcap -z io,phs -q

===================================================================
Protocol Hierarchy Statistics
Filter: 

eth                                      frames:1 bytes:62
  ip                                     frames:1 bytes:62
    tcp                                  frames:1 bytes:62
===================================================================
```

Answer: `62`

#### In which packet lengths row is our packet listed?

Hint: The "Packet Lengths Tree" can help.

```bash
ubuntu@ip-10-67-132-77:~/Desktop/exercise-files$ tshark -r write-demo.pcap -z plen,tree -q

==================================================================================================================================
Packet Lengths:
Topic / Item       Count         Average       Min val       Max val       Rate (ms)     Percent       Burst rate    Burst start  
----------------------------------------------------------------------------------------------------------------------------------
Packet Lengths     1             62.00         62            62                          100%          0.0100        0.000        
 0-19              0             -             -             -                           0.00%         -             -            
 20-39             0             -             -             -                           0.00%         -             -            
 40-79             1             62.00         62            62                          100.00%       0.0100        0.000        
 80-159            0             -             -             -                           0.00%         -             -            
 160-319           0             -             -             -                           0.00%         -             -            
 320-639           0             -             -             -                           0.00%         -             -            
 640-1279          0             -             -             -                           0.00%         -             -            
 1280-2559         0             -             -             -                           0.00%         -             -            
 2560-5119         0             -             -             -                           0.00%         -             -            
 5120 and greater  0             -             -             -                           0.00%         -             -            

----------------------------------------------------------------------------------------------------------------------------------
```

Answer: `40-79`

#### What is the summary of the expert info?

```bash
ubuntu@ip-10-67-132-77:~/Desktop/exercise-files$ tshark -r write-demo.pcap -z expert -q

Chats (1)
=============
   Frequency      Group           Protocol  Summary
           1   Sequence                TCP  Connection establish request (SYN): server port 80
```

Answer: `Connection establish request (SYN): server port 80`

Use the "**demo.pcapng**" to answer the question.

#### List the communications. What is the IP address that exists in all IPv4 conversations? Enter your answer in defanged format

Hint: Cyberchef can defang. The "Conversations" can help.

```bash
ubuntu@ip-10-67-132-77:~/Desktop/exercise-files$ tshark -r demo.pcapng -z conv,ip -q  
================================================================================
IPv4 Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
65.208.228.223       <-> 145.254.160.237           16      1351      18     19344      34     20695     0.000000000        30.3937
145.254.160.237      <-> 216.239.59.99              4      3236       3       883       7      4119     2.984291000         1.7926
145.253.2.203        <-> 145.254.160.237            1        89       1       188       2       277     2.553672000         0.3605
================================================================================
```

Answer: `145[.]254[.]160[.]237`

### Task 3: Command-Line Wireshark Features II | Statistics II

#### Command-Line Wireshark Features II | Specific Filters for Particular Protocols

There are plenty of filters designed for multiple protocols. The common filtering options for specific protocols are explained below. Note that most of the commands shown below are CLI versions of the Wireshark features discussed in [Wireshark: Packet Operations](https://tryhackme.com/room/wiresharkpacketoperations) (Task 3)

#### Statistics | IPv4 and IPv6

This option provides statistics on IPv4 and IPv6 packets, as shown below. Having the protocol statistics helps analysts to overview packet distribution according to the protocol type. You can filter the available protocol types and view the details using the `-z ptype,tree -q` parameters.

```bash
user@ubuntu$ tshark -r demo.pcapng -z ptype,tree -q
==========================================================================================================================
IPv4 Statistics/IP Protocol Types:
Topic / Item       Count         Average       Min val       Max val Rate (ms)     Percent       Burst rate    Burst start  
--------------------------------------------------------------------------------------------------------------------------
IP Protocol Types  43                                                0.0014        100          0.0400        2.554        
 TCP               41                                                0.0013        95.35        0.0300        0.911        
 UDP               2                                                 0.0001        4.65         0.0100        2.554        
--------------------------------------------------------------------------------------------------------------------------
```

Having the summary of the hosts in a single view is useful as well. Especially when you are working with large captures, viewing all hosts with a single command can help you to detect an anomalous host at a glance. You can filter all IP addresses using the parameters given below.

**IPv4**: `-z ip_hosts,tree -q`  
**IPv6**: `-z ipv6_hosts,tree -q`

```bash
user@ubuntu$ tshark -r demo.pcapng -z ip_hosts,tree -q
===========================================================================================================================
IPv4 Statistics/All Addresses:
Topic / Item      Count         Average       Min val       Max val  Rate (ms)     Percent       Burst rate    Burst start  
---------------------------------------------------------------------------------------------------------------------------
All Addresses     43                                                 0.0014        100          0.0400        2.554        
 145.254.160.237  43                                                 0.0014        100.00       0.0400        2.554        
 65.208.228.223   34                                                 0.0011        79.07        0.0300        0.911            
---------------------------------------------------------------------------------------------------------------------------
```

For complex cases and in-depth analysis, you will need to correlate the finding by focusing on the source and destination addresses. You can filter all source and destination addresses using the parameters given below.

**IPv4**: `-z ip_srcdst,tree -q`  
**IPv6**: `-z ipv6_srcdst,tree -q`

```bash
user@ubuntu$ tshark -r demo.pcapng -z ip_srcdst,tree -q
==========================================================================================================================
IPv4 Statistics/Source and Destination Addresses:
Topic / Item                     Count         Average       Min val       Max val  Rate (ms)     Percent       Burst rate    Burst start  
--------------------------------------------------------------------------------------------------------------------------
Source IPv4 Addresses            43                                                 0.0014        100          0.0400              
 145.254.160.237                 20                                                 0.0007        46.51        0.0200               
 65.208.228.223                  18                                                 0.0006        41.86        0.0200
...                        
Destination IPv4 Addresses       43                                                 0.0014        100          0.0400             
 145.254.160.237                 23                                                 0.0008        53.49        0.0200             
 65.208.228.223                  16                                                 0.0005        37.21        0.0200
...                          
------------------------------------------------------------------------------------------------------------------------
```

In some cases, you will need to focus on the outgoing traffic to spot the used services and ports. You can filter all outgoing traffic by using the parameters given below.

**IPv4**: `-z dests,tree -q`  
**IPv6**: `-z ipv6_dests,tree -q`

```bash
user@ubuntu$ tshark -r demo.pcapng -z dests,tree -q
=============================================================================================================================
IPv4 Statistics/Destinations and Ports:
Topic / Item            Count         Average       Min val       Max val       Rate (ms)     Percent       Burst rate    Burst start  
-----------------------------------------------------------------------------------------------------------------------------
Destinations and Ports  43                                                      0.0014        100          0.0400        2.554        
 145.254.160.237        23                                                      0.0008        53.49        0.0200        2.554        
  TCP                   22                                                      0.0007        95.65        0.0200        2.554        
   3372                 18                                                      0.0006        81.82        0.0200        2.554        
   3371                 4                                                       0.0001        18.18        0.0200        3.916        
  UDP                   1                                                       0.0000        4.35         0.0100        2.914        
   3009                 1                                                       0.0000        100.00       0.0100        2.914        
 65.208.228.223         16                                                      0.0005        37.21        0.0200        0.911        
 ...
-----------------------------------------------------------------------------------------------------------------------------
```

#### Statistics | DNS

This option provides statistics on DNS packets by summarising the available info. You can filter the packets and view the details using the `-z dns,tree -q` parameters.

```bash
user@ubuntu$ tshark -r demo.pcapng -z dns,tree -q
===========================================================================================================================
DNS:
Topic / Item                   Count         Average       Min val       Max val       Rate (ms)     Percent       Burst rate    Burst start  
---------------------------------------------------------------------------------------------------------------------------
Total Packets                  2                                             0.0055        100          0.0100        2.554        
 rcode                         2                                             0.0055        100.00       0.0100        2.554        
  No error                     2                                             0.0055        100.00       0.0100        2.554        
 opcodes                       2                                             0.0055        100.00       0.0100        2.554        
  Standard query               2                                             0.0055        100.00       0.0100        2.554                  
 ...
-------------------------------------------------------------------------------------------------------------------------
```

#### Statistics | HTTP

This option provides statistics on HTTP packets by summarising the load distribution, requests, packets, and status info. You can filter the packets and view the details using the parameters given below.

**Packet and status counter for HTTP**: `-z http,tree -q`  
**Packet and status counter for HTTP2**: `-z http2,tree -q`  
**Load distribution**: `-z http_srv,tree -q`  
**Requests**: `-z http_req,tree -q`  
**Requests and responses**: `-z http_seq,tree -q`

```bash
user@ubuntu$ tshark -r demo.pcapng -z http,tree -q
=============================================================================================================================
HTTP/Packet Counter:
Topic / Item            Count         Average       Min val       Max val       Rate (ms)     Percent     Burst rate  Burst start  
----------------------------------------------------------------------------------------------------------------------------
Total HTTP Packets      4                                                       0.0010        100          0.0100     0.911        
 HTTP Response Packets  2                                                       0.0005        50.00        0.0100     3.956        
  2xx: Success          2                                                       0.0005        100.00       0.0100     3.956        
   200 OK               2                                                       0.0005        100.00       0.0100     3.956        
  ???: broken           0                                                       0.0000        0.00         -          -                     
  3xx: Redirection      0                                                       0.0000        0.00         -          -                    
 ...
-----------------------------------------------------------------------------------------------------------------------
```

----------------------------------------------------------------------

Use the "**demo.pcapng**" to answer the questions.

#### Which IP address has 7 appearances? Enter your answer in defanged format

Hint: The "ip_srcdst" statistics can help.

```bash
ubuntu@ip-10-67-132-77:~/Desktop/exercise-files$ tshark -r demo.pcapng -z ip_srcdst,tree -q

================================================================================================================================================
IPv4 Statistics/Source and Destination Addresses:
Topic / Item                     Count         Average       Min val       Max val       Rate (ms)     Percent       Burst rate    Burst start  
------------------------------------------------------------------------------------------------------------------------------------------------
Source IPv4 Addresses            43                                                      0.0014        100%          0.0400        2.554        
 145.254.160.237                 20                                                      0.0007        46.51%        0.0200        0.911        
 65.208.228.223                  18                                                      0.0006        41.86%        0.0200        2.554        
 216.239.59.99                   4                                                       0.0001        9.30%         0.0200        3.916        
 145.253.2.203                   1                                                       0.0000        2.33%         0.0100        2.914        
Destination IPv4 Addresses       43                                                      0.0014        100%          0.0400        2.554        
 145.254.160.237                 23                                                      0.0008        53.49%        0.0200        2.554        
 65.208.228.223                  16                                                      0.0005        37.21%        0.0200        0.911        
 216.239.59.99                   3                                                       0.0001        6.98%         0.0100        2.984        
 145.253.2.203                   1                                                       0.0000        2.33%         0.0100        2.554        

------------------------------------------------------------------------------------------------------------------------------------------------
```

IP 216.239.59.99 is source 4 times and destination 3 times.

Answer: `216[.]239[.]59[.]99`

#### What is the "destination address percentage" of the previous IP address?

Hint: Cyberchef can defang. The "ip_hosts" statistics can help.

From the output above.

Answer: `6.98%`

#### Which IP address constitutes "2.33% of the destination addresses"? Enter your answer in defanged format

From the output above.

Answer: `145[.]253[.]2[.]203`

#### What is the average "Qname Len" value?

Hint: The "dns" statistics can help.

```bash
ubuntu@ip-10-67-132-77:~/Desktop/exercise-files$ tshark -r demo.pcapng -z dns,tree -q

==============================================================================================================================================
DNS:
Topic / Item                   Count         Average       Min val       Max val       Rate (ms)     Percent       Burst rate    Burst start  
----------------------------------------------------------------------------------------------------------------------------------------------
Total Packets                  2                                                       0.0055        100%          0.0100        2.554        
 rcode                         2                                                       0.0055        100.00%       0.0100        2.554        
  No error                     2                                                       0.0055        100.00%       0.0100        2.554        
 opcodes                       2                                                       0.0055        100.00%       0.0100        2.554        
  Standard query               2                                                       0.0055        100.00%       0.0100        2.554        
 Query/Response                2                                                       0.0055        100.00%       0.0100        2.554        
  Response                     1                                                       0.0028        50.00%        0.0100        2.914        
  Query                        1                                                       0.0028        50.00%        0.0100        2.554        
 Query Type                    2                                                       0.0055        100.00%       0.0100        2.554        
  A (Host Address)             2                                                       0.0055        100.00%       0.0100        2.554        
 Class                         2                                                       0.0055        100.00%       0.0100        2.554        
  IN                           2                                                       0.0055        100.00%       0.0100        2.554        
Payload size                   2             96.50         47            146           0.0055        100%          0.0100        2.554        
Query Stats                    0                                                       0.0000        100%          -             -            
 Qname Len                     1             29.00         29            29            0.0028                      0.0100        2.554        
 Label Stats                   0                                                       0.0000                      -             -            
  3rd Level                    1                                                       0.0028                      0.0100        2.554        
  4th Level or more            0                                                       0.0000                      -             -            
  2nd Level                    0                                                       0.0000                      -             -            
  1st Level                    0                                                       0.0000                      -             -            
Response Stats                 0                                                       0.0000        100%          -             -            
 no. of questions              2             1.00          1             1             0.0055                      0.0200        2.914        
 no. of authorities            2             0.00          0             0             0.0055                      0.0200        2.914        
 no. of answers                2             4.00          4             4             0.0055                      0.0200        2.914        
 no. of additionals            2             0.00          0             0             0.0055                      0.0200        2.914        
Service Stats                  0                                                       0.0000        100%          -             -            
 request-response time (secs)  1             0.36          0.360518      0.360518      0.0028                      0.0100        2.914        
 no. of unsolicited responses  0                                                       0.0000                      -             -            
 no. of retransmissions        0                                                       0.0000                      -             -            

----------------------------------------------------------------------------------------------------------------------------------------------
```

Answer: `29.00`

### Task 4: Command-Line Wireshark Features III | Streams, Objects and Credentials

#### Command-Line Wireshark Features III | Streams, Objects and Credentials

There are plenty of filters designed for multiple purposes. The common filtering options for specific operations are explained below. Note that most of the commands shown below are CLI versions of the Wireshark features discussed in the [Wireshark module](https://tryhackme.com/module/wireshark).

**Follow Stream**

This option helps analysts to follow traffic streams similar to Wireshark. The query structure is explained in the table given below.

|Main Parameter|Protocol|View Mode|Stream Number|Additional Parameter|
|----|----|----|----|----|
|-z follow|TCP<br>UDP<br>HTTP<br>HTTP2|HEX<br>ASCII|0 \| 1 \| 2 \| 3 ...|-q|

**Note**: Streams start from "0". You can filter the packets and follow the streams by using the parameters given below.

- **TCP Streams**: `-z follow,tcp,ascii,0 -q`  
- **UDP Streams**: `-z follow,udp,ascii,0 -q`  
- **HTTP Streams**: `-z follow,http,ascii,0 -q`

```bash
user@ubuntu$ tshark -r demo.pcapng -z follow,tcp,ascii,1 -q
===================================================================
Follow: tcp,ascii
Filter: tcp.stream eq 1
Node 0: 145.254.160.237:3371
Node 1: 216.239.59.99:80
GET /pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020&format=468x60_as&outp...
Host: pagead2.googlesyndication.com
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113
...

HTTP/1.1 200 OK
P3P: policyref="http://www.googleadservices.com/pagead/p3p.xml", CP="NOI DEV PSA PSD IVA PVD OTP OUR OTR IND OTC"
Content-Type: text/html; charset=ISO-8859-1
Content-Encoding: gzip
Server: CAFE/1.0
Cache-control: private, x-gzip-ok=""
Content-length: 1272
Date: Thu, 13 May 2004 10:17:14 GMT

...mmU.x..o....E1...X.l.(.AL.f.....dX..KAh....Q....D...'.!...Bw..{.Y/T...<...GY9J....?;.ww...Ywf..... >6..Ye.X..H_@.X.YM.......#:.....D..~O..STrt..,4....H9W..!E.....&.X.=..P9..a...<...-.O.l.-m....h..p7.(O?.a..:..-knhie...
..g.A.x..;.M..6./...{..9....H.W.a.qz...O.....B..
===================================================================
```

**Export Objects**

This option helps analysts to extract files from DICOM, HTTP, IMF, SMB and TFTP. The query structure is explained in the table given below.

|Main Parameter|Protocol|Target Folder|Additional Parameter|
|----|----|----|----|
|--export-objects|DICOM<br>HTTP<br>IMF<br>SMB<br>TFTP|Target folder to save the files.|-q|

You can filter the packets and follow the streams by using the parameters given below.

- `--export-objects http,/home/ubuntu/Desktop/extracted-by-tshark -q`

```bash
# Extract the files from HTTP traffic.
user@ubuntu$ tshark -r demo.pcapng --export-objects http,/home/ubuntu/Desktop/extracted-by-tshark -q

# view the target folder content.
user@ubuntu$ ls -l /home/ubuntu/Desktop/extracted-by-tshark/
total 24
-rw-r--r-- 1 ubuntu ubuntu  'ads%3fclient=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020&format=468x60_as&o
-rw-r--r-- 1 ubuntu ubuntu download.html
```

**Credentials**

This option helps analysts to detect and collect cleartext credentials from FTP, HTTP, IMAP, POP and SMTP. You can filter the packets and find the cleartext credentials using the parameters below.

- `-z credentials -q`

```bash
user@ubuntu$ tshark -r credentials.pcap -z credentials -q
===================================================================
Packet     Protocol         Username         Info            
------     --------         --------         --------
72         FTP              admin            Username in packet: 37
80         FTP              admin            Username in packet: 47
83         FTP              admin            Username in packet: 54
118        FTP              admin            Username in packet: 93
123        FTP              admin            Username in packet: 97
167        FTP              administrator    Username in packet: 133
207        FTP              administrator    Username in packet: 170
220        FTP              administrator    Username in packet: 184
230        FTP              administrator    Username in packet: 193
....
===================================================================
```

----------------------------------------------------------------------

Use the "**demo.pcapng**" to answer the questions.

#### Follow the "UDP stream 0". What is the "Node 0" value? Enter your answer in defanged format

Hint: Cyberchef can defang.

```bash
ubuntu@ip-10-66-150-207:~/Desktop/exercise-files$ tshark -r demo.pcapng -z follow,udp,ascii,0 -q

===================================================================
Follow: udp,ascii
Filter: udp.stream eq 0
Node 0: 145.254.160.237:3009
Node 1: 145.253.2.203:53
47
.#...........pagead2.googlesyndication.com.....
146
.#...........pagead2.googlesyndication.com..................pagead2.google.&.;.......z...pagead.google.akadns.net..X.......{....;h.X.......{....;c
===================================================================
```

Answer: `145[.]254[.]160[.]237:3009`

#### Follow the "HTTP stream 1". What is the "Referer" value? Enter your answer in defanged format

```bash
ubuntu@ip-10-66-150-207:~/Desktop/exercise-files$ tshark -r demo.pcapng -z follow,http,ascii,1 -q

===================================================================
Follow: http,ascii
Filter: tcp.stream eq 1
Node 0: 145.254.160.237:3371
Node 1: 216.239.59.99:80
721
GET /pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020&format=468x60_as&output=html&url=http%3A%2F%2Fwww.ethereal.com%2Fdownload.html&color_bg=FFFFFF&color_text=333333&color_link=000000&color_url=666633&color_border=666633 HTTP/1.1
Host: pagead2.googlesyndication.com
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Keep-Alive: 300
Connection: keep-alive
Referer: http://www.ethereal.com/download.html


318
HTTP/1.1 200 OK
P3P: policyref="http://www.googleadservices.com/pagead/p3p.xml", CP="NOI DEV PSA PSD IVA PVD OTP OUR OTR IND OTC"
Content-Type: text/html; charset=ISO-8859-1
Content-Encoding: gzip
Server: CAFE/1.0
Cache-control: private, x-gzip-ok=""
<---snip--->
```

Answer: `hxxp[://]www[.]ethereal[.]com/download[.]html`

Use the "**credentials.pcap**" to answer the question.

#### What is the total number of detected credentials?

Hint: The "nl" command can help. Exclude the banner lines!

```bash
ubuntu@ip-10-66-150-207:~/Desktop/exercise-files$ tshark -r credentials.pcap -z credentials -q | grep 'in packet' | wc -l
75
```

Answer: `75`

### Task 5: Advanced Filtering Options | Contains, Matches and Fields

#### Advanced Filtering Options | Contains, Matches and Extract Fields

Accomplishing in-depth packet analysis sometimes ends up with a special filtering requirement that cannot be covered with default filters. TShark supports Wireshark's "**contains**" and "**matches**" operators, which are the key to the advanced filtering options. You can visit the Wireshark: Packet Operations room (Task 6) if you are unfamiliar with these filters.

A quick recap from the [Wireshark: Packet Operations](https://tryhackme.com/room/wiresharkpacketoperations) room:

**Contains Filter**

- Search a value inside packets.
- Case sensitive.
- Similar to Wireshark's "find" option.

**Matches Filter**

- Search a pattern inside packets.
- Supports regex.
- Case insensitive.
- Complex queries have a margin of error.

**Note**: The "contains" and "matches" operators cannot be used with fields consisting of "integer" values.

**Tip**: Using HEX and regex values instead of ASCII always has a better chance of a match.

#### Extract Fields

This option helps analysts to extract specific parts of data from the packets. In this way, analysts have the opportunity to collect and correlate various fields from the packets. It also helps analysts manage the query output on the terminal. The query structure is explained in the table given below.

|Main Filter|Target Field|Show Field Name|
|----|----|----|
|`-T fields`|`-e <field name>`|`-E header=y`|

**Note**: You need to use the `-e <parameter>` for each field you want to display.

You can filter any field by using the field names as shown below.

- `-T fields -e ip.src -e ip.dst -E header=y`

```bash
user@ubuntu$ tshark -r demo.pcapng -T fields -e ip.src -e ip.dst -E header=y -c 5         
ip.src            ip.dst
145.254.160.237   65.208.228.223
65.208.228.223    145.254.160.237
145.254.160.237   65.208.228.223
145.254.160.237   65.208.228.223
65.208.228.223    145.254.160.237
```

#### Filter: "contains"

**Type**: Comparison operator  
**Description**: Search a value inside packets. It is case-sensitive and provides similar functionality to the "Find" option by focusing on a specific field.  
**Example**: Find all "Apache" servers.  
**Workflow**: List all HTTP packets where the "server" field contains the "Apache" keyword.  
**Usage**: `http.server contains "Apache"`

```bash
user@ubuntu$ tshark -r demo.pcapng -Y 'http.server contains "Apache"'                          
   38   4.846969 65.208.228.223 ? 145.254.160.237 HTTP/XML HTTP/1.1 200 OK 

user@ubuntu$ tshark -r demo.pcapng -Y 'http.server contains "Apache"' -T fields -e ip.src -e ip.dst -e http.server -E header=y
ip.src  ip.dst  http.server
65.208.228.223  145.254.160.237  Apache 
```

#### Filter: "matches"

**Type**: Comparison operator  
**Description**: Search a pattern of a regular expression. It is case-insensitive, and complex queries have a margin of error.  
**Example**: Find all .php and .html pages.  
**Workflow**: List all HTTP packets where the "request method" field matches the keywords "GET" or "POST".  
**Usage**: `http.request.method matches "(GET|POST)"`

```bash
user@ubuntu$ tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"'               
    4   0.911310 145.254.160.237 ? 65.208.228.223 HTTP GET /download.html HTTP/1.1 
   18   2.984291 145.254.160.237 ? 216.239.59.99 HTTP GET /pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&

user@ubuntu$ tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"' -T fields -e ip.src -e ip.dst -e http.request.method -E header=y
ip.src  ip.dst  http.request.method
145.254.160.237  65.208.228.223  GET
145.254.160.237  216.239.59.99  GET 
```

----------------------------------------------------------------------

Use the "**demo.pcapng**" to answer questions.

#### What is the HTTP packet number that contains the keyword "CAFE"?

Hint: The "contains" filter can help.

```bash
ubuntu@ip-10-66-150-207:~/Desktop/exercise-files$ tshark -r demo.pcapng -Y 'http contains "CAFE"'
   27   3.955688 216.239.59.99 ? 145.254.160.237 HTTP 214 HTTP/1.1 200 OK  (text/html)
```

Answer: `27`

#### Filter the packets with "GET" and "POST" requests and extract the packet frame time. What is the first time value found?

Hint: The "matches" and "extract fields" filters can help. Also, the "-T fields -e frame.time" can help.

```bash
ubuntu@ip-10-66-150-207:~/Desktop/exercise-files$ tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"' -T fields -e frame.time
May 13, 2004 10:17:08.222534000 UTC
May 13, 2004 10:17:10.295515000 UTC
```

Answer: `May 13, 2004 10:17:08.222534000 UTC`

### Task 6: Use Cases | Extract Information

#### Use Cases

When investigating a case, a security analyst should know how to extract hostnames, DNS queries, and user agents to hunt low-hanging fruits after viewing the statistics and creating an investigation plan. The most common four use cases for every security analyst are demonstrated below. If you want to learn more about the mentioned protocols and benefits of the extracted info, please refer to the [Wireshark Traffic Analysis](https://tryhackme.com/room/wiresharktrafficanalysis) room.

#### Extract Hostnames

```bash
user@ubuntu$ tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname     
92-rkd
92-rkd
T3400

T3400

60-alfb-sec2
60-alfb-sec2

aminott
...
```

The above example shows how to extract hostnames from DHCP packets with TShark. However, the output is hard to manage when multiple duplicate values exist. A skilled analyst should know how to use native Linux tools/utilities to manage and organise the command line output, as shown below.

```bash
user@ubuntu$ tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname | awk NF | sort -r | uniq -c | sort -r
     26 202-ac
     18 92-rkd
     14 93-sts-sec
... 
```

Now the output is organised and ready to process/use. The logic of the query is explained below.

|Query|Purpose|
|----|----|
|`tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname`|Main query.<br>Extract the DHCP hostname value.|
|`awk NF`|Remove empty lines.|
|`sort -r`|Sort recursively before handling the values.|
|`uniq -c`|Show unique values, but calculate and show the number of occurrences.|
|`sort -r`|The final sort process.<br>Show the output/results from high occurrences to less.|

#### Extract DNS Queries

```bash
user@ubuntu$ tshark -r dns-queries.pcap -T fields -e dns.qry.name | awk NF | sort -r | uniq -c | sort -r
     96 connectivity-check.ubuntu.com.rhodes.edu
     94 connectivity-check.ubuntu.com
      8 3.57.20.10.in-addr.arpa
      4 e.9.d.b.c.9.d.7.1.b.0.f.a.2.0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa
      4 0.f.2.5.6.b.e.f.f.f.b.7.2.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa
      2 _ipps._tcp.local,_ipp._tcp.local
      2 84.170.224.35.in-addr.arpa
      2 22.2.10.10.in-addr.arpa
```

#### Extract User Agents

```bash
user@ubuntu$ tshark -r user-agents.pcap -T fields -e http.user_agent | awk NF | sort -r | uniq -c | sort -r
      6 Mozilla/5.0 (Windows; U; Windows NT 6.4; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.237 Safari/534.10
      5 Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0
      5 Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.32 Safari/537.36
      4 sqlmap/1.4#stable (http://sqlmap.org)
      3 Wfuzz/2.7
      3 Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
```

----------------------------------------------------------------------

Use the "**hostnames.pcapng**" to answer the questions.

#### What is the total number of unique hostnames?

```bash
ubuntu@ip-10-66-150-207:~/Desktop/exercise-files$ tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname | grep -v '^$' | sort | uniq | wc -l
30
```

Answer: `30`

#### What is the total appearance count of the "prus-pc" hostname?

```bash
ubuntu@ip-10-66-150-207:~/Desktop/exercise-files$ tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname | grep -v '^$' | sort | uniq -c | sort -nr | grep 'prus-pc'
     12 prus-pc
```

Answer: `12`

Use the "**dns-queries.pcap**" to answer the question.

#### What is the total number of queries of the most common DNS query?

```bash
ubuntu@ip-10-66-150-207:~/Desktop/exercise-files$ tshark -r dns-queries.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -n1
    472 db.rhodes.edu
```

Answer: `472`

Use the "**user-agents.pcap**" to answer questions.

#### What is the total number of the detected "Wfuzz user agents"?

```bash
ubuntu@ip-10-66-150-207:~/Desktop/exercise-files$ tshark -r user-agents.pcap -Y http -T fields -e http.user_agent | sort | uniq -c | sort -rn | grep -i wfuzz
      9 Wfuzz/2.4
      3 Wfuzz/2.7
```

Answer: `12`

#### What is the "HTTP hostname" of the nmap scans? Enter your answer in defanged format

Hints:

- Cyberchef can defang.
- Extract the "User-Agent" field as shown in the task.
- Enhance the query by adding the "HTTP hostname" information with the "http.host" option.

```bash
ubuntu@ip-10-66-150-207:~/Desktop/exercise-files$ tshark -r user-agents.pcap -Y http -T fields -e http.user_agent -e http.host | sort | uniq -c | sort -rn | grep -i nmap
      2 Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)  172.16.172.129:8180
      1 Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)  172.16.172.129
```

Answer: `172[.]16[.]172[.]129`

### Task 7: Conclusion

**Congratulations**! You just finished the TShark: CLI Wireshark Features room. In this room, we covered how to implement Wireshark GUI's features into the TShark CLI, advanced filtering options, and use case examples.

Now, we invite you to complete the TShark challenge rooms:

- [TShark Challenge I: Teamwork](https://tryhackme.com/r/room/tsharkchallengesone)
- [TShark Challenge II: Directory](https://tryhackme.com/r/room/tsharkchallengestwo)

For additional information, please see the references below.

## References

- [awk - Linux manual page](https://man7.org/linux/man-pages/man1/awk.1p.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [head - Linux manual page](https://man7.org/linux/man-pages/man1/head.1.html)
- [pcap - Wikipedia](https://en.wikipedia.org/wiki/Pcap)
- [sort - Linux manual page](https://man7.org/linux/man-pages/man1/sort.1.html)
- [uniq - Linux manual page](https://man7.org/linux/man-pages/man1/uniq.1.html)
- [wc - Linux manual page](https://man7.org/linux/man-pages/man1/wc.1.html)
- [Wireshark - Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark - Homepage](https://www.wireshark.org/)
- [Wireshark - tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Wireshark - Wikipedia](https://en.wikipedia.org/wiki/Wireshark)
- [Wireshark - wireshark-filter Manual Page](https://www.wireshark.org/docs/man-pages/wireshark-filter.html)
