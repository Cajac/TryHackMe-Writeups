# Wireshark: Traffic Analysis

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
OS: N/A
Subscription type: Premium
Description: Learn the basics of traffic analysis with Wireshark and how to find anomalies on your network!
```

Room link: [https://tryhackme.com/room/wiresharktrafficanalysis](https://tryhackme.com/room/wiresharktrafficanalysis)

## Solution

### Task 1: Introduction

In this room, we will cover the techniques and key points of traffic analysis with Wireshark and detect suspicious activities. Note that this is the third and last room of the Wireshark room trio, and it is suggested to visit the first two rooms stated below to practice and refresh your Wireshark skills before starting this one.

- [Wireshark: The Basics](https://tryhackme.com/room/wiresharkthebasics)
- [Wireshark: Packet Operations](https://tryhackme.com/room/wiresharkpacketoperations)

In the first two rooms, we have covered how to use Wireshark and do packet-level searches. Now, it is time to investigate and correlate the packet-level information to see the big picture in the network traffic, like detecting anomalies and malicious activities. For a security analyst, it is vital to stop and understand pieces of information spread in packets by applying the analyst's knowledge and tool functionality. This room will cover investigating packet-level details by synthesising the analyst knowledge and  Wireshark functionality for detecting anomalies and odd situations for a given case.

**Note**: A VM is attached to this room. You don't need SSH or RDP; the room provides a "Split View" feature. **DO NOT** directly interact with any domains and IP addresses in this room. The domains and IP addresses are included only for reference reasons.

### Task 2: Nmap Scans

Nmap is an industry-standard tool for mapping networks, identifying live hosts and discovering the services. As it is one of the most used network scanner tools, a security analyst should identify the network patterns created with it. This section will cover identifying the most common Nmap scan types.

- TCP connect scans
- SYN scans
- UDP scans

It is essential to know how Nmap scans work to spot scan activity on the network. However, it is impossible to understand the scan details without using the correct filters. Below are the base filters to probe Nmap scan behaviour on the network. 

TCP flags in a nutshell.

| Notes | Wireshark Filters |
|----|----|
|Global search.|`tcp` or `udp`|
|Only SYN flag.|`tcp.flags == 2`|
|SYN flag is set. The rest of the bits are not important.|`tcp.flags.syn == 1`|
|Only ACK flag.|`tcp.flags == 16`|
|ACK flag is set. The rest of the bits are not important.|`tcp.flags.ack == 1`|
|Only SYN, ACK flags.|`tcp.flags == 18`|
|SYN and ACK are set. The rest of the bits are not important.|`(tcp.flags.syn == 1) && (tcp.flags.ack == 1)`|
|Only RST flag.|`tcp.flags == 4`|
|RST flag is set. The rest of the bits are not important.|`tcp.flags.reset == 1`|
|Only RST, ACK flags.|`tcp.flags == 20`|
|RST and ACK are set. The rest of the bits are not important.|`(tcp.flags.reset == 1) && (tcp.flags.ack == 1)`|
|Only FIN flag|`tcp.flags == 1`|
|FIN flag is set. The rest of the bits are not important.|`tcp.flags.fin == 1`|

#### TCP Connect Scans

TCP Connect Scan in a nutshell:

- Relies on the three-way handshake (needs to finish the handshake process).
- Usually conducted with `nmap -sT` command.
- Used by non-privileged users (only option for a non-root user).
- Usually has a windows size larger than 1024 bytes as the request expects some data due to the nature of the protocol.

Open TCP Port

- SYN -->
- <-- SYN, ACK
- ACK -->
- RST, ACK -->

Closed TCP Port

- SYN -->
- <-- RST, ACK

The images below show the three-way handshake process of the open and close TCP ports. Images and pcap samples are split to make the investigation easier and understand each case's details.

Open TCP port (Connect):

![Wireshark Nmap TCP Connect Scan Open Port](Images/Wireshark_Nmap_TCP_Connect_Scan_Open_Port.png)

Closed TCP port (Connect):

![Wireshark Nmap TCP Connect Scan Closed Port](Images/Wireshark_Nmap_TCP_Connect_Scan_Closed_Port.png)

The above images provide the patterns in isolated traffic. However, it is not always easy to spot the given patterns in big capture files. Therefore analysts need to use a generic filter to view the initial anomaly patterns, and then it will be easier to focus on a specific traffic point. The given filter shows the TCP Connect scan patterns in a capture file.

`tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024`

#### SYN Scans

TCP SYN Scan in a nutshell:

- Doesn't rely on the three-way handshake (no need to finish the handshake process).
- Usually conducted with `nmap -sS` command.
- Used by privileged users.
- Usually have a size less than or equal to 1024 bytes as the request is not finished and it doesn't expect to receive data.

Open TCP Port

- SYN -->
- <-- SYN,ACK
- RST-->

Close TCP Port

- SYN -->
- <-- RST,ACK

Open TCP port (SYN):

![Wireshark Nmap TCP SYN Scan Open Port](Images/Wireshark_Nmap_TCP_SYN_Scan_Open_Port.png)

Closed TCP port (SYN):

![Wireshark Nmap TCP SYN Scan Closed Port](Images/Wireshark_Nmap_TCP_SYN_Scan_Closed_Port.png)

The given filter shows the TCP SYN scan patterns in a capture file.

`tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024`

#### UDP Scans

UDP Scan in a nutshell:

- Doesn't require a handshake process
- No prompt for open ports
- ICMP error message for close ports
- Usually conducted with `nmap -sU` command.

Open UDP Port

- UDP packet -->

Closed UDP Port

- UDP packet -->
- ICMP Type 3, Code 3 message. (Destination unreachable, port unreachable)

Closed (port no 69) and open (port no 68) UDP ports:

![Wireshark Nmap UDP Scan](Images/Wireshark_Nmap_UDP_Scan.png)

The above image shows that the closed port returns an ICMP error packet. No further information is provided about the error at first glance, so how can an analyst decide where this error message belongs? The ICMP error message uses the original request as encapsulated data to show the source/reason of the packet. Once you expand the ICMP section in the packet details pane, you will see the encapsulated data and the original request.

The given filter shows the UDP scan patterns in a capture file.

`icmp.type==3 && icmp.code==3`

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. 

Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!

----------------------------------------------------------------------

Use the "**Desktop/exercise-pcaps/nmap/Exercise.pcapng**" file.

#### What is the total number of the "TCP Connect" scans?

Set a display filter of `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024` and check the status bar value for `Displayed`.

Answer: 1000

#### Which scan type is used to scan the TCP port 80?

Set a display filter of `tcp.port == 80` and check the involved packets.

Answer: TCP Connect

#### How many "UDP close port" messages are there?

Set a display filter of `icmp.type==3 && icmp.code==3` and check the status bar value for `Displayed`.

Answer: 1083

#### Which UDP port in the 55-70 port range is open?

Hint: Remember, half of the traffic analysis is done by hand when using Wireshark. Filter the traffic as shown in the task, then filter the destination port (UDP) with the "filter a column" option. Finally, scroll the bar in the packet list section and investigate the findings manually.

Set a display filter of `udp.dstport in {55 .. 70}` and add a column for `Destination Port`. Sort on the `Destination Port` column.  
There are connection requests sent to ports 67, 68 and 69 and two ICMP `Destination unreachable` answers for ports 67 and 69.

Answer: 68

### Task 3: ARP Poisoning & Man In The Middle

#### ARP Poisoning/Spoofing (A.K.A. Man In The Middle Attack)

ARP protocol, or Address Resolution Protocol (ARP), is the technology responsible for allowing devices to identify themselves on a network. Address Resolution Protocol Poisoning (also known as ARP Spoofing or Man In The Middle (MITM) attack) is a type of attack that involves network jamming/manipulating by sending malicious ARP packets to the default gateway. The ultimate aim is to manipulate the "**IP to MAC address table**" and sniff the traffic of the target host.

There are a variety of tools available to conduct ARP attacks. However, the mindset of the attack is static, so it is easy to detect such an attack by knowing the ARP protocol workflow and Wireshark skills.

ARP analysis in a nutshell:

- Works on the local network
- Enables the communication between MAC addresses
- Not a secure protocol
- Not a routable protocol
- It doesn't have an authentication function
- Common patterns are request & response, announcement and gratuitous packets.

Before investigating the traffic, let's review some legitimate and suspicious ARP packets. The legitimate requests are similar to the shown picture: a broadcast request that asks if any of the available hosts use an IP address and a reply from the host that uses the particular IP address.

| Notes | Wireshark filter |
|----|----|
|Global search|`arp`|
|Opcode 1: ARP requests.|`arp.opcode == 1`|
|Opcode 2: ARP responses.|`arp.opcode == 2`|
|Hunt: Arp scanning|`arp.dst.hw_mac==00:00:00:00:00:00`|
|Hunt: Possible ARP poisoning detection|`arp.duplicate-address-detected \|\| arp.duplicate-address-frame`|
|Hunt: Possible ARP flooding from detection|`((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address)`|

![Wireshark ARP Request and Reply](Images/Wireshark_ARP_Request_and_Reply.png)

A suspicious situation means having two different ARP responses (conflict) for a particular IP address. In that case, Wireshark's expert info tab warns the analyst. However, it only shows the second occurrence of the duplicate value to highlight the conflict. Therefore, identifying the malicious packet from the legitimate one is the analyst's challenge. A possible IP spoofing case is shown in the picture below.

![Wireshark Duplicate IP Address](Images/Wireshark_Duplicate_IP_Address.png)

Here, knowing the network architecture and inspecting the traffic for a specific time frame can help detect the anomaly. As an analyst, you should take notes of your findings before going further. This will help you be organised and make it easier to correlate the further findings. Look at the given picture; there is a conflict; the MAC address that ends with "b4" crafted an ARP request with the "192.168.1.25" IP address, then claimed to have the "192.168.1.1" IP address.

| Notes | Detection Notes | Findings |
|----|----|----|
|Possible IP address match.|1 IP address announced from a MAC address.|MAC: 00:0c:29:e2:18:b4, IP: 192.168.1.25|
|Possible ARP spoofing attempt.|2 MAC addresses claimed the same IP address (192.168.1.1). The " 192.168.1.1" IP address is a possible gateway address.|MAC 1: 50:78:b3:f3:cd:f4, MAC 2: 00:0c:29:e2:18:b4|
|Possible ARP flooding attempt.|The MAC address that ends with "b4" claims to have a different/new IP address.|MAC: 00:0c:29:e2:18:b4, IP: 192.168.1.1|

Let's keep inspecting the traffic to spot any other anomalies. Note that the case is split into multiple capture files to make the investigation easier.

![Wireshark ARP Spoofing](Images/Wireshark_ARP_Spoofing.png)

At this point, it is evident that there is an anomaly. A security analyst cannot ignore a flood of ARP requests. This could be malicious activity, scan or network problems. There is a new anomaly; the MAC address that ends with "b4" crafted multiple ARP requests with the "192.168.1.25" IP address. Let's focus on the source of this anomaly and extend the taken notes.

| Notes | Detection Notes | Findings |
|----|----|----|
|Possible IP address match.|1 IP address announced from a MAC address.|MAC: 00:0c:29:e2:18:b4, IP: 192.168.1.25|
|Possible ARP spoofing attempt.|2 MAC addresses claimed the same IP address (192.168.1.1). The "192.168.1.1" IP address is a possible gateway address.|MAC 1: 50:78:b3:f3:cd:f4, MAC 2: 00:0c:29:e2:18:b4|
|Possible ARP spoofing attempt.|The MAC address that ends with "b4" claims to have a different/new IP address.|MAC: 00:0c:29:e2:18:b4, IP: 192.168.1.1|
|Possible ARP flooding attempt.|The MAC address that ends with "b4" crafted multiple ARP requests against a range of IP addresses.|MAC: 00:0c:29:e2:18:b4, IP: 192.168.1.xxx|

Up to this point, it is evident that the MAC address that ends with "b4" owns the "192.168.1.25" IP address and crafted suspicious ARP requests against a range of IP addresses. It also claimed to have the possible gateway address as well. Let's focus on other protocols and spot the reflection of this anomaly in the following sections of the time frame.

![Wireshark ARP MITM Attack 1](Images/Wireshark_ARP_MITM_Attack_1.png)

There is HTTP traffic, and everything looks normal at the IP level, so there is no linked information with our previous findings. Let's add the MAC addresses as columns in the packet list pane to reveal the communication behind the IP addresses.

![Wireshark ARP MITM Attack 2](Images/Wireshark_ARP_MITM_Attack_2.png)

One more anomaly! The MAC address that ends with "b4" is the destination of all HTTP packets! It is evident that there is a MITM attack, and the attacker is the host with the MAC address that ends with "b4". All traffic linked to "192.168.1.12" IP addresses is forwarded to the malicious host. Let's summarise the findings before concluding the investigation.

| Notes | Detection Notes | Findings |
|----|----|----|
|IP to MAC matches.|3 IP to MAC address matches.|MAC: 00:0c:29:e2:18:b4 = IP: 192.168.1.25, MAC: 50:78:b3:f3:cd:f4 = IP: 192.1681.1, MAC: 00:0c:29:98:c7:a8 = IP: 192.168.1.12|
|Attacker|The attacker created noise with ARP packets.|MAC: 00:0c:29:e2:18:b4 = IP: 192.168.1.25|
|Router/gateway|Gateway address.|MAC: 50:78:b3:f3:cd:f4 = IP: 192.1681.1|
|Victim|The attacker sniffed all traffic of the victim.|MAC: 50:78:b3:f3:cd:f4 = IP: 192.1681.12|

Detecting these bits and pieces of information in a big capture file is challenging. However, in real-life cases, you will not have "tailored data" ready for investigation. Therefore you need to have the analyst mindset, knowledge and tool skills to filter and detect the anomalies.

Note: In traffic analysis, there are always alternative solutions available. The solution type and the approach depend on the analyst's knowledge and skill level and the available data sources.

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!

----------------------------------------------------------------------

Use the "**Desktop/exercise-pcaps/arp/Exercise.pcapng**" file.

#### What is the number of ARP requests crafted by the attacker?

Hint: Only requests made by the attacker are relevant to this question!

Start by setting a display filter of `arp` and add two columns for `Send MAC address` and `Target MAC address`.  
The attacker seems to be `00:0c:29:98:c7:a8`. Filter for ARP reqests from this machine with `eth.src == 00:0c:29:e2:18:b4 && arp.opcode==1`.  
Then check the status bar value for `Displayed`.

Answer: 284

#### What is the number of HTTP packets received by the attacker?

Set a display filter of `eth.dst == 00:0c:29:e2:18:b4 && http` and check the status bar value for `Displayed`.

Answer: 90

#### What is the number of sniffed username&password entries?

Hint: Filter the site visited by the victim, then filter the post requests. Focusing on URI sections of the packet details after filtering could help.

Filter for POST requests since passwords will likely be sent with that method: `eth.dst == 00:0c:29:e2:18:b4 && http.request.method==POST`.  
There are 10 reuests to 3 URI:s

- `http://testphp.vulnweb.com/userinfo.php`
- `http://testphp.vulnweb.com/secured/newuser.php`
- `http://testphp.vulnweb.com/comment.php`

Going through the HTML form data the following likely credentials are found:

| Username | Password |
|----|----|
|uname=test|pass=test|
|uuname=test_THM_test|upass=insecurepw, upass2=insecurepw|
|uname=test_THM_test|pass=insecurepw|
|uname=admin|pass=supersecret!|
|uname=client468|pass=premiumsoda-_-|
|uname=client986|clientnothere!|
|uname=tourist-audt|pass=captainciso|

Maybe the `uuname` and `upass` was something else because 6 (rather than 7) was the accepted answer.

Answer: 6

#### What is the password of the "Client986"?

From table above

Answer: clientnothere!

#### What is the comment provided by the "Client354"?

Hint: Special characters are displayed in HEX format. Make sure that you convert them to ASCII.

Answer: Nice work!

### Task 4: Identifying Hosts: DHCP, NetBIOS and Kerberos



![Wireshark Go to Packet](Images/Wireshark_Go_to_Packet.png)



#### Search the "r4w" string in packet details. What is the name of artist 1?

Answer: r4w8173

#### Go to packet 12 and read the comments. What is the answer?

Hint: Use the "Right-click --> Packet Comment" menu to view the comments. If the comment is long, you can scroll down to follow the rest of the paragraph. Remember, you can also use the "Statistics --> Capture File Properties" to view the available comments.

Answer: 911cd574a42865a956ccde2d04495ebf

#### There is a ".txt" file inside the capture file. Find the file and read it; what is the alien's name?

Answer: PACKETMASTER

#### Look at the expert info section. What is the number of warnings?

Answer: 1636

### Task 5: Packet Filtering

#### Packet Filtering

Wireshark has a powerful filter engine that helps analysts to narrow down the traffic and focus on the event of interest. Wireshark has two types of filtering approaches: capture and display filters. Capture filters are used for "**capturing**" only the packets valid for the used filter. Display filters are used for "**viewing**" the packets valid for the used filter. We will discuss these filters' differences and advanced usage in the next room. Now let's focus on basic usage of the display filters, which will help analysts in the first place.

Filters are specific queries designed for protocols available in Wireshark's official protocol reference. While the filters are only the option to investigate the event of interest, there are two different ways to filter traffic and remove the noise from the capture file. The first one uses queries, and the second uses the right-click menu. Wireshark provides a powerful GUI, and there is a golden rule for analysts who don't want to write queries for basic tasks: "**If you can click on it, you can filter and copy it**".

#### Apply as Filter

This is the most basic way of filtering traffic. While investigating a capture file, you can click on the field you want to filter and use the "right-click menu" or `Analyse` --> `Apply as Filter` menu to filter the specific value. Once you apply the filter, Wireshark will generate the required filter query, apply it, show the packets according to your choice, and hide the unselected packets from the packet list pane. Note that the number of total and displayed packets are always shown on the status bar.

![Wireshark Apply as Filter](Images/Wireshark_Apply_as_Filter.png)

#### Conversation filter

When you use the "Apply as a Filter" option, you will filter only a single entity of the packet. This option is a good way of investigating a particular value in packets. However, suppose you want to investigate a specific packet number and all linked packets by focusing on IP addresses and port numbers. In that case, the `Conversation Filter` option helps you view only the related packets and hide the rest of the packets easily. You can use the "right-click menu" or `Analyse` --> `Conversation Filter` menu to filter conversations.

![Wireshark Conversation Filter](Images/Wireshark_Conversation_Filter.png)

#### Colourise Conversation

This option is similar to the "Conversation Filter" with one difference. It highlights the linked packets without applying a display filter and decreasing the number of viewed packets. This option works with the "Colouring Rules" option ad changes the packet colours without considering the previously applied colour rule. You can use the "right-click menu" or "View --> Colourise Conversation" menu to colourise a linked packet in a single click. Note that you can use the "View --> Colourise Conversation --> Reset Colourisation" menu to undo this operation.

#### Prepare as Filter

Similar to "Apply as Filter", this option helps analysts create display filters using the "right-click" menu. However, unlike the previous one, this model doesn't apply the filters after the choice. It adds the required query to the pane and waits for the execution command (enter) or another chosen filtering option by using the ".. and/or.." from the "right-click menu".

#### Apply as Column

By default, the packet list pane provides basic information about each packet. You can use the "right-click menu" or "Analyse --> Apply as Column" menu to add columns to the packet list pane. Once you click on a value and apply it as a column, it will be visible on the packet list pane. This function helps analysts examine the appearance of a specific value/field across the available packets in the capture file. You can enable/disable the columns shown in the packet list pane by clicking on the top of the packet list pane.

#### Follow Stream

Wireshark displays everything in packet portion size. However, it is possible to reconstruct the streams and view the raw traffic as it is presented at the application level. Following the protocol, streams help analysts recreate the application-level data and understand the event of interest. It is also possible to view the unencrypted protocol data like usernames, passwords and other transferred data.

You can use the"right-click menu" or "Analyse --> Follow TCP/UDP/HTTP Stream" menu to follow traffic streams. Streams are shown in a separate dialogue box; packets originating from the server are highlighted with blue, and those originating from the client are highlighted with red.

![Wireshark Follow Stream](Images/Wireshark_Follow_Stream.png)

Once you follow a stream, Wireshark automatically creates and applies the required filter to view the specific stream. Remember, once a filter is applied, the number of the viewed packets will change. You will need to use the "**X button**" located on the right upper side of the display filter bar to remove the display filter and view all available packets in the capture file.

#### Go to packet number 4. Right-click on the "Hypertext Transfer Protocol" and apply it as a filter. Now, look at the filter pane. What is the filter query?

Answer: http

#### What is the number of displayed packets?

Answer: 1089

#### Go to packet number 33790 and follow the stream. What is the total number of artists?

Answer: 3

#### What is the name of the second artist?

Answer: Blad3

For additional information, please see the references below.

## References

- [pcap - Wikipedia](https://en.wikipedia.org/wiki/Pcap)
- [Wireshark - Homepage](https://www.wireshark.org/)
- [Wireshark - Wikipedia](https://en.wikipedia.org/wiki/Wireshark)
