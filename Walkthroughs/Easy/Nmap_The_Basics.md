# Nmap: The Basics

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Premium
Description: Learn how to use Nmap to discover live hosts, find open ports, and detect service versions.
```

Room link: [https://tryhackme.com/room/nmap](https://tryhackme.com/room/nmap)

## Solution

### Task 1: Introduction

Imagine the scenario where you are connected to a network and using various network resources, such as email and web browsing. Two questions arise. The first is how we can discover other live devices on this network or on other networks. The second is how we can find out the network services running on these live devices; examples include SSH and web servers.

One approach is to do it manually. If asked to uncover which devices are live on the `192.168.0.1/24` network, one can use basic tools such as `ping`, `arp-scan`, or some other tool to check the 254 IP addresses. Although this network has 256 IP addresses, we counted 254 IP addresses because two are reserved. Each tool has its limitations. For example, `ping` won’t give any information if the target system’s firewall blocks ICMP traffic. Moreover, `arp-scan` only works if your device is connected to the same network, i.e., over Ethernet or WiFi. In brief, this will be a significant waste of time without an advanced and reliable tool. With the right tools and enough time, one would have a list of the live hosts on a target network. We need a flexible tool that can handle the various scenarios.

Discovering the running services on a specific host is equally time-consuming if one relies on manual solutions or inefficient scripts. For instance, one can use `telnet` to try one port after the other; however, with thousands of ports to scan, this can be a very time-consuming task, even if a script was created to automate the `telnet` connection attempts.

A very efficient solution that can solve the above two requirements and many more is the Nmap network scanner. Nmap is an open-source network scanner that was first published in 1997. Since then, plenty of features and options have been added. It is a powerful and flexible network scanner that can be adapted to various scenarios and setups.

#### Learning Objectives

This room aims to provide you with the basics necessary to use the Nmap scanner or simply `nmap`. In particular, you will learn how to:

- Discover live hosts
- Find running services on the live hosts
- Distinguish the different types of port scans
- Detect the versions of the running services
- Control the timing
- Format the output

#### Room Prerequisites

The user should be familiar with the TCP/IP model, the related concepts, and its various protocols. The following rooms provide the necessary knowledge to make the best use of this room:

- Networking Concepts
- Networking Essentials
- Networking Core Protocols
- Networking Secure Protocols

### Task 2: Host Discovery: Who Is Online

Let’s start with the first question: who is online? This task aims to find out how to use Nmap to discover the live hosts. Nmap uses various sophisticated ways to discover live hosts.

Before we start, we should mention that Nmap uses multiple ways to specify its targets:

- IP range using `-`: If you want to scan all the IP addresses from 192.168.0.1 to 192.168.0.10, you can write `192.168.0.1-10`
- IP subnet using `/`: If you want to scan a subnet, you can express it as `192.168.0.1/24`, and this would be equivalent to `192.168.0.0-255`
- Hostname: You can also specify your target by hostname, for example, `example.thm`

Let’s say you want to discover the online hosts on a network. Nmap offers the `-sn` option, i.e., ping scan. However, don’t expect this to be limited like `ping`. Let’s see this in action.

Before we get started, we should note that throughout this room, we are either running `nmap` as `root` or using `sudo` because we don’t want to restrict Nmap’s abilities with our account privileges. Running Nmap as a local (non-root) user would limit us to fundamental types of scans such as ICMP echo and TCP connect scans; we will revisit this at the end of this room.

#### Scanning a “Local” Network

In this context, we use the term “local” to refer to the network we are directly connected to, such as an Ethernet or WiFi network. In the first demonstration, we will scan the WiFi network to which we are connected. Our IP address is `192.168.66.89`, and we are scanning the `192.168.66.0/24` network. The `nmap -sn 192.168.66.0/24` command and its output are shown in the terminal below.

```bash
root@tryhackme:~# nmap -sn 192.168.66.0/24
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-07 13:49 EEST
Nmap scan report for XiaoQiang (192.168.66.1)
Host is up (0.0069s latency).
MAC Address: 44:DF:65:D8:FE:6C (Unknown)
Nmap scan report for S190023240007 (192.168.66.88)
Host is up (0.090s latency).
MAC Address: 7C:DF:A1:D3:8C:5C (Espressif)
Nmap scan report for wlan0 (192.168.66.97)
Host is up (0.20s latency).
MAC Address: 10:D5:61:E2:18:E6 (Tuya Smart)
Nmap scan report for 192.168.66.179
Host is up (0.10s latency).
MAC Address: E4:AA:EC:8F:88:C9 (Tianjin Hualai Technology)
[...]
Nmap done: 256 IP addresses (7 hosts up) scanned in 2.64 seconds
```

Because we are scanning the local network, where we are connected via Ethernet or WiFi, we can look up the MAC addresses of the devices. Consequently, we can figure out the network card vendors, which is beneficial information as it can help us guess the type of target device(s).

When scanning a directly connected network, Nmap starts by sending ARP requests. When a device responds to the ARP request, Nmap labels it with “Host is up”.

### Scanning a “Remote” Network

Consider the case of a “remote” network. In this context, “remote” means that at least one router separates our system from this network. As a result, all our traffic to the target systems must go through one or more routers. Unlike scanning a local network, we cannot send an ARP request to the target.

Our system has the IP address `192.168.66.89` and belongs to the `192.168.66.0/24` network. In the terminal below we scan the target network `192.168.11.0/24` where there are two or more routers (hops) separate our local system from the target hosts.

```bash
root@tryhackme:~# nmap -sn 192.168.11.0/24
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-07 14:05 EEST
Nmap scan report for 192.168.11.1
Host is up (0.018s latency).
Nmap scan report for 192.168.11.151
Host is up (0.0013s latency).
Nmap scan report for 192.168.11.152
Host is up (0.13s latency).
Nmap scan report for 192.168.11.154
Host is up (0.22s latency).
Nmap scan report for 192.168.11.155
Host is up (2.3s latency).
Nmap done: 256 IP addresses (5 hosts up) scanned in 10.67 seconds
```

The Nmap output shows that five hosts are up. But how did Nmap discover this? To learn more, let’s see some sample traffic generated by Nmap. In the screenshot below, we can see the responses from two hosts:

- `192.168.11.1` is live and responded to the ICMP echo (ping) request.
- `192.168.11.2` seems down. Nmap sent two ICMP echo (ping) requests, two ICMP timestamp requests, two TCP packets to port 443 with the SYN flag set, and two TCP packets to port 80 with the ACK flag set. The target didn’t respond to any.

It is worth noting that we can have more control over how Nmap discovers live hosts such as `-PS[portlist]`, `-PA[portlist]`, `-PU[portlist]` for TCP SYN, TCP ACK, and UDP discovery via the given ports. However, this is beyond the scope of this room.

As a final point, Nmap offers a list scan with the option `-sL`. This scan only lists the targets to scan without actually scanning them. For example, `nmap -sL 192.168.0.1/24` will list the 256 targets that will be scanned. This option helps confirm the targets before running the actual scan.

As we mentioned earlier, `-sn` aims to discover live hosts without attempting to discover the services running on them. This scan might be helpful if you want to discover the devices on a network without causing much noise. However, this won’t tell us which services are running. If we want to learn more about the network services running on the live hosts, we need a more “noisy” type of scan, which we will explore in the next task.

#### What is the last IP address that will be scanned when your scan target is 192.168.0.1/27?

Hint: Use Nmap’s list scan, i.e., -sL

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap-The_Basics]
└─$ nmap -sL 192.168.0.1/27 | tail -n 5
Nmap scan report for 192.168.0.28
Nmap scan report for 192.168.0.29
Nmap scan report for 192.168.0.30
Nmap scan report for 192.168.0.31
Nmap done: 32 IP addresses (0 hosts up) scanned in 0.05 seconds
```

Answer: 192.168.0.31

### Task 3: Port Scanning: Who Is Listening

Earlier, we used `-sn` to discover the live hosts. In this task, we want to discover the network services listening on these live hosts. By network service, we mean any process that is listening for incoming connections on a TCP or UDP port. Common network services include web servers, which usually listen on TCP ports 80 and 443, and DNS servers, which typically listen on UDP (and TCP) port 53.

By design, TCP has 65,535 ports, and the same applies to UDP. How can we determine which ports have a service bound to it? Let’s find out.

#### Scanning TCP Ports

The easiest and most basic way to know whether a TCP port is open would be to attempt to `telnet` to the port. If you are inclined to scan with a Telnet client, try to establish a TCP connection with every target port. In other words, you attempt to complete the TCP three-way handshake with every target port; however, only open TCP ports would respond appropriately and allow a TCP connection to be established. This procedure is not very different from Nmap’s connect scan.

#### Connect Scan

The connect scan can be triggered using `-sT`. It tries to complete the TCP three-way handshake with every target TCP port. If the TCP port turns out to be open and Nmap connects successfully, Nmap will tear down the established connection.

In the screenshot below, our scanning machine has the IP address 192.168.124.148 and the target system has TCP port 22 open and port 23 closed. In the part marked with 1, you can see how the TCP three-way handshake was completed and later torn down with a TCP RST-ACK packet by Nmap. The part marked with 2 shows a connection attempt to a closed port, and the target system responded with a TCP RST-ACK packet.

![Nmap Connect Scan in Wireshark](Images/Nmap_Connect_Scan_in_Wireshark.png)

#### SYN Scan (Stealth)

Unlike the **connect** scan, which tries to connect to the target TCP port, i.e., complete a three-way handshake, the SYN scan only executes the first step: it sends a TCP SYN packet. Consequently, the TCP three-way handshake is never completed. The advantage is that this is expected to lead to fewer logs as the connection is never established, and hence, it is considered a relatively stealthy scan. You can select the SYN scan using the `-sS` flag.

In the screenshot below, we scan the same system with port 22 open. The part marked with 1 shows the listening service replying with a TCP SYN-ACK packet. However, Nmap responded with a TCP RST packet instead of completing the TCP three-way handshake. The part marked with 2 shows a TCP connection attempt to a closed port. In this case, the packet exchange is the same as in the connect scan.

![Nmap SYN Scan in Wireshark](Images/Nmap_SYN_Scan_in_Wireshark.png)

#### Scanning UDP Ports

Although most services use TCP for communication, many use UDP. Examples include DNS, DHCP, NTP (Network Time Protocol), SNMP (Simple Network Management Protocol), and VoIP (Voice over IP). UDP does not require establishing a connection and tearing it down afterwards. Furthermore, it is very suitable for real-time communication, such as live broadcasts. All these are reasons to consider scanning for and discovering services listening on UDP ports.

Nmap offers the option `-sU` to scan for UDP services. Because UDP is simpler than TCP, we expect the traffic to differ. The screenshot below shows several ICMP destination unreachable (port unreachable) responses as Nmap sends UDP packets to closed UDP ports.

![Nmap UDP Scan in Wireshark](Images/Nmap_UDP_Scan_in_Wireshark.png)

#### Limiting the Target Ports

Nmap scans the most common 1,000 ports by default. However, this might not be what you are looking for. Therefore, Nmap offers you a few more options.

- `-F` is for Fast mode, which scans the 100 most common ports (instead of the default 1000).
- `-p[range]` allows you to specify a range of ports to scan. For example, `-p10-1024` scans from port 10 to port 1024, while `-p-25` will scan all the ports between 1 and 25. Note that `-p-` scans all the ports and is equivalent to `-p1-65535` and is the best option if you want to be as thorough as possible.

#### Summary

| Option | Explanation |
|----|----|
|`-sT`|TCP connect scan – complete three-way handshake|
|`-sS`|TCP SYN – only first step of the three-way handshake|
|`-sU`|UDP scan|
|`-F`|Fast mode – scans the 100 most common ports|
|`-p[range]`|Specifies a range of port numbers – `-p-` scans all the ports|

#### How many TCP ports are open on the target system at 10.10.74.24?

```bash
root@ip-10-10-223-10:~# nmap -sS -p- 10.10.74.24
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-21 19:10 BST
Nmap scan report for 10.10.74.24
Host is up (0.00017s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE
7/tcp    open  echo
9/tcp    open  discard
13/tcp   open  daytime
17/tcp   open  qotd
22/tcp   open  ssh
8008/tcp open  http
MAC Address: 02:4A:43:71:CC:75 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.26 seconds
root@ip-10-10-223-10:~# 
```

Answer: 6

#### Find the listening web server on 10.10.74.24 and access it with your browser. What is the flag that appears on its main page?

Hint: Use Firefox to access http://IP_ADDRESS:PORT_NUMBER, where IP_ADDRESS is the IP address of the target server,  
and PORT_NUMBER is the TCP port number of the listening web server.

```bash
root@ip-10-10-223-10:~# curl -s http://10.10.74.24:8008 | grep -oE 'THM{.*}'
THM{<REDACTED>}
```

Answer: `THM{<REDACTED>}`

### Task 4: Version Detection: Extract More Information

#### OS Detection

You can enable OS detection by adding the `-O` option. As the name implies, the OS detection option triggers Nmap to rely on various indicators to make an educated guess about the target OS. In this case, it is detecting the target has Linux 4.x or 5.x running. That’s actually true. However, there is no perfectly accurate OS detector. The statement that it is between 4.15 and 5.8 is very close as the target host’s OS is 5.15.

```bash
root@tryhackme:~# nmap -sS -O 192.168.124.211 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-13 13:37 EEST
Nmap scan report for ubuntu22lts-vm (192.168.124.211)
Host is up (0.00043s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 52:54:00:54:FA:4E (QEMU virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.44 seconds
```

#### Service and Version Detection

You discovered several open ports and want to know what services are listening on them. `-sV` enables version detection. This is very convenient for gathering more information about your target with fewer keystrokes. The terminal output below shows an additional column called “VERSION”, indicating the detected SSH server version.

```bash
root@tryhackme:~# nmap -sS -sV 192.168.124.211
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-13 13:33 EEST
Nmap scan report for ubuntu22lts-vm (192.168.124.211)
Host is up (0.000046s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
MAC Address: 52:54:00:54:FA:4E (QEMU virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.25
```

What if you can have both `-O`, `-sV` and some more in one option? That would be `-A`. This option enables OS detection, version scanning, and traceroute, among other things.

#### Forcing the Scan

When we run our port scan, such as using `-sS`, there is a possibility that the target host does not reply during the host discovery phase (e.g. a host doesn’t reply to ICMP requests). Consequently, Nmap will mark this host as down and won’t launch a port scan against it. We can ask Nmap to treat all hosts as online and port scan every host, including those that didn’t respond during the host discovery phase. This choice can be triggered by adding the `-Pn` option.

#### Summary

| Option | Explanation |
|----|----|
|`-O`|OS detection|
|`-sV`|Service and version detection|
|`-A`|OS detection, version detection, and other additions|
|`-Pn`|Scan hosts that appear to be down|

#### What is the name and detected version of the web server running on 10.10.74.24?

```bash
root@ip-10-10-223-10:~# nmap -sS -p 8008 -sV 10.10.74.24
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-21 19:21 BST
Nmap scan report for 10.10.74.24
Host is up (0.00012s latency).

PORT     STATE SERVICE VERSION
8008/tcp open  http    lighttpd 1.4.74
MAC Address: 02:4A:43:71:CC:75 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.84 seconds
```

Answer: lighttpd 1.4.74

### Task 5: Timing: How Fast is Fast

Nmap provides various options to control the scan speed and timing.

Running your scan at its normal speed might trigger an IDS or other security solutions. It is reasonable to control how fast a scan should go. Nmap gives you six timing templates, and the names say it all: paranoid (0), sneaky (1), polite (2), normal (3), aggressive (4), and insane (5). You can pick the timing template by its name or number. For example, you can add `-T0` (or `-T 0`) or `-T paranoid` to opt for the slowest timing.

In the Nmap scans below, we launch a SYN scan targeting the 100 most common TCP ports, `nmap -sS 10.10.74.24 -F`. We repeated the scan with different timings: T0, T1, T2, T3, and T4. In our lab setup, Nmap took different amounts of time to scan the 100 ports. The table below should give you an idea, but you will get different results depending on the network setup and target system.

| Timing | Total Duration | Time Between Tries |
|----|----|----|
|T0 (paranoid)|9.8 hours|5 min between ports|
|T1 (sneaky)|27.53 minutes|15 sec between ports|
|T2 (polite)|40.56 seconds|0.4 sec between ports|
|T3 (normal)|0.15 seconds|As fast as it can|
|T4 (aggressive)|0.13 seconds|As fast as it can|

A second helpful option is the number of parallel service probes. The number of parallel probes can be controlled with `--min-parallelism <numprobes>` and `--max-parallelism <numprobes>`. These options can be used to set a minimum and maximum on the number of TCP and UDP port probes active simultaneously for a host group. By default, `nmap` will automatically control the number of parallel probes. If the network is performing poorly, i.e., dropping packets, the number of parallel probes might fall to one; furthermore, if the network performs flawlessly, the number of parallel probes can reach several hundred.

A similar helpful option is the `--min-rate <number>` and `--max-rate <number>`. As the names indicate, they can control the minimum and maximum rates at which `nmap` sends packets. The rate is provided as the number of packets per second. It is worth mentioning that the specified rate applies to the whole scan and not to a single host.

The last option we will cover in this task is `--host-timeout <time>`. This option specifies the maximum time you are willing to wait, and it is suitable for slow hosts or hosts with slow network connections.

#### What is the non-numeric equivalent of -T4?

Answer: -T aggressive

### Task 6: Output: Controlling What You See

This task focuses on two main features:

- Showing additional information while a scan takes place
- Choosing the file format to save the scan report

#### Verbosity and Debugging

In some cases, the scan takes a very long time to finish or to produce any output that will be displayed on the screen. Furthermore, sometimes you might be interested in more real-time information about the scan progress. The best way to get more updates about what’s happening is to enable verbose output by adding `-v`. Consider the following terminal output showing the network scan repeated twice. In the first case, we opted for the default output verbosity.

```bash
root@tryhackme:~# nmap -sS 192.168.139.1/24
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-13 18:57 EEST
Nmap scan report for 192.168.139.254
Host is up (0.000030s latency).
All 1000 scanned ports on 192.168.139.254 are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)
MAC Address: 00:50:56:E0:FC:AE (VMware)

Nmap scan report for g5000 (192.168.139.1)
Host is up (0.000010s latency).
Not shown: 999 closed tcp ports (reset)
PORT    STATE SERVICE
902/tcp open  iss-realsecure

Nmap done: 256 IP addresses (2 hosts up) scanned in 41.84 seconds
```

Then, we repeated the same scan; however, the second time, we used the `-v` option for verbosity. The amount of details present below can be very useful, especially when you are learning about Nmap and exploring the different options. In the terminal output below, we can see how Nmap is moving from one stage to another: ARP ping scan, parallel DNS resolution, and finally, SYN stealth scan for every live host.

```bash
root@tryhackme:~# nmap 192.168.139.1/24 -v
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-13 19:01 EEST
Initiating ARP Ping Scan at 19:01
Scanning 255 hosts [1 port/host]
Completed ARP Ping Scan at 19:01, 7.94s elapsed (255 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:01
Completed Parallel DNS resolution of 1 host. at 19:02, 13.00s elapsed
Nmap scan report for 192.168.139.0 [host down]
Nmap scan report for 192.168.139.2 [host down]
[...]
Nmap scan report for 192.168.139.253 [host down]
Nmap scan report for 192.168.139.255 [host down]
Initiating Parallel DNS resolution of 1 host. at 19:02
Completed Parallel DNS resolution of 1 host. at 19:02, 0.05s elapsed
Initiating SYN Stealth Scan at 19:02
Scanning 192.168.139.254 [1000 ports]
[...]
Initiating SYN Stealth Scan at 19:02
Scanning g5000 (192.168.139.1) [1000 ports]
Discovered open port 902/tcp on 192.168.139.1
Completed SYN Stealth Scan at 19:02, 0.03s elapsed (1000 total ports)
Nmap scan report for g5000 (192.168.139.1)
Host is up (0.0000090s latency).
Not shown: 999 closed tcp ports (reset)
PORT    STATE SERVICE
902/tcp open  iss-realsecure

Read data files from: /usr/bin/../share/nmap
Nmap done: 256 IP addresses (2 hosts up) scanned in 42.19 seconds
           Raw packets sent: 3512 (146.336KB) | Rcvd: 2005 (84.156KB)
```

Most likely, the `-v` option is more than enough for verbose output; however, if you are still unsatisfied, you can increase the verbosity level by adding another “v” such as `-vv` or even `-vvvv`. You can also specify the verbosity level directly, for example, `-v2` and `-v4`. You can even increase the verbosity level by pressing “v” after the scan already started.

If all this verbosity does not satisfy your needs, you must consider the `-d` for debugging-level output. Similarly, you can increase the debugging level by adding one or more “d” or by specifying the debugging level directly. The maximum level is `-d9`; before choosing that, make sure you are ready for thousands of information and debugging lines.

#### Saving Scan Report

In many cases, we would need to save the scan results. Nmap gives us various formats. The three most useful are normal (human-friendly) output, XML output, and grepable output, in reference to the grep command. You can select the scan report format as follows:

- `-oN <filename>` - Normal output
- `-oX <filename>` - XML output
- `-oG <filename>` - grep-able output (useful for grep and awk)
- `-oA <basename>` - Output in all major formats

In the terminal below, we can see an example of using the `-oA` option. It resulted in three reports with the extensions `nmap`, `xml`, and `gnmap` for normal, XML, and grep-able output.

```bash
root@tryhackme:~# nmap -sS 192.168.139.1 -oA gateway
Starting Nmap 7.92 ( https://nmap.org ) at 2024-08-13 19:35 EEST
Nmap scan report for g5000 (192.168.139.1)
Host is up (0.0000070s latency).
Not shown: 999 closed tcp ports (reset)
PORT    STATE SERVICE
902/tcp open  iss-realsecure

Nmap done: 1 IP address (1 host up) scanned in 0.13 seconds
# ls
gateway.gnmap  gateway.nmap  gateway.xml
```

#### What option must you add to your nmap command to enable debugging?

Answer: -d

### Task 7: Conclusion and Summary

In this room, we learned how to use Nmap to discover live hosts on any network. We also explored the common types of port scans and how we can use Nmap to find service version numbers. We also learned how to control the timing of the scan, and finally, we covered the different formats for saving Nmap scan results.

It is worth noting that it is best to run Nmap with `sudo` privileges so that we can make use of all its features. Running Nmap with local user privileges will still work; however, you should expect many features to be unavailable. You get a minimal portion of Nmap’s power when running it as a local user. For instance, Nmap would automatically use SYN scan (`-sS`) if you are running it with `sudo` privileges and will default to connect scan (`-sT`) if run as a local user. The reason is that crafting certain packets, such as sending a TCP SYN packet, requires root privileges.

Nmap is a very rich tool, and we only covered the most common and essential features in this room. In the Network Security module, four rooms are dedicated exclusively to Nmap. The table below lists most of the options we explained in this room to help you review and remember them.

| Option | Explanation |
|----|----|
|`-sL`|List scan – list targets without scanning|
|**Host Discovery**| |
|`-sn`|Ping scan – host discovery only|
|**Port Scanning**| |
|`-sT`|TCP connect scan – complete three-way handshake|
|`-sS`|TCP SYN – only first step of the three-way handshake|
|`-sU`|UDP Scan|
|`-F`|Fast mode – scans the 100 most common ports|
|`-p[range]`|Specifies a range of port numbers – `-p-` scans all the ports|
|`-Pn`|Treat all hosts as online – scan hosts that appear to be down|
|**Service Detection**| |
|`-O`|OS detection|
|`-sV`|Service version detection|
|`-A`|OS detection, version detection, and other additions|
|**Timing**| |
|`-T<0-5>`|Timing template – paranoid (0), sneaky (1), polite (2), normal (3), aggressive (4), and insane (5)|
|`--min-parallelism <numprobes>` and `--max-parallelism <numprobes>`|Minimum and maximum number of parallel probes|
|`--min-rate <number>` and `--max-rate <number>`|Minimum and maximum rate (packets/second)|
|`--host-timeout`|Maximum amount of time to wait for a target host|
|**Real-time output**| |
|`-v`|Verbosity level – for example, `-vv` and `-v4`|
|`-d`|Debugging level – for example `-d` and `-d9`|
|**Report**| |
|`-oN <filename>`|Normal output|
|`-oX <filename>`|XML output|
|`-oG <filename>`|grep-able output|
|`-oA <basename>`|Output in all major formats|

#### What kind of scan will Nmap use if you run nmap 10.10.74.24 with local user privileges?

Answer: Connect Scan

For additional information, please see the references below.

## References

- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Nmap - Wikipedia](https://en.wikipedia.org/wiki/Nmap)
- [tail - Linux manual page](https://man7.org/linux/man-pages/man1/tail.1.html)
