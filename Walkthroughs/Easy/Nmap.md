# Nmap

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: -
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
An in depth look at scanning with Nmap, a powerful network scanning tool.
```

Room link: [https://tryhackme.com/room/furthernmap](https://tryhackme.com/room/furthernmap)

## Solution

### Task 1: Deploy

Press the green button to **deploy the machine**!

**Please Note**: This machine is for scanning purposes only. You do not need to log into it, or exploit any vulnerabilities to gain access.

If you are using the TryHackMe AttackBox then you will need to deploy this separately. Click the **Start AttackBox** button on the top-right side to launch the machine.

![Start AttackBox](Images/Start_AttackBox.png)

---------------------------------------------------------------------------------------

### Task 2: Introduction

When it comes to hacking, knowledge is power. The more knowledge you have about a target system or network, the more options you have available. This makes it imperative that proper enumeration is carried out before any exploitation attempts are made.

Say we have been given an IP (or multiple IP addresses) to perform a security audit on. Before we do anything else, we need to get an idea of the “landscape” we are attacking. What this means is that we need to establish which services are running on the targets. For example, perhaps one of them is running a webserver, and another is acting as a Windows Active Directory Domain Controller. The first stage in establishing this “map” of the landscape is something called port scanning. When a computer runs a network service, it opens a networking construct called a “port” to receive the connection.  Ports are necessary for making multiple network requests or having multiple services available. For example, when you load several webpages at once in a web browser, the program must have some way of determining which tab is loading which web page. This is done by establishing connections to the remote webservers using different ports on your local machine. Equally, if you want a server to be able to run more than one service (for example, perhaps you want your webserver to run both HTTP and HTTPS versions of the site), then you need some way to direct the traffic to the appropriate service. Once again, ports are the solution to this. Network connections are made between two ports – an open port listening on the server and a randomly selected port on your own computer. For example, when you connect to a web page, your computer may open port 49534 to connect to the server’s port 443.

![Network and Ports Example](Images/Network_and_Ports_Example.png)

As in the previous example, the diagram shows what happens when you connect to numerous websites at the same time. Your computer opens up a different, high-numbered port (at random), which it uses for all its communications with the remote server.

Every computer has a total of 65535 available ports; however, many of these are registered as standard ports. For example, a HTTP Webservice can nearly always be found on port 80 of the server. A HTTPS Webservice can be found on port 443. Windows NETBIOS can be found on port 139 and SMB can be found on port 445. It is important to note; however, that especially in a CTF setting, it is not unheard of for even these standard ports to be altered, making it even more imperative that we perform appropriate enumeration on the target.

If we do not know which of these ports a server has open, then we do not have a hope of successfully attacking the target; thus, it is crucial that we begin any attack with a port scan. This can be accomplished in a variety of ways – usually using a tool called nmap, which is the focus of this room. Nmap can be used to perform many different kinds of port scan – the most common of these will be introduced in upcoming tasks; however, the basic theory is this: nmap will connect to each port of the target in turn. Depending on how the port responds, it can be determined as being open, closed, or filtered (usually by a firewall). Once we know which ports are open, we can then look at enumerating which services are running on each port – either manually, or more commonly using nmap.

So, why nmap? The short answer is that it's currently the industry standard for a reason: no other port scanning tool comes close to matching its functionality (although some newcomers are now matching it for speed). It is an extremely powerful tool – made even more powerful by its scripting engine which can be used to scan for vulnerabilities, and in some cases even perform the exploit directly! Once again, this will be covered more in upcoming tasks.

For now, it is important that you understand: what port scanning is; why it is necessary; and that nmap is the tool of choice for any kind of initial enumeration.

---------------------------------------------------------------------------------------

#### What networking constructs are used to direct traffic to the right application on a server?

Answer: `Ports`

#### How many of these are available on any network-enabled computer?

Answer: `65535`

#### Research - How many of these are considered "well-known"? (These are the "standard" numbers mentioned in the task)

Hint: Search in Google "How many well-known ____ are there", substituting in your answer to Question 1.

From [https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)

Answer: `192.168.0.31`

---------------------------------------------------------------------------------------

### Task 3: Nmap Switches

Like most pentesting tools, **nmap** is run from the terminal. There are versions available for both Windows and Linux. For this room we will assume that you are using Linux; however, the switches should be identical. Nmap is installed by default in both Kali Linux and the [TryHackMe Attack Box](https://tryhackme.com/my-machine).

Nmap can be accessed by typing `nmap` into the terminal command line, followed by some of the "switches" (command arguments which tell a program to do different things) we will be covering below.

All you'll need for this is the help menu for nmap (accessed with `nmap -h`) and/or the nmap man page (access with `man nmap`). For each answer, include all parts of the switch unless otherwise specified. This includes the hyphen at the start (`-`).

---------------------------------------------------------------------------------------

#### What is the first switch listed in the help menu for a 'Syn Scan' (more on this later!)?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ nmap -h                      
Nmap 7.95 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks
  -iR <num hosts>: Choose random targets
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
  --excludefile <exclude_file>: Exclude list from file
HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  -Pn: Treat all hosts as online -- skip host discovery
  -PS/PA/PU/PY[portlist]: TCP SYN, TCP ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -PO[protocol list]: IP Protocol Ping
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OS's DNS resolver
  --traceroute: Trace hop path to each host
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
<---snip--->
```

Answer: `-sS`

#### Which switch would you use for a "UDP scan"?

See output above.

Answer: `-sU`

#### If you wanted to detect which operating system the target is running on, which switch would you use?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ nmap -h                      
Nmap 7.95 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks
  -iR <num hosts>: Choose random targets
<---snip--->
OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets
  --osscan-guess: Guess OS more aggressively
<---snip--->
```

Answer: `-O`

#### Nmap provides a switch to detect the version of the services running on the target. What is this switch?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ nmap -h                      
Nmap 7.95 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks
<---snip--->
SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
  --version-light: Limit to most likely probes (intensity 2)
  --version-all: Try every single probe (intensity 9)
  --version-trace: Show detailed version scan activity (for debugging)
<---snip--->
```

Answer: `-sV`

#### The default output provided by nmap often does not provide enough information for a pentester. How would you increase the verbosity?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ nmap -h                      
Nmap 7.95 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
<---snip--->
OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
     and Grepable format, respectively, to the given filename.
  -oA <basename>: Output in the three major formats at once
  -v: Increase verbosity level (use -vv or more for greater effect)
  -d: Increase debugging level (use -dd or more for greater effect)
<---snip--->
```

Answer: `-v`

#### Verbosity level one is good, but verbosity level two is better! How would you set the verbosity level to two?

**Note**: it's highly advisable to always use at least this option

See output above.

Answer: `-vv`

We should always save the output of our scans -- this means that we only need to run the scan once (reducing network traffic and thus chance of detection), and gives us a reference to use when writing reports for clients.

#### What switch would you use to save the nmap results in three major formats?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ nmap -h                      
Nmap 7.95 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
<---snip--->
OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
     and Grepable format, respectively, to the given filename.
  -oA <basename>: Output in the three major formats at once
<---snip--->
```

Answer: `-oA`

#### What switch would you use to save the nmap results in a "normal" format?

See output above.

Answer: `-oN`

#### A very useful output format: how would you save results in a "grepable" format?

See output above.

Answer: `-oG`

Sometimes the results we're getting just aren't enough. If we don't care about how loud we are, we can enable "aggressive" mode. This is a shorthand switch that activates service detection, operating system detection, a traceroute and common script scanning.

#### How would you activate this setting?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ nmap -h                      
Nmap 7.95 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
<---snip--->
MISC:
  -6: Enable IPv6 scanning
  -A: Enable OS detection, version detection, script scanning, and traceroute
<---snip--->
```

Answer: `-A`

Nmap offers five levels of "timing" template. These are essentially used to increase the speed your scan runs at. Be careful though: higher speeds are noisier, and can incur errors!

#### How would you set the timing template to level 5?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ nmap -h                      
Nmap 7.95 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
<---snip--->
TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  -T<0-5>: Set timing template (higher is faster)
<---snip--->
```

Answer: `-T5`

We can also choose which port(s) to scan.

#### How would you tell nmap to only scan port 80?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ nmap -h                      
Nmap 7.95 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
<---snip--->
PORT SPECIFICATION AND SCAN ORDER:
  -p <port ranges>: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  --exclude-ports <port ranges>: Exclude the specified ports from scanning
<---snip--->
```

Answer: `-p 80`

#### How would you tell nmap to scan ports 1000-1500?

See output above.

Answer: `-p 1000-1500`

A very useful option that should not be ignored:

#### How would you tell nmap to scan all ports?

Answer: `-p-`

#### How would you activate a script from the nmap scripting library (lots more on this later!)?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ nmap -h                      
Nmap 7.95 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
<---snip--->
SCRIPT SCAN:
  -sC: equivalent to --script=default
  --script=<Lua scripts>: <Lua scripts> is a comma separated list of
           directories, script-files or script-categories
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
  --script-args-file=filename: provide NSE script args in a file
  --script-trace: Show all data sent and received
  --script-updatedb: Update the script database.
  --script-help=<Lua scripts>: Show help about scripts.
           <Lua scripts> is a comma-separated list of script-files or
           script-categories.
<---snip--->
```

Answer: `--script`

#### How would you activate all of the scripts in the "vuln" category?

Hint: There are two variants of this switch. One with a space, one with the equals sign. Look at the asterisks in the answer field to see which one it is.

See output above.

Answer: `--script=vuln`

---------------------------------------------------------------------------------------

### Task 4: Scan Types - Overview

When port scanning with Nmap, there are three basic scan types. These are:

- TCP Connect Scans (`-sT`)
- SYN "Half-open" Scans (`-sS`)
- UDP Scans (`-sU`)

Additionally there are several less common port scan types, some of which we will also cover (albeit in less detail). These are:

- TCP Null Scans (`-sN`)
- TCP FIN Scans (`-sF`)
- TCP Xmas Scans (`-sX`)

Most of these (with the exception of UDP scans) are used for very similar purposes, however, the way that they work differs between each scan. This means that, whilst one of the first three scans are likely to be your go-to in most situations, it's worth bearing in mind that other scan types exist.

In terms of network scanning, we will also look briefly at ICMP (or "ping") scanning.

---------------------------------------------------------------------------------------

### Task 5: Scan Types - TCP Connect Scans

To understand TCP Connect scans (`-sT`), it's important that you're comfortable with the TCP *three-way handshake*. If this term is new to you then completing [Introductory Networking](https://tryhackme.com/room/introtonetworking) before continuing would be advisable.

As a brief recap, the three-way handshake consists of three stages. First the connecting terminal (our attacking machine, in this instance) sends a TCP request to the target server with the SYN flag set. The server then acknowledges this packet with a TCP response containing the SYN flag, as well as the ACK flag. Finally, our terminal completes the handshake by sending a TCP request with the ACK flag set.

![Three-way handshake](Images/Three-way_handshake.png)

![Three-way handshake 2](Images/Three-way_handshake_2.png)

This is one of the fundamental principles of TCP/IP networking, but how does it relate to Nmap?

Well, as the name suggests, a TCP Connect scan works by performing the three-way handshake with each target port in turn. In other words, Nmap tries to connect to each specified TCP port, and determines whether the service is open by the response it receives.

---------------------------------------------------------------------------------------

For example, if a port is closed, [RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293) states that:

"*... If the connection does not exist (CLOSED), then a reset is sent in response to any incoming segment except another reset. A SYN segment that does not match an existing connection is rejected by this means.*"

In other words, if Nmap sends a TCP request with the *SYN* flag set to a **closed** port, the target server will respond with a TCP packet with the *RST* (Reset) flag set. By this response, Nmap can establish that the port is closed.

![Closed TCP Port](Images/Closed_TCP_Port.png)

If, however, the request is sent to an open port, the target will respond with a TCP packet with the SYN/ACK flags set. Nmap then marks this port as being open (and completes the handshake by sending back a TCP packet with ACK set).

---------------------------------------------------------------------------------------

This is all well and good, however, there is a third possibility.

What if the port is open, but hidden behind a firewall?

Many firewalls are configured to simply **drop** incoming packets. Nmap sends a TCP SYN request, and receives nothing back. This indicates that the port is being protected by a firewall and thus the port is considered to be *filtered*.

That said, it is very easy to configure a firewall to respond with a RST TCP packet. For example, in IPtables for Linux, a simple version of the command would be as follows:

`iptables -I INPUT -p tcp --dport <port> -j REJECT --reject-with tcp-reset`

This can make it extremely difficult (if not impossible) to get an accurate reading of the target(s).

---------------------------------------------------------------------------------------

#### Which RFC defines the appropriate behaviour for the TCP protocol?

Hint: RFC 793 was deprecated and replaced by a newer RFC. What is it?

Answer: `RFC 9293`

#### If a port is closed, which flag should the server send back to indicate this?

Answer: `RST`

---------------------------------------------------------------------------------------

### Task 6: Scan Types - SYN Scans

As with TCP scans, SYN scans (`-sS`) are used to scan the TCP port-range of a target or targets; however, the two scan types work slightly differently. SYN scans are sometimes referred to as "*Half-open*" scans, or "*Stealth*" scans.

Where TCP scans perform a full three-way handshake with the target, SYN scans sends back a RST TCP packet after receiving a SYN/ACK from the server (this prevents the server from repeatedly trying to make the request). In other words, the sequence for scanning an **open** port looks like this:

![Half-open Scan](Images/Half-open_Scan.png)

![Half-open Scan 2](Images/Half-open_Scan_2.png)

This has a variety of advantages for us as hackers:

- It can be used to bypass older Intrusion Detection systems as they are looking out for a full three way handshake. This is often no longer the case with modern IDS solutions; it is for this reason that SYN scans are still frequently referred to as "stealth" scans.
- SYN scans are often not logged by applications listening on open ports, as standard practice is to log a connection once it's been fully established. Again, this plays into the idea of SYN scans being stealthy.
- Without having to bother about completing (and disconnecting from) a three-way handshake for every port, SYN scans are significantly faster than a standard TCP Connect scan.

There are, however, a couple of disadvantages to SYN scans, namely:

- They require sudo permissions [1] in order to work correctly in Linux. This is because SYN scans require the ability to create raw packets (as opposed to the full TCP handshake), which is a privilege only the root user has by default.
- Unstable services are sometimes brought down by SYN scans, which could prove problematic if a client has provided a production environment for the test.

All in all, the pros outweigh the cons.

For this reason, SYN scans are the **default scans** used by Nmap if run with **sudo permissions**. If run without sudo permissions, Nmap defaults to the **TCP Connect** scan we saw in the previous task.

[1] SYN scans can also be made to work by giving Nmap the CAP_NET_RAW, CAP_NET_ADMIN and CAP_NET_BIND_SERVICE capabilities; however, this may not allow many of the NSE scripts to run properly.

---------------------------------------------------------------------------------------

When using a SYN scan to identify closed and filtered ports, the exact same rules as with a TCP Connect scan apply.

If a port is closed then the server responds with a RST TCP packet. If the port is filtered by a firewall then the TCP SYN packet is either dropped, or spoofed with a TCP reset.

In this regard, the two scans are identical: the big difference is in how they handle *open* ports.

---------------------------------------------------------------------------------------

#### There are two other names for a SYN scan, what are they?

Answer: `Half-Open, Stealth`

#### Can Nmap use a SYN scan without Sudo permissions (Y/N)?

Answer: `N`

---------------------------------------------------------------------------------------

### Task 7: Scan Types - UDP Scans

Unlike TCP, UDP connections are *stateless*. This means that, rather than initiating a connection with a back-and-forth "handshake", UDP connections rely on sending packets to a target port and essentially hoping that they make it. This makes UDP superb for connections which rely on speed over quality (e.g. video sharing), but the lack of acknowledgement makes UDP significantly more difficult (and much slower) to scan. The switch for an Nmap UDP scan is (`-sU`)

When a packet is sent to an open UDP port, there should be no response. When this happens, Nmap refers to the port as being `open|filtered`. In other words, it suspects that the port is open, but it could be firewalled. If it gets a UDP response (which is very unusual), then the port is marked as *open*. More commonly there is no response, in which case the request is sent a second time as a double-check. If there is still no response then the port is marked *open|filtered* and Nmap moves on.

When a packet is sent to a *closed* UDP port, the target should respond with an ICMP (ping) packet containing a message that the port is unreachable. This clearly identifies closed ports, which Nmap marks as such and moves on.

---------------------------------------------------------------------------------------

Due to this difficulty in identifying whether a UDP port is actually open, UDP scans tend to be incredibly slow in comparison to the various TCP scans (in the region of 20 minutes to scan the first 1000 ports, with a good connection). For this reason it's usually good practice to run an Nmap scan with `--top-ports <number>` enabled. For example, scanning with `nmap -sU --top-ports 20 <target>`. Will scan the top 20 most commonly used UDP ports, resulting in a much more acceptable scan time.

---------------------------------------------------------------------------------------

When scanning UDP ports, Nmap usually sends completely empty requests -- just raw UDP packets. That said, for ports which are usually occupied by well-known services, it will instead send a protocol-specific payload which is more likely to elicit a response from which a more accurate result can be drawn.

---------------------------------------------------------------------------------------

#### If a UDP port doesn't respond to an Nmap scan, what will it be marked as?

Answer: `open|filtered`

#### When a UDP port is closed, by convention the target should send back a "port unreachable" message. Which protocol would it use to do so?

Answer: `ICMP`

---------------------------------------------------------------------------------------

### Task 8: Scan Types - NULL, FIN and Xmas

NULL, FIN and Xmas TCP port scans are less commonly used than any of the others we've covered already, so we will not go into a huge amount of depth here. All three are interlinked and are used primarily as they tend to be even stealthier, relatively speaking, than a SYN "stealth" scan. Beginning with NULL scans:

#### NULL scans

As the name suggests, NULL scans (`-sN`) are when the TCP request is sent with no flags set at all. As per the RFC, the target host should respond with a RST if the port is closed.

![Null Scan](Images/Null_Scan.png)

#### FIN scans

FIN scans (`-sF`) work in an almost identical fashion; however, instead of sending a completely empty packet, a request is sent with the FIN flag (usually used to gracefully close an active connection). Once again, Nmap expects a RST if the port is closed.

![FIN Scan](Images/FIN_Scan.png)

#### Xmas scans

As with the other two scans in this class, Xmas scans (`-sX`) send a malformed TCP packet and expects a RST response for closed ports. It's referred to as an xmas scan as the flags that it sets (PSH, URG and FIN) give it the appearance of a blinking christmas tree when viewed as a packet capture in Wireshark.

![Xmas Scan](Images/Xmas_Scan.png)

---------------------------------------------------------------------------------------

The expected response for *open* ports with these scans is also identical, and is very similar to that of a UDP scan. If the port is open then there is no response to the malformed packet. Unfortunately (as with open UDP ports), that is also an expected behaviour if the port is protected by a firewall, so NULL, FIN and Xmas scans will only ever identify ports as being *open|filtered*, *closed*, or *filtered*. If a port is identified as filtered with one of these scans then it is usually because the target has responded with an ICMP unreachable packet.

It's also worth noting that while RFC 793 mandates that network hosts respond to malformed packets with a RST TCP packet for closed ports, and don't respond at all for open ports; this is not always the case in practice. In particular Microsoft Windows (and a lot of Cisco network devices) are known to respond with a RST to any malformed TCP packet -- regardless of whether the port is actually open or not. This results in all ports showing up as being closed.

That said, the goal here is, of course, firewall evasion. Many firewalls are configured to drop incoming TCP packets to blocked ports which have the SYN flag set (thus blocking new connection initiation requests). By sending requests which do not contain the SYN flag, we effectively bypass this kind of firewall. Whilst this is good in theory, most modern IDS solutions are savvy to these scan types, so don't rely on them to be 100% effective when dealing with modern systems.

---------------------------------------------------------------------------------------

#### Which of the three shown scan types uses the URG flag?

Answer: `xmas`

#### Why are NULL, FIN and Xmas scans generally used?

Answer: `Firewall Evasion`

#### Which common OS may respond to a NULL, FIN or Xmas scan with a RST for every port?

Answer: `Microsoft Windows`

---------------------------------------------------------------------------------------

### Task 9: Scan Types - ICMP Network Scanning

On first connection to a target network in a black box assignment, our first objective is to obtain a "map" of the network structure -- or, in other words, we want to see which IP addresses contain active hosts, and which do not.

One way to do this is by using Nmap to perform a so called "ping sweep". This is exactly as the name suggests: Nmap sends an ICMP packet to each possible IP address for the specified network. When it receives a response, it marks the IP address that responded as being alive. For reasons we'll see in a later task, this is not always accurate; however, it can provide something of a baseline and thus is worth covering.

To perform a **ping sweep**, we use the `-sn` switch in conjunction with IP ranges which can be specified with either a hypen (`-`) or CIDR notation. i.e. we could scan the 192.168.0.x network using:

- `nmap -sn 192.168.0.1-254`

or

- `nmap -sn 192.168.0.0/24`

The `-sn` switch tells Nmap not to scan any ports -- forcing it to rely primarily on ICMP echo packets (or ARP requests on a local network, if run with sudo or directly as the root user) to identify targets. In addition to the ICMP echo requests, the `-sn` switch will also cause nmap to send a TCP SYN packet to port 443 of the target, as well as a TCP ACK (or TCP SYN if not run as root) packet to port 80 of the target.

---------------------------------------------------------------------------------------

#### How would you perform a ping sweep on the 172.16.x.x network (Netmask: 255.255.0.0) using Nmap? (CIDR notation)

Hint: The CIDR notation for a Class B network with a default netmask is /16

Answer: `nmap -sn 172.16.0.0/16`

---------------------------------------------------------------------------------------

### Task 10: NSE Scripts - Overview

The **N**map **S**cripting **E**ngine (NSE) is an incredibly powerful addition to Nmap, extending its functionality quite considerably. NSE Scripts are written in the *Lua* programming language, and can be used to do a variety of things: from scanning for vulnerabilities, to automating exploits for them. The NSE is particularly useful for reconnaisance, however, it is well worth bearing in mind how extensive the script library is.

There are many categories available. Some useful categories include:

- `safe`:- Won't affect the target
- `intrusive`:- Not safe: likely to affect the target
- `vuln`:- Scan for vulnerabilities
- `exploit`:- Attempt to exploit a vulnerability
- `auth`:- Attempt to bypass authentication for running services (e.g. Log into an FTP server anonymously)
- `brute`:- Attempt to bruteforce credentials for running services
- `discovery`:- Attempt to query running services for further information about the network (e.g. query an SNMP server).

A more exhaustive list can be found [here](https://nmap.org/book/nse-usage.html).

In the next task we'll look at how to interact with the NSE and make use of the scripts in these categories.

---------------------------------------------------------------------------------------

#### What language are NSE scripts written in?

Answer: `Lua`

#### Which category of scripts would be a very bad idea to run in a production environment?

Answer: `intrusive`

---------------------------------------------------------------------------------------

### Task 11: NSE Scripts - Working with the NSE

In Task 3 we looked very briefly at the `--script` switch for activating NSE scripts from the `vuln` category using `--script=vuln`. It should come as no surprise that the other categories work in exactly the same way. If the command `--script=safe` is run, then any applicable safe scripts will be run against the target (Note: only scripts which target an active service will be activated).

---------------------------------------------------------------------------------------

To run a specific script, we would use `--script=<script-name>`, e.g. `--script=http-fileupload-exploiter`.

Multiple scripts can be run simultaneously in this fashion by separating them by a comma. For example: `--script=smb-enum-users,smb-enum-shares`.

Some scripts require arguments (for example, credentials, if they're exploiting an authenticated vulnerability). These can be given with the `--script-args` Nmap switch. An example of this would be with the `http-put` script (used to upload files using the PUT method). This takes two arguments: the URL to upload the file to, and the file's location on disk.  For example:

`nmap -p 80 --script http-put --script-args http-put.url='/dav/shell.php',http-put.file='./shell.php'`

Note that the arguments are separated by commas, and connected to the corresponding script with periods (i.e. `<script-name>.<argument>`).

A full list of scripts and their corresponding arguments (along with example use cases) can be found [here](https://nmap.org/nsedoc/).

---------------------------------------------------------------------------------------

Nmap scripts come with built-in help menus, which can be accessed using nmap `--script-help <script-name>`. This tends not to be as extensive as in the link given above, however, it can still be useful when working locally.

---------------------------------------------------------------------------------------

#### What optional argument can the ftp-anon.nse script take?

From [https://nmap.org/nsedoc/scripts/ftp-anon.html](https://nmap.org/nsedoc/scripts/ftp-anon.html)

Answer: `maxlist`

---------------------------------------------------------------------------------------

### Task 12: NSE Scripts - Searching for Scripts

Ok, so we know how to use the scripts in Nmap, but we don't yet know how to find these scripts.

We have two options for this, which should ideally be used in conjunction with each other. The first is the page on the [Nmap website](https://nmap.org/nsedoc/) (mentioned in the previous task) which contains a list of all official scripts. The second is the local storage on your attacking machine. Nmap stores its scripts on Linux at `/usr/share/nmap/scripts`. All of the NSE scripts are stored in this directory by default -- this is where Nmap looks for scripts when you specify them.

There are two ways to search for installed scripts. One is by using the `/usr/share/nmap/scripts/script.db` file. Despite the extension, this isn't actually a database so much as a formatted text file containing filenames and categories for each available script.

![Nmap Scripts 1](Images/Nmap_Scripts_1.png)

Nmap uses this file to keep track of (and utilise) scripts for the scripting engine; however, we can also `grep` through it to look for scripts. For example: `grep "ftp" /usr/share/nmap/scripts/script.db`.

![Nmap Scripts 2](Images/Nmap_Scripts_2.png)

The second way to search for scripts is quite simply to use the `ls` command. For example, we could get the same results as in the previous screenshot by using `ls -l /usr/share/nmap/scripts/*ftp*`:

![Nmap Scripts 3](Images/Nmap_Scripts_3.png)

Note the use of asterisks (`*`) on either side of the search term

The same techniques can also be used to search for categories of script. For example:  
`grep "safe" /usr/share/nmap/scripts/script.db`

![Nmap Scripts 4](Images/Nmap_Scripts_4.png)

---------------------------------------------------------------------------------------

#### Installing New Scripts

We mentioned previously that the Nmap website contains a list of scripts, so, what happens if one of these is missing in the `scripts` directory locally? A standard `sudo apt update && sudo apt install nmap` should fix this; however, it's also possible to install the scripts manually by downloading the script from Nmap (`sudo wget -O /usr/share/nmap/scripts/<script-name>.nse https://svn.nmap.org/nmap/scripts/<script-name>.nse`). This must then be followed up with nmap `--script-updatedb`, which updates the `script.db` file to contain the newly downloaded script.

It's worth noting that you would require the same "updatedb" command if you were to make your own NSE script and add it into Nmap -- a more than manageable task with some basic knowledge of Lua!

---------------------------------------------------------------------------------------

Search for "smb" scripts in the `/usr/share/nmap/scripts/` directory using either of the demonstrated methods.

#### What is the filename of the script which determines the underlying OS of the SMB server?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ grep -l smb /usr/share/nmap/scripts/*.nse          
/usr/share/nmap/scripts/clock-skew.nse
/usr/share/nmap/scripts/http-ntlm-info.nse
/usr/share/nmap/scripts/imap-ntlm-info.nse
/usr/share/nmap/scripts/msrpc-enum.nse
/usr/share/nmap/scripts/ms-sql-brute.nse
/usr/share/nmap/scripts/ms-sql-config.nse
/usr/share/nmap/scripts/ms-sql-empty-password.nse
/usr/share/nmap/scripts/ms-sql-hasdbaccess.nse
/usr/share/nmap/scripts/ms-sql-info.nse
/usr/share/nmap/scripts/ms-sql-ntlm-info.nse
/usr/share/nmap/scripts/ms-sql-query.nse
/usr/share/nmap/scripts/ms-sql-tables.nse
/usr/share/nmap/scripts/ms-sql-xp-cmdshell.nse
/usr/share/nmap/scripts/nntp-ntlm-info.nse
/usr/share/nmap/scripts/oracle-enum-users.nse
/usr/share/nmap/scripts/p2p-conficker.nse
/usr/share/nmap/scripts/pop3-ntlm-info.nse
/usr/share/nmap/scripts/rdp-ntlm-info.nse
/usr/share/nmap/scripts/samba-vuln-cve-2012-1182.nse
/usr/share/nmap/scripts/shodan-api.nse
/usr/share/nmap/scripts/smb2-capabilities.nse
/usr/share/nmap/scripts/smb2-security-mode.nse
/usr/share/nmap/scripts/smb2-time.nse
/usr/share/nmap/scripts/smb2-vuln-uptime.nse
/usr/share/nmap/scripts/smb-brute.nse
/usr/share/nmap/scripts/smb-double-pulsar-backdoor.nse
/usr/share/nmap/scripts/smb-enum-domains.nse
/usr/share/nmap/scripts/smb-enum-groups.nse
/usr/share/nmap/scripts/smb-enum-processes.nse
/usr/share/nmap/scripts/smb-enum-services.nse
/usr/share/nmap/scripts/smb-enum-sessions.nse
/usr/share/nmap/scripts/smb-enum-shares.nse
/usr/share/nmap/scripts/smb-enum-users.nse
/usr/share/nmap/scripts/smb-flood.nse
/usr/share/nmap/scripts/smb-ls.nse
/usr/share/nmap/scripts/smb-mbenum.nse
/usr/share/nmap/scripts/smb-os-discovery.nse
/usr/share/nmap/scripts/smb-print-text.nse
/usr/share/nmap/scripts/smb-protocols.nse
/usr/share/nmap/scripts/smb-psexec.nse
/usr/share/nmap/scripts/smb-security-mode.nse
/usr/share/nmap/scripts/smb-server-stats.nse
/usr/share/nmap/scripts/smb-system-info.nse
/usr/share/nmap/scripts/smb-vuln-conficker.nse
/usr/share/nmap/scripts/smb-vuln-cve2009-3103.nse
/usr/share/nmap/scripts/smb-vuln-cve-2017-7494.nse
/usr/share/nmap/scripts/smb-vuln-ms06-025.nse
/usr/share/nmap/scripts/smb-vuln-ms07-029.nse
/usr/share/nmap/scripts/smb-vuln-ms08-067.nse
/usr/share/nmap/scripts/smb-vuln-ms10-054.nse
/usr/share/nmap/scripts/smb-vuln-ms10-061.nse
/usr/share/nmap/scripts/smb-vuln-ms17-010.nse
/usr/share/nmap/scripts/smb-vuln-regsvc-dos.nse
/usr/share/nmap/scripts/smb-vuln-webexec.nse
/usr/share/nmap/scripts/smb-webexec-exploit.nse
/usr/share/nmap/scripts/smtp-ntlm-info.nse
/usr/share/nmap/scripts/stuxnet-detect.nse
/usr/share/nmap/scripts/telnet-ntlm-info.nse
/usr/share/nmap/scripts/tls-alpn.nse
```

Answer: `smb-os-discovery.nse`

#### Read through this script. What does it depend on?

Hint: Look for dependencies = {} in the Lua script.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ cat /usr/share/nmap/scripts/smb-os-discovery.nse      
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local os = require "os"
local datetime = require "datetime"
<---snip--->
author = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"smb-brute"}
<---snip--->
```

Answer: `smb-brute`

---------------------------------------------------------------------------------------

### Task 13: Firewall Evasion

We have already seen some techniques for bypassing firewalls (think stealth scans, along with NULL, FIN and Xmas scans); however, there is another very common firewall configuration which it's imperative we know how to bypass.

Your typical Windows host will, with its default firewall, block all ICMP packets. This presents a problem: not only do we often use ping to manually establish the activity of a target, Nmap does the same thing by default. This means that Nmap will register a host with this firewall configuration as dead and not bother scanning it at all.

So, we need a way to get around this configuration. Fortunately Nmap provides an option for this: `-Pn`, which tells Nmap to not bother pinging the host before scanning it. This means that Nmap will always treat the target host(s) as being alive, effectively bypassing the ICMP block; however, it comes at the price of potentially taking a very long time to complete the scan (if the host really is dead then Nmap will still be checking and double checking every specified port).

It's worth noting that if you're already directly on the local network, Nmap can also use ARP requests to determine host activity.

---------------------------------------------------------------------------------------

There are a variety of other switches which Nmap considers useful for firewall evasion. We will not go through these in detail, however, they can be found [here](https://nmap.org/book/man-bypass-firewalls-ids.html).

The following switches are of particular note:

- `-f`:- Used to fragment the packets (i.e. split them into smaller pieces) making it less likely that the packets will be detected by a firewall or IDS.
- An alternative to `-f`, but providing more control over the size of the packets: `--mtu <number>`, accepts a maximum transmission unit size to use for the packets sent. This must be a multiple of 8.
- `--scan-delay <time>ms`:- used to add a delay between packets sent. This is very useful if the network is unstable, but also for evading any time-based firewall/IDS triggers which may be in place.
- `--badsum`:- this is used to generate in invalid checksum for packets. Any real TCP/IP stack would drop this packet, however, firewalls may potentially respond automatically, without bothering to check the checksum of the packet. As such, this switch can be used to determine the presence of a firewall/IDS.

---------------------------------------------------------------------------------------

#### Which simple (and frequently relied upon) protocol is often blocked, requiring the use of the `-Pn` switch?

Answer: `ICMP`

#### [Research] Which Nmap switch allows you to append an arbitrary length of random data to the end of packets?

From [https://nmap.org/book/man-bypass-firewalls-ids.html](https://nmap.org/book/man-bypass-firewalls-ids.html)

Answer: `--data-length`

---------------------------------------------------------------------------------------

### Task 14: Practical

Use what you've learnt to scan the target machine and answer the following questions!

The IP address of the VM you powered on in Task1 is `10.66.137.86`

**Note**: If you're not a subscriber, make sure that this machine has had around **ten minutes** to start

---------------------------------------------------------------------------------------

#### Does the target ip respond to ICMP echo (ping) requests (Y/N)?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ export TARGET_IP=10.66.137.86

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ ping $TARGET_IP         
PING 10.66.137.86 (10.66.137.86) 56(84) bytes of data.
^C
--- 10.66.137.86 ping statistics ---
6 packets transmitted, 0 received, 100% packet loss, time 5124ms
```

Answer: `N`

#### Perform an Xmas scan on the first 999 ports of the target -- how many ports are shown to be open or filtered?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ sudo nmap -sX -p 1-999 $TARGET_IP
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-08 11:49 CET
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.11 seconds

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ sudo nmap -sX -p 1-999 -Pn $TARGET_IP
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-08 11:49 CET
Nmap scan report for 10.66.137.86
Host is up.
All 999 scanned ports on 10.66.137.86 are in ignored states.
Not shown: 999 open|filtered tcp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 201.51 seconds
```

Answer: `999`

#### There is a reason given for this -- what is it?

Hint: Run this command with the -vv switch enabled. It's good practice to always increase the verbosity in your scans.

**Note**: The answer will be in your scan results. Think carefully about which switches to use -- and read the hint before asking for help!

See output above.

Answer: `No Response`

#### Perform a TCP SYN scan on the first 5000 ports of the target -- how many ports are shown to be open?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ sudo nmap -sS -p 1-5000 -Pn $TARGET_IP
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-08 11:54 CET
Nmap scan report for 10.66.137.86
Host is up (0.11s latency).
Not shown: 4995 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
53/tcp   open  domain
80/tcp   open  http
135/tcp  open  msrpc
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 19.06 seconds
```

Answer: `5`

Open Wireshark (see Cryillic's [Wireshark Room](https://tryhackme.com/room/wireshark) for instructions) and perform a TCP Connect scan against port 80 on the target, monitoring the results. Make sure you understand what's going on. Deploy the ftp-anon script against the box.

#### Can Nmap login successfully to the FTP server on port 21? (Y/N)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Nmap]
└─$ sudo nmap -p 21 --script ftp-anon -Pn -vv $TARGET_IP
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-08 11:59 CET
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 1) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 11:59
Completed Parallel DNS resolution of 1 host. at 11:59, 0.01s elapsed
Initiating SYN Stealth Scan at 11:59
Scanning 10.66.137.86 [1 port]
Discovered open port 21/tcp on 10.66.137.86
Completed SYN Stealth Scan at 11:59, 0.14s elapsed (1 total ports)
NSE: Script scanning 10.66.137.86.
NSE: Starting runlevel 1 (of 1) scan.
Initiating NSE at 11:59
NSE Timing: About 0.00% done
Completed NSE at 11:59, 30.56s elapsed
Nmap scan report for 10.66.137.86
Host is up, received user-set (0.11s latency).
Scanned at 2026-02-08 11:59:17 CET for 31s

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 126
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 1) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 30.85 seconds
           Raw packets sent: 1 (44B) | Rcvd: 1 (44B)
```

![Wireshark FTP](Images/Wireshark_FTP.png)

Answer: `Y`

---------------------------------------------------------------------------------------

### Task 15: Conclusion

You have now completed the Further Nmap room -- hopefully you enjoyed it, and learnt something new!

There are lots of great resources for learning more about Nmap on your own. Front and center are Nmaps own (highly extensive) docs which have already been mentioned several times throughout the room. These are a superb resource, so, whilst reading through them line-by-line and learning them by rote is entirely unnecessary, it would be highly advisable to use them as a point of reference, should you need it.

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [Internet Control Message Protocol - Wikipedia](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
- [iptables - Linux manual page](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [List of TCP and UDP port numbers - Wikipedia](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)
- [man - Linux manual page](https://man7.org/linux/man-pages/man1/man.1.html)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Nmap - Wikipedia](https://en.wikipedia.org/wiki/Nmap)
- [Nmap Scripting Engine - Nmap.org](https://nmap.org/book/nse.html)
- [NSEDoc Reference Portal - Nmap.org](https://nmap.org/nsedoc/index.html)
- [NSE Categories - Nmap.org](https://nmap.org/nsedoc/categories/)
- [NSE Scripts - Nmap.org](https://nmap.org/nsedoc/scripts/)
- [RFC 9293 - Transmission Control Protocol (TCP)](https://datatracker.ietf.org/doc/html/rfc9293)
- [Transmission Control Protocol - Wikipedia](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
