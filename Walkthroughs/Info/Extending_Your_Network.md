# Extending Your Network

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
OS: N/A
Subscription type: Premium
Description: Learn about some of the technologies used to extend networks out onto the Internet and the motivations for this.
```

Room link: [https://tryhackme.com/room/extendingyournetwork](https://tryhackme.com/room/extendingyournetwork)

## Solution

### Task 1: Introduction to Port Forwarding

Port forwarding is an essential component in connecting applications and services to the Internet. Without port forwarding,  
applications and services such as web servers are only available to devices within the same direct network.

#### What is the name of the device that is used to configure port forwarding?

Answer: router

### Task 2: Firewalls 101

A firewall is a device within a network responsible for determining what traffic is allowed to enter and exit. Think of a  
firewall as border security for a network. An administrator can configure a firewall to permit or deny traffic from entering  
or exiting a network based on numerous factors such as:

- Where the traffic is coming from? (has the firewall been told to accept/deny traffic from a specific network?)
- Where is the traffic going to? (has the firewall been told to accept/deny traffic destined for a specific network?)
- What port is the traffic for? (has the firewall been told to accept/deny traffic destined for port 80 only?)
- What protocol is the traffic using? (has the firewall been told to accept/deny traffic that is UDP, TCP or both?)

#### What layers of the OSI model do firewalls operate at?

Hint: They operate on the Network and Transport layers of the OSI

Answer: 3 & 4

#### What category of firewall inspects the entire connection?

Answer: stateful

#### What category of firewall inspects individual packets?

Answer: stateless

### Task 3: Practical - Firewall

#### What is the flag?

Answer: `THM{<REDACTED>}`

### Task 4: VPN Basics

A Virtual Private Network (or VPN for short) is a technology that allows devices on separate networks to communicate  
securely by creating a dedicated path between each other over the Internet (known as a tunnel). Devices connected  
within this tunnel form their own private network.

#### What VPN technology only encrypts & provides the authentication of data?

Hint: This technology is non-routable

Answer: PPP

#### What VPN technology uses the IP framework?

Hint: It is difficult to set up in comparison to PPTP

Answer: IPSec

### Task 5: LAN Networking Devices

#### What is a Router?

It's a router's job to connect networks and pass data between them. It does this by using routing (hence the name router!).

Routing is the label given to the process of data travelling across networks. Routing involves creating a path between  
networks so that this data can be successfully delivered. Routers operate at Layer 3 of the OSI model.

#### What is a Switch?

A switch is a dedicated networking device responsible for providing a means of connecting to multiple devices. Switches  
can facilitate many devices (from 3 to 63) using Ethernet cables.

Switches can operate at both layer 2 and layer 3 of the OSI model. However, these are exclusive in the sense that Layer  
2 switches cannot operate at layer 3.

A technology called VLAN (Virtual Local Area Network) allows specific devices within a network to be virtually split up.  
This split means they can all benefit from things such as an Internet connection but are treated separately.

#### What is the verb for the action that a router does?

Hint: A router performs ******* to route packets

Answer: routing

#### What are the two different layers of switches? Separate these by a comma I.e.: Layer X,Layer Y

Hint: Think of the OSI model. Submit your question with the following formatting: Answer1,Answer2

Answer: Layer 2,Layer 3

### Task 6: Practical - Network Simulator

#### What is the flag from the network simulator?

Hint: Make sure the entire network simulation is complete to get the flag.

Answer: `THM{<REDACTED>}`

#### How many HANDSHAKE entries are there in the Network Log?

Hint: Try sending a TCP packet from computer1 to computer3

Answer: 5

For additional information, please see the references below.

## References

- [Internet Protocol - Wikipedia](https://en.wikipedia.org/wiki/Internet_Protocol)
- [Internet protocol suite - Wikipedia](https://en.wikipedia.org/wiki/Internet_protocol_suite)
- [Transmission Control Protocol - Wikipedia](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
- [User Datagram Protocol - Wikipedia](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
- [Virtual private network - Wikipedia](https://en.wikipedia.org/wiki/Virtual_private_network)
