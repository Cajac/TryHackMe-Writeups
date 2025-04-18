# Intro to LAN

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
OS: N/A
Subscription type: Premium
Description: Learn about some of the technologies and designs that power private networks
```

Room link: [https://tryhackme.com/room/introtolan](https://tryhackme.com/room/introtolan)

## Solution

### Task 1 - Introducing LAN Topologies

#### Star Topology

The main premise of a star topology is that devices are individually connected via a central networking device  
such as a switch or hub. This topology is the most commonly found today because of its reliability and  
scalability - despite the cost.

#### Bus Topology

This type of connection relies upon a single connection which is known as a backbone cable. This type of  
topology is similar to the leaf off of a tree in the sense that devices (leaves) stem from where the branches  
are on this cable.

#### Ring Topology

The ring topology (also known as token topology) boasts some similarities. Devices such as computers are  
connected directly to each other to form a loop, meaning that there is little cabling required and less  
dependence on dedicated hardware such as within a star topology.

#### What is a Switch?

Switches are dedicated devices within a network that are designed to aggregate multiple other devices such as  
computers, printers, or any other networking-capable device using ethernet.

#### What is a Router?

It's a router's job to connect networks and pass data between them. It does this by using routing (hence the  
name router!).

Routing is the label given to the process of data travelling across networks. Routing involves creating a path  
between networks so that this data can be successfully delivered.

#### What does LAN stand for?

Answer: Local Area Network

#### What is the verb given to the job that Routers perform?

Hint: This is the term given to deciding what route packets should take

Answer: Routing

#### What device is used to centrally connect multiple devices on the local network and transmit data to the correct location?

Hint: Something smarter than a hub/repeater.

Answer: Switch

#### What topology is cost-efficient to set up?

Hint: *** Topology

Answer: Bus Topology

#### Complete the interactive lab attached to this task. What is the flag given at the end?

Answer: `THM{<REDACTED>}`

### Task 2 - A Primer on Subnetting

#### What is the technical term for dividing a network up into smaller pieces?

Answer: Subnetting

#### How many bits are in a subnet mask?

Hint: This can be converted into 4 bytes

Answer: 32

#### What is the range of a section (octet) of a subnet mask?

Hint: Smallest to largest

Answer: 0-255

#### What address is used to identify the start of a network?

Hint: ******* Address

Answer: Network Address

#### What address is used to identify devices within a network?

Hint: **** Address

Answer: Host Address

#### What is the name used to identify the device responsible for sending data to another network?

Answer: Default Gateway

### Task 3 - ARP

The Address Resolution Protocol (ARP), is the technology that is responsible for allowing devices to identify  
themselves on a network.

Simply, ARP allows a device to associate its MAC address with an IP address on the network. Each device on a  
network will keep a log of the MAC addresses associated with other devices.

#### What does ARP stand for?

Answer: Address Resolution Protocol

#### What category of ARP Packet asks a device whether or not it has a specific IP address?

Answer: Request

#### What address is used as a physical identifier for a device on a network?

Hint: *** Address

Answer: MAC Address

#### What address is used as a logical identifier for a device on a network?

Hint: ** Address

Answer: IP Address

### Task 4 - DHCP

IP addresses can be assigned either manually, by entering them physically into a device, or automatically and most  
commonly by using a DHCP (Dynamic Host Configuration Protocol) server.

When a device connects to a network, if it has not already been manually assigned an IP address, it sends out a  
request (DHCP Discover) to see if any DHCP servers are on the network. The DHCP server then replies back with an  
IP address the device could use (DHCP Offer). The device then sends a reply confirming it wants the offered IP  
Address (DHCP Request), and then lastly, the DHCP server sends a reply acknowledging this has been completed, and  
the device can start using the IP Address (DHCP ACK).

#### What type of DHCP packet is used by a device to retrieve an IP address?

Hint: DHCP ********

Answer: DHCP Discover

#### What type of DHCP packet does a device send once it has been offered an IP address by the DHCP server?

Hint: DHCP *******

Answer: DHCP Request

#### Finally, what is the last DHCP packet that is sent to a device from a DHCP server?

Hint: DHCP ***

Answer: DHCP ACK

For additional information, please see the references below.

## References

- [Address Resolution Protocol - Wikipedia](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
- [Dynamic Host Configuration Protocol - Wikipedia](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol)
- [Ethernet - Wikipedia](https://en.wikipedia.org/wiki/Ethernet)
- [Internet Protocol - Wikipedia](https://en.wikipedia.org/wiki/Internet_Protocol)
