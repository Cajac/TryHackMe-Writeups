# What is Networking?

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
OS: N/A
Subscription type: Free
Description: Begin learning the fundamentals of computer networking in this bite-sized and interactive module.
```

Room link: [https://tryhackme.com/room/whatisnetworking](https://tryhackme.com/room/whatisnetworking)

## Solution

### Task 1 - What is Networking?

Networks are simply things connected. Networks can be found in all walks of life:

- A city's public transportation system
- Infrastructure such as the national power grid for electricity
- Meeting and greeting your neighbours
- Postal systems for sending letters and parcels

#### What is the key term for devices that are connected together?

Answer: Network

### Task 2 - What is the Internet?

The first iteration of the Internet was within the ARPANET project in the late 1960s. This project was funded  
by the United States Defence Department and was the first documented network in action. However, it wasn't  
until 1989 when the Internet as we know it was invented by Tim Berners-Lee by the creation of the World Wide  
Web (WWW). It wasn't until this point that the Internet started to be used as a repository for storing and  
sharing information, just like it is today.

#### Who invented the World Wide Web?

Answer: Tim Berners-Lee

### Task 3 - Identifying Devices on a Network

#### IP Addresses

An IP address (or Internet Protocol) address can be used as a way of identifying a host on a network for a  
period of time.

An IP address is a set of numbers that are divided into four octets, such as 192.168.101.42.

#### MAC Addresses

Devices on a network will all have a physical network interface, which is a microchip board found on the  
device's motherboard. This network interface is assigned a unique address at the factory it was built at,  
called a MAC (Media Access Control) address. The MAC address is a twelve-character hexadecimal number split  
into two's and separated by a colon.

#### What does the term "IP" stand for?

Answer: Internet Protocol

#### What is each section of an IP address called?

Answer: Octet

#### How many sections (in digits) does an IPv4 address have?

Answer: 4

#### What does the term "MAC" stand for?

Answer: Media Access Control

### Task 4 - Ping (ICMP)

Ping is one of the most fundamental network tools available to us. Ping uses ICMP (Internet Control Message  
Protocol) packets to determine the performance of a connection between devices, for example, if the connection  
exists or is reliable.

#### What protocol does ping use?

Answer: ICMP

#### What is the syntax to ping 10.10.10.10?

Answer: ping 10.10.10.10

#### What flag do you get when you ping 8.8.8.8?

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [Internet - Wikipedia](https://en.wikipedia.org/wiki/Internet)
- [Internet Control Message Protocol - Wikipedia](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
- [Internet Protocol - Wikipedia](https://en.wikipedia.org/wiki/Internet_Protocol)
- [Internet protocol suite - Wikipedia](https://en.wikipedia.org/wiki/Internet_protocol_suite)
- [ping - Linux manual page](https://man7.org/linux/man-pages/man8/ping.8.html)
