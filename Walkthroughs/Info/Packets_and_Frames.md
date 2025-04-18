# Packets & Frames

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
OS: N/A
Subscription type: Premium
Description: Understand how data is divided into smaller pieces and transmitted across a network to another device
```

Room link: [https://tryhackme.com/room/packetsframes](https://tryhackme.com/room/packetsframes)

## Solution

### Task 1: What are Packets and Frames

Packets and frames are small pieces of data that, when forming together, make a larger piece of information or message.  
However, they are two different things in the OSI model.

A frame is at layer 2 - the data link layer, meaning there is no such information as IP addresses.

When we are talking about anything IP addresses, we are talking about packets.

#### What is the name for a piece of data when it does have IP addressing information?

Hint: Packet/Frame

Answer: Packet

#### What is the name for a piece of data when it does not have IP addressing information?

Hint: Packet/Frame

Answer: Frame

### Task 2: TCP/IP (The Three-Way Handshake)

The TCP/IP protocol suite consists of four layers and is arguably just a summarised version of the OSI model.  
These layers are:

- Application
- Transport
- Internet
- Network Interface

TCP (or Transmission Control Protocol for short) is another one of these rules used in networking.

One defining feature of TCP is that it is connection-based, which means that TCP must establish a connection  
between both a client and a device acting as a server before data is sent.

Because of this, TCP guarantees that any data sent will be received on the other end. This process is named  
the Three-way handshake.

The Three-way handshake communicates using a few special messages - the table below highlights the main ones:

| Step | Message | Description |
|----|----|----|
|1|SYN|A SYN message is the initial packet sent by a client during the handshake.|
|2|SYN/ACK|This packet is sent by the receiving device (server) to acknowledge the synchronisation attempt from the client.|
|3|ACK|This acknowledgement packet can be used by either the client or server.|
|4|DATA|Once a connection has been established, data (such as bytes of a file) is sent.|
|5|FIN|This packet is used to cleanly (properly) close the connection after it has been complete.|
|#|RST|This packet abruptly ends all communication.|

#### What is the header in a TCP packet that ensures the integrity of data?

Answer: checksum

#### Provide the order of a normal Three-way handshake (with each step separated by a comma)

Hint: For example: step1,step2,step3

Answer: SYN,SYN/ACK,ACK

### Task 3: Practical - Handshake

#### What is the value of the flag given at the end of the conversation?

Answer: `THM{<REDACTED>}`

### Task 4: UDP/IP

The User Datagram Protocol (UDP) is another protocol that is used to communicate data between devices.

Unlike its brother TCP, UDP is a stateless protocol that doesn't require a constant connection between the two devices  
for data to be sent. For example, the Three-way handshake does not occur, nor is there any synchronisation between the  
two devices.

#### What does the term "UDP" stand for?

Answer: User Datagram Protocol

#### What type of connection is "UDP"?

Answer: stateless

#### What protocol would you use to transfer a file?

Answer: TCP

#### What protocol would you use to have a video call?

Answer: UDP

### Task 5: Ports 101 (Practical)

Perhaps aptly titled by their name, ports are an essential point in which data can be exchanged.

Networking devices use ports to enforce strict rules when communicating with one another. When a connection has been  
established (recalling from the OSI model's room), any data sent or received by a device will be sent through these  
ports. In computing, ports are a numerical value between 0 and 65535 (65,535).

While the standard rule for web data is port 80, a few other protocols have been allocated a standard rule.  
Any port that is within 0 and 1024 (1,024) is known as a common port.

#### What is the flag received from the challenge?

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [Internet Protocol - Wikipedia](https://en.wikipedia.org/wiki/Internet_Protocol)
- [Internet protocol suite - Wikipedia](https://en.wikipedia.org/wiki/Internet_protocol_suite)
- [Transmission Control Protocol - Wikipedia](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
- [User Datagram Protocol - Wikipedia](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
