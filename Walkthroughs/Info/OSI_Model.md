# OSI Model

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
OS: N/A
Subscription type: Premium
Description: Learn about the fundamental networking framework that determines the various 
stages in which data is handled across a network
```

Room link: [https://tryhackme.com/room/osimodelzi](https://tryhackme.com/room/osimodelzi)

## Solution

### Task 1: What is the OSI Model?

The OSI model (or Open Systems Interconnection Model) is an essential model used in networking.  
This critical model provides a framework dictating how all networked devices will send, receive  
and interpret data.

One of the main benefits of the OSI model is that devices can have different functions and designs  
on a network while communicating with other devices. Data sent across a network that follows the  
uniformity of the OSI model can be understood by other devices.

The OSI model consists of seven layers which are illustrated in the diagram below. Each layer has  
a different set of responsibilities and is arranged from Layer 7 to Layer 1.

The seven OSI layers are:

1. Physical
2. Data link
3. Network
4. Transport
5. Session
6. Presentation
7. Application

#### What does the "OSI" in "OSI Model" stand for?

Answer: Open Systems Interconnection

#### How many layers (in digits) does the OSI model have?

Answer: 7

#### What is the key term for when pieces of information get added to data?

Answer: encapsulation

### Task 2: Layer 1 - Physical

This layer is one of the easiest layers to grasp. Put simply, this layer references the physical components  
of the hardware used in networking and is the lowest layer that you will find. Devices use electrical signals  
to transfer data between each other in a binary numbering system (1's and 0's).

#### What is the name of this Layer?

Answer: Physical

#### What is the name of the numbering system that is both 0's and 1's?

Answer: Binary

#### What is the name of the cables that are used to connect devices?

Answer: Ethernet Cables

### Task 3: Layer 2 - Data Link

The data link layer focuses on the physical addressing of the transmission. It receives a packet from the  
network layer (including the IP address for the remote computer) and adds in the physical MAC (Media Access  
Control) address of the receiving endpoint. Inside every network-enabled computer is a Network Interface Card  
(NIC) which comes with a unique MAC address to identify it.

#### What is the name of this Layer?

Answer: Data Link

#### What is the name of the piece of hardware that all networked devices come with?

Hint: NIC

Answer: Network Interface Card

### Task 4: Layer 3 - Network

The third layer of the OSI model (network layer) is where the magic of routing & re-assembly of data takes place  
(from these small chunks to the larger chunk). Firstly, routing simply determines the most optimal path in which  
these chunks of data should be sent.

#### What is the name of this Layer?

Answer: Network

#### Will packets take the most optimal route across a network? (Y/N)

Answer: Y

#### What does the acronym "OSPF" stand for?

Answer: Open Shortest Path First

#### What does the acronym "RIP" stand for?

Answer: Routing Information Protocol

#### What type of addresses are dealt with at this layer?

Hint: Devices on a network use these. For example, 192.168.1.100

Answer: IP Addresses

### Task 5: Layer 4 - Transport

Layer 4 of the OSI model plays a vital part in transmitting data across a network and can be a little bit difficult  
to grasp. When data is sent between devices, it follows one of two different protocols that are decided based upon  
several factors:

- TCP
- UDP

Let's begin with TCP. The Transmission Control Protocol (TCP). Potentially hinted by the name, this protocol is  
designed with reliability and guarantee in mind. This protocol reserves a constant connection between the two devices  
for the amount of time it takes for the data to be sent and received.

Now let's move onto the User Datagram Protocol (or UDP for short). This protocol is not nearly as advanced as its  
brother - the TCP protocol. It doesn't boast the many features offered by TCP, such as error checking and reliability.  
In fact, any data that gets sent via UDP is sent to the computer whether it gets there or not. There is no  
synchronisation between the two devices or guarantee; just hope for the best, and fingers crossed.

#### What is the name of this Layer?

Answer: Transport

#### What does TCP stand for?

Answer: Transmission Control Protocol

#### What does UDP stand for?

Answer: User Datagram Protocol

#### What protocol guarantees the accuracy of data?

Answer: TCP

#### What protocol doesn't care if data is received or not by the other device?

Answer: UDP

#### What protocol would an application such as an email client use?

Answer: TCP

#### What protocol would an application that downloads files use?

Answer: TCP

#### What protocol would an application that streams video use?

Answer: UDP

### Task 6: Layer 5 - Session

Once data has been correctly translated or formatted from the presentation layer (layer 6), the session layer  
(layer 5) will begin to create and maintain the connection to other computer for which the data is destined.  
When a connection is established, a session is created. Whilst this connection is active, so is the session.

#### What is the name of this Layer?

Answer: Session

#### What is the technical term for when a connection is succesfully established?

Hint: These are unique per connection

Answer: Session

### Task 7: Layer 6 - Presentation

Layer 6 of the OSI model is the layer in which standardisation starts to take place. Because software developers  
can develop any software such as an email client differently, the data still needs to be handled in the same way  
— no matter how the software works.

This layer acts as a translator for data to and from the application layer (layer 7).

#### What is the name of this Layer?

Answer: Presentation

#### What is the main purpose that this Layer acts as?

Hint: This layer translates data from one format to another

Answer: Translator

### Task 8: Layer 7 - Application

The application layer of the OSI model is the layer that you will be most familiar with. This familiarity is because  
the application layer is the layer in which protocols and rules are in place to determine how the user should interact  
with data sent or received.

#### What is the name of this Layer?

Answer: Application

#### What is the technical term that is given to the name of the software that users interact with?

Answer: Graphical User Interface

### Task 9: Practical - OSI Game

#### Escape the dungeon to retrieve the flag. What is the flag?

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [Address Resolution Protocol - Wikipedia](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
- [Dynamic Host Configuration Protocol - Wikipedia](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol)
- [Ethernet - Wikipedia](https://en.wikipedia.org/wiki/Ethernet)
- [Internet Protocol - Wikipedia](https://en.wikipedia.org/wiki/Internet_Protocol)
- [OSI model - Wikipedia](https://en.wikipedia.org/wiki/OSI_model)
- [Open Shortest Path First - Wikipedia](https://en.wikipedia.org/wiki/Open_Shortest_Path_First)
- [Routing - Wikipedia](https://en.wikipedia.org/wiki/Routing)
- [Routing Information Protocol - Wikipedia](https://en.wikipedia.org/wiki/Routing_Information_Protocol)
- [Transmission Control Protocol - Wikipedia](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
- [User Datagram Protocol - Wikipedia](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
