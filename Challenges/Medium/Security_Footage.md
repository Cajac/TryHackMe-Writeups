# Security Footage

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Medium
OS: N/A
Subscription type: Free
Description: Perform digital forensics on a network capture to recover footage from a camera.
```

Room link: [https://tryhackme.com/room/securityfootage](https://tryhackme.com/room/securityfootage)

## Solution

### Security Footage

Someone broke into our office last night, but they destroyed the hard drives with the security footage. Can you recover the footage?

Note: If you are using the AttackBox, you can find the task files inside the `/root/Rooms/securityfootage/` directory.

#### Basic analysis of the file

We start with some basic analysis of the given file

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Security_Footage]
└─$ file security-footage.pcap                                                                                                                    
security-footage.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Security_Footage]
└─$ capinfos security-footage.pcap 
File name:           security-footage.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 262144 bytes
Number of packets:   1,109
File size:           6,040 kB
Data size:           6,023 kB
Capture duration:    24.052005 seconds
Earliest packet time: 2022-04-02 22:31:18.452531
Latest packet time:   2022-04-02 22:31:42.504536
Data byte rate:      250 kBps
Data bit rate:       2,003 kbps
Average packet size: 5431.13 bytes
Average packet rate: 46 packets/s
SHA256:              2db28e5c626203deadbfdcce4c0ebd9d47ea811d7c32757184dceaab4ed91645
SHA1:                01da24408ee7f86f8d3446f1f6cc5b6549c200c3
Strict time order:   True
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 262144
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 1109
```

#### Get an overview of the traffic

Next, we get an overview of the protocols included in the traffic:

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Security_Footage]
└─$ tshark -q -z io,phs -r security-footage.pcap 

===================================================================
Protocol Hierarchy Statistics
Filter: 

eth                                      frames:1109 bytes:6023125
  ip                                     frames:1109 bytes:6023125
    tcp                                  frames:1109 bytes:6023125
      http                               frames:1 bytes:402
===================================================================
```

Only HTTP-traffic. Let's dig deeper:

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Security_Footage]
└─$ tshark -q -z http,tree -r security-footage.pcap

=======================================================================================================================================
HTTP / Packet Counter:
Packet Type             Count         Average       Min Val       Max Val       Rate (ms)     Percent       Burst Rate    Burst Start  
---------------------------------------------------------------------------------------------------------------------------------------
Total HTTP Packets      1                                                                     100%          0.0100        0.000        
 HTTP Request Packets   1                                                                     100.00%       0.0100        0.000        
  GET                   1                                                                     100.00%       0.0100        0.000        
 Other HTTP Packets     0                                                                     0.00%         -             -            
 HTTP Response Packets  0                                                                     0.00%         -             -            
  ???: broken           0                                                                                   -             -            
  5xx: Server Error     0                                                                                   -             -            
  4xx: Client Error     0                                                                                   -             -            
  3xx: Redirection      0                                                                                   -             -            
  2xx: Success          0                                                                                   -             -            
  1xx: Informational    0                                                                                   -             -            

---------------------------------------------------------------------------------------------------------------------------------------
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Security_Footage]
└─$ tshark -q -z http,stat -r security-footage.pcap 

===================================================================
HTTP Statistics
* HTTP Response Status Codes                Packets
* HTTP Request Methods                      Packets
  GET                                             1 
===================================================================
```

Only one HTTP GET-request...!?

A failed attempt was then made to `Export Object` -> `HTTP...` but Wireshark couldn't extract anything.

#### Extract image files

We need to try another tool. `tcpxtract` to the rescue:

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Security_Footage]
└─$ tcpxtract -f security-footage.pcap 
Found file of type "html" in session [10.0.2.15:18597 -> 192.168.1.100:37151], exporting to 00000000.html
Found file of type "html" in session [10.0.2.15:18597 -> 192.168.1.100:37151], exporting to 00000001.html
Found file of type "jpg" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000002.jpg
Found file of type "bmp" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000003.bmp
Found file of type "jpg" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000004.jpg
Found file of type "bmp" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000005.bmp
Found file of type "jpg" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000006.jpg
Found file of type "bmp" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000007.bmp
Found file of type "jpg" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000008.jpg
Found file of type "bmp" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000009.bmp
Found file of type "jpg" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000010.jpg
Found file of type "bmp" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000011.bmp
Found file of type "jpg" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000012.jpg
Found file of type "bmp" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000013.bmp
Found file of type "jpg" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000014.jpg
Found file of type "bmp" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000015.bmp
Found file of type "jpg" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000016.jpg
Found file of type "bmp" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000017.bmp
Found file of type "jpg" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000018.jpg
Found file of type "bmp" in session [192.168.1.100:37151 -> 10.0.2.15:18597], exporting to 00000019.bmp
<---snip--->
```

Looking at the .jpg images we see a small piece of the flag in each frame

![Security Footage Example Frame](Images/Security_Footage_Example_Frame.jpg)

#### Get the flag

The flag was manually created by looking through the images:

`flag{5<REDACTED>}`

For additional information, please see the references below.

## References

- [tcpxtract - Linux manual page](https://linux.die.net/man/1/tcpxtract)
- [tshark(1) Manual Page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Wireshark Home page](https://www.wireshark.org/)
