# TShark Challenge II: Directory

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
Tags: Linux
Subscription type: Premium
Description:
Put your TShark skills into practice and analyse some network traffic.
```

Room link: [https://tryhackme.com/room/tsharkchallengestwo](https://tryhackme.com/room/tsharkchallengestwo)

## Solution

### Task 1: Introduction

This room presents you with a challenge to investigate some traffic data as a part of the SOC team. Let's start working with TShark to analyse the captured traffic. We recommend completing the [TShark: The Basics](https://tryhackme.com/room/tsharkthebasics) and [TShark: CLI Wireshark Features](https://tryhackme.com/room/tsharkcliwiresharkfeatures) rooms first, which will teach you how to use the tool in depth.

Start the VM by pressing the green **Start Machine** button attached to this task. The machine will start in split view, so you don't need SSH or RDP. In case the machine does not appear, you can click the blue **Show Split View** button located at the top of this room.

**NOTE**: Exercise files contain real examples. **DO NOT** interact with them outside of the given VM. Direct interaction with samples and their contents (files, domains, and IP addresses) outside the given VM can pose security threats to your machine.

### Task 2: Case: Directory Curiosity

An **alert has been triggered**: "A user came across a poor file index, and their curiosity led to problems".

The case was assigned to you. Inspect the provided **directory-curiosity.pcap** located in `~/Desktop/exercise-files` and retrieve the artefacts to confirm that this alert is a true positive.

**Your tools**: TShark, [VirusTotal](https://www.virustotal.com/gui/home/upload).

---------------------------------------------------------------------------------------

#### What is the name of the malicious/suspicious domain? Enter your answer in defanged format

Hint: Cyberchef can defang.

We start by checking for DNS-requests

```bash
ubuntu@ip-10-66-142-97:~$ cd Desktop/exercise-files/
ubuntu@ip-10-66-142-97:~/Desktop/exercise-files$ ls -l
total 184
-rw-r--r-- 1 ubuntu ubuntu 186280 Feb 19  2024 directory-curiosity.pcap
ubuntu@ip-10-66-142-97:~/Desktop/exercise-files$ tshark -r directory-curiosity.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -rn
      4 www.bing.com
      2 r20swj13mr.microsoft.com
      2 ocsp.digicert.com
      2 jx2-bavuong.com
      2 iecvlist.microsoft.com
      2 api.bing.com
```

and for HTTP requests

```bash
ubuntu@ip-10-66-142-97:~/Desktop/exercise-files$ tshark -Y http.request -T fields -e http.host -e http.request.method -e http.request.uri -r directory-curiosity.pcap | sort | uniq -c | sort -rn
      8 239.255.255.250:1900    M-SEARCH    *
      3 ocsp.digicert.com    GET    /MFEwTzBNMEswSTAJBgUrDgMCGgUABBSAUQYBMq2awn1Rh6Doh%2FsBYgFV7gQUA95QNVbRTLtm8KPiGxvDl7I90VUCEAJ0LqoXyo4hxxe7H%2Fz9DKA%3D
      2 jx2-bavuong.com    GET    /vlauto.exe
      1 www.bing.com    GET    /favicon.ico
      1 jx2-bavuong.com    GET    /newbot/target.port
      1 jx2-bavuong.com    GET    /newbot/target.method
      1 jx2-bavuong.com    GET    /newbot/target.ip
      1 jx2-bavuong.com    GET    /newbot/target
      1 jx2-bavuong.com    GET    /newbot/proxy
      1 jx2-bavuong.com    GET    /newbot/botlogger.php
      1 jx2-bavuong.com    GET    /newbot/blog
      1 jx2-bavuong.com    GET    /icons/text.gif
      1 jx2-bavuong.com    GET    /icons/blank.gif
      1 jx2-bavuong.com    GET    /icons/binary.gif
      1 jx2-bavuong.com    GET    /favicon.ico
      1 jx2-bavuong.com    GET    /
```

The domain that sticks out is `jx2-bavuong.com`.

Checking it on [VirusTotal](https://www.virustotal.com/gui/domain/jx2-bavuong.com) results in 4 hits as a `Malicious` or `Malware` domain.

Answer: `jx2-bavuong[.]com`

#### What is the total number of HTTP requests sent to the malicious domain?

Hint: The "http.request.full_uri" filter can help.

```bash
ubuntu@ip-10-66-142-97:~/Desktop/exercise-files$ tshark -Y 'http.host contains "jx2-bavuong.com"' -T fields -e http.host -e http.request.method -e http.request.uri -r directory-curiosity.pcap | wc -l
14
```

Answer: `14`

#### What is the IP address of the malicious domain? Enter your answer in defanged format

```bash
ubuntu@ip-10-66-142-97:~/Desktop/exercise-files$ tshark -r directory-curiosity.pcap -Y dns.a -T fields -e dns.qry.name -e dns.a | sort | uniq -c | sort -rn | grep jx2
      1 jx2-bavuong.com    141.164.41.174
```

Answer: `141[.]164[.]41[.]174`

#### What is the server info of the suspicious domain?

We extract the HTTP Server headers and also the source IPs so we know which header is the malicious one.

```bash
ubuntu@ip-10-66-142-97:~/Desktop/exercise-files$ tshark -Y 'http.server' -T fields -e ip.src -e http.server -r directory-curiosity.pcap | sort | uniq -c | sort -rn
     14 141.164.41.174    Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9
      3 93.184.220.29    ECS (pab/6FA8)
      2 93.184.220.29    ECS (pab/6F8D)
      1 204.79.197.200    Kestrel
```

Answer: `Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9`

#### Follow the "first TCP stream" in "ASCII". Investigate the output carefully. What is the number of listed files?

The first TCP stream has index 0. Let's extract it.

```bash
ubuntu@ip-10-66-142-97:~/Desktop/exercise-files$ tshark -q -z "follow,tcp,ascii,0" -r directory-curiosity.pcap 

===================================================================
Follow: tcp,ascii
Filter: tcp.stream eq 0
Node 0: 192.168.100.116:49170
Node 1: 141.164.41.174:80
251
GET / HTTP/1.1
Accept: text/html, application/xhtml+xml, */*
Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: gzip, deflate
Host: jx2-bavuong.com
DNT: 1
Connection: Keep-Alive


    1078
HTTP/1.1 200 OK
Date: Sun, 13 Dec 2020 00:51:46 GMT
Server: Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9
Content-Length: 829
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html;charset=UTF-8

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /</title>
 </head>
 <body>
<h1>Index of /</h1>
<pre><img src="/icons/blank.gif" alt="Icon "> <a href="?C=N;O=D">Name</a>                    <a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>  <a href="?C=D;O=A">Description</a><hr><img src="/icons/text.gif" alt="[TXT]"> <a href="123.php">123.php</a>                 12-Jul-2020 08:43    1   
<img src="/icons/binary.gif" alt="[   ]"> <a href="vlauto.exe">vlauto.exe</a>              06-May-2020 23:32   40K  
<img src="/icons/text.gif" alt="[TXT]"> <a href="vlauto.php">vlauto.php</a>              10-Jul-2020 23:25   93   
<hr></pre>
<address>Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9 Server at jx2-bavuong.com Port 80</address>
</body></html>

313
GET /icons/blank.gif HTTP/1.1
Accept: image/png, image/svg+xml, image/*;q=0.8, */*;q=0.5
Referer: http://jx2-bavuong.com/
Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: gzip, deflate
Host: jx2-bavuong.com
DNT: 1
Connection: Keep-Alive


    490
HTTP/1.1 200 OK
Date: Sun, 13 Dec 2020 00:51:46 GMT
Server: Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9
Last-Modified: Sat, 20 Nov 2004 13:16:24 GMT
ETag: "20000000053c6-94-3e9506e1a3a00"
Accept-Ranges: bytes
Content-Length: 148
Keep-Alive: timeout=5, max=99
Connection: Keep-Alive
Content-Type: image/gif

GIF89a...................!.NThis art is in the public domain. Kevin Hughes, kevinh@eit.com, September 1995.!.......,............................I..;
===================================================================
```

Formatting the HTML body slightly makes it easier to read

```html
 <body>
<h1>Index of /</h1>
<pre><img src="/icons/blank.gif" alt="Icon "> <a href="?C=N;O=D">Name</a>                    <a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>  <a href="?C=D;O=A">Description</a><hr>
<img src="/icons/text.gif" alt="[TXT]"> <a href="123.php">123.php</a>                 12-Jul-2020 08:43    1   
<img src="/icons/binary.gif" alt="[   ]"> <a href="vlauto.exe">vlauto.exe</a>              06-May-2020 23:32   40K  
<img src="/icons/text.gif" alt="[TXT]"> <a href="vlauto.php">vlauto.php</a>              10-Jul-2020 23:25   93   
<hr></pre>
<address>Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9 Server at jx2-bavuong.com Port 80</address>
</body>
```

We have 3 files (2 PHP-scripts and one EXE-file).

Answer: `3`

#### What is the filename of the first file? Enter your answer in a defanged format

Answer: `123[.]php`

Next, we export all HTTP traffic objects to the current directory.

```bash
ubuntu@ip-10-66-142-97:~/Desktop/exercise-files$ tshark -q --export-objects http,. -r directory-curiosity.pcap 
ubuntu@ip-10-66-142-97:~/Desktop/exercise-files$ ls
 %2f
 MFEwTzBNMEswSTAJBgUrDgMCGgUABBSAUQYBMq2awn1Rh6Doh%2FsBYgFV7gQUA95QNVbRTLtm8KPiGxvDl7I90VUCEAJ0LqoXyo4hxxe7H%2Fz9DKA%3D
'MFEwTzBNMEswSTAJBgUrDgMCGgUABBSAUQYBMq2awn1Rh6Doh%2FsBYgFV7gQUA95QNVbRTLtm8KPiGxvDl7I90VUCEAJ0LqoXyo4hxxe7H%2Fz9DKA%3D(1)'
'MFEwTzBNMEswSTAJBgUrDgMCGgUABBSAUQYBMq2awn1Rh6Doh%2FsBYgFV7gQUA95QNVbRTLtm8KPiGxvDl7I90VUCEAJ0LqoXyo4hxxe7H%2Fz9DKA%3D(2)'
'MFEwTzBNMEswSTAJBgUrDgMCGgUABBSAUQYBMq2awn1Rh6Doh%2FsBYgFV7gQUA95QNVbRTLtm8KPiGxvDl7I90VUCEAJ0LqoXyo4hxxe7H%2Fz9DKA%3D(3)'
'MFEwTzBNMEswSTAJBgUrDgMCGgUABBSAUQYBMq2awn1Rh6Doh%2FsBYgFV7gQUA95QNVbRTLtm8KPiGxvDl7I90VUCEAJ0LqoXyo4hxxe7H%2Fz9DKA%3D(4)'
 binary.gif
 blank.gif
 blog
 botlogger.php
 directory-curiosity.pcap
'favicon(1).ico'
 favicon.ico
 proxy
 target
 target.ip
 target.method
 target.port
 text.gif
'vlauto(1).exe'
 vlauto.exe
```

#### What is the name of the downloaded executable file? Enter your answer in a defanged format

Answer: `vlauto[.]exe`

#### What is the SHA256 value of the malicious file?

```bash
ubuntu@ip-10-66-142-97:~/Desktop/exercise-files$ sha256sum vlauto.exe 
b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de  vlauto.exe
```

Answer: `b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de`

#### What is the "PEiD packer" value?

Searching for this hash on VirtusTotal results in [this report](https://www.virustotal.com/gui/file/b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de).

The `Details` table gives us more information, including the PEiD packer.

Answer: `.NET executable`

#### What does the "Lastline Sandbox" flag this as?

The `Behaviour` tab shows us information from sandbox detonations where we also find the Lastline sandbox detection.

Answer: `MALWARE TROJAN`

For additional information, please see the references below.

## References

- [Domain Name System - Wikipedia](https://en.wikipedia.org/wiki/Domain_Name_System)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [HTTP - Wikipedia](https://en.wikipedia.org/wiki/HTTP)
- [pcap - Wikipedia](https://en.wikipedia.org/wiki/Pcap)
- [sha256sum - Linux manual page](https://man7.org/linux/man-pages/man1/sha256sum.1.html)
- [sort - Linux manual page](https://man7.org/linux/man-pages/man1/sort.1.html)
- [uniq - Linux manual page](https://man7.org/linux/man-pages/man1/uniq.1.html)
- [wc - Linux manual page](https://man7.org/linux/man-pages/man1/wc.1.html)
- [VirusTotal - Homepage](https://www.virustotal.com/gui/home/upload)
- [Wireshark - Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark - Homepage](https://www.wireshark.org/)
- [Wireshark - tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Wireshark - Wikipedia](https://en.wikipedia.org/wiki/Wireshark)
- [Wireshark - wireshark-filter Manual Page](https://www.wireshark.org/docs/man-pages/wireshark-filter.html)
