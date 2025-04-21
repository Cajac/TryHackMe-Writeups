# Networking Core Protocols

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Premium
Description: Learn about the core TCP/IP protocols.
```

Room link: [https://tryhackme.com/room/networkingcoreprotocols](https://tryhackme.com/room/networkingcoreprotocols)

## Solution

### Task 1: Introduction

This room is the third room in a series of four rooms about computer networking:

- Networking Concepts
- Networking Essentials
- Networking Core Protocols (this room)
- Networking Secure Protocols

#### Room Prerequisites

To benefit from this room, we recommend that you know the following:

- ISO OSI model and layers
- TCP/IP model and layers
- Ethernet, IP, and TCP protocols

In other words, starting this room after Networking Concepts is the recommended approach.

#### Learning Objectives

By the time you finish this room, you will have learned about the following protocols:

- WHOIS
- DNS
- HTTP and FTP
- SMTP, POP3, and IMAP

### Task 2: DNS: Remembering Addresses

Do you remember the IP addresses of your favourite websites? Unless it is a private IP address of a local device, no one needs to worry about memorizing IP addresses. This is in part due to the Domain Name System (DNS), which is responsible for properly mapping a domain name to an IP address.

DNS operates at the Application Layer, i.e., Layer 7 of the ISO OSI model. DNS traffic uses UDP port 53 by default and TCP port 53 as a default fallback. There are many types of DNS records; however, in this task, we will focus on the following four:

- **A record**: The A (Address) record maps a hostname to one or more IPv4 addresses. For example, you can set `example.com` to resolve to `172.17.2.172`.
- **AAAA Record**: The AAAA record is similar to the A Record, but it is for IPv6. Remember that it is AAAA (quad-A), as AA and AAA would refer to a battery size; furthermore, AAA refers to Authentication, Authorization, and Accounting; neither falls under DNS.
- **CNAME Record**: The CNAME (Canonical Name) record maps a domain name to another domain name. For example, `www.example.com` can be mapped to `example.com` or even to `example.org`.
- **MX Record**: The MX (Mail Exchange) record specifies the mail server responsible for handling emails for a domain.

In other words, when you type `example.com` in your browser, your browser tries to resolve this domain name by querying the DNS server for the `A` record. However, when you try to send an email to `test@example.com`, the mail server would query the DNS server to find the `MX` record.

If you want to look up the IP address of a domain from the command line, you can use a tool such as `nslookup`. Consider the example in the terminal below where we look up `example.com`.

```bash
user@TryHackMe$ nslookup www.example.com
Server:         127.0.0.53
Address:        127.0.0.53#53

Non-authoritative answer:
Name:   www.example.com
Address: 93.184.215.14
Name:   www.example.com
Address: 2606:2800:21f:cb07:6820:80da:af6b:8b2c
```

The query above led to four packets. In the terminal below, we can see that the first and third packets send DNS queries for the `A` and `AAAA` records, respectively. The second and fourth packets show the DNS query responses.

```bash
user@TryHackMe$ tshark -r dns-query.pcapng -Nn
    1 0.000000000 192.168.66.89 → 192.168.66.1 DNS 86 Standard query 0x2e0f A www.example.com OPT
    2 0.059049584 192.168.66.1 → 192.168.66.89 DNS 102 Standard query response 0x2e0f A www.example.com A 93.184.215.14 OPT
    3 0.059721705 192.168.66.89 → 192.168.66.1 DNS 86 Standard query 0x96e1 AAAA www.example.com OPT
    4 0.101568276 192.168.66.1 → 192.168.66.89 DNS 114 Standard query response 0x96e1 AAAA www.example.com AAAA 2606:2800:21f:cb07:6820:80da:af6b:8b2c OPT
```

#### Which DNS record type refers to IPv6?

Answer: AAAA

#### Which DNS record type refers to the email server?

Answer: MX

### Task 3: WHOIS

In the previous task, we covered how a domain name is resolved into an IP address. However, for this to happen, someone needs to have the authority to set the `A`, `AAAA`, and `MX` records, among other DNS records for the domain. Whoever registers a domain name is granted this power. Therefore, if you register `example.com`, you can set any valid DNS records for `example.com`.

You can register any available domain name for one or more years. You need to pay the annual fee, and you are required to provide accurate contact information as the registrant. This information is part of the data available via WHOIS records and is available publicly. (Although written in uppercase, WHOIS is not an acronym; it is pronounced who is.) However, don’t worry if you want to register a domain without revealing your contact information publicly; you can use one of the privacy services that hide all your information from the WHOIS records.

You can look up the WHOIS records of any registered domain name using one of the online services or via the command-line tool `whois`, available on Linux systems, among others. As expected, a WHOIS record provides information about the entity that registered a domain name, including name, phone number, email, and address. In the screenshot shown below, you can see when the record was first created and when it was last updated. Moreover, you can find the registrant’s name, address, phone, and email.

In the terminal output below, we have used the whois command to look up a domain whose WHOIS record is protected by privacy protection.

```bash
user@TryHackMe$ whois [REDACTED].com
[...]
Domain Name: [REDACTED].COM
Registry Domain ID: [REDACTED]
Registrar WHOIS Server: whois.godaddy.com
Registrar URL: https://www.godaddy.com
Updated Date: 2017-07-05T16:02:43Z
Creation Date: 1993-04-02T00:00:00Z
Registrar Registration Expiration Date: 2026-10-20T14:56:17Z
Registrar: GoDaddy.com, LLC
Registrar IANA ID: 146
Registrar Abuse Contact Email: abuse@godaddy.com
Registrar Abuse Contact Phone: +1.4806242505
[...]
Registrant Name: Registration Private
Registrant Organization: Domains By Proxy, LLC
Registrant Street: DomainsByProxy.com
[...]
```

#### When was the x.com record created? Provide the answer in YYYY-MM-DD format.

Hint: You can use the command line tool whois on the AttackBox. Alternatively, you can use an online WHOIS lookup service.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Networking_Core_Protocols]
└─$ whois x.com                                                  
   Domain Name: X.COM
   Registry Domain ID: 1026563_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.godaddy.com
   Registrar URL: http://www.godaddy.com
   Updated Date: 2024-12-03T21:03:37Z
   Creation Date: 1993-04-02T05:00:00Z
   Registry Expiry Date: 2034-10-20T19:56:17Z
   Registrar: GoDaddy.com, LLC
   Registrar IANA ID: 146
   Registrar Abuse Contact Email: abuse@godaddy.com
   Registrar Abuse Contact Phone: 480-624-2505
<---snip--->
```

Answer: 1993-04-02

#### When was the twitter.com record created? Provide the answer in YYYY-MM-DD format.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Networking_Core_Protocols]
└─$ whois twitter.com
   Domain Name: TWITTER.COM
   Registry Domain ID: 18195971_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.corporatedomains.com
   Registrar URL: http://cscdbs.com
   Updated Date: 2025-01-17T06:08:06Z
   Creation Date: 2000-01-21T16:28:17Z
   Registry Expiry Date: 2026-01-21T16:28:17Z
   Registrar: CSC Corporate Domains, Inc.
   Registrar IANA ID: 299
   Registrar Abuse Contact Email: domainabuse@cscglobal.com
   Registrar Abuse Contact Phone: 8887802723
<---snip--->
```

Answer: 2000-01-21

### Task 4: HTTP(S): Accessing the Web

When you fire up your browser, you mainly use HTTP and HTTPS protocols. HTTP stands for Hypertext Transfer Protocol; the S in HTTPS stands for Secure. This protocol relies on TCP and defines how your web browser communicates with the web servers.

Some of the commands or methods that your web browser commonly issues to the web server are:

- **GET** retrieves data from a server, such as an HTML file or an image.
- **POST** allows us to submit new data to the server, such as submitting a form or uploading a file.
- **PUT** is used to create a new resource on the server and to update and overwrite existing information.
- **DELETE**, as the name suggests, is used to delete a specified file or resource on the server.

HTTP and HTTPS commonly use TCP ports 80 and 443, respectively, and less commonly other ports such as 8080 and 8443.

As you remember from Networking Concepts, we used the `telnet` client to connect to the web server running on `10.10.24.38` at port `80`. We had to send a couple of lines: `GET / HTTP/1.1` and `Host: anything` to get the page we wanted. (On some servers, you might get the file without sending `Host: anything`.) You can use this method to access any page and not just the default page `/`. To get `file.html`, you would send `GET /file.html HTTP/1.1`, for instance (`GET /file.html` might work depending on the web server in use). This approach is efficient for troubleshooting as you would be “talking HTTP” with the server.

#### Use telnet to access the file flag.html on 10.10.24.38. What is the hidden flag?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Networking_Core_Protocols]
└─$ telnet 10.10.24.38 80
Trying 10.10.24.38...
Connected to 10.10.24.38.
Escape character is '^]'.
GET /flag.html HTTP/1.0

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 21 Apr 2025 10:47:38 GMT
Content-Type: text/html
Content-Length: 478
Last-Modified: Thu, 27 Jun 2024 07:28:15 GMT
Connection: close
ETag: "667d148f-1de"
Accept-Ranges: bytes

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hidden Message</title>
    <style>
        body {
            background-color: white;
            color: white;
            font-family: Arial, sans-serif;
        }
        .hidden-text {
            font-size: 1px;
        }
    </style>
</head>
<body>
    <div class="hidden-text">THM{<REDACTED>}</div>
</body>
</html>

Connection closed by foreign host.
```

Answer: `THM{<REDACTED>}`

### Task 5: FTP: Transferring Files

Unlike HTTP, which is designed to retrieve web pages, File Transfer Protocol (FTP) is designed to transfer files. As a result, FTP is very efficient for file transfer, and when all conditions are equal, it can achieve higher speeds than HTTP.

Example commands defined by the FTP protocol are:

- **USER** is used to input the username
- **PASS** is used to enter the password
- **RETR** (retrieve) is used to download a file from the FTP server to the client.
- **STOR** (store) is used to upload a file from the client to the FTP server.

FTP server listens on TCP port 21 by default; data transfer is conducted via another connection from the client to the server.

In the terminal below we executed the command ftp 10.10.24.38 to connect to the remote FTP server using the local ftp client. Then we went through the following steps:

- We used the username `anonymous` to log in
- We didn’t need to provide any password
- Issuing `ls` returned a list of files available for download
- `type ascii` switched to ASCII mode as this is a text file
- `get coffee.txt` allowed us to retrieve the file we want

The command exchange via the FTP client is shown in the terminal below.

```bash
user@TryHackMe$ ftp 10.10.24.38
Connected to 10.10.24.38 (10.10.24.38).
220 (vsFTPd 3.0.5)
Name (10.10.24.38:strategos): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
227 Entering Passive Mode (10,10,41,192,134,10).
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1480 Jun 27 08:03 coffee.txt
-rw-r--r--    1 0        0              14 Jun 27 08:04 flag.txt
-rw-r--r--    1 0        0            1595 Jun 27 08:05 tea.txt
226 Directory send OK.
ftp> type ascii
200 Switching to ASCII mode.
ftp> get coffee.txt
local: coffee.txt remote: coffee.txt
227 Entering Passive Mode (10,10,41,192,57,100).
150 Opening BINARY mode data connection for coffee.txt (1480 bytes).
WARNING! 47 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
1480 bytes received in 8e-05 secs (18500.00 Kbytes/sec)
ftp> quit
221 Goodbye.
```

#### Using the FTP client ftp on the AttackBox, access the FTP server at 10.10.24.38 and retrieve flag.txt. What is the flag found?

Hint: Use anonymous access, i.e., enter anonymous as USER and a blank password.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Networking_Core_Protocols]
└─$ ftp 10.10.24.38 
Connected to 10.10.24.38.
220 (vsFTPd 3.0.5)
Name (10.10.24.38:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||47126|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1480 Jun 27  2024 coffee.txt
-rw-r--r--    1 0        0              14 Jun 27  2024 flag.txt
-rw-r--r--    1 0        0            1595 Jun 27  2024 tea.txt
226 Directory send OK.
ftp> ascii
200 Switching to ASCII mode.
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||55479|)
150 Opening BINARY mode data connection for flag.txt (14 bytes).
100% |**********************************************************************************************************************************************|    14       58.67 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 1 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
14 bytes received in 00:00 (0.26 KiB/s)
ftp> close
221 Goodbye.
ftp> quit

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Networking_Core_Protocols]
└─$ cat flag.txt                
THM{<REDACTED>}
```

Answer: `THM{<REDACTED>}`

### Task 6: SMTP: Sending Email

As with browsing the web and downloading files, sending email needs its own protocol. Simple Mail Transfer Protocol (SMTP) defines how a mail client talks with a mail server and how a mail server talks with another.

The analogy for the SMTP protocol is when you go to the local post office to send a package. You greet the employee, tell them where you want to send your package, and provide the sender’s information before handing them the package. Depending on the country you are in, you might be asked to show your identity card. This process is not very different from an SMTP session.

Let’s present some of the commands used by your mail client when it transfers an email to an SMTP server:

- `HELO` or `EHLO` initiates an SMTP session
- `MAIL FROM` specifies the sender’s email address
- `RCPT TO` specifies the recipient’s email address
- `DATA` indicates that the client will begin sending the content of the email message
- `.` is sent on a line by itself to indicate the end of the email message

The terminal below shows an example of an email sent via telnet. The SMTP server listens on TCP port 25 by default.

```bash
user@TryHackMe$ telnet 10.10.24.38 25
Trying 10.10.24.38...
Connected to 10.10.24.38.
Escape character is '^]'.
220 example.thm ESMTP Exim 4.95 Ubuntu Thu, 27 Jun 2024 16:18:09 +0000
HELO client.thm
250 example.thm Hello client.thm [10.11.81.126]
MAIL FROM: <user@client.thm>
250 OK
RCPT TO: <strategos@server.thm>
250 Accepted
DATA
354 Enter message, ending with "." on a line by itself
From: user@client.thm
To: strategos@server.thm
Subject: Telnet email

Hello. I am using telnet to send you an email!
.
250 OK id=1sMrpq-0001Ah-UT
QUIT
221 example.thm closing connection
Connection closed by foreign host.
```

Now that we have covered some basic HTTP, FTP, and SMTP commands, you should have gained a solid understanding of how protocols are designed and used. It should be effortless to learn how other text-based protocols, such as POP3 and IMAP, work.

#### Which SMTP command indicates that the client will start the contents of the email message?

Answer: DATA

#### What does the email client send to indicate that the email message has been fully entered?

Answer: .

### Task 7: POP3: Receiving Email

You’ve received an email and want to download it to your local mail client. The Post Office Protocol version 3 (POP3) is designed to allow the client to communicate with a mail server and retrieve email messages.

Without going into in-depth technical details, an email client sends its messages by relying on SMTP and retrieves them using POP3. SMTP is similar to handing your envelope or package to the post office, and POP3 is similar to checking your local mailbox for new letters or packages.

Some common POP3 commands are:

- `USER <username>` identifies the user
- `PASS <password>` provides the user’s password
- `STAT` requests the number of messages and total size
- `LIST` lists all messages and their sizes
- `RETR <message_number>` retrieves the specified message
- `DELE <message_number>` marks a message for deletion
- `QUIT` ends the POP3 session applying changes, such as deletions

In the terminal below, we can see a POP3 session over telnet. Since the POP3 server listens on TCP port 110 by default, the command to connect to the TELNET port is telnet 10.10.24.38 110. The exchange below retrieves the email message sent in the previous task.

```bash
user@TryHackMe$ telnet 10.10.24.38 110
Trying 10.10.24.38...
Connected to 10.10.24.38.
Escape character is '^]'.
+OK [XCLIENT] Dovecot (Ubuntu) ready.
AUTH
+OK
PLAIN
.
USER strategos
+OK
PASS 
+OK Logged in.
STAT
+OK 3 1264
LIST
+OK 3 messages:
1 407
2 412
3 445
.
RETR 3
+OK 445 octets
Return-path: <user@client.thm>
Envelope-to: strategos@server.thm
Delivery-date: Thu, 27 Jun 2024 16:19:35 +0000
Received: from [10.11.81.126] (helo=client.thm)
        by example.thm with smtp (Exim 4.95)
        (envelope-from <user@client.thm>)
        id 1sMrpq-0001Ah-UT
        for strategos@server.thm;
        Thu, 27 Jun 2024 16:19:35 +0000
From: user@client.thm
To: strategos@server.thm
Subject: Telnet email

Hello. I am using telnet to send you an email!
.
QUIT
+OK Logging out.
Connection closed by foreign host.
```

Connecting to a POP3 server requires authentication. Use the following login credentials when needed:

- Username: linda
- Password: Pa$$123

#### Looking at the traffic exchange, what is the name of the POP3 server running on the remote server?

Hint: Use your favourite search engine for the word next to Ubuntu.

```bash
user@TryHackMe$ telnet 10.10.24.38 110
Trying 10.10.24.38...
Connected to 10.10.24.38.
Escape character is '^]'.
+OK [XCLIENT] Dovecot (Ubuntu) ready.
AUTH
<---snip--->
```

Answer: Dovecot

#### Use telnet to connect to 10.10.24.38’s POP3 server. What is the flag contained in the fourth message?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Networking_Core_Protocols]
└─$ telnet 10.10.24.38 110
Trying 10.10.24.38...
Connected to 10.10.24.38.
Escape character is '^]'.
+OK [XCLIENT] Dovecot (Ubuntu) ready.
USER linda
+OK
PASS Pa$$123
+OK Logged in.
RETR 4
+OK 454 octets
Return-path: <user@client.thm>
Envelope-to: linda@server.thm
Delivery-date: Thu, 12 Sep 2024 20:12:42 +0000
Received: from [10.11.81.126] (helo=client.thm)
        by example.thm with smtp (Exim 4.95)
        (envelope-from <user@client.thm>)
        id 1soqAj-0007li-39
        for linda@server.thm;
        Thu, 12 Sep 2024 20:12:42 +0000
From: user@client.thm
To: linda@server.thm
Subject: Your Flag

Hello!
Here's your flag:
THM{<REDACTED>}
Enjoy your journey!
.
QUIT
+OK Logging out.
Connection closed by foreign host.
```

Answer: `THM{<REDACTED>}`

### Task 8: IMAP: Synchronizing Email

POP3 is enough when working from one device, e.g., your favourite email client on your desktop computer. However, what if you want to check your email from your office desktop computer and from your laptop or smartphone? In this scenario, you need a protocol that allows synchronization of messages instead of deleting a message after retrieving it. One solution to maintaining a synchronized mailbox across multiple devices is Internet Message Access Protocol (IMAP).

IMAP allows synchronizing read, moved, and deleted messages. IMAP is quite convenient when you check your email via multiple clients. Unlike POP3, which tends to minimize server storage as email is downloaded and deleted from the remote server, IMAP tends to use more storage as email is kept on the server and synchronized across the email clients.

The IMAP protocol commands are more complicated than the POP3 protocol commands. We list a few examples below:

- `LOGIN <username> <password>` authenticates the user
- `SELECT <mailbox>` selects the mailbox folder to work with
- `FETCH <mail_number> <data_item_name>` Example `fetch 3 body[]` to fetch message number 3, header and body.
- `MOVE <sequence_set> <mailbox>` moves the specified messages to another mailbox
- `COPY <sequence_set> <data_item_name>` copies the specified messages to another mailbox
- `LOGOUT` logs out

Knowing that the IMAP server listens on TCP port 143 by default, we will use telnet to connect to 10.10.24.38’s port 143 and fetch the message we sent in an earlier task.

```bash
user@TryHackMe$ telnet 10.10.41.192 143
Trying 10.10.41.192...
Connected to 10.10.41.192.
Escape character is '^]'.
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN] Dovecot (Ubuntu) ready.
A LOGIN strategos
A OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY PREVIEW STATUS=SIZE SAVEDATE LITERAL+ NOTIFY SPECIAL-USE] Logged in
B SELECT inbox
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
* 4 EXISTS
* 0 RECENT
* OK [UNSEEN 2] First unseen.
* OK [UIDVALIDITY 1719824692] UIDs valid
* OK [UIDNEXT 5] Predicted next UID
B OK [READ-WRITE] Select completed (0.001 + 0.000 secs).
C FETCH 3 body[]
* 3 FETCH (BODY[] {445}
Return-path: <user@client.thm>
Envelope-to: strategos@server.thm
Delivery-date: Thu, 27 Jun 2024 16:19:35 +0000
Received: from [10.11.81.126] (helo=client.thm)
        by example.thm with smtp (Exim 4.95)
        (envelope-from <user@client.thm>)
        id 1sMrpq-0001Ah-UT
        for strategos@server.thm;
        Thu, 27 Jun 2024 16:19:35 +0000
From: user@client.thm
To: strategos@server.thm
Subject: Telnet email

Hello. I am using telnet to send you an email!
)
C OK Fetch completed (0.001 + 0.000 secs).
D LOGOUT
* BYE Logging out
D OK Logout completed (0.001 + 0.000 secs).
Connection closed by foreign host.
```

#### What IMAP command retrieves the fourth email message?

Hint: We want to download the body[]

Answer: fetch 4 body[]

### Task 9: Conclusion

In the previous room, we discussed the TELNET protocol; this room focused on other fundamental protocols: DNS, HTTP, FTP, SMTP, POP3, and IMAP. With the protocols covered, we now have a better understanding of how domain names are resolved, how web pages are served, and how email is sent and received. Another primary purpose of this room is to give you a good understanding of how a protocol functions behind the graphical interfaces.

The table below summarizes the default port numbers of the protocols we have covered so far.

| Protocol | Transport Protocol | Default Port Number |
|----|----|----|
|TELNET|TCP|23|
|DNS|UDP or TCP|53|
|HTTP|TCP|80|
|HTTPS|TCP|443|
|FTP|TCP|21|
|SMTP|TCP|25|
|POP3|TCP|110|
|IMAP|TCP|143|

For additional information, please see the references below.

## References

- [Domain Name System - Wikipedia](https://en.wikipedia.org/wiki/Domain_Name_System)
- [File Transfer Protocol - Wikipedia](https://en.wikipedia.org/wiki/File_Transfer_Protocol)
- [ftp - Linux manual page](https://linux.die.net/man/1/ftp)
- [HTTP - Wikipedia](https://en.wikipedia.org/wiki/HTTP)
- [HTTPS - Wikipedia](https://en.wikipedia.org/wiki/HTTPS)
- [HTTP request methods - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods)
- [Internet Message Access Protocol - Wikipedia](https://en.wikipedia.org/wiki/Internet_Message_Access_Protocol)
- [List of DNS record types - Wikipedia](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
- [nslookup - Linux manual page](https://linux.die.net/man/1/nslookup)
- [Post Office Protocol - Wikipedia](https://en.wikipedia.org/wiki/Post_Office_Protocol)
- [Simple Mail Transfer Protocol - Wikipedia](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol)
- [telnet - Linux manual page](https://linux.die.net/man/1/telnet)
- [Telnet - Wikipedia](https://en.wikipedia.org/wiki/Telnet)
- [whois - Linux manual page](https://linux.die.net/man/1/whois)
- [WHOIS - Wikipedia](https://en.wikipedia.org/wiki/WHOIS)
