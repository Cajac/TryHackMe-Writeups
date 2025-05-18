# Web Enumeration

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Premium
Description: Learn the methodology of enumerating websites by using tools such as Gobuster, Nikto and WPScan
```

Room link: [https://tryhackme.com/room/webenumerationv2](https://tryhackme.com/room/webenumerationv2)

## Solution

### Task 1: Introduction

#### Introduction

Welcome to Web Enumeration! In this room, we'll be showcasing some of the most fundamental tools used in the enumeration stage of a web target. Good enumeration skills are vital in penetration testing -- how else are you supposed to know what you're targeting?! It is, however, rather easy to fall into rabbit holes.

The tools we'll showcase will hopefully make this process easier. You'll be able to apply the knowledge gained for each tool on an Instance dedicated to each tool.

#### Prerequisities for this lab

You will need to be connected to the [TryHackMe network](https://tryhackme.com/room/openvpn) if you are not using the TryHackMe AttackBox or Kali instance. Other than that, all you need is a good posture and some willpower!

**Note**: This room has been written as if you were using the TryHackMe AttackBox.

### Task 2: Manual Enumeration

We don't need to start unrolling the fancy toolkit from the get-go. More often than not, the results of using our own initiative over automated scans bare more results. For example, we may be able to find the "golden ticket" without making all of the noise. Let's outline some fundamentals skills involving you and your browser.

Your browser is as extensive as you are (and some!) and keeps records of the data it receives and who from. We can use this for a range of activities: finding that exact photo or more usefully -- the location of certain files or assets being loaded. This could include things from scripts to page URLs.

#### Using our Browsers Developer Console

Modern-day browsers including Chrome and Firefox have a suite of tools located in the "Developer Tools/Console". We're going to be discussing Firefox's, however, Chrome has a very similar suite. This suite includes a range of tools including:

- Viewing page source code
- Finding assets
- Debugging & executing code such as javascript on the client-side (our Browser)

Using `F12` on our keyboard, this is a shortcut to launch this suite of tools.

Inspecting Tool

![DevTools Inpecting Tools](Images/DevTools_Inpecting_Tools.png)

At first, we can see the web page with the heading "Hi Friend" and a section of the screen filled with the "Inspector" tool. This allows us to view the HTML source code of the webpage we have loaded in our browser. This often contains things such as developer comments, and the name to certain aspects of web page features including forms and the likes.

Developers often leave behind comments in the form of the `<!-- -->` tags...for example: `<!-- This is a comment -->` which are not rendered in the browser as we can see here:

![DevTools Inspecting Comments](Images/DevTools_Inspecting_Comments.png)

![DevTools Inspecting Comments 2](Images/DevTools_Inspecting_Comments_2.png)

### Task 3: 1. Introduction to Gobuster

#### Introduction to Gobuster

Welcome to the Gobuster portion of this room! This part of the room is aimed at complete beginners to enumeration and penetration testing. By completing this portion, you will have learned:

- How to install Gobuster on Kali Linux
- How to use the "dir" mode to enumerate directories and several of its most useful options
- How to use the "dns" mode to enumerate domains/subdomains and several of its most useful option
- Where to go for help

At the end of this section, you will have the opportunity to practice what you have learned by using Gobuster on another room, [Blog](https://tryhackme.com/room/blog). This room utilizes what's called a Content Management System (CMS) in order to make things easier for the user. These typically have large and varied directory structures...perfect for directory enumeration with Gobuster!

With the introduction out of the way, let's get started!

#### What is Gobuster?

As the name implies, Gobuster is written in [Go](https://golang.org/). Go is an open-source, low-level language (much like C or Rust) developed by a team at Google and other contributors. If you'd like to learn more about Go, visit the website linked above.

#### Installing Gobuster on Kali Linux

Luckily, installing Gobuster on Kali Linux does not require any installation of Go and does not carry with it a complicated install process. This means no building from source or running any other complicated commands. Ready?

`sudo apt install gobuster`

Done.

#### Useful Global Flags

There are some useful Global flags that can be used as well. I've included them in the table below. You can review these in the main documentation as well - [here](https://github.com/OJ/gobuster).

| Flag | Long Flag | Description |
|----|----|----|
|`-t`|`--threads`|Number of concurrent threads (default 10)|
|`-v`|`--verbose`|Verbose output|
|`-z`|`--no-progress`|Don't display progress|
|`-q`|`--quiet`|Don't print the banner and other noise|
|`-o`|`--output`|Output file to write results to|

I will typically change the number of threads to 64 to increase the speed of my scans. If you don't change the number of threads, Gobuster can be a little slow.

### Task 4: 1.1. Gobuster Modes

#### "dir" Mode

Dirbuster has a "dir" mode that allows the user to enumerate website directories. This is useful when you are performing a penetration test and would like to see what the directory structure of a website is. Often, directory structures of websites and web-apps follow a certain convention, making them susceptible to brute-forcing using wordlists. At the end of this room, you'll run Gobuster on [Blog](https://tryhackme.com/room/blog) which uses WordPress, a very common Content Management System (CMS). WordPress uses a very specific directory structure for its websites.

Gobuster is powerful because it not only allows you to scan the website, but it will return the status codes as well. This will immediately let you know if you as an outside user can request that directory or not. Additional functionality of Gobuster is that it lets you search for files as well with the addition of a simple flag!

#### Using "dir" Mode

To use "dir" mode, you start by typing `gobuster dir`. This isn't the full command, but just the start. This tells Gobuster that you want to perform a directory search, instead of one of its other methods (which we'll get to). It has to be written like this or else Gobuster will complain. After that, you will need to add the URL and wordlist using the `-u` and `-w` options, respectively. Like so:

`gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

**Note**: The URL is going to be the base path where Gobuster starts looking from. So the URL above is using the root web directory. For example, in a typical Apache installation on Linux, this is `/var/www/html`. So if you have a "**products**" directory and you want to enumerate that directory, you'd set the URL as `http://10.10.10.10/products`. You can also think of this like `http://example.com/path/to/folder`. Also notice that I specified the protocol of HTTP. This is important and required.

This is a very common, simple, and straightforward command for Gobuster. This is typically what I will run when doing capture the flag style rooms on TryHackMe. However, there are some other helpful flags that can be useful in certain scenarios

#### Other Useful Flags

These flags are useful in certain scenarios.  Note that these are not all of the flag options, but some of the more common ones that you'll use in penetration tests and in capture the flag events. If you'd like the full list, you can see that [here](https://github.com/OJ/gobuster#dir-mode-options).

| Flag | Long Flag | Description |
|----|----|----|
|`-c`|`--cookies`|Cookies to use for requests|
|`-x`|`--extensions`|File extension(s) to search for|
|`-H`|`--headers`|Specify HTTP headers, `-H 'Header1: val1'` `-H 'Header2: val2'`|
|`-k`|`--no-tls-validation`|Skip TLS certificate verification|
|`-n`|`--no-status`|Don't print status codes|
|`-U`|`--username`|Username for Basic Auth|
|`-P`|`--password`|Password for Basic Auth|
|`-s`|`--status-codes`|Positive status codes|
|`-b`|`--status-codes-blacklist`|Negative status codes|

A very common use of Gobuster's "dir" mode is the ability to use it's `-x` or `--extensions` flag to search for the contents of directories that you have already enumerated by providing a list of file extensions. File extensions are generally representative of the data they may contain. For example, **.conf** or **.config** files usually contain configurations for the application - including sensitive info such as database credentials.

A few other files that you may wish to search for are **.txt** files or other web application pages such as **.html** or **.php**. Let's assemble a command that would allow us to search the "myfolder" directory on a webserver for the following three files:

1. html
2. js
3. css

`gobuster dir -u http://10.10.252.123/myfolder -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x.html,.css,.js`

#### The -k Flag

The `-k` flag is special because it has an important use during penetration tests and captures the flag events. In a capture the flag room on TryHackMe for example, if HTTPS is enabled, you will most likely encounter an invalid cert error like the one below

![Web Error Cert Date Invalid](Images/Web_Error_Cert_Date_Invalid.png)

In instances like this, if you try to run Gobuster against this without the `-k` flag, it won't return anything and will most likely error out with something gross and will leave you sad. Don't worry though, easy fix! Just add the `-k` flag to your scan and it will bypass this invalid certification and continue scanning and deliver the goods!

**Note**: This flag can be used with "dir" mode and "vhost" modes

#### "dns" Mode

The next mode we'll focus on is the "dns" mode. This allows Gobuster to brute-force subdomains. During a penetration test (or capture the flag), it's important to check sub-domains of your target's top domain. Just because something is patched in the regular domain, does not mean it is patched in the sub-domain. There may be a vulnerability for you to exploit in one of these sub-domains. For example, if State Farm owns statefarm.com and mobile.statefarm.com, there may be a hole in mobile.statefarm.com that is not present in statefarm.com. This is why it is important to search for subdomains too!

#### Using "dns" Mode

To use "dns" mode, you start by typing `gobuster dns`. Just like "dir" mode, this isn't the full command, but just the start. This tells Gobuster that you want to perform a sub-domain brute-force, instead of one of one of the other methods as previously mentioned. It has to be written like this or else Gobuster will complain. After that, you will need to add the domain and wordlist using the `-d` and `-w` options, respectively. Like so:

`gobuster dns -d mydomain.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`

This tells Gobuster to do a sub-domain scan on the domain "mydomain.thm". If there are any sub-domains available, Gobuster will find them and report them to you in the terminal.

#### Other Useful Flags

`-d` and `-w` are the main flags that you'll need for most of your scans. But there are a few others that are worth mentioning that we can go over. They are in the table below.

| Flag | Long Flag | Description |
|----|----|----|
|`-c`|`--show-cname`|Show CNAME Records (cannot be used with '-i' option)|
|`-i`|`--show-ips`|Show IP Addresses|
|`-r`|`--resolver`|Use custom DNS server (format server.com or server.com:port)|

There aren't many additional flags to be used with this mode, but these are the main useful ones that you may use from time to time. If you'd like to see the full list of flags that can be used with this mode, check out the [documentation](https://github.com/OJ/gobuster#dns-mode-help)

#### "vhost" Mode

The last and final mode we'll focus on is the "vhost" mode. This allows Gobuster to brute-force virtual hosts. Virtual hosts are different websites on the same machine. In some instances, they can appear to look like sub-domains, but don't be deceived! Virtual Hosts are IP based and are running on the same server. This is not usually apparent to the end-user. On an engagement, it may be worthwhile to just run Gobuster in this mode to see if it comes up with anything. You never know, it might just find something! While participating in rooms on TryHackMe, virtual hosts would be a good way to hide a completely different website if nothing turned up on your main port 80/443 scan.

#### Using "vhost" Mode

To use "vhost" mode, you start by typing `gobuster vhost`. Just like the other modes, this isn't the full command, but just the start. This tells Gobuster that you want to perform a virtual host brute-force, instead of one of the other methods as previously mentioned. It has to be written like this or else Gobuster will complain. After that, you will need to add the domain and wordlist using the `-u` and `-w` options, respectively. Like so:

`gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`

This will tell Gobuster to do a virtual host scan `http://example.com` using the selected wordlist.

#### Other Useful Flags

A lot of the same flags that are useful for "dir" mode actually still apply to virtual host mode. Please check out the "dir" mode section for these and take a look at the [official documentation](https://github.com/OJ/gobuster#vhost-mode-options) for the full list. There's really too many that are similar to put them back here.

### Task 5: 1.2. Useful Wordlists

#### Useful Wordlists

There are many useful wordlists to use for each mode. These may or may not come in handy later on during the VM portion of the room! I'll go over some of the ones that are on Kali by default as well as a short section on SecLists.

#### Kali Linux Default Lists

Below you will find a useful list of wordlists that are installed on Kali Linux by default. This is as of the latest version at the time of writing which is 2020.3. Anything with a wildcard (*) character indicates there's more than one list that matches. Keep in mind, a lot of these can be interchanged between modes. For example, "dir" mode wordlists (such as ones from the dirbuster directory) will contain words like "admin", "index", "about", "events", etc. A lot of these could be subdomains as well. Give them a try with the different modes!

- /usr/share/wordlists/dirbuster/directory-list-2.3-*.txt
- /usr/share/wordlists/dirbuster/directory-list-1.0.txt
- /usr/share/wordlists/dirb/big.txt
- /usr/share/wordlists/dirb/common.txt
- /usr/share/wordlists/dirb/small.txt
- /usr/share/wordlists/dirb/extensions_common.txt - Useful for when fuzzing for files!

#### Non-Standard Lists

In addition to the above, Daniel Miessler has created an amazing GitHub repo called [SecLists](https://github.com/danielmiessler/SecLists). It compiles many different lists used for many different things. The best part is, it's in apt! You can `sudo apt install seclists` and get the entire repo! We won't dive into any other lists as there are many. However, between what's installed by default on Kali and the SecLists repo, I doubt you'll need anything else.

### Task 6: 1.3. Practical: Gobuster (Deploy #1)

#### Gobuster Challenges

Now's your chance to check what you've learned. Deploy the VM, **allow five minutes for it to fully deploy** and answer the following questions! Good luck!

You will also need to add "**webenum.thm**" to your `/etc/hosts` file to start off with like so:

`echo "MACHINE_IP webenum.thm" >> /etc/hosts`

You will also need to add any virtual hosts that you discover through the same way, before you can visit them in your browser i.e.:

`echo "MACHINE_IP mysubdomain.webenum.thm" >> /etc/hosts`

Any answer that has a list of items will have its answer formatted in the following way: **ans1,ans2**. Be sure to format your answers like that to get credit.

---------------------------------------------------------------------------------------

#### Run a directory scan on the host. Other than the standard css, images and js directories, what other directories are available?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -u http://webenum.thm
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://webenum.thm
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://webenum.thm/images/]
/public               (Status: 301) [Size: 311] [--> http://webenum.thm/public/]
/css                  (Status: 301) [Size: 308] [--> http://webenum.thm/css/]
/js                   (Status: 301) [Size: 307] [--> http://webenum.thm/js/]
/Changes              (Status: 301) [Size: 312] [--> http://webenum.thm/Changes/]
/VIDEO                (Status: 301) [Size: 310] [--> http://webenum.thm/VIDEO/]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

Answer: public,Changes,VIDEO

#### Run a directory scan on the host. In the "C******" directory, what file extensions exist?

Hint: You'll need to run a scan with the -x flag to look for some of the potentially interesting file types. Don't forget your wordlist!

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 64 -u http://webenum.thm/Changes -x html,txt,js,php,conf  
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://webenum.thm/Changes
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,js,php,conf,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 276]
/.php                 (Status: 403) [Size: 276]
/changes.conf         (Status: 200) [Size: 24]
/.html                (Status: 403) [Size: 276]
/.php                 (Status: 403) [Size: 276]
/bootstrap.js         (Status: 200) [Size: 151880]
Progress: 525984 / 525990 (100.00%)
===============================================================
Finished
===============================================================
```

Answer: conf,js

#### There's a flag out there that can be found by directory scanning! Find it

Hint: You can navigate to the directory or perform a directory scan with the file extension flag on this directory

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 64 -u http://webenum.thm/VIDEO -x html,txt,js,php,conf
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://webenum.thm/VIDEO
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              conf,html,txt,js,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/.html                (Status: 403) [Size: 276]
/flag.php             (Status: 200) [Size: 14]
Progress: 164488 / 525990 (31.27%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 165117 / 525990 (31.39%)
===============================================================
Finished
===============================================================

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ curl http://webenum.thm/VIDEO/flag.php 
thm{<REDACTED>}
```

Answer: `thm{<REDACTED>}`

#### There are some virtual hosts running on this server. What are they?

Hint: Can't find a wordlist to use? Check out SecLists

Scanning with gobuster v3.6 gave this strange result

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ gobuster vhost -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://webenum.thm
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://webenum.thm
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: 1 Status: 400 [Size: 424]
Found: 11192521404255 Status: 400 [Size: 424]
Found: 11192521403954 Status: 400 [Size: 424]
Found: gc._msdcs Status: 400 [Size: 424]
Found: 2 Status: 400 [Size: 424]
Found: 11285521401250 Status: 400 [Size: 424]
Found: 2012 Status: 400 [Size: 424]
Found: 11290521402560 Status: 400 [Size: 424]
Found: 123 Status: 400 [Size: 424]
Found: 2011 Status: 400 [Size: 424]
Found: 3 Status: 400 [Size: 424]
Found: 4 Status: 400 [Size: 424]
Found: 2013 Status: 400 [Size: 424]
Found: 2010 Status: 400 [Size: 424]
Found: 911 Status: 400 [Size: 424]
Found: 11 Status: 400 [Size: 424]
Found: 24 Status: 400 [Size: 424]
Found: 10 Status: 400 [Size: 424]
Found: 7 Status: 400 [Size: 424]
Found: 99 Status: 400 [Size: 424]
Found: 2009 Status: 400 [Size: 424]
Found: www.1 Status: 400 [Size: 424]
Found: 50 Status: 400 [Size: 424]
Found: 12 Status: 400 [Size: 424]
Found: 20 Status: 400 [Size: 424]
Found: 2008 Status: 400 [Size: 424]
Found: 25 Status: 400 [Size: 424]
Found: 15 Status: 400 [Size: 424]
Found: 5 Status: 400 [Size: 424]
Found: www.2 Status: 400 [Size: 424]
Found: 13 Status: 400 [Size: 424]
Found: 100 Status: 400 [Size: 424]
Found: 44 Status: 400 [Size: 424]
Found: 54 Status: 400 [Size: 424]
Found: 9 Status: 400 [Size: 424]
Found: 70 Status: 400 [Size: 424]
Found: 01 Status: 400 [Size: 424]
Found: 16 Status: 400 [Size: 424]
Found: 39 Status: 400 [Size: 424]
Found: 6 Status: 400 [Size: 424]
Found: www.123 Status: 400 [Size: 424]
Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================
```

So I rescanned with an older version on a Windows machine instead

```text
C:\Training>gobuster vhost -w C:\Sec-Lists\Discovery\DNS\subdomains-top1million-5000.txt -u http://webenum.thm
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://webenum.thm
[+] Threads:      10
[+] Wordlist:     C:\Sec-Lists\Discovery\DNS\subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2025/05/17 20:10:44 Starting gobuster
===============================================================
Found: learning.webenum.thm (Status: 200) [Size: 13245]
Found: products.webenum.thm (Status: 200) [Size: 4941]
===============================================================
2025/05/17 20:11:06 Finished
===============================================================
```

Answer: learning,products

#### There's another flag to be found in one of the virtual hosts! Find it

Hint: Remember, you'll have to perform a dir scan on these vhosts and use the file extension flag. What file format are flags usually stored in?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ cat /etc/hosts | grep webenum
10.10.247.203   webenum.thm learning.webenum.thm products.webenum.thm

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ echo 'flag' > only_flag.dict                          

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ gobuster dir -w only_flag.dict -t 64 -u http://learning.webenum.thm -x html,txt,js,php,conf 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://learning.webenum.thm
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                only_flag.dict
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,txt,js,php,conf
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 6 / 12 (50.00%)
===============================================================
Finished
===============================================================

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ gobuster dir -w only_flag.dict -t 64 -u http://products.webenum.thm -x html,txt,js,php,conf
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://products.webenum.thm
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                only_flag.dict
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,js,php,conf,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/flag.txt             (Status: 200) [Size: 21]

===============================================================
Finished
===============================================================

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ curl http://products.webenum.thm/flag.txt                            
thm{<REDACTED>}
```

Answer: `thm{<REDACTED>}`

### Task 7: 2. Introduction to WPScan

#### Introduction to WPScan

First released in June 2011, WPScan has survived the tests of time and stood out as a tool that every pentester should have in their toolkits.

The WPScan framework is capable of enumerating & researching a few security vulnerability categories present in WordPress sites - including - but not limited to:

- Sensitive Information Disclosure (Plugin & Theme installation versions for disclosed vulnerabilities or CVE's)
- Path Discovery (Looking for misconfigured file permissions i.e. wp-config.php)
- Weak Password Policies (Password bruteforcing)
- Presence of Default Installation (Looking for default files)
- Testing Web Application Firewalls (Common WAF plugins)

#### Installing WPScan

Thankfully for us, WPScan comes pre-installed on the latest versions of penetration testing systems such as Kali Linux and Parrot. If you are using an older version of Kali Linux (such as 2019) for example, WPScan is in the apt repository, so can be installed by a simple `sudo apt update && sudo apt install wpscan`

Installing WPScan on other operating systems such as Ubuntu or Debian involves extra steps. Whilst the TryHackMe AttackBox comes pre-installed with WPScan, you can follow the [developer's installation guide](https://github.com/wpscanteam/wpscan#install) for your local environment.

#### A Primer on WPScan's Database

WPScan uses information within a local database as a primary reference point when enumerating for themes and plugins. As we'll come to detail later, a technique that WPScan uses when enumerating is looking for common themes and plugins. Before using WPScan, it is highly recommended that you update this database before performing any scans.

Thankfully, this is an easy process to do. Simply run `wpscan --update`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ wpscan --update
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.
```

In the next task, we will explore some of the more useful features of WPScan!

### Task 8: 2.1. WPScan Modes

We briefly discussed the various things that `WPScan` is capable of discovering on a system running WordPress in Task 7. However, let's dive into this a bit further, demonstrate a few examples of the various scans used to retrieve this information and highlighting how these scans work exactly.

#### Enumerating for Installed Themes

`WPScan` has a few methods of determining the active theme on a running WordPress installation. At a premise, it boils down to a technique that we can manually do ourselves. Simply, we can look at the assets our web browser loads and then looks for the location of these on the webserver. Using the "Network" tab in your web browsers developer tools, you can see what files are loaded when you visit a webpage.

Take the screenshot below, we can see many assets are loaded, some of these will be scripts & the stylings of the theme that determines how the browser renders the website. Highlighted in the screenshot below is the URL: `http://redacted/wp-content/themes/twentytwentyone/assets/`

![WPScan Manual Discover Theme](Images/WPScan_Manual_Discover_Theme.png)

 We can take a pretty good guess that the name of the current theme is "twentytwentyone". After inspecting the source code of the website, we can note additional references to "twentytwentyone"

![WPScan Manual Discover Source](Images/WPScan_Manual_Discover_Source.png)

However, let's use `WPScan` to speed this process up by using the `--enumerate` flag with the `t` argument like so:

`wpscan --url http://cmnatics.playground/ --enumerate t`

After a couple of minutes, we can begin to see some results:

![WPScan Enumerating Themes](Images/WPScan_Enumerating_Themes.png)

The great thing about WPScan is that the tool lets you know how it determined the results it has got. In this case, we're told that the "twentytwenty" theme was confirmed by scanning "*Known Locations*". The "twentytwenty" theme is the default WordPress theme for WordPress versions in 2020.

#### Enumerating for Installed Plugins

A very common feature of webservers is "Directory Listing" and is often enabled by default. Simply, "Directory Listing" is the listing of files in the directory that we are navigating to (just as if we were to use Windows Explorer or Linux's `ls` command. URL's in this context are very similar to file paths. The URL `http://cmnatics.playground/a/directory` is actually the configured root of the webserver/a/directory.

"Directory Listing" occurs when there is no file present that the webserver has been told to process. A very common file is "index.html" and "index.php". As these files aren't present in /a/directory, the contents are instead displayed:

![WPScan Directory Listing](Images/WPScan_Directory_Listing.png)

`WPScan` can leverage this feature as one technique to look for plugins installed. Since they will all be located in `/wp-content/plugins/pluginname`, `WPScan` can enumerate for common/known plugins.

In the screenshot below, "easy-table-of-contents" has been discovered. Great! This could be vulnerable. To determine that, we need to know the version number. Luckily, this handed to us on a plate by WordPress.

![WPScan Enumerating Plugins](Images/WPScan_Enumerating_Plugins.png)

Reading through WordPress' developer documentation, we can learn about "[Plugin Readme's](https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/#how-the-readme-is-parsed)" to figure out how WPScan determined the version number. Simply, plugins must have a "README.txt" file. This file contains meta-information such as the plugin name, the versions of WordPress it is compatible with and a description.

![WPScan Example Plugin Readme](Images/WPScan_Example_Plugin_Readme.png)

[An Example ReadMe](https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/#example-readme). (WordPress Developer Documentation., 2021)

WPScan uses additional methods to discover plugins (such as looking for references or embeds on pages for plugin assets). We can use the `--enumerate` flag with the `p` argument like so:

`wpscan --url http://cmnatics.playground/ --enumerate p`

#### Enumerating for Users

We've highlighted that `WPScan` is capable of performing brute-forcing attacks. Whilst we must provide a password list such as `rockyou.txt`, the way how `WPScan` enumerates for users is interestingly simple. WordPress sites use authors for posts. Authors are in fact a type of user.

![WPScan User Example](Images/WPScan_User_Example.png)

And sure enough, this author is picked up by our WPScan:

![WPScan Enumerating Users](Images/WPScan_Enumerating_Users.png)

This scan was performed by using the `--enumerate` flag with the `u` argument like so:

`wpscan --url http://cmnatics.playground/ --enumerate u`

#### The "Vulnerable" Flag

In the commands so far, we have only enumerated WordPress to discover what themes, plugins and users are present. At the moment, we'd have to look at the output and use sites such as MITRE, NVD and CVEDetails to look up the names of these plugins and the version numbers to determine any vulnerabilities.

`WPScan` has the `v` argument for the `--enumerate` flag. We provide this argument alongside another (such as `p` for plugins). For example, our syntax would like so:

`wpscan --url http://cmnatics.playground/ --enumerate vp`

**Note**, that this requires setting up WPScan to use the WPVulnDB API which is out-of-scope for this room.

![WPScan WPVulnDB](Images/WPScan_WPVulnDB.png)

#### Performing a Password Attack

After determining a list of possible usernames on the WordPress install, we can use `WPScan` to perform a bruteforcing technique against the username we specify and a password list that we provide. Simply, we use the output of our username enumeration to build a command like so:

`wpscan –-url http://cmnatics.playground –-passwords rockyou.txt –-usernames cmnatic`

![WPScan Password Attack](Images/WPScan_Password_Attack.png)

#### Adjusting WPScan's Aggressiveness (WAF)

Unless specified, WPScan will try to be as least "noisy" as possible. Lots of requests to a web server can trigger things such as firewalls and ultimately result in you being blocked by the server.

This means that some plugins and themes may be missed by our WPScan. Luckily, we can use arguments such as `--plugins-detection` and an aggressiveness profile (passive/aggressive) to specify this. For example: `--plugins-detection aggressive`

#### Summary - Cheatsheet

| Flag | Description | Full Example |
|----|----|----|
|p|Enumerate Plugins|`--enumerate p`|
|t|Enumerate Themes|`--enumerate t`|
|u|Enumerate Usernames|`--enumerate -u`|
|v|Use WPVulnDB to cross-reference for vulnerabilities. Example command looks for vulnerable plugins (p)|`--enumerate vp`|
|aggressive|This is an aggressiveness profile for WPScan to use.|`--plugins-detection aggressive`|

---------------------------------------------------------------------------------------

#### What would be the full URL for the theme "twentynineteen" installed on the WordPress site: "http://cmnatics.playground"

Hint: We detail the default location for themes & plugins throughout this task!

Answer: `http://cmnatics.playground/wp-content/themes/twentynineteen`

#### What argument would we provide to enumerate a WordPress site?

Hint: We're looking for the keyword here

Answer: enumerate

#### What is the name of the other aggressiveness profile that we can use in our WPScan command?

Hint: This is more likely to bypass a Web Application Firewall (WAF)

Answer: passive

### Task 9: 2.2. Practical: WPScan (Deploy #2)

Deploy the Instance attached to this task. You will need to add the 10.10.231.106 and domain **wpscan.thm** to your `/etc/hosts` file like below:

`echo "10.10.231.106 wpscan.thm" >> /etc/hosts`

Replacing "DEPLOYED_INSTANCE_IP_HERE" with MACHINE_IP and waiting 5 minutes for the Instance to setup before scanning.

#### Enumerate the site, what is the name of the theme that is detected as running?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ wpscan --url http://wpscan.thm --enumerate t
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://wpscan.thm/ [10.10.231.106]
[+] Started: Sat May 17 21:11:27 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://wpscan.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://wpscan.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://wpscan.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.0 identified (Insecure, released on 2018-12-06).
 | Found By: Rss Generator (Passive Detection)
 |  - http://wpscan.thm/?feed=rss2, <generator>https://wordpress.org/?v=5.0</generator>
 |  - http://wpscan.thm/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.0</generator>

[+] WordPress theme in use: twentynineteen
 | Location: http://wpscan.thm/wp-content/themes/twentynineteen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://wpscan.thm/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://wpscan.thm/wp-content/themes/twentynineteen/style.css?ver=1.0
 | Style Name: Twenty Nineteen
 | Style URI: https://github.com/WordPress/twentynineteen
 | Description: A new Gutenberg-ready theme....
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://wpscan.thm/wp-content/themes/twentynineteen/style.css?ver=1.0, Match: 'Version: 1.0'

[+] Enumerating Most Popular Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:34 <======================================================================================================================> (400 / 400) 100.00% Time: 00:00:34
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] Theme(s) Identified:

[+] twentynineteen
 | Location: http://wpscan.thm/wp-content/themes/twentynineteen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://wpscan.thm/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://wpscan.thm/wp-content/themes/twentynineteen/style.css
 | Style Name: Twenty Nineteen
 | Style URI: https://github.com/WordPress/twentynineteen
 | Description: A new Gutenberg-ready theme....
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://wpscan.thm/wp-content/themes/twentynineteen/style.css, Match: 'Version: 1.0'

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat May 17 21:12:07 2025
[+] Requests Done: 832
[+] Cached Requests: 12
[+] Data Sent: 212.334 KB
[+] Data Received: 4.501 MB
[+] Memory used: 232.5 MB
[+] Elapsed time: 00:00:40
```

Answer: twentynineteen

#### Enumerate the site, what is the name of the plugin that WPScan has found?

Hint: You may have to use different aggressive profiles!

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ wpscan --url http://wpscan.thm --enumerate p
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://wpscan.thm/ [10.10.231.106]
[+] Started: Sat May 17 21:13:48 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://wpscan.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://wpscan.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://wpscan.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.0 identified (Insecure, released on 2018-12-06).
 | Found By: Rss Generator (Passive Detection)
 |  - http://wpscan.thm/?feed=rss2, <generator>https://wordpress.org/?v=5.0</generator>
 |  - http://wpscan.thm/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.0</generator>

[+] WordPress theme in use: twentynineteen
 | Location: http://wpscan.thm/wp-content/themes/twentynineteen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://wpscan.thm/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://wpscan.thm/wp-content/themes/twentynineteen/style.css?ver=1.0
 | Style Name: Twenty Nineteen
 | Style URI: https://github.com/WordPress/twentynineteen
 | Description: A new Gutenberg-ready theme....
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://wpscan.thm/wp-content/themes/twentynineteen/style.css?ver=1.0, Match: 'Version: 1.0'

[+] Enumerating Most Popular Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] nextcellent-gallery-nextgen-legacy
 | Location: http://wpscan.thm/wp-content/plugins/nextcellent-gallery-nextgen-legacy/
 | Latest Version: 1.9.35 (up to date)
 | Last Updated: 2017-10-16T09:19:00.000Z
 |
 | Found By: Comment (Passive Detection)
 |
 | Version: 3.5.0 (60% confidence)
 | Found By: Comment (Passive Detection)
 |  - http://wpscan.thm/, Match: '<meta name="NextGEN" version="3.5.0"'

[+] nextgen-gallery
 | Location: http://wpscan.thm/wp-content/plugins/nextgen-gallery/
 | Last Updated: 2025-04-24T16:35:00.000Z
 | [!] The version is out of date, the latest version is 3.59.12
 |
 | Found By: Comment (Passive Detection)
 |
 | Version: 3.5.0 (100% confidence)
 | Found By: Comment (Passive Detection)
 |  - http://wpscan.thm/, Match: '<meta name="NextGEN" version="3.5.0"'
 | Confirmed By:
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://wpscan.thm/wp-content/plugins/nextgen-gallery/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://wpscan.thm/wp-content/plugins/nextgen-gallery/readme.txt

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat May 17 21:13:52 2025
[+] Requests Done: 5
[+] Cached Requests: 36
[+] Data Sent: 1.646 KB
[+] Data Received: 102.674 KB
[+] Memory used: 264.895 MB
[+] Elapsed time: 00:00:04
```

Answer: nextgen-gallery

#### Enumerate the site, what username can WPScan find?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ wpscan --url http://wpscan.thm --enumerate u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://wpscan.thm/ [10.10.231.106]
[+] Started: Sat May 17 21:16:39 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://wpscan.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://wpscan.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://wpscan.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.0 identified (Insecure, released on 2018-12-06).
 | Found By: Rss Generator (Passive Detection)
 |  - http://wpscan.thm/?feed=rss2, <generator>https://wordpress.org/?v=5.0</generator>
 |  - http://wpscan.thm/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.0</generator>

[+] WordPress theme in use: twentynineteen
 | Location: http://wpscan.thm/wp-content/themes/twentynineteen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://wpscan.thm/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://wpscan.thm/wp-content/themes/twentynineteen/style.css?ver=1.0
 | Style Name: Twenty Nineteen
 | Style URI: https://github.com/WordPress/twentynineteen
 | Description: A new Gutenberg-ready theme....
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://wpscan.thm/wp-content/themes/twentynineteen/style.css?ver=1.0, Match: 'Version: 1.0'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <========================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] Phreakazoid
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] phreakazoid
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat May 17 21:16:43 2025
[+] Requests Done: 24
[+] Cached Requests: 37
[+] Data Sent: 6.305 KB
[+] Data Received: 89.572 KB
[+] Memory used: 188.809 MB
[+] Elapsed time: 00:00:03
```

Answer: phreakazoid

#### Construct a WPScan command to brute-force the site with this username, using the rockyou wordlist as the password list. What is the password to this user?

Hint: If this password attack takes longer than 5 minutes, you are using the wrong username / password list or URL.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ wpscan --url http://wpscan.thm --passwords /usr/share/wordlists/rockyou.txt --usernames phreakazoid
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://wpscan.thm/ [10.10.231.106]
[+] Started: Sat May 17 21:19:43 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://wpscan.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://wpscan.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://wpscan.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.0 identified (Insecure, released on 2018-12-06).
 | Found By: Rss Generator (Passive Detection)
 |  - http://wpscan.thm/?feed=rss2, <generator>https://wordpress.org/?v=5.0</generator>
 |  - http://wpscan.thm/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.0</generator>

[+] WordPress theme in use: twentynineteen
 | Location: http://wpscan.thm/wp-content/themes/twentynineteen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://wpscan.thm/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://wpscan.thm/wp-content/themes/twentynineteen/style.css?ver=1.0
 | Style Name: Twenty Nineteen
 | Style URI: https://github.com/WordPress/twentynineteen
 | Description: A new Gutenberg-ready theme....
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://wpscan.thm/wp-content/themes/twentynineteen/style.css?ver=1.0, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] nextcellent-gallery-nextgen-legacy
 | Location: http://wpscan.thm/wp-content/plugins/nextcellent-gallery-nextgen-legacy/
 | Latest Version: 1.9.35 (up to date)
 | Last Updated: 2017-10-16T09:19:00.000Z
 |
 | Found By: Comment (Passive Detection)
 |
 | Version: 3.5.0 (60% confidence)
 | Found By: Comment (Passive Detection)
 |  - http://wpscan.thm/, Match: '<meta name="NextGEN" version="3.5.0"'

[+] nextgen-gallery
 | Location: http://wpscan.thm/wp-content/plugins/nextgen-gallery/
 | Last Updated: 2025-04-24T16:35:00.000Z
 | [!] The version is out of date, the latest version is 3.59.12
 |
 | Found By: Comment (Passive Detection)
 |
 | Version: 3.5.0 (100% confidence)
 | Found By: Comment (Passive Detection)
 |  - http://wpscan.thm/, Match: '<meta name="NextGEN" version="3.5.0"'
 | Confirmed By:
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://wpscan.thm/wp-content/plugins/nextgen-gallery/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://wpscan.thm/wp-content/plugins/nextgen-gallery/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:02 <=======================================================================================================================> (137 / 137) 100.00% Time: 00:00:02

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - phreakazoid / linkinpark
Trying phreakazoid / turtle Time: 00:00:16 <                                                                                                                  > (505 / 14344897)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: phreakazoid, Password: linkinpark

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat May 17 21:20:09 2025
[+] Requests Done: 647
[+] Cached Requests: 39
[+] Data Sent: 297.169 KB
[+] Data Received: 347.363 KB
[+] Memory used: 288.492 MB
[+] Elapsed time: 00:00:25
```

Answer: linkinpark

### Task 10: 3. Introduction to Nikto

#### Introduction to Nikto

Initially released in 2001, Nikto has made leaps and bounds over the years and has proven to be a very popular vulnerability scanner due to being both open-source nature and feature-rich. Nikto is capable of performing an assessment on all types of webservers (and isn't application-specific such as WPScan.). Nikto can be used to discover possible vulnerabilities including:

- Sensitive files
- Outdated servers and programs (i.e. [vulnerable web server installs](https://httpd.apache.org/security/vulnerabilities_24.html))
- Common server and software misconfigurations (Directory indexing, cgi scripts, x-ss protections)

#### Installing Nikto

Thankfully for us, Nikto comes pre-installed on the latest versions of penetration testing systems such as Kali Linux and Parrot. If you are using an older version of Kali Linux (such as 2019) for example, Nikto is in the apt repository, so can be installed by a simple `sudo apt update && sudo apt install nikto`

Installing Nikto on other operating systems such as Ubuntu or Debian involves extra steps. Whilst the TryHackMe AttackBox comes pre-installed with Nikto, you can follow the [developer's installation guide](https://github.com/sullo/nikto/wiki) for your local environment.

In the next task, we will explore some common syntax and features of Nikto!

### Task 11: 3.1. Nikto Modes

#### Basic Scanning

The most basic scan can be performed by using the `-h` flag and providing an IP address or domain name as an argument. This scan type will retrieve the headers advertised by the webserver or application (I.e. Apache2, Apache Tomcat, Jenkins or JBoss) and will look for any sensitive files or directories (i.e. login.php, /admin/, etc)

An example of this is the following: `nikto -h vulnerable_ip`

![Nikto Basic Scan](Images/Nikto_Basic_Scan.png)

Note a few interesting things are given to us in this example:

- Nikto has identified that the application is Apache Tomcat using the favicon and the presence of `/examples/servlets/index.html` which is the location for the default Apache Tomcat application.
- HTTP Methods "PUT" and "DELETE" can be performed by clients - we may be able to leverage these to exploit the application by uploading or deleting files.

#### Scanning Multiple Hosts & Ports

Nikto is extensive in the sense that we can provide multiple arguments in a way that's similar to tools such as Nmap. In fact, so much so, we can take input directly from an Nmap scan to scan a host range. By scanning a subnet, we can look for hosts across an entire network range. We must instruct Nmap to output a scan into a format that is friendly for Nikto to read using Nmap's `-oG` flags

For example, we can scan 172.16.0.0/24 (subnet mask 255.255.255.0, resulting in 254 possible hosts) with Nmap (using the default web port of 80) and parse the output to Nikto like so: `nmap -p80 172.16.0.0/24 -oG - | nikto -h -`

There are not many circumstances where you would use this other than when you have gained access to a network. A much more common scenario will be scanning multiple ports on one specific host. We can do this by using the `-p` flag and providing a list of port numbers delimited by a comma - such as the following: `nikto -h 10.10.10.1 -p 80,8000,8080`

#### Introduction to Plugins

Plugins further extend the capabilities of Nikto. Using information gathered from our basic scans, we can pick and choose plugins that are appropriate to our target. You can use the `--list-plugins` flag with Nikto to list the plugins or view the whole list in an easier to read format online.

Some interesting plugins include:

| Plugin Name | Description |
|----|----|
|apacheusers|Attempt to enumerate Apache HTTP Authentication Users|
|cgi|Look for CGI scripts that we may be able to exploit|
|robots|Analyse the robots.txt file which dictates what files/folders we are able to navigate to|
|dir_traversal|Attempt to use a directory traversal attack (i.e. LFI) to look for system files such as `/etc/passwd` on Linux (`http://ip_address/application.php?view=../../../../../../../etc/passwd`)|

We can specify the plugin we wish to use by using the `-Plugin` argument and the name of the plugin we wish to use...For example, to use the "apacheuser" plugin, our Nikto scan would look like so: `nikto -h 10.10.10.1 -Plugin apacheuser`

#### Verbosing our Scan

We can increase the verbosity of our Nikto scan by providing the following arguments with the `-Display` flag. Unless specified, the output given by Nikto is not the entire output, as it can sometimes be irrelevant (but that isn't always the case!)

| Argument | Description | Reasons for Use |
|1|Show any redirects that are given by the web server.|Web servers may want to relocate us to a specific file or directory, so we will need to adjust our scan accordingly for this.|
|2|Show any cookies received|Applications often use cookies as a means of storing data. For example, web servers use sessions, where e-commerce sites may store products in your basket as these cookies. Credentials can also be stored in cookies.|
|E|Output any errors|This will be useful for debugging if your scan is not returning the results that you expect!|

#### Tuning Your Scan for Vulnerability Searching

Nikto has several categories of vulnerabilities that we can specify our scan to enumerate and test for. The following list is not extensive and only include the ones that you may commonly use. We can use the `-Tuning` flag and provide a value in our Nikto scan:

| Category Name | Description | Tuning Option |
|----|----|----|
|File Upload|Search for anything on the web server that may permit us to upload a file. This could be used to upload a reverse shell for an application to execute.|0|
|Misconfigurations / Default Files|Search for common files that are sensitive (and shouldn't be accessible such as configuration files) on the web server.|2|
|Information Disclosure|Gather information about the web server or application (i.e. verison numbers, HTTP headers, or any information that may be useful to leverage in our attack later)|3|
|Injection|Search for possible locations in which we can perform some kind of injection attack such as XSS or HTML|4|
|Command Execution|Search for anything that permits us to execute OS commands (such as to spawn a shell)|8|
|SQL Injection|Look for applications that have URL parameters that are vulnerable to SQL Injection|9|

#### Saving Your Findings

Rather than working with the output on the terminal, we can instead, just dump it directly into a file for further analysis - making our lives much easier!

Nikto is capable of putting to a few file formats including:

- Text File
- HTML report

We can use the `-o` argument (short for -Output) and provide both a filename and compatible extension. We can specify the format (`-f`) specifically, but Nikto is smart enough to use the extension we provide in the `-o` argument to adjust the output accordingly.

For example, let's scan a web server and output this to "report.html": `nikto -h http://ip_address -o report.html`

---------------------------------------------------------------------------------------

#### What argument would we use if we wanted to scan port 80 and 8080 on a host?

Hint: Lowest port number to highest!

Answer: -p 80,8080

#### What argument would we use if we wanted to see any cookies given by the web server?

Answer: -Display 2

### Task 12: 3.2. Nikto Practical (Deploy #3)

Deploy the Instance attached to this task. **Allow five minutes** for it to fully deploy before you begin your Nikto scans!

Use Nikto to assess the ports on 10.10.43.238 to answer the following questions:

#### What is the name & version of the web server that Nikto has determined running on port 80?

Hint: Provide the full answer from the output

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ nikto -h 10.10.43.238 -p 80
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.43.238
+ Target Hostname:    10.10.43.238
+ Target Port:        80
+ Start Time:         2025-05-18 17:24:00 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 40e0, size: 5a0311fe9980a, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Multiple index files found: /index.xml, /index.html.
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: POST, OPTIONS, GET, HEAD .
+ /sitemap.xml: This gives a nice listing of the site content.
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /images/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8074 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2025-05-18 17:30:28 (GMT2) (388 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Answer: Apache/2.4.7

#### There is another web server running on another port. What is the name & version of this web server?

Hint: Ensure you have waited 5 minutes for the Instance to fully deploy

Scan with `nmap` and pipe the result to `nikto`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ nmap 10.10.43.238 -oG - | nikto -h -
- Nikto v2.5.0
---------------------------------------------------------------------------
+ nmap Input Queued: 10.10.43.238:80
+ nmap Input Queued: 10.10.43.238:8080
+ Target IP:          10.10.43.238
+ Target Hostname:    10.10.43.238
+ Target Port:        8080
+ Start Time:         2025-05-18 17:37:09 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache-Coyote/1.1
+ /: Retrieved x-powered-by header: Servlet/3.0; JBossAS-6.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /favicon.ico: identifies this app/server as: JBoss Server. See: https://en.wikipedia.org/wiki/Favicon
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS .
+ HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ /admin-console/config.php: Cookie JSESSIONID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ 8077 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2025-05-18 17:43:56 (GMT2) (407 seconds)
---------------------------------------------------------------------------
+ Target IP:          10.10.43.238
+ Target Hostname:    10.10.43.238
+ Target Port:        80
+ Start Time:         2025-05-18 17:43:56 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 40e0, size: 5a0311fe9980a, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: POST, OPTIONS, GET, HEAD .
+ /sitemap.xml: This gives a nice listing of the site content.
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /images/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 16129 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2025-05-18 17:50:22 (GMT2) (386 seconds)                                                                                                                              
---------------------------------------------------------------------------                                                                                                                 
+ 2 host(s) tested    
```

Answer: Apache-Coyote/1.1

#### What is the name of the Cookie that this JBoss server gives?

Hint: You may have to play around with how Nikto outputs the scan results to you! The answer is looking for the name of the cookie -- not the value

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Web_Enumeration]
└─$ nikto -h 10.10.43.238 -p 8080 -Display 2
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.43.238
+ Target Hostname:    10.10.43.238
+ Target Port:        8080
+ Start Time:         2025-05-18 17:51:16 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache-Coyote/1.1
+ /: Retrieved x-powered-by header: Servlet/3.0; JBossAS-6.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /favicon.ico: identifies this app/server as: JBoss Server. See: https://en.wikipedia.org/wiki/Favicon
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS .
+ HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ /admin-console/config.php sent cookie: JSESSIONID=86B97B736E6F6E22C64F764DAEC7A219; Path=/admin-console
+ /admin-console/config.php: Cookie JSESSIONID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /jmx-console/ sent cookie: JSESSIONID=626432E4DBD03FB4E4C3DAD33661361C; Path=/jmx-console
+ /jmx-console/HtmlAdaptor?action=inspectMBean&name=Catalina%3Atype%3DServer sent cookie: JSESSIONID=7FD467D02E6DB2199C2F98354BC19A3C; Path=/jmx-console
+ 8076 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2025-05-18 17:57:37 (GMT2) (381 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Answer: JSESSIONID

### Task 13: 4. Conclusion

Where to go from here (recommended rooms)

GoBuster:

- [OWASP Top 10](https://tryhackme.com/room/owasptop10) (Walkthrough)
- [EasyPeasyCTF](https://tryhackme.com/room/easypeasyctf) (Challenge)

WPScan:

- [Blog](https://tryhackme.com/room/blog) (Challenge)

Nikto:

- [OWASP Top 10](https://tryhackme.com/room/owasptop10) (Walkthrough)
- [ToolsRUs](https://tryhackme.com/room/toolsrus) (Walkthrough)
- [EasyCTF](https://tryhackme.com/room/easyctf) (Challenge)

For additional information, please see the references below.

## References

- [Gobuster - GitHub](https://github.com/OJ/gobuster/)
- [Gobuster - Kali Tools](https://www.kali.org/tools/gobuster/)
- [Nikto - Documentation](https://github.com/sullo/nikto/wiki)
- [Nikto - GitHub](https://github.com/sullo/nikto)
- [Nikto - Homepage](https://cirt.net/Nikto2)
- [Nikto - Kali Tools](https://www.kali.org/tools/nikto/)
- [WPScan - Documentation](https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation)
- [WPScan - GitHub](https://github.com/wpscanteam/wpscan)
