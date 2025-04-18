# Linux Fundamentals Part 3

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
OS: Linux
Subscription type: Premium
Power-up your Linux skills and get hands-on with some common utilities that you are likely to use day-to-day!
```

Room link: [https://tryhackme.com/room/linuxfundamentalspart3](https://tryhackme.com/room/linuxfundamentalspart3)

## Solution

### Task 2 - Accessing Your Linux Machine Using SSH (Deploy)

#### I've logged into the Linux Fundamentals Part 3 machine using SSH and have deployed the AttackBox successfully!

Login to the machine using `ssh` with the credentials `tryhackme:tryhackme`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Info/Linux_Fundamentals_Part_1-3]
└─$ ssh tryhackme@10.10.224.80 
The authenticity of host '10.10.224.80 (10.10.224.80)' can't be established.
ED25519 key fingerprint is SHA256:1abO+hYsNbqirya1+DAhmIkVSKRmJ2ujOldL3/cFrSo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.224.80' (ED25519) to the list of known hosts.
tryhackme@10.10.224.80's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-1075-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri Apr 18 08:56:07 UTC 2025

  System load:  0.88               Processes:             108
  Usage of /:   11.6% of 29.01GB   Users logged in:       0
  Memory usage: 14%                IPv4 address for eth0: 10.10.224.80
  Swap usage:   0%

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

tryhackme@linux3:~$ 
```

### Task 3 - Terminal Text Editors

Useful commands:

- nano
- vim

#### Edit "task3" located in "tryhackme"'s home directory using Nano. What is the flag?

Answer: THM{TEXT_EDITORS}

### Task 4 - General/Useful Utilities

Useful commands:

- curl
- scp
- wget

Python3's "HTTPServer" will serve the files in the directory where you run the command

```python
python3 -m http.server
```

The default port is 8000.

#### Now, use Python 3's "HTTPServer" module to start a web server in the home directory of the "tryhackme" user on the deployed instance

Hint: python3 -m http.server

```bash
tryhackme@linux3:~$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

#### Download the file http://10.10.224.80:8000/.flag.txt onto the TryHackMe AttackBox. What are the contents?

```bash
root@ip-10-10-153-108:~# curl http://10.10.224.80:8000/.flag.txt
THM{WGET_WEBSERVER}
```

Answer: THM{WGET_WEBSERVER}

#### Use Ctrl + C to stop the Python3 HTTPServer module once you are finished

Hint: `https://docs.python.org/3/library/http.server.html`

```bash
tryhackme@linux3:~$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.153.108 - - [18/Apr/2025 09:09:47] "GET /.flag.txt HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
```

### Task 5 - Processes 101

Useful commands:

- fg
- kill
- ps
- systemctl
- top

#### If we were to launch a process where the previous ID was "300", what would the ID of this new process be?

Answer: 301

#### If we wanted to cleanly kill a process, what signal would we send it?

Answer: SIGTERM

#### Locate the process that is running on the deployed instance (10.10.224.80). What flag is given?

Hint: Use ps aux to list all running processes. We're looking for a process that seems "out of the ordinary"

```bash
tryhackme@linux3:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.4  0.6 103692 12536 ?        Ss   08:54   0:06 /sbin/init
<---snip--->
root         505  0.0  0.0   2616   596 ?        Ss   08:55   0:00 /bin/sh -c /root/process
root         509  0.0  0.0   2364   516 ?        S    08:55   0:00 THM{PROCESSES}
root         510  0.0  0.0      0     0 ?        I    08:55   0:00 [kworker/0:3-events]
root         535  0.0  0.5 241344 11220 ?        Ssl  08:55   0:00 /usr/sbin/ModemManager
<---snip--->
root        2036  0.0  0.0      0     0 ?        I    09:17   0:00 [kworker/u30:8]
tryhack+    3606  0.0  0.1  10620  3248 pts/0    R+   09:18   0:00 ps aux
```

Answer: THM{PROCESSES}

#### What command would we use to stop the service "myservice"?

Hint: systemctl [option] [service]

Answer: systemctl stop myservice

#### What command would we use to start the same service on the boot-up of the system?

Hint: systemctl [option] [service]

Answer: systemctl enable myservice

#### What command would we use to bring a previously backgrounded process back to the foreground?

Answer: fg

### Task 6 - Maintaining Your System: Automation

#### When will the crontab on the deployed instance (10.10.224.80) run?

Hint: Take a look at the position and the value within the appropriate column

```bash
tryhackme@linux3:~$ crontab -l
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command
@reboot /var/opt/processes.sh
```

Answer: @reboot

### Task 7 - Maintaining Your System: Package Management

Useful commands:

- apt

### Task 8 - Maintaining Your System: Logs

#### Look for the apache2 logs on the deployable Linux machine. What is the IP address of the user who visited the site?

Hint: Located in /var/log/apache2

```bash
tryhackme@linux3:~$ cd /var/log/apache2/
tryhackme@linux3:/var/log/apache2$ ls -la
total 20
drwxrwxrwx  2 root      adm       4096 Feb  3 19:32 .
drwxrwxr-x 10 root      syslog    4096 Apr 18 08:55 ..
-rw-r-----  1 root      adm          0 Feb  3 19:32 access.log
-rwxrwxrwx  1 tryhackme tryhackme  209 May  4  2021 access.log.1
-rw-r-----  1 root      adm          0 Feb  3 19:32 error.log
-rw-r-----  1 root      adm        810 Oct 18  2022 error.log.1
-rwxrwxrwx  1 root      adm        464 May  5  2021 error.log.2.gz
-rw-r-----  1 root      adm          0 May  4  2021 other_vhosts_access.log
tryhackme@linux3:/var/log/apache2$ cat access.log.1 
10.9.232.111 - - [04/May/2021:18:18:16 +0000] "GET /catsanddogs.jpg HTTP/1.1" 200 51395 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
tryhackme@linux3:/var/log/apache2$ cat access.log.1 | cut -d ' ' -f1
10.9.232.111
```

Answer: 10.9.232.111

#### What file did they access?

```bash
tryhackme@linux3:/var/log/apache2$ cat access.log.1 | cut -d ' ' -f7
/catsanddogs.jpg
```

Answer: catsanddogs.jpg

For additional information, please see the references below.

## References

- [apt - Ubuntu manuals](https://manpages.ubuntu.com/manpages/xenial/man8/apt.8.html)
- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [cd - Linux manual page](https://man7.org/linux/man-pages/man1/cd.1p.html)
- [cp - Linux manual page](https://man7.org/linux/man-pages/man1/cp.1.html)
- [cron - Wikipedia](https://en.wikipedia.org/wiki/Cron)
- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [cut - Linux manual page](https://man7.org/linux/man-pages/man1/cut.1.html)
- [echo - Linux manual page](https://man7.org/linux/man-pages/man1/echo.1.html)
- [fg - Linux manual page](https://man7.org/linux/man-pages/man1/fg.1p.html)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [kill - Linux manual page](https://man7.org/linux/man-pages/man1/kill.1.html)
- [Linux - Wikipedia](https://en.wikipedia.org/wiki/Linux)
- [ls - Linux manual page](https://man7.org/linux/man-pages/man1/ls.1.html)
- [man - Linux manual page](https://man7.org/linux/man-pages/man1/man.1.html)
- [mkdir - Linux manual page](https://man7.org/linux/man-pages/man1/mkdir.1.html)
- [mv - Linux manual page](https://man7.org/linux/man-pages/man1/mv.1.html)
- [nano - Linux manual page](https://linux.die.net/man/1/nano)
- [ps - Linux manual page](https://man7.org/linux/man-pages/man1/ps.1.html)
- [pwd - Linux manual page](https://man7.org/linux/man-pages/man1/pwd.1.html)
- [rm - Linux manual page](https://man7.org/linux/man-pages/man1/rm.1.html)
- [scp - Linux manual page](https://man7.org/linux/man-pages/man1/scp.1.html)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [su - Linux manual page](https://man7.org/linux/man-pages/man1/su.1.html)
- [systemctl - Linux manual page](https://www.man7.org/linux/man-pages/man1/systemctl.1.html)
- [top - Linux manual page](https://man7.org/linux/man-pages/man1/top.1.html)
- [touch - Linux manual page](https://man7.org/linux/man-pages/man1/touch.1.html)
- [vim - Linux manual page](https://linux.die.net/man/1/vi)
- [wc - Linux manual page](https://man7.org/linux/man-pages/man1/wc.1.html)
- [wget - Linux manual page](https://man7.org/linux/man-pages/man1/wget.1.html)
- [whoami - Linux manual page](https://man7.org/linux/man-pages/man1/whoami.1.html)
