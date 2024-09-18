# Ninja Skills

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information
```
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Practise your Linux skills and complete the challenges.
```
Room link: [https://tryhackme.com/r/room/ninjaskills](https://tryhackme.com/r/room/ninjaskills)

## Solution

### Login with SSH

We begin by logging in with SSH 
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Ninja_Skills]
└─$ ssh newuser@10.10.209.181
The authenticity of host '10.10.209.181 (10.10.209.181)' can't be established.
ED25519 key fingerprint is SHA256:XQkQoLVSwAPAeFiIGecbk+mfw2WfcLjSp+GSZSajTP8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.209.181' (ED25519) to the list of known hosts.
new-user@10.10.209.181's password: 
Last login: Wed Sep 18 16:03:41 2024 from ip-10-100-1-36.eu-west-1.compute.internal
████████╗██████╗ ██╗   ██╗██╗  ██╗ █████╗  ██████╗██╗  ██╗███╗   ███╗███████╗
╚══██╔══╝██╔══██╗╚██╗ ██╔╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝████╗ ████║██╔════╝
   ██║   ██████╔╝ ╚████╔╝ ███████║███████║██║     █████╔╝ ██╔████╔██║█████╗  
   ██║   ██╔══██╗  ╚██╔╝  ██╔══██║██╔══██║██║     ██╔═██╗ ██║╚██╔╝██║██╔══╝  
   ██║   ██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗██║ ╚═╝ ██║███████╗
   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
        Let the games begin!
[new-user@ip-10-10-209-181 ~]$ 
```

Before diving in let's prepare a file with all the names of our file candidates
```bash
[new-user@ip-10-10-209-181 ~]$ cd /tmp
[new-user@ip-10-10-209-181 tmp]$ echo 8V2L > file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ echo bny0 >> file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ echo c4ZX >> file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ echo D8B3 >> file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ echo FHl1 >> file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ echo oiMO >> file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ echo PFbD >> file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ echo rmfX >> file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ echo SRSq >> file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ echo uqyw >> file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ echo v2Vb >> file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ echo X1Uy >> file_candidates.txt
[new-user@ip-10-10-209-181 tmp]$ cat file_candidates.txt 
8V2L
bny0
c4ZX
D8B3
FHl1
oiMO
PFbD
rmfX
SRSq
uqyw
v2Vb
X1Uy
```

Now we use this list to get the full path of the files
```bash
[new-user@ip-10-10-209-181 tmp]$ for f in $(cat file_candidates.txt); do find / -type f -name $f 2>/dev/null; done >> file_candidates_full.txt 
[new-user@ip-10-10-209-181 tmp]$ cat file_candidates_full.txt 
/etc/8V2L
/mnt/c4ZX
/mnt/D8B3
/var/FHl1
/opt/oiMO
/opt/PFbD
/media/rmfX
/etc/ssh/SRSq
/var/log/uqyw
/home/v2Vb
/X1Uy
```
Note that the file named `bny0` is missing from the list.

### Which of the above files are owned by the best-group group?

We can use `find` for this
```bash
[new-user@ip-10-10-209-181 tmp]$ find / -type f -group best-group 2>/dev/null
/mnt/D8B3
/home/v2Vb
```

### Which of these files contain an IP address?

We can use `grep` to solve this
```bash
[new-user@ip-10-10-209-181 tmp]$ for f in $(cat file_candidates_full.txt); do grep -H -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.[0-9]{1,3}' $f; done 
/opt/oiMO:1.1.1.1
```

### WWhich file has the SHA1 hash of 9d54da7584015647ba052173b84d45e8007eba94

We can `sha1sum` and `grep` to find out
```bash
[new-user@ip-10-10-209-181 tmp]$ for f in $(cat file_candidates_full.txt); do sha1sum $f | grep 9d54da7584015647ba052173b84d45e8007eba94; done 
9d54da7584015647ba052173b84d45e8007eba94  /mnt/c4ZX
```

### Which file contains 230 lines?

We can use `wc` together with `grep` to solve this
```bash
[new-user@ip-10-10-209-181 tmp]$ for f in $(cat file_candidates_full.txt); do wc -l $f | grep 230; done 
[new-user@ip-10-10-209-181 tmp]$ 
```
No file found!? Then the answer ought to be the missing file.

### Which file's owner has an ID of 502?

We can use `find` to get the answer
```bash
[new-user@ip-10-10-209-181 tmp]$ find / -type f -user 502 2>/dev/null
/var/spool/mail/newer-user
/X1Uy
```

### Which file is executable by everyone?

Again we can use `find` for this
```bash
[new-user@ip-10-10-209-181 tmp]$ for f in $(cat file_candidates_full.txt); do find $f -perm -o+x 2>/dev/null; done 
/etc/8V2L
```

For additional information, please see the references below.

## References

- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [sha1sum - Linux manual page](https://www.man7.org/linux/man-pages/man1/sha1sum.1.html)
