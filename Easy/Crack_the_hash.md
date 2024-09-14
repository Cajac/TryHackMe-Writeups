# Crack the hash

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information
```
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Cracking hashes challenges
```
Room link: [https://tryhackme.com/r/room/crackthehash](https://tryhackme.com/r/room/crackthehash)

## Solution

You should always try to Google for the hash before attempting to crack it. This usually works for easier hashes from common passwords.

Note that you will find examples below from both September 2020 when I originally solved the room and September 2024 when I made this more formal writeup.

### Hash identification

The first hashes will likely be one of the following:
- [MD5-hashes](https://en.wikipedia.org/wiki/MD5) (32 hex chars)
- [SHA-1 hashes](https://en.wikipedia.org/wiki/SHA-1) (40 hex chars)
- [SHA-2 hashes](https://en.wikipedia.org/wiki/SHA-2) (64 hex chars)

You can also use tools such as [hashid](https://www.kali.org/tools/hashid/) or [hash-identifier](https://www.kali.org/tools/hash-identifier/) to help you identify hash types.

Finally, there are a bunch of online services that can also help, for example:
- [dcode.fr](https://www.dcode.fr/hash-identifier)
- [hashes.pro](https://hashes.pro/)
- [tunnelsup.com](https://www.tunnelsup.com/hash-analyzer/)

### Wordlists

The main wordlist to use in CTFs is the [rockyou.txt wordlist](https://github.com/zacheller/rockyou).

`rockyou.txt` is a list of over 14 million plaintext passwords from the 2009 RockYou hack. 

The list is available on default Kali Linux installations in the `/usr/share/wordlists/` directory.

### Level 1 hashes

**Hash: 48bb6e862e54f2a795ffc4e541caed4d**

The hash [can be found](https://md5.gromweb.com/?md5=48bb6e862e54f2a795ffc4e541caed4d) through a Google-search.

You can also use an online service to lookup this `MD5`-hash:
- [crackstation.net](https://crackstation.net/)
- [md5.gromweb.com](https://md5.gromweb.com/)

Plaintext password: `e<REDACTED>y`

**Hash: CBFDAC6008F9CAB4083784CBD1874F76618D2A97**

The hash [can be found](https://md5hashing.net/hash/sha1/cbfdac6008f9cab4083784cbd1874f76618d2a97) through a Google-search.

You can also use an online service to lookup this `SHA1`-hash:
- [crackstation.net](https://crackstation.net/)
- [sha1.gromweb.com](https://sha1.gromweb.com/)

Plaintext password: `p<REDACTED>3`

**Hash: 1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032**

The hash [can be found](https://md5hashing.net/hash/sha256/1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032) through a Google-search.

You can also use an online service to lookup this `SHA2`-hash:
- [crackstation.net](https://crackstation.net/)

Plaintext password: `l<REDACTED>n`

**Hash: $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom**

First, we identify the hash type with `hashid` (note the need for single quotes aound the hash)
```bash
┌──(kali㉿kali)-[~]
└─$ hashid -m -j $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom
Analyzing 'y'
[+] Unknown hash

┌──(kali㉿kali)-[~]
└─$ hashid -m -j '$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom'
Analyzing '$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom'
[+] Blowfish(OpenBSD) [Hashcat Mode: 3200][JtR Format: bcrypt]
[+] Woltlab Burning Board 4.x 
[+] bcrypt [Hashcat Mode: 3200][JtR Format: bcrypt]
```

Since [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) is one of the more time-consuming hashes to crack we cannot simply try to crack it with the rockyou wordlist.  
This could take a number days!
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Crack_the_hash]
└─$ hashcat -a 0 -m 3200 '$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom' /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz, 1438/2940 MB (512 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72
<---snip--->
* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX...8wsRom
Time.Started.....: Sat Sep 14 11:10:26 2024 (12 mins, 20 secs)
Time.Estimated...: Fri Sep 20 14:46:09 2024 (6 days, 3 hours)                           <------ Here !
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       27 H/s (8.55ms) @ Accel:8 Loops:16 Thr:1 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 19904/14344385 (0.14%)
Rejected.........: 0/19904 (0.00%)
Restore.Point....: 19904/14344385 (0.14%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1552-1568
Candidate.Engine.: Device Generator
Candidates.#1....: ratita -> jonel
Hardware.Mon.#1..: Util: 84%
<---snip--->
```

Instead, we utilize the fact that the correct answer is a four-letter word and try a mask attack (`-a 3`) with all four letter lower case words
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Crack_the_hash]
└─$ hashcat -a 3 -m 3200 '$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom' ?l?l?l?l                       
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz, 1438/2940 MB (512 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72
<---snip--->
$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom:b<REDACTED>h

Session..........: hashcat
Status...........: Cracked
Hash.Type........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX...8wsRom
<---snip--->
```
Note that the cracking time is still **several hours**!

Plaintext password: `b<REDACTED>h`

**Hash: 279412f945939ba78ce0758d3fd83daa**

The hash [can be found](https://md5hashing.net/hash/md4/279412f945939ba78ce0758d3fd83daa) through a Google-search.

You can also use an online service to lookup this `MD4`-hash:
- [crackstation.net](https://crackstation.net/)
- [md5hashing.net](https://md5hashing.net/hash/md4/)

If we want to crack the hash manually we can't just use the rockyou wordlist as is
```
C:\Program Files\hashcat-6.2.6>hashcat -a 0 -m 900 279412f945939ba78ce0758d3fd83daa D:\Wordlists\Straight\01_Small\rockyou_sorted.dict
hashcat (v6.2.6) starting

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
* Device #2: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
CUDA API (CUDA 12.2)
====================
* Device #1: NVIDIA GeForce GTX 1050 Ti, 3370/4095 MB, 6MCU
<---snip--->
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 900 (MD4)
Hash.Target......: 279412f945939ba78ce0758d3fd83daa
Time.Started.....: Sat Sep 14 11:57:37 2024 (5 secs)
Time.Estimated...: Sat Sep 14 11:57:42 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (D:\Wordlists\Straight\01_Small\rockyou_sorted.dict)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2529.4 kH/s (2.92ms) @ Accel:512 Loops:1 Thr:32 Vec:1
Speed.#*.........:  2529.4 kH/s
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)                   <------- Nope !
Progress.........: 14344379/14344379 (100.00%)
Rejected.........: 0/14344379 (0.00%)
Restore.Point....: 14344379/14344379 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: zhareen -> zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
Hardware.Mon.#1..: Temp: 32c Fan: 40% Util: 33% Core: 670MHz Mem: 810MHz Bus:16

Started: Sat Sep 14 11:56:40 2024
Stopped: Sat Sep 14 11:57:45 2024
```
Since the plaintext password isn't in the wordlist.

We need to apply rules as well, such as the `best64.rule` rules
```
C:\Program Files\hashcat-6.2.6>hashcat -a 0 -m 900 -r rules\best64.rule 279412f945939ba78ce0758d3fd83daa D:\Wordlists\Straight\01_Small\rockyou_sorted.dict
hashcat (v6.2.6) starting

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
* Device #2: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
CUDA API (CUDA 12.2)
====================
* Device #1: NVIDIA GeForce GTX 1050 Ti, 3370/4095 MB, 6MCU
<---snip--->
Dictionary cache hit:
* Filename..: D:\Wordlists\Straight\01_Small\rockyou_sorted.dict
* Passwords.: 14344379
* Bytes.....: 154265834
* Keyspace..: 1104517183

279412f945939ba78ce0758d3fd83daa:E<REDACTED>2

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 900 (MD4)
Hash.Target......: 279412f945939ba78ce0758d3fd83daa
Time.Started.....: Sat Sep 14 12:00:42 2024 (5 secs)
Time.Estimated...: Sat Sep 14 12:00:47 2024 (0 secs)
<---snip--->
```

Plaintext password: `E<REDACTED>2`

### Level 2 hashes

**Hash: F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85**

First, we identify the hash type with `hashid`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Crack_the_hash]
└─$ hashid -m -j F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85               
Analyzing 'F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85'
[+] Snefru-256 [JtR Format: snefru-256]
[+] SHA-256 [Hashcat Mode: 1400][JtR Format: raw-sha256]
[+] RIPEMD-256 
[+] Haval-256 [JtR Format: haval-256-3]
[+] GOST R 34.11-94 [Hashcat Mode: 6900][JtR Format: gost]
[+] GOST CryptoPro S-Box 
[+] SHA3-256 [Hashcat Mode: 5000][JtR Format: raw-keccak-256]
[+] Skein-256 [JtR Format: skein-256]
[+] Skein-512(256) 
```
A `SHA-256` hash seems to be the most likely candidate here.

Then we try to crack it with the rockyou wordlist and the `best64.rule` rules
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Crack_the_hash]
└─$ hashcat -a 0 -m 1400 -r /usr/share/hashcat/rules/best64.rule F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz, 1438/2940 MB (512 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 77

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
<---snip--->
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 1104517645

f09edcb1fcefc6dfb23dc3505a882655ff77375ed8aa2d1c13f640fccc2d0c85:p<REDACTED>e
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: f09edcb1fcefc6dfb23dc3505a882655ff77375ed8aa2d1c13f...2d0c85
Time.Started.....: Sat Sep 14 12:14:24 2024 (0 secs)
Time.Estimated...: Sat Sep 14 12:14:24 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7157.4 kH/s (8.75ms) @ Accel:256 Loops:38 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 155648/1104517645 (0.01%)
Rejected.........: 0/155648 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:38-76 Iteration:0-38
Candidate.Engine.: Device Generator
Candidates.#1....: 123man -> lover1
Hardware.Mon.#1..: Util: 12%

Started: Sat Sep 14 12:14:06 2024
Stopped: Sat Sep 14 12:14:25 2024
```

Plaintext password: `p<REDACTED>e`

**Hash: 1DFECA0C002AE40B8619ECF94819CC1B**

As usual, we identify the hash type with `hashid`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Crack_the_hash]
└─$ hashid -m -j 1DFECA0C002AE40B8619ECF94819CC1B                                                                                                         

Analyzing '1DFECA0C002AE40B8619ECF94819CC1B'
[+] MD2 [JtR Format: md2]
[+] MD5 [Hashcat Mode: 0][JtR Format: raw-md5]
[+] MD4 [Hashcat Mode: 900][JtR Format: raw-md4]
[+] Double MD5 [Hashcat Mode: 2600]
[+] LM [Hashcat Mode: 3000][JtR Format: lm]
[+] RIPEMD-128 [JtR Format: ripemd-128]
[+] Haval-128 [JtR Format: haval-128-4]
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 [Hashcat Mode: 8600][JtR Format: lotus5]
[+] Skype [Hashcat Mode: 23]
[+] Snefru-128 [JtR Format: snefru-128]
[+] NTLM [Hashcat Mode: 1000][JtR Format: nt]
[+] Domain Cached Credentials [Hashcat Mode: 1100][JtR Format: mscach]
[+] Domain Cached Credentials 2 [Hashcat Mode: 2100][JtR Format: mscach2]
[+] DNSSEC(NSEC3) [Hashcat Mode: 8300]
[+] RAdmin v2.x [Hashcat Mode: 9900][JtR Format: radmin]
```
Here there are several possible hash types.  
Let's go through them in some likelihood order.

First we try MD5
```bash
hashcat -a 0 -m 0 -r /usr/share/hashcat/rules/best64.rule 1DFECA0C002AE40B8619ECF94819CC1B /usr/share/wordlists/rockyou.txt 
```
No solution found!

Then we try MD4
```bash
kali@kali:~$ hashcat -a 0 -m 900 -r /usr/share/hashcat/rules/best64.rule 1DFECA0C002AE40B8619ECF94819CC1B /usr/share/wordlists/rockyou.txt
```
No solution found!

We try NTLM next
```bash
kali@kali:~$ hashcat -a 0 -m 1000 -r /usr/share/hashcat/rules/best64.rule 1DFECA0C002AE40B8619ECF94819CC1B /usr/share/wordlists/rockyou.txt
<---snip--->
1dfeca0c002ae40b8619ecf94819cc1b:n<REDACTED>i    
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NTLM
Hash.Target......: 1dfeca0c002ae40b8619ecf94819cc1b
Time.Started.....: Sat Sep 12 11:04:36 2020 (19 secs)
Time.Estimated...: Sat Sep 12 11:04:55 2020 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 21305.6 kH/s (13.49ms) @ Accel:1024 Loops:77 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 403701760/1104517645 (36.55%)
Rejected.........: 0/403701760 (0.00%)
Restore.Point....: 5238784/14344385 (36.52%)
Restore.Sub.#1...: Salt:0 Amplifier:0-77 Iteration:0-77
Candidates.#1....: n6ri2fdkgm9y -> nw3nnw

Started: Sat Sep 12 11:04:20 2020
Stopped: Sat Sep 12 11:04:56 2020
```

Plaintext password: `n<REDACTED>i`

**Hash: $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.**

Given salt: aReallyHardSalt

Hash type identification with `hashid`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Crack_the_hash]
└─$ hashid -m -j '$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.'
Analyzing '$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.'
[+] SHA-512 Crypt [Hashcat Mode: 1800][JtR Format: sha512crypt]
```

This is also a somewhat time-consuming hash to crack so:
- Crack it on a native OS (rather than a virtual machine)
- Add the `-O` parameter to enable optimized kernels (but limit password length)

Cracking with `hashcat`
```
C:\Program Files\hashcat-6.2.6>hashcat.exe -a 0 -m 1800 -O "$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02." D:\Wordlists\Straight\01_Small\rockyou_sorted.dict
hashcat (v6.2.6) starting

<---snip--->
$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.:w<REDACTED>9

Session..........: hashcat
Status...........: Cracked
Hash.Type........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPM...ZAs02.
Time.Started.....: Sat Sep 12 19:42:48 2020 (28 mins, 38 secs)
Time.Estimated...: Sat Sep 12 20:11:26 2020 (0 secs)
Guess.Base.......: File (D:\Wordlists\Straight\01_Small\rockyou_sorted.dict)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     7997 H/s (9.37ms) @ Accel:64 Loops:32 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 13737984/14344379 (95.77%)
Rejected.........: 0/13737984 (0.00%)
Restore.Point....: 13725696/14344379 (95.69%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4992-5000
Candidates.#1....: waited1 -> valicik
Hardware.Mon.#1..: Temp: 64c Fan: 54% Util: 99% Core:1670MHz Mem:3504MHz Bus:16

Started: Sat Sep 12 19:42:24 2020
Stopped: Sat Sep 12 20:11:27 2020
```
The cracking time is around 20-30 minutes or so.

Plaintext password: `w<REDACTED>9`

**Hash: e5d8870e5bdd26602cab8dbe07a942c8669e56d6**

Given salt: tryhackme

Hash type identification with `hashid`
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Crack_the_hash]
└─$ hashid -m -j e5d8870e5bdd26602cab8dbe07a942c8669e56d6                                                                                                            
Analyzing 'e5d8870e5bdd26602cab8dbe07a942c8669e56d6'
[+] SHA-1 [Hashcat Mode: 100][JtR Format: raw-sha1]
[+] Double SHA-1 [Hashcat Mode: 4500]
[+] RIPEMD-160 [Hashcat Mode: 6000][JtR Format: ripemd-160]
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn [Hashcat Mode: 190][JtR Format: raw-sha1-linkedin]
[+] Skein-256(160) 
[+] Skein-512(160) 
```
Hhm, this was harder to figure out since a salt should be involved.

Let's use the hint to help us: `HMAC-SHA1`.

We need to search for the correct hashcat mode
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Crack_the_hash]
└─$ hashcat --help | grep -i hmac-sha1
    150 | HMAC-SHA1 (key = $pass)                                    | Raw Hash authenticated
    160 | HMAC-SHA1 (key = $salt)                                    | Raw Hash authenticated
  12000 | PBKDF2-HMAC-SHA1                                           | Generic KDF
  25000 | SNMPv3 HMAC-MD5-96/HMAC-SHA1-96                            | Network Protocol
  25200 | SNMPv3 HMAC-SHA1-96                                        | Network Protocol
   7300 | IPMI2 RAKP HMAC-SHA1                                       | Network Protocol
  27400 | VMware VMX (PBKDF2-HMAC-SHA1 + AES-256-CBC)                | Full-Disk Encryption (FDE)
  24800 | Umbraco HMAC-SHA1                                          | Forums, CMS, E-Commerce
  18100 | TOTP (HMAC-SHA1)                                           | One-Time Password
  12001 | Atlassian (PBKDF2-HMAC-SHA1)                               | Framework
  24410 | PKCS#8 Private Keys (PBKDF2-HMAC-SHA1 + 3DES/AES)          | Private Key
  22600 | Telegram Desktop < v2.1.14 (PBKDF2-HMAC-SHA1)              | Instant Messaging Service
```
The mode is likely `160`.

Now we can start cracking (note the syntax of the hash and salt)
```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/Crack_the_hash]
└─$ hashcat -a 0 -m 160 'e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme' /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz, 1438/2940 MB (512 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1
<---snip--->
e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme:4<REDACTED>6
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 160 (HMAC-SHA1 (key = $salt))
Hash.Target......: e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme
Time.Started.....: Sat Sep 14 12:49:06 2024 (11 secs)
Time.Estimated...: Sat Sep 14 12:49:17 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1132.0 kH/s (0.44ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 12314624/14344385 (85.85%)
Rejected.........: 0/12314624 (0.00%)
Restore.Point....: 12312576/14344385 (85.84%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 48162450 -> 481101133
Hardware.Mon.#1..: Util: 32%

Started: Sat Sep 14 12:48:48 2024
Stopped: Sat Sep 14 12:49:18 2024
```

Plaintext password: `4<REDACTED>6`

For additional information, please see the references below.

## References

- [bcrypt - Wikipedia](https://en.wikipedia.org/wiki/Bcrypt)
- [Hashcat - Homepage](https://hashcat.net/hashcat/)
- [Hashcat - Kali Tools](https://www.kali.org/tools/hashcat/)
- [hashid - Kali Tools](https://www.kali.org/tools/hashid/)
- [hash-identifier - Kali Tools](https://www.kali.org/tools/hash-identifier/)
- [MD4 - Wikipedia](https://en.wikipedia.org/wiki/MD4)
- [MD5 - Wikipedia](https://en.wikipedia.org/wiki/MD5)
- [rockyou.txt wordlist](https://github.com/zacheller/rockyou)
- [SHA-1 - Wikipedia](https://en.wikipedia.org/wiki/SHA-1)
- [SHA-2 - Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
