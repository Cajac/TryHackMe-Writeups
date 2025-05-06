# Yara

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Premium
Description: Learn the applications and language that is Yara for everything threat intelligence, 
forensics, and threat hunting!
```

Room link: [https://tryhackme.com/room/yara](https://tryhackme.com/room/yara)

## Solution

### Task 1 - Introduction

#### Introduction

This room will expect you to understand basic Linux familiarity, such as installing software and commands for general navigation of the system. Moreso, this room isn't designed to test your knowledge or for point-scoring. It is here to encourage you to follow along and experiment with what you have learned here.

As always, I hope you take a few things away from this room, namely, the wonder that Yara (Yet Another Ridiculous Acronym) is and its importance in infosec today. Yara was developed by Victor M. Alvarez ([@plusvic](https://twitter.com/plusvic)) and [@VirusTotal](https://twitter.com/virustotal). Check the GitHub repo [here](https://github.com/virustotal/yara).

### Task 2 - What is Yara?

#### All about Yara

"*The pattern matching swiss knife for malware researchers (and everyone else)*" (Virustotal., 2020)

With such a fitting quote, Yara can identify information based on both binary and textual patterns, such as hexadecimal and strings contained within a file.

Rules are used to label these patterns. For example, Yara rules are frequently written to determine if a file is malicious or not, based upon the features - or patterns - it presents. Strings are a fundamental component of programming languages. Applications use strings to store data such as text.

For example, the code snippet below prints "Hello World" in Python. The text "Hello World" would be stored as a string.

```python
print("Hello World!")
```

We could write a Yara rule to search for "hello world" in every program on our operating system if we would like.

#### Why does Malware use Strings?

Malware, just like our "Hello World" application, uses strings to store textual data. Here are a few examples of the data that various malware types store within strings:

| Type | Data | Description |
|----|----|----|
|Ransomware|12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw|Bitcoin Wallet for ransom payments|
|Botnet|12.34.56.7|The IP address of the Command and Control (C&C) server|

#### Caveat: Malware Analysis

Explaining the functionality of malware is vastly out of scope for this room due to the sheer size of the topic. I have covered strings in much more detail in "Task 12 - Strings" of my [MAL: Introductory room](https://tryhackme.com/room/malmalintroductory). In fact, I am creating a whole Learning Path for it. If you'd like to get a taster whilst learning the fundamentals, I'd recommend my room.

#### What is the name of the base-16 numbering system that Yara can detect?

Hint: This is also known as "hex". An example of this is: ff745c9b137d86e

Answer: hexadecimal

#### Would the text "Enter your Name" be a string in an application? (Yay/Nay)

Answer: Yay

### Task 3 - Deploy

This room deploys an Instance with the tools being showcased already installed for you.  Press the "**Start Machine**" button and wait for an IP address to be displayed and connect in one of two ways:

#### In-Browser (No  VPN required)

Deploy your own instance by pressing the green "Start Machine" button and scroll up to the top of the room and await the timer. The machine will start in a split-screen view. In case the VM is not visible, use the blue "Show Split View" button at the top-right of the page.

#### Using SSH (TryHackMe VPN required)

You must be connected to the TryHackMe VPN if you wish to connect your deployed Instance from your own device.  If you are unfamiliar with this process, please visit the TryHackMe OpenVPN room to get started. If you have any issues, please read our support articles.

- IP Address: 10.10.249.121
- Username: cmnatic
- Password: yararules!
- SSH Port: 22

### Task 4 - Introduction to Yara Rules

#### Your First Yara Rule

The proprietary language that Yara uses for rules is fairly trivial to pick up, but hard to master. This is because your rule is only as effective as your understanding of the patterns you want to search for.

Using a Yara rule is simple. Every `yara` command requires two arguments to be valid, these are:

1. The rule file we create
2. Name of file, directory, or process ID to use the rule for.

Every rule must have a name and condition. For example, if we wanted to use "myrule.yar" on directory "some directory", we would use the following command:  
`yara myrule.yar somedirectory`

Note that **.yar** is the standard file extension for all Yara rules. We'll make one of the most basic rules you can make below.

1. Make a file named "somefile" via `touch somefile`
2. Create a new file and name it "**myfirstrule.yar**" like below:

```bash
cmnatic@thm:~$ touch somefile
cmnatic@thm touch myfirstrule.yar
```

3. Open the "myfirstrule.yar" using a text editor such as `nano` and input the snippet below and save the file:

```text
rule examplerule {
        condition: true
}
```

The **name** of the rule in this snippet is `examplerule`, where we have one condition - in this case, the **condition** is `condition`.

As previously discussed, every rule requires both a name and a condition to be valid. This rule has satisfied those two requirements.

Simply, the rule we have made checks to see if the file/directory/PID that we specify exists via `condition: true`. If the file does exist, we are given the output of `examplerule`

Let's give this a try on the file "**somefile**" that we made in step one:  
`yara myfirstrule.yar somefile`

If "somefile" exists, Yara will say `examplerule` because the pattern has been met - as we can see below:

```bash
cmnatic@thm:~$ yara myfirstrule.yar somefile 
examplerule somefile
```

If the file does not exist, Yara will output an error such as that below:

```bash
cmnatic@thm:~$ yara myfirstrule.yar sometextfile
error scanning sometextfile: could not open file
```

Congrats! You've made your first rule.

### Task 5 - Expanding on Yara Rules

#### Yara Conditions Continued...

Checking whether or not a file exists isn't all that helpful. After all, we can figure that out for ourselves...Using much better tools for the job.

Yara has a few conditions, which I encourage you to read [here](https://yara.readthedocs.io/en/stable/writingrules.html) at your own leisure. However, I'll detail a few below and explain their purpose.

#### Meta

This section of a Yara rule is reserved for descriptive information by the author of the rule. For example, you can use `desc`, short for **description**, to summarise what your rule checks for. Anything within this section does not influence the rule itself. Similar to commenting code, it is useful to summarise your rule.

#### Strings

Remember our discussion about strings in Task 2? Well, here we go. You can use strings to search for specific text or hexadecimal in files or programs. For example, say we wanted to search a directory for all files containing "Hello World!", we would create a rule such as below:

```text
rule helloworld_checker{
    strings:
        $hello_world = "Hello World!"
}
```

We define the keyword `Strings` where the string that we want to search, i.e., "Hello World!" is stored within the variable `$hello_world`.

Of course, we need a condition here to make the rule valid. In this example, to make this string the condition, we need to use the variable's name. In this case, `$hello_world`:

```text
rule helloworld_checker{
    strings:
        $hello_world = "Hello World!"

    condition:
        $hello_world
}
```

Essentially, if any file has the string "Hello World!" then the rule will match. However, this is literally saying that it will only match if "Hello World!" is found and will not match if "hello world" or "HELLO WORLD."

To solve this, the condition `any of them` allows multiple strings to be searched for, like below:

```text
rule helloworld_checker{
    strings:
        $hello_world = "Hello World!"
        $hello_world_lowercase = "hello world"
        $hello_world_uppercase = "HELLO WORLD"

    condition:
        any of them
}
```

Now, any file with the strings of:

1. Hello World!
2. hello world
3. HELLO WORLD

Will now trigger the rule.

#### Conditions

We have already used the `true` and `any of them` condition. Much like regular programming, you can use operators such as:

- `<=` (less than or equal to)
- `>=` (more than or equal to)
- `!=` (not equal to)

For example, the rule below would do the following:

```text
rule helloworld_checker{
    strings:
        $hello_world = "Hello World!"

    condition:
        #hello_world <= 10
}
```

The rule will now:

1. Look for the "Hello World!" string
2. Only say the rule matches if there are less than or equal to ten occurrences of the "Hello World!" string

#### Combining keywords

Moreover, you can use keywords such as:

- and
- not
- or

To combine multiple conditions. Say if you wanted to check if a file has a string and is of a certain size (in this example, the sample file we are checking is **less than** <10 kb and has "Hello World!" you can use a rule like below:

```text
rule helloworld_checker{
    strings:
        $hello_world = "Hello World!" 
        
        condition:
            $hello_world and filesize < 10KB 
}
```

The rule will only match if both conditions are true. To illustrate: below, the rule we created, in this case, did not match because although the file has "Hello World!", it has a file size larger than 10KB:

```bash
cmnatic@thm:~$ yara myfirstrule.yar mytextfile.txt
cmnatic@thm:~$ 
```

However, the rule matched this time because the file has both "Hello World!" and a file size of less than 10KB.

```bash
cmnatic@thm:~$ yara myfirstrule.yar mytextfile.txt
helloworld_textfile_checker mytextfile.txt
cmnatic@thm:~$ 
```

#### Anatomy of a Yara Rule

![Anatomy of a Yara Rule](Images/Anatomy_of_a_Yara_Rule.png)

Information security researcher "fr0gger_" has recently created a [handy cheatsheet](https://medium.com/malware-buddy/security-infographics-9c4d3bd891ef#18dd) that breaks down and visualises the elements of a YARA rule (shown above, all image credits go to him). It's a great reference point for getting started!

### Task 6 - Yara Modules

#### Integrating With Other Libraries

Frameworks such as the [Cuckoo Sandbox](https://github.com/cuckoosandbox/cuckoo) or [Python's PE Module](https://pypi.org/project/pefile/) allow you to improve the technicality of your Yara rules ten-fold.

#### Cuckoo

Cuckoo Sandbox is an automated malware analysis environment. This module allows you to generate Yara rules based upon the behaviours discovered from Cuckoo Sandbox. As this environment executes malware, you can create rules on specific behaviours such as runtime strings and the like.

#### Python PE

Python's PE module allows you to create Yara rules from the various sections and elements of the Windows Portable Executable (PE) structure.

Explaining this structure is out of scope as it is covered in my [malware introductory room](https://tryhackme.com/room/malmalintroductory). However, this structure is the standard formatting of all executables and DLL files on windows. Including the programming libraries that are used.

Examining a PE file's contents is an essential technique in malware analysis; this is because behaviours such as cryptography or worming can be largely identified without reverse engineering or execution of the sample.

### Task 7 - Other tools and Yara

#### Yara Tools

Knowing how to create custom Yara rules is useful, but luckily you don't have to create many rules from scratch to begin using Yara to search for evil. There are plenty of GitHub [resources](https://github.com/InQuest/awesome-yara) and open-source tools (along with commercial products) that can be utilized to leverage Yara in hunt operations and/or incident response engagements.

#### LOKI (What, not who, is Loki?)

LOKI is a free open-source IOC (Indicator of Compromise) scanner created/written by Florian Roth.

Based on the GitHub page, detection is based on 4 methods:

1. File Name IOC Check
2. Yara Rule Check (**we are here**)
3. Hash Check
4. C2 Back Connect Check

There are additional checks that LOKI can be used for. For a full rundown, please reference the [GitHub readme](https://github.com/Neo23x0/Loki/blob/master/README.md).

LOKI can be used on both Windows and Linux systems and can be downloaded [here](https://github.com/Neo23x0/Loki/releases).

*Please note that you are not expected to use this tool in this room.*

```bash
cmnatic@thm:~/Loki$ python3 loki.py -h
usage: loki.py [-h] [-p path] [-s kilobyte] [-l log-file] [-r remote-loghost]
               [-t remote-syslog-port] [-a alert-level] [-w warning-level]
               [-n notice-level] [--allhds] [--alldrives] [--printall]
               [--allreasons] [--noprocscan] [--nofilescan] [--vulnchecks]
               [--nolevcheck] [--scriptanalysis] [--rootkit] [--noindicator]
               [--dontwait] [--intense] [--csv] [--onlyrelevant] [--nolog]
               [--update] [--debug] [--maxworkingset MAXWORKINGSET]
               [--syslogtcp] [--logfolder log-folder] [--nopesieve]
               [--pesieveshellc] [--python PYTHON] [--nolisten]
               [--excludeprocess EXCLUDEPROCESS] [--force]

Loki - Simple IOC Scanner

optional arguments:
  -h, --help            show this help message and exit
```

#### THOR (superhero named programs for a superhero blue teamer)

THOR Lite is Florian's newest multi-platform IOC AND YARA scanner. There are precompiled versions for Windows, Linux, and macOS. A nice feature with THOR Lite is its scan throttling to limit exhausting CPU resources. For more information and/or to download the binary, start [here](https://www.nextron-systems.com/thor-lite/). You need to subscribe to their mailing list to obtain a copy of the binary. **Note that THOR is geared towards corporate customers**. THOR Lite is the free version.

*Please note that you are not expected to use this tool in this room*.

```bash
cmnatic@thm:~$ ./thor-lite-linux-64 -h
Thor Lite
APT Scanner
Version 10.7.3 (2022-07-27 07:33:47)
cc) Nextron Systems GmbH
Lite Version

> Scan Options
  -t, --template string      Process default scan parameters from this YAML file
  -p, --path strings         Scan a specific file path. Define multiple paths by specifying this option multiple times. Append ':NOWALK' to the path for non-recursive scanning (default: only the system drive) (default [])
      --allhds               (Windows Only) Scan all local hard drives (default: only the system drive)
      --max_file_size uint   Max. file size to check (larger files are ignored). Increasing this limit will also increase memory usage of THOR. (default 30MB)

> Scan Modes
      --quick     Activate a number of flags to speed up the scan at cost of some detection.
                  This is equivalent to: --noeventlog --nofirewall --noprofiles --nowebdirscan --nologscan --noevtx --nohotfixes --nomft --lookback 3 --lookback-modules filescan
```

#### FENRIR (naming convention still mythical themed)

This is the 3rd [tool](https://github.com/Neo23x0/Fenrir) created by Neo23x0 (Florian Roth). You guessed it; the previous 2 are named above. The updated version was created to address the issue from its predecessors, where requirements must be met for them to function. Fenrir is a bash script; it will run on any system capable of running bash (nowadays even Windows).

*Please note that you are not expected to use this tool in this room*.

```bash
cmnatic@thm-yara:~/tools$ ./fenrir.sh
##############################################################
    ____             _
   / __/__ ___  ____(_)___
  / _// -_) _ \/ __/ / __/
 /_/  \__/_//_/_/ /_/_/
 v0.9.0-log4shell

 Simple Bash IOC Checker
 Florian Roth, Dec 2021
##############################################################
```

#### YAYA (Yet Another Yara Automaton)

YAYA was created by the [EFF](https://www.eff.org/deeplinks/2020/09/introducing-yaya-new-threat-hunting-tool-eff-threat-lab) (Electronic Frontier Foundation) and released in September 2020. Based on their website, "*YAYA is a new open-source tool to help researchers manage multiple YARA rule repositories. YAYA starts by importing a set of high-quality YARA rules and then lets researchers add their own rules, disable specific rulesets, and run scans of files.*"

Note: Currently, YAYA will only run on Linux systems.

```bash
cmnatic@thm-yara:~/tools$ yaya
YAYA - Yet Another Yara Automaton
Usage:
yaya [-h]  
    -h print this help screen
Commands:
   update - update rulesets
   edit - ban or remove rulesets
   add - add a custom ruleset, located at 
   scan - perform a yara scan on the directory at 
```

In the next section, we will examine [LOKI](https://github.com/Neo23x0/Loki) further...

### Task 8 - Using LOKI and its Yara rule set

#### Using LOKI

As a security analyst, you may need to research various threat intelligence reports, blog postings, etc. and gather information on the latest tactics and techniques used in the wild, past or present. Typically in these readings, IOCs (hashes, IP addresses, domain names, etc.) will be shared so rules can be created to detect these threats in your environment, along with Yara rules. On the flip side, you might find yourself in a situation where you've encountered something unknown, that your security stack of tools can't/didn't detect. Using tools such as Loki, you will need to add your own rules based on your threat intelligence gathers or findings from an incident response engagement (forensics).

As mentioned before, Loki already has a set of Yara rules that we can benefit from and start scanning for evil on the endpoint straightaway.

Loki is located in the `tools` directory.

```bash
cmnatic@thm-yara:~/tools$ ls
Loki  yarGen
```

Navigate to the `Loki` directory. Run `python loki.py -h` to see what options are available.

If you are running Loki on your own system, the first command you should run is `--update`. This will add the `signature-base` directory, which Loki uses to scan for known evil. This command was already executed within the attached VM.

```bash
cmnatic@thm-yara:~/tools/Loki/signature-base$ ls
iocs  misc  yara
```

Navigate to the `yara` directory. Feel free to inspect the different Yara files used by Loki to get an idea of what these rules will hunt for.

To run Loki, you can use the following command (**note that I am calling Loki from within the file 1 directory**)

```bash
cmnatic@thm-yara:~/suspicious-files/file1$ python ../../tools/Loki/loki.py -p .
```

**Scenario**: You are the security analyst for a mid-size law firm. A co-worker discovered suspicious files on a web server within your organization. These files were discovered while performing updates to the corporate website. The files have been copied to your machine for analysis. The files are located in the `suspicious-files` directory. Use Loki to answer the questions below.

#### Scan file 1. Does Loki detect this file as suspicious/malicious or benign?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Yara]
└─$ ssh cmnatic@10.10.249.121     
The authenticity of host '10.10.249.121 (10.10.249.121)' can't be established.
ED25519 key fingerprint is SHA256:RieZYTsQ1UtM4KeZPtl6iqUw/0na+7ckuREypwHYLjI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.249.121' (ED25519) to the list of known hosts.
cmnatic@10.10.249.121's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-163-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue May  6 15:20:53 UTC 2025

  System load:  0.05              Processes:           112
  Usage of /:   78.7% of 8.79GB   Users logged in:     1
  Memory usage: 7%                IP address for eth0: 10.10.249.121
  Swap usage:   0%


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue May  6 15:15:46 2025 from 10.100.2.17
cmnatic@thm-yara:~$ cd suspicious-files/file1/
cmnatic@thm-yara:~/suspicious-files/file1$ python ../../tools/Loki/loki.py -p .
                                                                               
      __   ____  __ ______                            
     / /  / __ \/ //_/  _/ 
    / /__/ /_/ / ,< _/ /   
   /____/\____/_/|_/___/   
      ________  _____  ____
     /  _/ __ \/ ___/ / __/______ ____  ___  ___ ____
    _/ // /_/ / /__  _\ \/ __/ _ `/ _ \/ _ \/ -_) __/
   /___/\____/\___/ /___/\__/\_,_/_//_/_//_/\__/_/
 
   Copyright by Florian Roth, Released under the GNU General Public License
   Version 0.32.1

   DISCLAIMER - USE AT YOUR OWN RISK
   Please report false positives via https://github.com/Neo23x0/Loki/issues



[NOTICE] Starting Loki Scan VERSION: 0.32.1 SYSTEM: thm-yara TIME: 20250506T15:21:35Z PLATFORM:     PROC: x86_64 ARCH: 64bit
[NOTICE] Registered plugin PluginWMI
[NOTICE] Loaded plugin /home/cmnatic/tools/Loki/plugins/loki-plugin-wmi.py
[NOTICE] PE-Sieve successfully initialized BINARY: /home/cmnatic/tools/Loki/tools/pe-sieve64.exe SOURCE: https://github.com/hasherezade/pe-sieve
[INFO] File Name Characteristics initialized with 2841 regex patterns
[INFO] C2 server indicators initialized with 1541 elements
[INFO] Malicious MD5 Hashes initialized with 19034 hashes
[INFO] Malicious SHA1 Hashes initialized with 7159 hashes
[INFO] Malicious SHA256 Hashes initialized with 22841 hashes
[INFO] False Positive Hashes initialized with 30 hashes
[INFO] Processing YARA rules folder /home/cmnatic/tools/Loki/signature-base/yara
[INFO] Initializing all YARA rules at once (composed string of all rule files)
[INFO] Initialized 653 Yara rules
[INFO] Reading private rules from binary ...
[NOTICE] Program should be run as 'root' to ensure all access rights to process memory and file objects.
[NOTICE] Running plugin PluginWMI
[NOTICE] Finished running plugin PluginWMI
[INFO] Scanning . ...
[WARNING]
FILE: ./ind3x.php SCORE: 70 TYPE: PHP SIZE: 80992
FIRST_BYTES: 3c3f7068700a2f2a0a09623337346b20322e320a / <?php/*b374k 2.2
MD5: 1606bdac2cb613bf0b8a22690364fbc5
SHA1: 9383ed4ee7df17193f7a034c3190ecabc9000f9f
SHA256: 5479f8cd1375364770df36e5a18262480a8f9d311e8eedb2c2390ecb233852ad CREATED: Mon Nov  9 15:15:32 2020 MODIFIED: Mon Nov  9 13:06:56 2020 ACCESSED: Tue May  6 15:18:03 2025
REASON_1: Yara Rule MATCH: webshell_metaslsoft SUBSCORE: 70
DESCRIPTION: Web Shell - file metaslsoft.php REF: -
MATCHES: Str1: $buff .= "<tr><td><a href=\\"?d=".$pwd."\\">[ $folder ]</a></td><td>LINK</t
[NOTICE] Results: 0 alerts, 1 warnings, 7 notices
[RESULT] Suspicious objects detected!
[RESULT] Loki recommends a deeper analysis of the suspicious objects.
[INFO] Please report false positives via https://github.com/Neo23x0/signature-base
[NOTICE] Finished LOKI Scan SYSTEM: thm-yara TIME: 20250506T15:21:39Z

Press Enter to exit ...
cmnatic@thm-yara:~/suspicious-files/file1$     
```

Answer: suspicious

#### What Yara rule did it match on?

```bash
<---snip--->
REASON_1: Yara Rule MATCH: webshell_metaslsoft SUBSCORE: 70
DESCRIPTION: Web Shell - file metaslsoft.php REF: -
MATCHES: Str1: $buff .= "<tr><td><a href=\\"?d=".$pwd."\\">[ $folder ]</a></td><td>LINK</t
[NOTICE] Results: 0 alerts, 1 warnings, 7 notices
<---snip--->
```

Answer: webshell_metaslsoft

#### What does Loki classify this file as?

Hint: Check description

```bash
<---snip--->
REASON_1: Yara Rule MATCH: webshell_metaslsoft SUBSCORE: 70
DESCRIPTION: Web Shell - file metaslsoft.php REF: -
MATCHES: Str1: $buff .= "<tr><td><a href=\\"?d=".$pwd."\\">[ $folder ]</a></td><td>LINK</t
[NOTICE] Results: 0 alerts, 1 warnings, 7 notices
<---snip--->
```

Answer: Web Shell

#### Based on the output, what string within the Yara rule did it match on?

```bash
<---snip--->
REASON_1: Yara Rule MATCH: webshell_metaslsoft SUBSCORE: 70
DESCRIPTION: Web Shell - file metaslsoft.php REF: -
MATCHES: Str1: $buff .= "<tr><td><a href=\\"?d=".$pwd."\\">[ $folder ]</a></td><td>LINK</t
[NOTICE] Results: 0 alerts, 1 warnings, 7 notices
<---snip--->
```

Answer: Str1

#### What is the name and version of this hack tool?

Hint: Check first_bytes

```bash
<---snip--->
FILE: ./ind3x.php SCORE: 70 TYPE: PHP SIZE: 80992
FIRST_BYTES: 3c3f7068700a2f2a0a09623337346b20322e320a / <?php/*b374k 2.2
MD5: 1606bdac2cb613bf0b8a22690364fbc5  
<---snip--->
```

Answer: b374k 2.2

#### Inspect the actual Yara file that flagged file 1. Within this rule, how many strings are there to flag this file?

Hint: yara/thor-webshells.yar

```bash
cmnatic@thm-yara:~/tools/Loki/signature-base/yara$ grep webshell_metaslsoft -A20 thor-webshells.yar 
rule webshell_metaslsoft {
        meta:
                description = "Web Shell - file metaslsoft.php"
                license = "https://creativecommons.org/licenses/by-nc/4.0/"
                author = "Florian Roth"
                date = "2014/01/28"
                score = 70
                hash = "aa328ed1476f4a10c0bcc2dde4461789"
        strings:
                $s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t"
        condition:
                all of them
}
rule webshell_asp_Ajan {
        meta:
                description = "Web Shell - file Ajan.asp"
                license = "https://creativecommons.org/licenses/by-nc/4.0/"
                author = "Florian Roth"
                date = "2014/01/28"
                score = 70
                hash = "b6f468252407efc2318639da22b08af0"
```

Answer: 1

#### Scan file 2. Does Loki detect this file as suspicious/malicious or benign?

```bash
cmnatic@thm-yara:~/suspicious-files/file2$ python ../../tools/Loki/loki.py -p .

      __   ____  __ ______
     / /  / __ \/ //_/  _/
    / /__/ /_/ / ,< _/ /
   /____/\____/_/|_/___/
      ________  _____  ____
     /  _/ __ \/ ___/ / __/______ ____  ___  ___ ____
    _/ // /_/ / /__  _\ \/ __/ _ `/ _ \/ _ \/ -_) __/
   /___/\____/\___/ /___/\__/\_,_/_//_/_//_/\__/_/

   Copyright by Florian Roth, Released under the GNU General Public License
   Version 0.32.1

   DISCLAIMER - USE AT YOUR OWN RISK
   Please report false positives via https://github.com/Neo23x0/Loki/issues



[NOTICE] Starting Loki Scan VERSION: 0.32.1 SYSTEM: thm-yara TIME: 20250506T15:43:25Z PLATFORM:     PROC: x86_64 ARCH: 64bit
[NOTICE] Registered plugin PluginWMI
[NOTICE] Loaded plugin /home/cmnatic/tools/Loki/plugins/loki-plugin-wmi.py
[NOTICE] PE-Sieve successfully initialized BINARY: /home/cmnatic/tools/Loki/tools/pe-sieve64.exe SOURCE: https://github.com/hasherezade/pe-sieve
[INFO] File Name Characteristics initialized with 2841 regex patterns
[INFO] C2 server indicators initialized with 1541 elements
[INFO] Malicious MD5 Hashes initialized with 19034 hashes
[INFO] Malicious SHA1 Hashes initialized with 7159 hashes
[INFO] Malicious SHA256 Hashes initialized with 22841 hashes
[INFO] False Positive Hashes initialized with 30 hashes
[INFO] Processing YARA rules folder /home/cmnatic/tools/Loki/signature-base/yara
[INFO] Initializing all YARA rules at once (composed string of all rule files)
[INFO] Initialized 653 Yara rules
[INFO] Reading private rules from binary ...
[NOTICE] Program should be run as 'root' to ensure all access rights to process memory and file objects.
[NOTICE] Running plugin PluginWMI
[NOTICE] Finished running plugin PluginWMI
[INFO] Scanning . ...
[NOTICE] Results: 0 alerts, 0 warnings, 7 notices
[RESULT] SYSTEM SEEMS TO BE CLEAN.
[INFO] Please report false positives via https://github.com/Neo23x0/signature-base
[NOTICE] Finished LOKI Scan SYSTEM: thm-yara TIME: 20250506T15:43:28Z

Press Enter to exit ...      
cmnatic@thm-yara:~/suspicious-files/file2$    
```

Answer: benign

#### Inspect file 2. What is the name and version of this web shell?

Hint: Read the comments in the file

```bash
cmnatic@thm-yara:~/suspicious-files/file2$ head 1ndex.php 
<?php
/*
        b374k shell 3.2.3
        Jayalah Indonesiaku
        (c)2014
        https://github.com/b374k/b374k

*/
$GLOBALS['pass'] = "fb621f5060b9f65acf8eb4232e3024140dea2b34"; // sha1(md5(pass))
$GLOBALS['module_to_load'] = array("explorer", "terminal", "eval", "convert", "database", "info", "mail", "network", "processes");$GLOBALS['resources']['b374k'] = "hVXZrrM4En6gjARhC8yoL9hXQ9gDd2xhJ5yw8/Tj/Oef7tPSSG3JwjZVXy1flZ0nc/Lvuk/KAhmH8j9pMhUU8a864CxnQ3W5fLFwmK5fiX4JV9xny9o8G32+Txphqs9CfjhSqDheisVojklHbHNcLDN17HJaGkpDHGhdFDpklnXd/aNwaGMgVWgoXoHVm2vqktW3PEmkD/Z7CBtSKFwVYXOX81wdh/mYNmh9uy2IWnNjLKB1cAYmEK+bjQWvxK+orA+8oiX9CB/f0dm1akNfVGEnrKGaM/na5bJYFvJ1SgdAFVAf+rRGvU999mkYoJFL16pSUlBmy+WJUVupTTGtU6XK9HlOSHG4FvwFHNcGCOKuChFmNCJqehEG3K0EDbuDmt4+06zR3RReV7N5HebBlir/ezZEeVe0Nm5G1xGjP/3Jeqe/u9orV5zNquk1x3PcGLLT6JkjPujd8lrSONnDONXDeED9+noWIYlGj3KG+s0PXDF+mE3WdzCGbk1r7ojliIpCbc0fNqPW6l85gHH+tAnPlt85WSKMmQ28qjKe3o2GXWHOiTTcl+wcIUec6XlonSgOmgmv1cBI6Od3roxffDJE9GBX4BKbgV1n4/jLZoY7bhxGjNpXaK6wlHEwS3b8yX+TYuhayNJmnOICeOYMlG6LXcaFMUH/teZTS3ENIE+QU2EUIOdVLjNHIDNrCjm1v/0vfbla4fmZyMymiqZn1uwrwLoF2sGzo/3WF6+m1XYL9KlKe7NzfZifT63w5JiENgVaRzIhx0CwCSCUB/AkCaCS4Ag5Z6LgtDx2N89Ysv3oBx60jwdzDLn5gdf+Hc//R7x7zdIffjwfpRw5OJJH3MVifMD8lL9zSCUheeayBLkKNAfG/pE3+g72xutwRB81m2gDTblZgroD3z9t3xRNVMTtE5CwfnGzDTgH1sP/8GBumjy8dung/MBz/o53/iPe+vHdwP9PLX5qlGd+1aPfOvK33He//eo/D/4XGCKTpSbBAlSVg+XT51mtIveF8kPtc+/oh+s7XKA0yVMyc1czK0m5FcizEtp3j9Uobo/VtFeRWwLVL9WirnUKcXlW93Szk17izDlPcX1EFbigsg1m4Bu3L7f8clGbN3VPcKlMC+WaGsjbLV5xpLikFwYn4nK/PwUux5s7Te7nMFjWuTxPwuXfN+fWDrpVEkUS5Ex458opjhDcjLNQQz05SfRiic/yxJYClJJ0GalwMFCLbU6gX550e9lKYn/sJnMVyGGiXy3NOwrpYvKrdGmF09vrvuSXhePUbezJ83DWELlMCqstgB6mN1DFTqlRJFHYXuoQS8VC57CK9a0j0aZJLwEtMql9hnM1CqajXPlsJmLrdJKyeyDCFF28zPzy/BwbK7F5Xa06LEld9yvNS5eEenjezdVXtzNGOeQowW+W0C5CpCdqTQ2rFy2snHfB5tLaxnjaATL3yDQw3ntK3pgFvqi3FeCPK7MNmeabrjgNujuF9XNHOT3yyrwS9lo0uWcT88uuFc0DDYnnO67Z2Iz9YA/06Nlnx6J76pWMd30jVPZGJDyv1qD4ioVxDtUloC8V2z4sSC9TJIZ5vFfrmY+EPCJSo3cjcFMDdBGWV3zCZ+Lga+VMThJhf7Wtqk8CO8uPgbFdr+pAL/ElXfq9aIzto2QY6WVupahhDceF44u7I/TE31hQI2KEiKvhc7bGjxbwGOxaCTKptWrZ3XMauYmqNLoVb4PhzUbTO0RLQ3T8zTOfK3wjk+6V52G/Lhhp7t65JjIFRMMJHjrilgb9VGKGbSbA6/4pfXGV29gx2755aq2/juOiGvnu325kquDsPUi7EG/wO6zHjEhlVTHv8G4hcjaT8nnqPPRmhdlaOYGmrsFcoggzVNpbBl9f4TlK6bWQoqUOnnnK8plsdesZ7WhmFVsSuPOx1BHp45oUpElV7XhhE/TYvfFXKszKl7t7TkzpzJO8l6zI9ki1soLaypb96wl3/cBydJKPVPWP/wI=";
cmnatic@thm-yara:~/suspicious-files/file2$ 
```

Answer: b374k 3.2.3

### Task 9 - Creating Yara rules with yarGen

#### Creating Yara rules with yarGen

From the previous section, we realized that we have a file that Loki didn't flag on. At this point, we are unable to run Loki on other web servers because if file 2 exists in any of the webs servers, it will go undetected.

We need to create a Yara rule to detect this specific web shell in our environment. Typically this is what is done in the case of an incident, which is an event that affects/impacts the organization in a negative fashion.

We can manually open the file and attempt to sift through lines upon lines of code to find possible strings that can be used in our newly created Yara rule.

Let's check how many lines this particular file has. You can run the following: `strings <file name> | wc -l`.

```bash
cmnatic@thm-yara:~/suspicious-files/file2$ strings 1ndex.php | wc -l
3580
```

If you try to go through each string, line by line manually, you should quickly realize that this can be a daunting task.

```bash
if(res=='error'){
$('.ulProgress'+ulType+i).html('( failed )');
}
else{
$('.ulRes'+ulType+i).html(res);
}
loading_stop();
},
error: function(){
loading_stop();
$('.ulProgress'+ulType+i).html('( failed )');
$('.ulProgress'+ulType+i).removeClass('ulProgress'+ulType+i);
$('.ulFilename'+ulType+i).removeClass('ulFilename'+ulType+i);
}
});
}

function ul_go(ulType){
ulFile = (ulType=='comp')? $('.ulFileComp'):$('.ulFileUrl');
ulResult = (ulType=='comp')? $('.ulCompResult'):$('.ulUrlResult');
ulResult.html('');

ulFile.each(function(i){
if(((ulType=='comp')&&this.files[0])||((ulType=='url')&&(this.value!=''))){
file = (ulType=='comp')? this.files[0]: this.value;
filename = (ulType=='comp')? file.name: file.substring(file.lastIndexOf('/')+1);

ulSaveTo = (ulType=='comp')? $('.ulSaveToComp')[i].value:$('.ulSaveToUrl')[i].value;
ulFilename = (ulType=='comp')? $('.ulFilenameComp')[i].value:$('.ulFilenameUrl')[i].value;

--snippet cropped for brevity--
```

Luckily, we can use [yarGen](https://github.com/Neo23x0/yarGen) (yes, another tool created by Florian Roth) to aid us with this task.

What is yarGen? yarGen is a generator for YARA rules.

From the README - "*The main principle is the creation of yara rules from strings found in malware files while removing all strings that also appear in goodware files. Therefore yarGen includes a big goodware strings and opcode database as ZIP archives that have to be extracted before the first use.*"

Navigate to the `yarGen` directory, which is within `tools`. If you are running yarGen on your own system, you need to update it first by running the following command: `python3 yarGen.py --update`.

This will update the good-opcodes and good-strings DB's from the online repository. This update will take a few minutes.

 Once it has been updated successfully, you'll see the following message at the end of the output.

```bash
cmnatic@thm-yara:~/tools/yarGen$ python3 yarGen.py --update
------------------------------------------------------------------------
                   _____
    __ _____ _____/ ___/__ ___
   / // / _ `/ __/ (_ / -_) _ \
   \_, /\_,_/_/  \___/\__/_//_/
  /___/  Yara Rule Generator
         Florian Roth, July 2020, Version 0.23.3

  Note: Rules have to be post-processed
  See this post for details: https://medium.com/@cyb3rops/121d29322282
------------------------------------------------------------------------
Downloading good-opcodes-part1.db from https://www.bsk-consulting.de/yargen/good-opcodes-part1.db ...
```

To use yarGen to generate a Yara rule for file 2, you can run the following command:

`python3 yarGen.py -m /home/cmnatic/suspicious-files/file2 --excludegood -o /home/cmnatic/suspicious-files/file2.yar`

A brief explanation of the parameters above:

- `-m` is the path to the files you want to generate rules for
- `--excludegood` force to exclude all goodware strings (these are strings found in legitimate software and can increase false positives)
- `-o` location & name you want to output the Yara rule

If all is well, you should see the following output.

```bash

           [=] Generated 1 SIMPLE rules.
           [=] All rules written to /home/cmnatic/suspicious-files/file2.yar
           [+] yarGen run finished
```

Generally, you would examine the Yara rule and remove any strings that you feel might generate false positives. For this exercise, we will leave the generated Yara rule as is and test to see if Yara will flag file 2 or no.

**Note**: Another tool created to assist with this is called [yarAnalyzer](https://github.com/Neo23x0/yarAnalyzer/) (you guessed it - created by Florian Roth). We will not examine that tool in this room, but you should read up on it, especially if you decide to start creating your own Yara rules.

Further Reading on creating Yara rules and using yarGen:

- [https://www.bsk-consulting.de/2015/02/16/write-simple-sound-yara-rules/](https://www.bsk-consulting.de/2015/02/16/write-simple-sound-yara-rules/)
- [https://www.bsk-consulting.de/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/](https://www.bsk-consulting.de/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)
- [https://www.bsk-consulting.de/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/](https://www.bsk-consulting.de/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/)

#### From within the root of the suspicious files directory, what command would you run to test Yara and your Yara rule against file 2?

Hint: Use the same name I called the Yara file to answer this question

Answer: yara file2.yar file2/1ndex.php

#### Did Yara rule flag file 2? (Yay/Nay)

```bash
cmnatic@thm-yara:~/suspicious-files$ yara file2.yar file2/1ndex.php
_home_cmnatic_suspicious_files_file2_1ndex file2/1ndex.php
cmnatic@thm-yara:~/suspicious-files$ 
```

Answer: Yay

#### Copy the Yara rule you created into the Loki signatures directory. Test the Yara rule with Loki, does it flag file 2? (Yay/Nay)

```bash
cmnatic@thm-yara:~/suspicious-files$ cp file2.yar ../tools/Loki/signature-base/yara/
cmnatic@thm-yara:~/suspicious-files$ cd file2/
cmnatic@thm-yara:~/suspicious-files/file2$ python ../../tools/Loki/loki.py -p .
                                                                               
      __   ____  __ ______       
     / /  / __ \/ //_/_/  
    / /__/ /_/ / ,<_/ /      
   /____/\____/_/|_/___/    
      ________  _____  ____    
     /  _/ __ \/ ___/ / __/______ ____  ___  ___ ____
    _/ // /_/ / /__  _\ \/ __/ _ `/ _ \/ _ \/ -_) __/
   /___/\____/\___/ /___/\__/\_,_/_//_/_//_/\__/_/

   Copyright by Florian Roth, Released under the GNU General Public License
   Version 0.32.1        

   DISCLAIMER - USE AT YOUR OWN RISK
   Please report false positives via https://github.com/Neo23x0/Loki/issues



[NOTICE] Starting Loki Scan VERSION: 0.32.1 SYSTEM: thm-yara TIME: 20250506T16:06:01Z PLATFORM:     PROC: x86_64 ARCH: 64bit
[NOTICE] Registered plugin PluginWMI
[NOTICE] Loaded plugin /home/cmnatic/tools/Loki/plugins/loki-plugin-wmi.py
[NOTICE] PE-Sieve successfully initialized BINARY: /home/cmnatic/tools/Loki/tools/pe-sieve64.exe SOURCE: https://github.com/hasherezade/pe-sieve
[INFO] File Name Characteristics initialized with 2841 regex patterns
[INFO] C2 server indicators initialized with 1541 elements
[INFO] Malicious MD5 Hashes initialized with 19034 hashes
[INFO] Malicious SHA1 Hashes initialized with 7159 hashes
[INFO] Malicious SHA256 Hashes initialized with 22841 hashes
[INFO] False Positive Hashes initialized with 30 hashes
[INFO] Processing YARA rules folder /home/cmnatic/tools/Loki/signature-base/yara
[INFO] Initializing all YARA rules at once (composed string of all rule files)
[INFO] Initialized 654 Yara rules
[INFO] Reading private rules from binary ...
[NOTICE] Program should be run as 'root' to ensure all access rights to process memory and file objects.
[NOTICE] Running plugin PluginWMI
[NOTICE] Finished running plugin PluginWMI
[INFO] Scanning . ...
[WARNING]                     
FILE: ./1ndex.php SCORE: 70 TYPE: PHP SIZE: 223978
FIRST_BYTES: 3c3f7068700a2f2a0a09623337346b207368656c / <?php/*b374k shel
MD5: c6a7ebafdbe239d65248e2b69b670157                
SHA1: 3926ab64dcf04e87024011cf39902beac32711da               
SHA256: 53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf CREATED: Mon Nov  9 15:16:03 2020 MODIFIED: Mon Nov  9 13:09:18 2020 ACCESSED: Tue May  6 15:43:28 2025
REASON_1: Yara Rule MATCH: _home_cmnatic_suspicious_files_file2_1ndex SUBSCORE: 70
DESCRIPTION: file2 - file 1ndex.php REF: https://github.com/Neo23x0/yarGen
MATCHES: Str1: var Zepto=function(){function G(a){return a==null?String(a):z[A.call(a)]||"object"}function H(a){return G(a)=="function"}fun Str2: $c ... (truncated)
[NOTICE] Results: 0 alerts, 2 warnings, 7 notices
[RESULT] Suspicious objects detected!
[RESULT] Loki recommends a deeper analysis of the suspicious objects.
[INFO] Please report false positives via https://github.com/Neo23x0/signature-base
[NOTICE] Finished LOKI Scan SYSTEM: thm-yara TIME: 20250506T16:06:05Z

Press Enter to exit ...      
cmnatic@thm-yara:~/suspicious-files/file2$  
```

Answer: Yay

#### What is the name of the variable for the string that it matched on?

Hint: Look at $x1

```bash
cmnatic@thm-yara:~/suspicious-files$ grep '$x' -B1 -A2 file2.yar 
   strings:
      $x1 = "var Zepto=function(){function G(a){return a==null?String(a):z[A.call(a)]||\"object\"}function H(a){return G(a)==\"function\"}fun" ascii
      $s2 = "$cmd = trim(execute(\"ps -p \".$pid));" fullword ascii
      $s3 = "return (res = new RegExp('(?:^|; )' + encodeURIComponent(key) + '=([^;]*)').exec(document.cookie)) ? (res[1]) : null;" fullword ascii
--
      uint16(0) == 0x3f3c and filesize < 700KB and
      1 of ($x*) and 4 of them
}
```

Answer: Zepto

#### Inspect the Yara rule, how many strings were generated?

```bash
rule _home_cmnatic_suspicious_files_file2_1ndex {
   meta:
      description = "file2 - file 1ndex.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-06"
      hash1 = "53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf"
   strings:
      $x1 = "var Zepto=function(){function G(a){return a==null?String(a):z[A.call(a)]||\"object\"}function H(a){return G(a)==\"function\"}fun" ascii
      $s2 = "$cmd = trim(execute(\"ps -p \".$pid));" fullword ascii
      $s3 = "return (res = new RegExp('(?:^|; )' + encodeURIComponent(key) + '=([^;]*)').exec(document.cookie)) ? (res[1]) : null;" fullword ascii
      $s4 = "$cmd = execute(\"taskkill /F /PID \".$pid);" fullword ascii
      $s5 = "$buff = execute(\"wget \".$url.\" -O \".$saveas);" fullword ascii
      $s6 = "$buff = execute(\"curl \".$url.\" -o \".$saveas);" fullword ascii
      $s7 = "(d=\"0\"+d);dt2=y+m+d;return dt1==dt2?0:dt1<dt2?-1:1},r:function(a,b){for(var c=0,e=a.length-1,g=h;g;){for(var g=j,f=c;f<e;++f)0" ascii
      $s8 = "$cmd = execute(\"tasklist /FI \\\"PID eq \".$pid.\"\\\"\");" fullword ascii
      $s9 = "$cmd = execute(\"kill -9 \".$pid);" fullword ascii
      $s10 = "execute(\"tar xf \\\"\".basename($archive).\"\\\" -C \\\"\".$target.\"\\\"\");" fullword ascii
      $s11 = "ngs.mimeType||xhr.getResponseHeader(\"content-type\")),result=xhr.responseText;try{dataType==\"script\"?(1,eval)(result):dataTyp" ascii
      $s12 = "execute(\"tar xzf \\\"\".basename($archive).\"\\\" -C \\\"\".$target.\"\\\"\");" fullword ascii
      $s13 = "$body = preg_replace(\"/<a href=\\\"http:\\/\\/www.zend.com\\/(.*?)<\\/a>/\", \"\", $body);" fullword ascii
      $s14 = "$buff = execute(\"lynx -source \".$url.\" > \".$saveas);" fullword ascii
      $s15 = "$check = strtolower(execute(\"perl -h\"));" fullword ascii
      $s16 = "$check = strtolower(execute(\"ruby -h\"));" fullword ascii
      $s17 = "$check = strtolower(execute(\"nodejs -h\"));" fullword ascii
      $s18 = "$check = strtolower(execute(\"java -help\"));" fullword ascii
      $s19 = "$check = strtolower(execute(\"python -h\"));" fullword ascii
      $s20 = "$buff = execute(\"lwp-download \".$url.\" \".$saveas);" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 700KB and
      1 of ($x*) and 4 of them
}
```

Answer: 20

#### One of the conditions to match on the Yara rule specifies file size. The file has to be less than what amount?

```bash
<---snip--->
   condition:
      uint16(0) == 0x3f3c and filesize < 700KB and
      1 of ($x*) and 4 of them
<---snip--->
```

Answer: 700KB

### Task 10 - Valhalla

#### Valhalla

**Valhalla** is an online Yara feed created and hosted by [Nextron-Systems](https://www.nextron-systems.com/valhalla/) (erm, Florian Roth). By now, you should be aware of the ridiculous amount of time and energy Florian has dedicated to creating these tools for the community. Maybe we should have just called this the Florian Roth room. (lol)

Per the website, "*Valhalla boosts your detection capabilities with the power of thousands of hand-crafted high-quality YARA rules.*"

![Valhalla web site](Images/Valhalla_web_site.png)

From the image above, we should denote that we can conduct searches based on a keyword, tag, ATT&CK technique, sha256, or rule name.

Note: For more information on ATT&CK, please visit the [MITRE room](https://tryhackme.com/room/mitre).

Taking a look at the data provided to us, let's examine the rule in the screenshot below:

![Valhalla Yara Example](Images/Valhalla_Yara_Example.png)

We are provided with the name of the rule, a brief description, a reference link for more information about the rule, along with the rule date.

Feel free to look at some rules to become familiar with the usefulness of Valhalla. The best way to learn the product is by just jumping right in.

Picking up from our scenario, at this point, you know that the 2 files are related. Even though Loki classified the files are suspicious, you know in your gut that they are malicious. Hence the reason you created a Yara rule using yarGen to detect it on other web servers. But let's further pretend that you are not code-savvy (FYI - not all security professionals know how to code/script or read it). You need to conduct further research regarding these files to receive approval to eradicate these files from the network.

Time to use Valhalla for some threat intelligence gathering...

#### Enter the SHA256 hash of file 1 into Valhalla. Is this file attributed to an APT group? (Yay/Nay)

SHA256: 5479f8cd1375364770df36e5a18262480a8f9d311e8eedb2c2390ecb233852ad

![Valhalla Search 1](Images/Valhalla_Search_1.png)

Answer: Yay

#### Do the same for file 2. What is the name of the first Yara rule to detect file 2?

SHA256: 53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf

Note: By "first" the seem to mean the "oldest"!?

![Valhalla Search 2](Images/Valhalla_Search_2.png)

Answer: Webshell_b374k_rule1

#### Examine the information for file 2 from Virus Total (VT). The Yara Signature Match is from what scanner?

Hint: This information is on the Community tab of the VirusTotal page, and not on the Detection tab.

From the community tab (`https://www.virustotal.com/gui/file/53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf/community`)

Answer: THOR APT Scanner

#### Enter the SHA256 hash of file 2 into Virus Total. Did every AV detect this as malicious? (Yay/Nay)

From `https://www.virustotal.com/gui/file/53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf`

Answer: Nay

#### Besides .PHP, what other extension is recorded for this file?

Hint: Look under the "details" tab in Virustotal to find out the extensions for this submission.

From `https://www.virustotal.com/gui/file/53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf/details`

Note: Had to try a couple of extensions here since more file types have been scan since the creation of the room!

Answer: exe

#### What JavaScript library is used by file 2?

Hint: Go to the Github page and search inside the index.php file

1. Search for `b374k shell` on GitHub => `https://github.com/b374k/b374k`
2. Find the `index.php` file => `https://github.com/b374k/b374k/blob/master/index.php`
3. Locate the library

From index.php

```php
/* JAVASCRIPT AND CSS FILES START */
$zepto_code = packer_read_file($GLOBALS['packer']['base_dir']."zepto.js");
```

Also check the requirements

```text
Requirements :
 * PHP version > 4.3.3 and PHP 5
 * As it using zepto.js v1.1.2, you need modern browser to use b374k shell. See browser support on zepto.js website http://zeptojs.com/
 * Responsibility of what you do with this shell
```

Answer: zepto

#### Is this Yara rule in the default Yara file Loki uses to detect these type of hack tools? (Yay/Nay)

Hint: Examine thor-webshell.yar and search for the rule name

Note: Very unclear what yara rule they are referring to, but it is probably `Webshell_b374k_rule1`

```bash
cmnatic@thm-yara:~/tools/Loki/signature-base/yara$ grep -i Webshell_b374k_rule1 *
cmnatic@thm-yara:~/tools/Loki/signature-base/yara$ 
```

Answer: Nay

### Task 11 - Conclusion

In this room, we explored Yara, how to use Yara, and manually created basic Yara rules. We also explored various open-source tools to hit the ground running that utilizes Yara rules to detect evil on endpoints.

By going through the room scenario, you should understand the need (as a blue teamer) to know how to create Yara rules effectively if we rely on such tools. Commercial products, even though not perfect, will have a much richer Yara ruleset than an open-source product. Both commercial and open-source will allow you to add Yara rules to expand its capabilities further to detect threats.

If it is not clear, the reason why **file 2** was not detected is that the Yara rule was not in the Yara file used by Loki to detect the hack tool (web shell) even though its the hack tool has been around for years and has even been attributed to at least 1 nation-state. The Yara rule is present in the commercial variant of Loki, which is Thor.

There is more that can be done with Yara and Yara rules. We encourage you to explore this tool further at your own leisure.

For additional information, please see the references below.

## References

- [Yara - Documentation](https://yara.readthedocs.io/en/latest/)
- [Yara - GitHub](https://github.com/virustotal/yara)
- [Yara - Homepage](https://virustotal.github.io/yara/)
