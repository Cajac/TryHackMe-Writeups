# ffuf

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: -
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
Enumeration, fuzzing, and directory brute forcing using ffuf
```

Room link: [https://tryhackme.com/room/ffuf](https://tryhackme.com/room/ffuf)

## Solution

### Task 1: Introduction

#### Summary

**ffuf** stands for **Fuzz Faster U Fool**. It's a tool used for web enumeration, fuzzing, and directory brute forcing.

#### Install ffuf

ffuf is already included in the following Linux distributions:

- BlackArch
- Pentoo
- Kali
- Parrot
- Search [Repology](https://repology.org/project/ffuf/versions) for other distributions

Note: Repology is a service that monitors a lot of package repositories and other sources and aggregates data on software package versions, reporting new releases and packaging problems.

If it's not included in your Linux distribution you can deploy it manually following [the installation instructions](https://github.com/ffuf/ffuf#installation).

#### Install SecLists

SecLists is a collection of multiple types of lists used during security assessments. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.

SecLists is already included in the following Linux distributions:

- BlackArch
- Pentoo
- Kali
- Parrot
- Search [Repology](https://repology.org/project/seclists/versions) for other distributions

If it's not included in your Linux distribution you can deploy it manually following [the installation instructions](https://github.com/danielmiessler/SecLists#install).

---------------------------------------------------------------------------

### Task 2: Basics

The Help page can be displayed using `ffuf -h` and it will be useful as we will use a lot of options.

```bash
Fuzz Faster U Fool - v1.3.0-dev

HTTP OPTIONS:
  -H                  Header `"Name: Value"`, separated by colon. Multiple -H flags are accepted.
  -X                  HTTP method to use
  -b                  Cookie data `"NAME1=VALUE1; NAME2=VALUE2"` for copy as curl functionality.
  -d                  POST data
  -ignore-body        Do not fetch the response content. (default: false)
  -r                  Follow redirects (default: false)
  -recursion          Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it. (default: false)
  -recursion-depth    Maximum recursion depth. (default: 0)
  -recursion-strategy Recursion strategy: "default" for a redirect based, and "greedy" to recurse on all matches (default: default)
  -replay-proxy       Replay matched requests using this proxy.
  -timeout            HTTP request timeout in seconds. (default: 10)
  -u                  Target URL
  -x                  Proxy URL (SOCKS5 or HTTP). For example: http://127.0.0.1:8080 or socks5://127.0.0.1:8080

GENERAL OPTIONS:
  -V                  Show version information. (default: false)
  -ac                 Automatically calibrate filtering options (default: false)
  -acc                Custom auto-calibration string. Can be used multiple times. Implies -ac
  -c                  Colorize output. (default: false)
  -config             Load configuration from a file
  -maxtime            Maximum running time in seconds for entire process. (default: 0)
  -maxtime-job        Maximum running time in seconds per job. (default: 0)
  -p                  Seconds of `delay` between requests, or a range of random delay. For example "0.1" or "0.1-2.0"
  -rate               Rate of requests per second (default: 0)
  -s                  Do not print additional information (silent mode) (default: false)
  -sa                 Stop on all error cases. Implies -sf and -se. (default: false)
  -se                 Stop on spurious errors (default: false)
  -sf                 Stop when > 95% of responses return 403 Forbidden (default: false)
  -t                  Number of concurrent threads. (default: 40)
  -v                  Verbose output, printing full URL and redirect location (if any) with the results. (default: false)

MATCHER OPTIONS:
  -mc                 Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403,405)
  -ml                 Match amount of lines in response
  -mr                 Match regexp
  -ms                 Match HTTP response size
  -mw                 Match amount of words in response

FILTER OPTIONS:
  -fc                 Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl                 Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr                 Filter regexp
  -fs                 Filter HTTP response size. Comma separated list of sizes and ranges
  -fw                 Filter by amount of words in response. Comma separated list of word counts and ranges

INPUT OPTIONS:
  -D                  DirSearch wordlist compatibility mode. Used in conjunction with -e flag. (default: false)
  -e                  Comma separated list of extensions. Extends FUZZ keyword.
  -ic                 Ignore wordlist comments (default: false)
  -input-cmd          Command producing the input. --input-num is required when using this input method. Overrides -w.
  -input-num          Number of inputs to test. Used in conjunction with --input-cmd. (default: 100)
  -input-shell        Shell to be used for running command
  -mode               Multi-wordlist operation mode. Available modes: clusterbomb, pitchfork (default: clusterbomb)
  -request            File containing the raw http request
  -request-proto      Protocol to use along with raw request (default: https)
  -w                  Wordlist file path and (optional) keyword separated by colon. eg. '/path/to/wordlist:KEYWORD'

OUTPUT OPTIONS:
  -debug-log          Write all of the internal logging to the specified file.
  -o                  Write output to file
  -od                 Directory path to store matched results to.
  -of                 Output file format. Available formats: json, ejson, html, md, csv, ecsv (or, 'all' for all formats) (default: json)
  -or                 Don't create the output file if we don't have results (default: false)
  ```

**Deploy the machine**.

At a minimum we're required to supply two options: `-u` to specify an URL and `-w` to specify a wordlist. The default keyword `FUZZ` is used to tell ffuf where the wordlist entries will be injected. We can append it to the end of the URL like so:

`ffuf -u http://10.114.186.69/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt`

You could also use any custom keyword instead of `FUZZ`, you just need to define it like this `wordlist.txt:KEYWORD`.

`ffuf -u http://10.114.186.69/NORAJ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt:NORAJ`

Note: The path to the wordlist may vary depending on where you stored them.

---------------------------------------------------------------------------

#### What is the first file you found with a 200 status code?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ export TARGET_IP=10.114.186.69 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://$TARGET_IP/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.114.186.69/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 289, Words: 21, Lines: 11, Duration: 1677ms]
.htaccess               [Status: 403, Size: 289, Words: 21, Lines: 11, Duration: 3673ms]
config                  [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 24ms]
docs                    [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 23ms]
external                [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 22ms]
favicon.ico             [Status: 200, Size: 1406, Words: 5, Lines: 2, Duration: 25ms]
robots.txt              [Status: 200, Size: 26, Words: 3, Lines: 2, Duration: 26ms]
server-status           [Status: 403, Size: 293, Words: 21, Lines: 11, Duration: 22ms]
:: Progress: [20478/20478] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

Answer: `favicon.ico`

---------------------------------------------------------------------------

### Task 3: Finding pages and directories

One approach you could take would be to start enumerating with a generic list of files such as `raft-medium-files-lowercase.txt`.

`ffuf -u http://10.114.186.69/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt`

However, using a large generic wordlist containing irrelevant file extensions is not very efficient.

Instead, we can usually assume `index.<extension>` is the default page on most websites so we can try common extensions for just the index page. With this method, we can usually determine what programming language or languages the site uses.

For example, we can append the extension after index.

```bash
head /usr/share/seclists/Discovery/Web-Content/web-extensions.txt                                                            
.asp
.aspx
.bat
.c
.cfm
.cgi
.css
.com
.dll
.exe
```

`ffuf -u http://10.114.186.69/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt`

Now that we know the extensions supported we can try a list of generic words (without of extension) and apply the extensions we know works (found from Q2) + some common ones like `.txt`.

We'll exclude the 4 letter extensions from this wordlist as it will result in many false positives.

`ffuf -u http://10.114.186.69/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .php,.txt`

Directory names are not always dependent on the type of environment you're enumerating and is often a good starting point before attempting to fuzz for files. If we wanted to fuzz directories we only need to provide a wordlist.

`ffuf -u http://10.114.186.69/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt`

---------------------------------------------------------------------------

#### What text file did you find?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .php,.txt -ac -u http://$TARGET_IP/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.114.186.69/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt
 :: Extensions       : .php .txt 
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 23ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 22ms]
config                  [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 21ms]
docs                    [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 21ms]
about.php               [Status: 200, Size: 4840, Words: 331, Lines: 109, Duration: 31ms]
.                       [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 22ms]
login.php               [Status: 200, Size: 1523, Words: 89, Lines: 77, Duration: 2493ms]
external                [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 22ms]
setup.php               [Status: 200, Size: 4067, Words: 308, Lines: 123, Duration: 26ms]
robots.txt              [Status: 200, Size: 26, Words: 3, Lines: 2, Duration: 21ms]
security.php            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 23ms]
phpinfo.php             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 22ms]
instructions.php        [Status: 200, Size: 14014, Words: 1484, Lines: 263, Duration: 28ms]
:: Progress: [168879/168879] :: Job [1/1] :: 1785 req/sec :: Duration: [0:01:44] :: Errors: 0 ::
```

Answer: `robots.txt`

#### What two file extensions were found for the index page?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -ac -u http://$TARGET_IP/indexFUZZ                     

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.114.186.69/indexFUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.phps                   [Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 3820ms]
.php                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 4829ms]
:: Progress: [43/43] :: Job [1/1] :: 9 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Answer: `php,phps`

#### What page has a size of 4840?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .php,.txt -u http://$TARGET_IP/FUZZ -ms 4840

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.114.186.69/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt
 :: Extensions       : .php .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response size: 4840
________________________________________________

about.php               [Status: 200, Size: 4840, Words: 331, Lines: 109, Duration: 23ms]
:: Progress: [168879/168879] :: Job [1/1] :: 1739 req/sec :: Duration: [0:01:44] :: Errors: 0 ::
```

Answer: `about.php`

#### How many directories are there?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://$TARGET_IP/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.114.186.69/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

config                  [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 22ms]
docs                    [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 22ms]
external                [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 22ms]
server-status           [Status: 403, Size: 293, Words: 21, Lines: 11, Duration: 22ms]
:: Progress: [26583/26583] :: Job [1/1] :: 1639 req/sec :: Duration: [0:00:19] :: Errors: 1 ::
```

Note that no auto-calibration (`-ac`) was used here!

Answer: `4`

---------------------------------------------------------------------------

### Task 4: Using filters

Remember the command we ran for Q1 of Task 3?

```bash
$ ffuf -u http://10.114.186.69/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.130.176/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

favicon.ico             [Status: 200, Size: 1406, Words: 5, Lines: 2]
.htaccess               [Status: 403, Size: 289, Words: 21, Lines: 11]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1]
robots.txt              [Status: 200, Size: 26, Words: 3, Lines: 2]
phpinfo.php             [Status: 302, Size: 0, Words: 1, Lines: 1]
.                       [Status: 302, Size: 0, Words: 1, Lines: 1]
php.ini                 [Status: 200, Size: 148, Words: 17, Lines: 5]
about.php               [Status: 200, Size: 4840, Words: 331, Lines: 109]
.html                   [Status: 403, Size: 285, Words: 21, Lines: 11]
login.php               [Status: 200, Size: 1523, Words: 89, Lines: 77]
.php                    [Status: 403, Size: 284, Words: 21, Lines: 11]
setup.php               [Status: 200, Size: 4067, Words: 308, Lines: 123]
.htpasswd               [Status: 403, Size: 289, Words: 21, Lines: 11]
security.php            [Status: 302, Size: 0, Words: 1, Lines: 1]
.htm                    [Status: 403, Size: 284, Words: 21, Lines: 11]
.htpasswds              [Status: 403, Size: 290, Words: 21, Lines: 11]
index.php               [Status: 302, Size: 0, Words: 1, Lines: 1]
.htgroup                [Status: 403, Size: 288, Words: 21, Lines: 11]
wp-forum.phps           [Status: 403, Size: 293, Words: 21, Lines: 11]
.htaccess.bak           [Status: 403, Size: 293, Words: 21, Lines: 11]
.htuser                 [Status: 403, Size: 287, Words: 21, Lines: 11]
.ht                     [Status: 403, Size: 283, Words: 21, Lines: 11]
.htc                    [Status: 403, Size: 284, Words: 21, Lines: 11]
:: Progress: [16243/16243] :: Job [1/1] :: 1690 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

We had a lot of output but not much was useful.

For example, a 403 [HTTP status code](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes) indicates that we're forbidden to access the requested resource. Let's hide responses with 403 status codes for now. We can accomplish this by using filters.

By adding `-fc 403` (filter code) we'll hide from the output all 403 HTTP status codes.

`ffuf -u http://10.114.186.69/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fc 403`

Sometimes you might want to filter out multiple status codes such as 500, 302, 301, 401, etc. For instance, if you know you want to see 200 status code responses, you could use `-mc 200` (match code) instead of having a long list of filtered codes.

`ffuf -u http://10.114.186.69/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -mc 200`

Sometimes it might be beneficial to see what requests the server doesn't handle by matching for HTTP 500 Internal Server Error response codes (`-mc 500`). Finding irregularities in behavior could help better understand how the web app works.

There are other filters and matchers. For example, you could encounter entries with a 200 status code with a response size of zero. eg. `functions.php` or `inc/myfile.php`.

```bash
$ ffuf -u http://10.114.186.69/config/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fc 403
...
.                       [Status: 200, Size: 1165, Words: 76, Lines: 18]
config.inc.php          [Status: 200, Size: 0, Words: 1, Lines: 1]
:: Progress: [16243/16243] :: Job [1/1] :: 1732 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

Unless we have a LFI (local file inclusion) this kind of files aren't interesting, so we can use `-fs 0` (filter size).

Here are all filters and matchers:

```bash
$ ffuf -h
...
MATCHER OPTIONS:
  -mc                 Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403,405)
  -ml                 Match amount of lines in response
  -mr                 Match regexp
  -ms                 Match HTTP response size
  -mw                 Match amount of words in response

FILTER OPTIONS:
  -fc                 Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl                 Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr                 Filter regexp
  -fs                 Filter HTTP response size. Comma separated list of sizes and ranges
  -fw                 Filter by amount of words in response. Comma separated list of word counts and ranges
...
```

We often see there are false positives with files beginning with a dot (eg. `.htgroups`, `.php`, etc.). They throw a 403 Forbidden error, however those files don't actually exist. It's tempting to use `-fc 403` but this could hide valuable files we don't have access to yet. So instead we can use a regexp to match all files beginning with a dot.

`ffuf -u http://10.114.186.69/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fr '/\..*'`

---------------------------------------------------------------------------

#### After applying the fc filter, how many results were returned?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://$TARGET_IP/FUZZ -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.114.186.69/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403
________________________________________________

index.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 34ms]
login.php               [Status: 200, Size: 1523, Words: 89, Lines: 77, Duration: 34ms]
favicon.ico             [Status: 200, Size: 1406, Words: 5, Lines: 2, Duration: 31ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 23ms]
robots.txt              [Status: 200, Size: 26, Words: 3, Lines: 2, Duration: 28ms]
phpinfo.php             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 24ms]
.                       [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 27ms]
php.ini                 [Status: 200, Size: 148, Words: 17, Lines: 5, Duration: 23ms]
about.php               [Status: 200, Size: 4840, Words: 331, Lines: 109, Duration: 24ms]
setup.php               [Status: 200, Size: 4067, Words: 308, Lines: 123, Duration: 23ms]
security.php            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 22ms]
:: Progress: [16244/16244] :: Job [1/1] :: 1360 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

Answer: `11`

#### After applying the mc filter, how many results were returned?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://$TARGET_IP/FUZZ -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.114.186.69/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

favicon.ico             [Status: 200, Size: 1406, Words: 5, Lines: 2, Duration: 22ms]
robots.txt              [Status: 200, Size: 26, Words: 3, Lines: 2, Duration: 22ms]
php.ini                 [Status: 200, Size: 148, Words: 17, Lines: 5, Duration: 22ms]
about.php               [Status: 200, Size: 4840, Words: 331, Lines: 109, Duration: 23ms]
login.php               [Status: 200, Size: 1523, Words: 89, Lines: 77, Duration: 1677ms]
setup.php               [Status: 200, Size: 4067, Words: 308, Lines: 123, Duration: 25ms]
:: Progress: [16244/16244] :: Job [1/1] :: 1754 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
```

Answer: `6`

#### Which valuable file would have been hidden if you used -fc 403 instead of -fr?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://$TARGET_IP/FUZZ -fr '/\..*'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.114.186.69/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: /\..*
________________________________________________

index.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 23ms]
favicon.ico             [Status: 200, Size: 1406, Words: 5, Lines: 2, Duration: 22ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 26ms]
robots.txt              [Status: 200, Size: 26, Words: 3, Lines: 2, Duration: 22ms]
phpinfo.php             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 29ms]
.                       [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 27ms]
php.ini                 [Status: 200, Size: 148, Words: 17, Lines: 5, Duration: 30ms]
about.php               [Status: 200, Size: 4840, Words: 331, Lines: 109, Duration: 24ms]
setup.php               [Status: 200, Size: 4067, Words: 308, Lines: 123, Duration: 27ms]
login.php               [Status: 200, Size: 1523, Words: 89, Lines: 77, Duration: 3213ms]
security.php            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 24ms]
wp-forum.phps           [Status: 403, Size: 293, Words: 21, Lines: 11, Duration: 23ms]
:: Progress: [16244/16244] :: Job [1/1] :: 1754 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
```

Answer: `wp-forum.phps`

---------------------------------------------------------------------------

### Task 5: Fuzzing parameters

Deploy the **new machine**.

For this task, we'll be looking at parameter fuzzing. This is the base URL we'll be fuzzing: `http://10.114.172.118/sqli-labs/Less-1/`.

What would you do when you find a page or API endpoint but don't know which parameters are accepted? You fuzz!

Discovering a vulnerable parameter could lead to file inclusion, path disclosure, XSS, SQL injection, or even command injection. Since ffuf allows you to put the keyword anywhere we can use it to fuzz for parameters.

`ffuf -u 'http://10.114.172.118/sqli-labs/Less-1/?FUZZ=1' -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fw 39`

`ffuf -u 'http://10.114.172.118/sqli-labs/Less-1/?FUZZ=1' -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fw 39`

Now that we found a parameter accepting integer values we'll start fuzzing values.

At this point, we could generate a wordlist and save a file containing integers. To cut out a step we can use `-w -` which tells `ffuf` to read a wordlist from stdout. This will allow us to generate a list of integers with a command of our choice then pipe the output to `ffuf`. Below is a list of 5 different ways to generate numbers 0 - 255.

1. `ruby -e '(0..255).each{|i| puts i}' | ffuf -u 'http://10.114.172.118/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33`
2. `ruby -e 'puts (0..255).to_a' | ffuf -u 'http://10.114.172.118/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33`
3. `for i in {0..255}; do echo $i; done | ffuf -u 'http://10.114.172.118/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33`
4. `seq 0 255 | ffuf -u 'http://10.114.172.118/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33`
5. `cook '[0-255]' | ffuf -u 'http://10.114.172.118/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33`

We can also use `ffuf` for wordlist-based brute-force attacks, for example, trying passwords on an authentication page.

`ffuf -u http://10.114.172.118/sqli-labs/Less-11/ -c -w /usr/share/seclists/Passwords/Leaked-Databases/hak5.txt -X POST -d 'uname=Dummy&passwd=FUZZ&submit=Submit' -fs 1435 -H 'Content-Type: application/x-www-form-urlencoded'`

Here we have to use the POST method (specified with `-X`) and to give the POST data (with `-d`) where we include the `FUZZ` keyword in place of the password.

We also have to specify a custom header `-H 'Content-Type: application/x-www-form-urlencoded'` because ffuf doesn't set this content-type header automatically as curl does.

---------------------------------------------------------------------------

#### What is the parameter you found?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ export TARGET_IP=10.114.172.118

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "http://$TARGET_IP/sqli-labs/Less-1/?FUZZ=1" -fw 39

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.114.172.118/sqli-labs/Less-1/?FUZZ=1
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 39
________________________________________________

id                      [Status: 200, Size: 721, Words: 37, Lines: 29, Duration: 26ms]
:: Progress: [6453/6453] :: Job [1/1] :: 1492 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Answer: `id`

#### What is the highest valid id?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ seq 0 255 | ffuf -c -u "http://$TARGET_IP/sqli-labs/Less-1/?id=FUZZ" -fw 33 -w - 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.114.172.118/sqli-labs/Less-1/?id=FUZZ
 :: Wordlist         : FUZZ: -
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 33
________________________________________________

6                       [Status: 200, Size: 728, Words: 37, Lines: 29, Duration: 25ms]
11                      [Status: 200, Size: 725, Words: 37, Lines: 29, Duration: 24ms]
12                      [Status: 200, Size: 725, Words: 37, Lines: 29, Duration: 27ms]
2                       [Status: 200, Size: 731, Words: 37, Lines: 29, Duration: 27ms]
8                       [Status: 200, Size: 723, Words: 37, Lines: 29, Duration: 28ms]
7                       [Status: 200, Size: 725, Words: 37, Lines: 29, Duration: 27ms]
1                       [Status: 200, Size: 721, Words: 37, Lines: 29, Duration: 27ms]
10                      [Status: 200, Size: 725, Words: 37, Lines: 29, Duration: 2813ms]
4                       [Status: 200, Size: 725, Words: 37, Lines: 29, Duration: 4823ms]
5                       [Status: 200, Size: 728, Words: 37, Lines: 29, Duration: 4823ms]
3                       [Status: 200, Size: 726, Words: 37, Lines: 29, Duration: 4826ms]
9                       [Status: 200, Size: 725, Words: 37, Lines: 29, Duration: 4825ms]
14                      [Status: 200, Size: 725, Words: 37, Lines: 29, Duration: 4817ms]
:: Progress: [256/256] :: Job [1/1] :: 42 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Answer: `14`

#### What is Dummy's password?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/ffuf]
└─$ ffuf -c -w /usr/share/seclists/Passwords/Leaked-Databases/hak5.txt -X POST -d 'uname=Dummy&passwd=FUZZ&submit=Submit' -fs 1435 -H 'Content-Type: application/x-www-form-urlencoded' -u "http://$TARGET_IP/sqli-labs/Less-11/"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.114.172.118/sqli-labs/Less-11/
 :: Wordlist         : FUZZ: /usr/share/seclists/Passwords/Leaked-Databases/hak5.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : uname=Dummy&passwd=FUZZ&submit=Submit
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1435
________________________________________________

p@ssword                [Status: 200, Size: 1526, Words: 100, Lines: 50, Duration: 23ms]
:: Progress: [2351/2351] :: Job [1/1] :: 131 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Answer: `p@ssword`

---------------------------------------------------------------------------

### Task 6: Finding vhosts and subdomains

ffuf may not be as efficient as specialized tools when it comes to subdomain enumeration but it's possible to do.

`ffuf -u http://FUZZ.mydomain.com -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

Some subdomains might not be resolvable by the DNS server you're using and are only resolvable from within the target's local network by their private DNS servers. So some virtual hosts (vhosts) may exist with private subdomains so the previous command doesn't find them. To try finding private subdomains we'll have to use the Host HTTP header as these requests might be accepted by the web server.

**Note**: [virtual hosts](https://httpd.apache.org/docs/2.4/en/vhosts/examples.html) (vhosts) is the name used by Apache httpd but for Nginx the right term is [Server Blocks](https://www.nginx.com/resources/wiki/start/topics/examples/server_blocks/).

You could compare the results obtained with direct subdomain enumeration and with vhost enumeration:

`ffuf -u http://FUZZ.mydomain.com -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0`

`ffuf -u http://mydomain.com -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.mydomain.com' -fs 0`

For example, it is possible that you can't find a sub-domain with direct subdomain enumeration (1st command) but that you can find it with vhost enumeration (2nd command).

Vhost enumeration technique shouldn't be discounted as it may lead to discovering content that wasn't meant to be accessed externally.

---------------------------------------------------------------------------

### Task 7: Proxifying ffuf traffic

Whether it's for [network pivoting](https://blog.raw.pm/en/state-of-the-art-of-network-pivoting-in-2019/) or for using BurpSuite plugins you can send all the ffuf traffic through a web proxy (HTTP or SOCKS5).

`ffuf -u http://10.114.172.118/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -x http://127.0.0.1:8080`

It's also possible to send only matches to your proxy for replaying:

`ffuf -u http://10.114.172.118/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -replay-proxy http://127.0.0.1:8080`

This may be useful if you don't need all the traffic to traverse an upstream proxy and want to minimize resource usage or to avoid polluting your proxy history.

---------------------------------------------------------------------------

### Task 8: Reviewing the options

As you start to use ffuf more, some options will prove to be very useful depending on your situation. For example, `-ic` allows you to ignore comments in wordlists that such as headers, copyright notes, comments, etc

```bash
$ head /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt                                                            
# directory-list-2.3-medium.txt
#
# Copyright 2007 James Fisher
#
# This work is licensed under the Creative Commons
# Attribution-Share Alike 3.0 License. To view a copy of this
# license, visit http://creativecommons.org/licenses/by-sa/3.0/
# or send a letter to Creative Commons, 171 Second Street,
# Suite 300, San Francisco, California, 94105, USA.
#
```

`ffuf -u http://10.114.172.118/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -fs 0`

We've only reviewed a small subset of the useful features and options ffuf has to offer for fuzzing.

Use `ffuf -h` to discover the other options that might be useful for you and to answer the remaining questions in this task.

---------------------------------------------------------------------------

#### How do you save the output to a markdown file (ffuf.md)?

Hint: format first

Answer: `-of md -o ffuf.md`

#### How do you re-use a raw http request file?

Answer: `-request`

#### How do you strip comments from a wordlist?

Answer: `-ic`

#### How would you read a wordlist from STDIN?

Answer: `-w -`

#### How do you print full URLs and redirect locations?

Answer: `-v`

#### What option would you use to follow redirects?

Answer: `-r`

#### How do you enable colorized output?

Answer: `-c`

---------------------------------------------------------------------------

### Task 9: About the author

I hoped you enjoyed the room.

To find out more about me (**noraj**) check out [pwn.by/noraj](https://pwn.by/noraj).

You can find my other THM rooms on [my THM profile](https://tryhackme.com/p/noraj).

---------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [ffuf - GitHub](https://github.com/ffuf/ffuf)
- [ffuf - Kali Tools](https://www.kali.org/tools/ffuf/)
- [ffuf - Wiki](https://github.com/ffuf/ffuf/wiki)
- [List of HTTP status codes - Wikipedia](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)
- [SecLists - GitHub](https://github.com/danielmiessler/SecLists)
- [seq - Linux manual page](https://man7.org/linux/man-pages/man1/seq.1.html)
- [Virtual hosting - Wikipedia](https://en.wikipedia.org/wiki/Virtual_hosting)
