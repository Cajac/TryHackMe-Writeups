# Content Discovery

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Premium
Description:
Learn the various ways of discovering hidden or private content on a webserver that could lead to new vulnerabilities.
```

Room link: [https://tryhackme.com/room/contentdiscovery](https://tryhackme.com/room/contentdiscovery)

## Solution

### Task 1: What Is Content Discovery?

Firstly, we should ask, in the context of web application security, what is content? Content can be many things, a file, video, picture, backup, a website feature. When we talk about content discovery, we're not talking about the obvious things we can see on a website; it's the things that aren't immediately presented to us and that weren't always intended for public access.

This content could be, for example, pages or portals intended for staff usage, older versions of the website, backup files, configuration files, administration panels, etc.

There are three main ways of discovering content on a website which we'll cover. Manually, Automated and OSINT (Open-Source Intelligence).

Start the AttackBox (by clicking the blue "Start AttackBox" button), and the machine on this task.

---------------------------------------------------------------------------------------

#### What is the Content Discovery method that begins with M?

Answer: `Manually`

#### What is the Content Discovery method that begins with A?

Answer: `Automated`

#### What is the Content Discovery method that begins with O?

Answer: `OSINT`

### Task 2: Manual Discovery - Robots.txt

There are multiple places we can manually check on a website to start discovering more content.

#### Robots.txt

The robots.txt file is a document that tells search engines which pages they are and aren't allowed to show on their search engine results or ban specific search engines from crawling the website altogether. It can be common practice to restrict certain website areas so they aren't displayed in search engine results. These pages may be areas such as administration portals or files meant for the website's customers. This file gives us a great list of locations on the website that the owners don't want us to discover as penetration testers.

Take a look at the robots.txt file on the Acme IT Support website to see if they have anything they don't want to list - To do this open Firefox on the AttackBox, and enter the url: `http://10.10.219.21/robots.txt` (this URL will update 2 minutes from when you start the machine in task 1)

---------------------------------------------------------------------------------------

#### What is the directory in the robots.txt that isn't allowed to be viewed by web crawlers?

Check the robots.txt file with curl

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Content_Discovery]
└─$ curl http://10.10.219.21/robots.txt 
User-agent: *
Allow: /
Disallow: /staff-portal  
```

Answer: `/staff-portal`

### Task 3: Manual Discovery - Favicon

#### Favicon

The favicon is a small icon displayed in the browser's address bar or tab used for branding a website.

![Favicon](Images/Favicon.png)

Sometimes when frameworks are used to build a website, a favicon that is part of the installation gets leftover, and if the website developer doesn't replace this with a custom one, this can give us a clue on what framework is in use. OWASP host a [database of common framework icons](https://wiki.owasp.org/index.php/OWASP_favicon_database) that you can use to check against the targets favicon. Once we know the framework stack, we can use external resources to discover more about it (see next section).

#### Practical Exercise

On the AttackBox, open firefox and enter the url `https://static-labs.tryhackme.cloud/sites/favicon/` here you'll see a basic website with a note saying "Website coming soon...", if you look at your tabs you'll notice an icon that confirms this site is using a favicon.

Viewing the page source you'll see line six contains a link to the images/favicon.ico file.

![Favicon HTML Source](Images/Favicon_HTML_Source.png)

If you run the following command on the AttackBox, it will download the favicon and get its md5 hash value which you can then lookup on the [OWASP database](https://wiki.owasp.org/index.php/OWASP_favicon_database).

```bash
user@machine$ curl https://static-labs.tryhackme.cloud/sites/favicon/images/favicon.ico | md5sum
```

Note: This curl will fail on the AttackBox if you are a free user, in which case you should use a VM for this. If your hash ends with 427e then your curl failed, and you may need to try it again. You could also run this on Windows in Powershell as shown below.

```powershell
PS C:\> curl https://static-labs.tryhackme.cloud/sites/favicon/images/favicon.ico -UseBasicParsing -o favicon.ico

PS C:\> Get-FileHash .\favicon.ico -Algorithm MD5 
```

---------------------------------------------------------------------------------------

#### What framework did the favicon belong to?

Calculate the MD5 hash of the favicon

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Content_Discovery]
└─$ curl -s https://static-labs.tryhackme.cloud/sites/favicon/images/favicon.ico | md5sum
f276b19aabcb4ae8cda4d22625c6735f  -
```

Then search for the hash on the [OWASP database](https://wiki.owasp.org/index.php/OWASP_favicon_database)

```text
<---snip--->
09f5ea65a2d31da8976b9b9fd2bf853c:caudium (1.4.12)
f276b19aabcb4ae8cda4d22625c6735f:cgiirc (0.5.9)
a18421fbf34123c03fb8b3082e9d33c8:chora2 (2.0.2) 
<---snip--->
```

Answer: `cgiirc`

### Task 4: Manual Discovery - Sitemap.xml

#### Sitemap.xml

Unlike the robots.txt file, which restricts what search engine crawlers can look at, the sitemap.xml file gives a list of every file the website owner wishes to be listed on a search engine. These can sometimes contain areas of the website that are a bit more difficult to navigate to or even list some old webpages that the current site no longer uses but are still working behind the scenes.

Take a look at the sitemap.xml file on the Acme IT Support website to see if there's any new content we haven't yet discovered: `http://10.10.219.21/sitemap.xml` (open this in the FireFox browser on the AttackBox).

---------------------------------------------------------------------------------------

#### What is the path of the secret area that can be found in the sitemap.xml file?

Check the sitemap.xml file with curl

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Content_Discovery]
└─$ curl http://10.10.219.21/sitemap.xml                                                 
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <url>
        <loc>http://10.10.219.21/</loc>
        <lastmod>2021-07-19T13:07:32+00:00</lastmod>
        <priority>1.00</priority>
    </url>
    <url>
        <loc>http://10.10.219.21/news</loc>
        <lastmod>2021-07-19T13:07:32+00:00</lastmod>
        <priority>0.80</priority>
    </url>
    <url>
        <loc>http://10.10.219.21/news/article?id=1</loc>
        <lastmod>2021-07-19T13:07:32+00:00</lastmod>
        <priority>0.80</priority>
    </url>
    <url>
        <loc>http://10.10.219.21/news/article?id=2</loc>
        <lastmod>2021-07-19T13:07:32+00:00</lastmod>
        <priority>0.80</priority>
    </url>
    <url>
        <loc>http://10.10.219.21/news/article?id=3</loc>
        <lastmod>2021-07-19T13:07:32+00:00</lastmod>
        <priority>0.80</priority>
    </url>
    <url>
        <loc>http://10.10.219.21/contact</loc>
        <lastmod>2021-07-19T13:07:32+00:00</lastmod>
        <priority>0.80</priority>
    </url>
    <url>
        <loc>http://10.10.219.21/customers/login</loc>
        <lastmod>2021-07-19T13:07:32+00:00</lastmod>
        <priority>0.80</priority>
    </url>
    <url>
        <loc>http://10.10.219.21/s3cr3t-area</loc>
        <lastmod>2021-07-19T13:07:32+00:00</lastmod>
        <priority>0.80</priority>
    </url>
</urlset>  
```

Answer: `/s3cr3t-area`

### Task 5: Manual Discovery - HTTP Headers

#### HTTP Headers

When we make requests to the web server, the server returns various HTTP headers. These headers can sometimes contain useful information such as the webserver software and possibly the programming/scripting language in use. In the below example, we can see the webserver is NGINX version 1.18.0 and runs PHP version 7.4.3. Using this information, we could find vulnerable versions of software being used. Try running the below curl command against the web server, where the -v switch enables verbose mode, which will output the headers (there might be something interesting!).

```bash
user@machine$ curl http://10.10.219.21 -v
*   Trying 10.10.219.21:80...
* TCP_NODELAY set
* Connected to 10.10.219.21 (10.10.219.21) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.219.21
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< X-Powered-By: PHP/7.4.3
< Date: Mon, 19 Jul 2021 14:39:09 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
```

---------------------------------------------------------------------------------------

#### What is the flag value from the X-FLAG header?

We can check this with the `-I` or `--head` parameters

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Content_Discovery]
└─$ curl -I http://10.10.219.21         
HTTP/1.1 404 Not Found
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 16 Oct 2025 08:52:26 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-FLAG: THM{<REDACTED>}
```

Answer: `THM{<REDACTED>}`

### Task 6: Manual Discovery - Framework Stack

#### Framework Stack

Once you've established the framework of a website, either from the above favicon example or by looking for clues in the page source such as comments, copyright notices or credits, you can then locate the framework's website. From there, we can learn more about the software and other information, possibly leading to more content we can discover.

Looking at the page source of our Acme IT Support website (`http://10.10.219.21`), you'll see a comment at the end of every page with a page load time and also a link to the framework's website, which is `https://static-labs.tryhackme.cloud/sites/thm-web-framework`. Let's take a look at that website. Viewing the documentation page gives us the path of the framework's administration portal, which gives us a flag if viewed on the Acme IT Support website.

---------------------------------------------------------------------------------------

#### What is the flag from the framework's administration portal?

Get the link to the framework

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Content_Discovery]
└─$ curl -s http://10.10.219.21 | tail -n 5
</body>
</html>
<!--
Page Generated in 0.04199 Seconds using the THM Framework v1.2 ( https://static-labs.tryhackme.cloud/sites/thm-web-framework )
-->  
```

Check the framework homepage

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Content_Discovery]
└─$ curl -L https://static-labs.tryhackme.cloud/sites/thm-web-framework
<!DOCTYPE html>

<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
    <link rel="stylesheet" href="/sites/templates/thm.css">
    <link rel="stylesheet" href="/sites/thm-web-framework/style.css">
</head>
<body>

    <div class="logo">
        <div><img src="/sites/templates/logo.png"></div>
        <h1>THM Web Framework</h1>
        <h3>Home</h3>
    </div>


    <div class="navigation">
        <a href="/sites/thm-web-framework/">Home</a> &bullet; <a href="/sites/thm-web-framework/changelog.html">Change Log</a> &bullet; <a href="/sites/thm-web-framework/documentation.html">Documentation</a>
    </div>


    <div class="content-sm">
        <p>Quickly build fully functioning websites with features such as news portal, contact forms, customer portals and more.</p>
        <div class="version">Current Version 1.3</div>
    </div>

</body> 
```

No flag. But the page contains links to both a documentation page and the change log.  
Let's check the documentation first

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Content_Discovery]
└─$ curl https://static-labs.tryhackme.cloud/sites/thm-web-framework/documentation.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
    <link rel="stylesheet" href="/sites/templates/thm.css">
    <link rel="stylesheet" href="/sites/thm-web-framework/style.css">
</head>
<body>

    <div class="logo">
        <div><img src="/sites/templates/logo.png"></div>
        <h1>THM Web Framework</h1>
        <h3>Documentation</h3>
    </div>

    <div class="navigation">
        <a href="/sites/thm-web-framework/">Home</a> &bullet; <a href="/sites/thm-web-framework/changelog.html">Change Log</a> &bullet; <a href="/sites/thm-web-framework/documentation.html">Documentation</a>
    </div>

    <div class="content">

        <div class="panel">
            <div class="panel-heading">Documentation</div>
            <div class="panel-body">
                <p>The documentation for the framework is pre-installed on your websites administration portal.</p>
                <p>Once you've installed the framework navigate to the <strong>/thm-framework-login</strong> path on your website.</p>
                <p>You can login with the username <strong>admin</strong> and password <strong>admin</strong> ( make sure you change this password )</p>
            </div>
        </div>
    </div>

</body>  
```

We have a link to an administration portal and a set of default credentials (`admin:admin`).

Login in with `admin:admin` at `http://10.10.219.21/thm-framework-login` reveals the flag.

![THM Web Framework Login](Images/THM_Web_Framework_Login.png)

Answer: `THM{<REDACTED>}`

### Task 7: OSINT - Google Hacking / Dorking

There are also external resources available that can help in discovering information about your target website; these resources are often referred to as OSINT or (Open-Source Intelligence) as they're freely available tools that collect information:

#### Google Hacking / Dorking

Google hacking / Dorking utilizes Google's advanced search engine features, which allow you to pick out custom content. You can, for instance, pick out results from a certain domain name using the site: filter, for example (site:tryhackme.com) you can then match this up with certain search terms, say, for example, the word admin (site:tryhackme.com admin) this then would only return results from the tryhackme.com website which contain the word admin in its content. You can combine multiple filters as well. Here is an example of more filters you can use:

| Filter | Example | Description |
|----|----|----|
|site|site:tryhackme.com|returns results only from the specified website address|
|inurl|inurl:admin|returns results that have the specified word in the URL|
|filetype|filetype:pdf|returns results which are a particular file extension|
|intitle|intitle:admin|returns results that contain the specified word in the title|

More information about google hacking can be found here: [https://en.wikipedia.org/wiki/Google_hacking](https://en.wikipedia.org/wiki/Google_hacking)

---------------------------------------------------------------------------------------

#### What Google dork operator can be used to only show results from a particular site?

Answer: `site:`

### Task 8: OSINT - Wappalyzer

#### Wappalyzer

Wappalyzer ([https://www.wappalyzer.com/](https://www.wappalyzer.com/)) is an online tool and browser extension that helps identify what technologies a website uses, such as frameworks, Content Management Systems (CMS), payment processors and much more, and it can even find version numbers as well.

---------------------------------------------------------------------------------------

#### What online tool can be used to identify what technologies a website is running?

Answer: `Wappalyzer`

### Task 9: OSINT - Wayback Machine

#### Wayback Machine

The Wayback Machine ([https://archive.org/web/](https://archive.org/web/)) is a historical archive of websites that dates back to the late 90s. You can search a domain name, and it will show you all the times the service scraped the web page and saved the contents. This service can help uncover old pages that may still be active on the current website.

---------------------------------------------------------------------------------------

#### What is the website address for the Wayback Machine?

Answer: `https://archive.org/web/`

### Task 10: OSINT - GitHub

#### GitHub

To understand GitHub, you first need to understand Git. Git is a **version control system** that tracks changes to files in a project. Working in a team is easier because you can see what each team member is editing and what changes they made to files. When users have finished making their changes, they commit them with a message and then push them back to a central location (repository) for the other users to then pull those changes to their local machines. GitHub is a hosted version of Git on the internet. Repositories can either be set to public or private and have various access controls. You can use GitHub's search feature to look for company names or website names to try and locate repositories belonging to your target. Once discovered, you may have access to source code, passwords or other content that you hadn't yet found.

---------------------------------------------------------------------------------------

#### What is Git?

Answer: `version control system`

### Task 11: OSINT - S3 Buckets

#### S3 Buckets

S3 Buckets are a storage service provided by Amazon AWS, allowing people to save files and even static website content in the cloud accessible over HTTP and HTTPS. The owner of the files can set access permissions to either make files public, private and even writable. Sometimes these access permissions are incorrectly set and inadvertently allow access to files that shouldn't be available to the public. The format of the S3 buckets is `http(s)://{name}.s3.amazonaws.com` where {name} is decided by the owner, such as tryhackme-assets.s3.amazonaws.com. S3 buckets can be discovered in many ways, such as finding the URLs in the website's page source, GitHub repositories, or even automating the process. One common automation method is by using the company name followed by common terms such as {name}-assets, {name}-www, {name}-public, {name}-private, etc.

---------------------------------------------------------------------------------------

#### What URL format do Amazon S3 buckets end in?

Answer: `.s3.amazonaws.com`

### Task 12: Automated Discovery

#### What is Automated Discovery?

Automated discovery is the process of using tools to discover content rather than doing it manually. This process is automated as it usually contains hundreds, thousands or even millions of requests to a web server. These requests check whether a file or directory exists on a website, giving us access to resources we didn't previously know existed. This process is made possible by using a resource called wordlists.

#### What are wordlists?

Wordlists are just text files that contain a long list of commonly used words; they can cover many different use cases. For example, a password wordlist would include the most frequently used passwords, whereas we're looking for content in our case, so we'd require a list containing the most commonly used directory and file names. An excellent resource for wordlists that is preinstalled on the THM AttackBox is `https://github.com/danielmiessler/SecLists` which Daniel Miessler curates.

#### Automation Tools

Although there are many different content discovery tools available, all with their features and flaws, we're going to cover three which are preinstalled on our attack box, ffuf, dirb and gobuster.

On the AttackBox execute the following three commands, targeting the Acme IT Support website and see what results you get.

Using ffuf:

```bash
user@machine$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://10.10.219.21/FUZZ
```

Using dirb:

```bash
user@machine$ dirb http://10.10.219.21/ /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
```

Using Gobuster:

```bash
user@machine$ gobuster dir --url http://10.10.219.21/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
```

Using the results from the commands above, please answer the below questions:

---------------------------------------------------------------------------------------

#### What is the name of the directory beginning "/mo...." that was discovered?

Scan with ffuf

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Content_Discovery]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.219.21/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.219.21/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

assets                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 42ms]
contact                 [Status: 200, Size: 3108, Words: 747, Lines: 65, Duration: 44ms]
customers               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 56ms]
development.log         [Status: 200, Size: 27, Words: 5, Lines: 1, Duration: 48ms]
monthly                 [Status: 200, Size: 28, Words: 4, Lines: 1, Duration: 42ms]
news                    [Status: 200, Size: 2538, Words: 518, Lines: 51, Duration: 43ms]
private                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 42ms]
robots.txt              [Status: 200, Size: 46, Words: 4, Lines: 3, Duration: 43ms]
sitemap.xml             [Status: 200, Size: 1383, Words: 260, Lines: 43, Duration: 43ms]
:: Progress: [4746/4746] :: Job [1/1] :: 851 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Answer: `/monthly`

#### What is the name of the log file that was discovered?

Answer: `/development.log`

For additional information, please see the references below.

## References

- [Amazon S3 - Wikipedia](https://en.wikipedia.org/wiki/Amazon_S3)
- [curl - Homepage](https://curl.se/)
- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [cURL - Wikipedia](https://en.wikipedia.org/wiki/CURL)
- [Dirb - Homepage](https://sourceforge.net/projects/dirb/)
- [Dirb - Kali Tools](https://www.kali.org/tools/dirb/)
- [ffuf - GitHub](https://github.com/ffuf/ffuf)
- [ffuf - Kali Tools](https://www.kali.org/tools/ffuf/)
- [Gobuster - GitHub](https://github.com/OJ/gobuster/)
- [Gobuster - Kali Tools](https://www.kali.org/tools/gobuster/)
- [Google hacking - Wikipedia](https://en.wikipedia.org/wiki/Google_hacking)
- [MD5 - Wikipedia](https://en.wikipedia.org/wiki/MD5)
- [Open-source intelligence - Wikipedia](https://en.wikipedia.org/wiki/Open-source_intelligence)
- [robots.txt - Wikipedia](https://en.wikipedia.org/wiki/Robots.txt)
- [Sitemaps - Wikipedia](https://en.wikipedia.org/wiki/Sitemaps)
- [Version control - Wikipedia](https://en.wikipedia.org/wiki/Version_control)
- [Wappalyzer - Homepage](https://www.wappalyzer.com/)
- [Wappalyzer - Firefox Plugin](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/)
- [Wayback Machine - Homepage](https://web.archive.org/)
