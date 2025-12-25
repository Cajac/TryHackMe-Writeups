# TShark Challenge I: Teamwork

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
Tags: Linux
Subscription type: Premium
Description:
Put your TShark skills into practice and analyse some network traffic.
```

Room link: [https://tryhackme.com/room/tsharkchallengesone](https://tryhackme.com/room/tsharkchallengesone)

## Solution

### Task 1: Introduction

This room presents you with a challenge to investigate some traffic data as a part of the SOC team. Let's start working with TShark to analyse the captured traffic. We recommend completing the [TShark: The Basics](https://tryhackme.com/room/tsharkthebasics) and [TShark: CLI Wireshark Features](https://tryhackme.com/room/tsharkcliwiresharkfeatures) rooms first, which will teach you how to use the tool in depth.

Start the VM by pressing the green **Start Machine** button attached to this task. The machine will start in split view, so you don't need SSH or RDP. In case the machine does not appear, you can click the blue **Show Split View** button located at the top of this room.

**NOTE**: Exercise files contain real examples. **DO NOT** interact with them outside of the given VM. Direct interaction with samples and their contents (files, domains, and IP addresses) outside the given VM can pose security threats to your machine.

### Task 2: Case: Teamwork

An **alert has been triggered**: "The threat research team discovered a suspicious domain that could be a potential threat to the organisation."

The case was assigned to you. Inspect the provided **teamwork.pcap** located in `~/Desktop/exercise-files` and create artefacts for detection tooling.

**Your tools**: TShark, [VirusTotal](https://www.virustotal.com/gui/home/upload).

---------------------------------------------------------------------------------------

#### What is the full URL of the malicious/suspicious domain address? Enter your answer in defanged format

Hint: Cyberchef can defang.

Investigate the contacted domains.

We start by checking for DNS-requests

```bash
ubuntu@ip-10-66-140-9:~/Desktop/exercise-files$ tshark -r teamwork.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -rn
     19 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com
      6 toolbarqueries.google.com
      4 wittyserver.hsd1.md.comcast.net
      4 wittyserver
```

and for HTTP requests

```bash
ubuntu@ip-10-66-140-9:~/Desktop/exercise-files$ tshark -r teamwork.pcap -Y http.request -T fields -e http.host -e http.request.uri | sort | uniq -c | sort -rn
      3 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /update.php
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /suspecious.php
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /js/script.js?_=1492480834538
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /js/jquery.creditCardValidator.min.js?_=1492480834539
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /js/cc.js?_=1492480834540
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /inc/visit.php
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /inc/login.php
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /img/shield.png
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /img/setting.png
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /img/profile.png
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /img/logo_ccVisa.gif
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /img/logo.svg
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /img/icon_uncheck.png
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /img/icon_checked.png
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /img/feedback.png
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /img/csc_standard.png
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /img/arrow.png
      1 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    /font/PayPalSansSmall-Medium.woff2
      1 toolbarqueries.google.com    /tbr?client=navclient-auto&ch=63514382238&features=Rank&q=info%3Ahttp%3A%2F%2Fwww.paypal.com4uswebappsresetaccountrecovery.timeseaways.com%2F%23
```

The domain that sticks out is `www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com` both is the relative amount and that it's probably a `paypal.com` look-alike domain.

Investigate the domains by using VirusTotal.

One AV-engine on [VirusTotal](https://www.virustotal.com/gui/domain/www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com) identifies it as a `Phishing` domain.

Finally, we create an URI of the root/homepage access and defang it with [CyberChef](https://gchq.github.io/CyberChef/#recipe=Defang_URL(true,true,true,'Valid%20domains%20and%20full%20URLs')).

Answer: `hxxp[://]www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com/`

#### When was the URL of the malicious/suspicious domain address first submitted to VirusTotal?

We check the URL on [VirusTotal](https://www.virustotal.com/gui/url/16db0aadc2423a67cd3a01af39655146b0f15d20dc2fd0e14b325026d8d1717e/details) under the `Details` tab.

Answer: `2017-04-17 22:52:53 UTC`

#### Which known service was the domain trying to impersonate?

Answer: `Paypal`

#### What is the IP address of the malicious domain? Enter your answer in defanged format

```bash
ubuntu@ip-10-66-140-9:~/Desktop/exercise-files$ tshark -r teamwork.pcap -Y dns.a -T fields -e dns.qry.name -e dns.a | sort | uniq -c | sort -rn
      5 www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com    184.154.127.226
      1 toolbarqueries.google.com    216.58.217.100
      1 toolbarqueries.google.com    172.217.7.228
```

Answer: `184[.]154[.]127[.]226`

#### What is the email address that was used?

Enter your answer in defanged format. (format: aaa[at]bbb[.]ccc)

An email is most likely used in SMTP traffic, which turns out nothing,

```bash
ubuntu@ip-10-66-140-9:~/Desktop/exercise-files$ tshark -r teamwork.pcap -Y smtp                           
ubuntu@ip-10-66-140-9:~/Desktop/exercise-files$ 
```

or in URL-encoded data in HTTP POST-requests

```bash
ubuntu@ip-10-66-140-9:~/Desktop/exercise-files$ tshark -r teamwork.pcap -Y urlencoded-form
  122  10.209199 192.168.1.100 ? 184.154.127.226 HTTP 642 POST /inc/visit.php HTTP/1.1  (application/x-www-form-urlencoded)
  202  22.629586 192.168.1.100 ? 184.154.127.226 HTTP 850 POST /inc/login.php HTTP/1.1  (application/x-www-form-urlencoded)
ubuntu@ip-10-66-140-9:~/Desktop/exercise-files$ tshark -r teamwork.pcap -Y urlencoded-form -V | grep '@'
    Form item: "user" = "johnny5alive@gmail.com"
        Value: johnny5alive@gmail.com
```

Answer: `johnny5alive[at]gmail[.]com`

For additional information, please see the references below.

## References

- [Domain Name System - Wikipedia](https://en.wikipedia.org/wiki/Domain_Name_System)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [HTTP - Wikipedia](https://en.wikipedia.org/wiki/HTTP)
- [pcap - Wikipedia](https://en.wikipedia.org/wiki/Pcap)
- [Simple Mail Transfer Protocol - Wikipedia](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol)
- [sort - Linux manual page](https://man7.org/linux/man-pages/man1/sort.1.html)
- [uniq - Linux manual page](https://man7.org/linux/man-pages/man1/uniq.1.html)
- [VirusTotal - Homepage](https://www.virustotal.com/gui/home/upload)
- [Wireshark - Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark - Homepage](https://www.wireshark.org/)
- [Wireshark - tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Wireshark - Wikipedia](https://en.wikipedia.org/wiki/Wireshark)
- [Wireshark - wireshark-filter Manual Page](https://www.wireshark.org/docs/man-pages/wireshark-filter.html)
