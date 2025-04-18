# Offensive Security Intro

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Hack your first website (legally in a safe environment) and experience 
an ethical hacker's job.
```

Room link: [https://tryhackme.com/room/offensivesecurityintro](https://tryhackme.com/room/offensivesecurityintro)

## Solution

### Beginning Your Learning Journey

#### Which of the following options better represents the process where you simulate a hacker's actions to find vulnerabilities in a system?

Hint: It involves breaking into computer systems, exploiting software bugs, and finding loopholes in applications to gain unauthorized access.

Answer: Offensive Security

### Hacking your first machine

Open a terminal window and run `gobuster` to enumerate directories

```bash
ubuntu@tryhackme:~/Desktop$ gobuster -u http://fakebank.thm -w wordlist.txt dir

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://fakebank.thm/
[+] Threads      : 10
[+] Wordlist     : wordlist.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2025/04/18 10:21:16 Starting gobuster
=====================================================
/images (Status: 301)
/bank-transfer (Status: 200)
=====================================================
2025/04/18 10:21:28 Finished
=====================================================
ubuntu@tryhackme:~/Desktop$ 
```

Ah, a `/bank-transfer` directory. Let's visit it in the browser.

![Bank Transfer Page](Images/Offensive_Security_Intro_1.png.png)

Next, we input the wanted information:  
Send from: 2276  
Send to: 8881  
Amount to send in USD: 2000  
And press the `Send Money`-button

### Get the flag

Finally, click the `Return to Your Account`-button and note the flag (redacted here) in the textbox:

```text
Congratulations - you hacked the bank!
The answer to the TryHackMe question is <REDACTED>
```

For additional information, please see the references below.

## References

- [Gobuster - GitHub](https://github.com/OJ/gobuster/)
- [Gobuster - Kali Tools](https://www.kali.org/tools/gobuster/)
