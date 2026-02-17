# Defensive Security Intro

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
Tags: Windows, Web
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description: 
Introducing defensive security, where you will protect FakeBank from an ongoing attack.
```

Room link: [https://tryhackme.com/room/defensivesecurityintroez](https://tryhackme.com/room/defensivesecurityintroez)

## Solution

### Task 1: Deploy

#### Think like a Defender

Defensive security is the process of defending and securing devices and systems.

Before you can defend a system, you need to understand what defenders are responsible for. Defensive security focuses on **detecting and investigating attacks, and responding before damage occurs**.

Unlike offensive security, you do not attack systems, instead, you monitor and protect them.

![Cyber Defender](Images/Cyber_Defender.png)

---------------------------------------------------------------------------------------

#### What is the main goal of defensive security?

Answer: `Detect and respond to attacks`

---------------------------------------------------------------------------------------

### Task 2: Detect Suspicious Activity

The first step in defensive security is spotting activity that doesn't look normal. This activity is stored in pieces of information known as alerts.

**You'll need to...**

1. Open the monitoring dashboard
2. Review recent alerts
3. Identify the suspicious source IP.

**Why you're doing this**

Defenders use tools similar to this monitoring dashboard to decide what activity needs investigating.

---------------------------------------------------------------------------------------

#### Which source IP address is generating the suspicious traffic?

Answer: `32.122.195.63`

---------------------------------------------------------------------------------------

### Task 3: Identify the Attack

#### Identify the Attack

Once suspicious activity is determined, defenders need to understand what kind of attack it is.

**You'll need to...**

1. Investigate the attack that has occured.
2. View the "URL Discovery Attempts" list.
3. Look at the latest "URL Discovery Attempts" entry to answer the question.

**Why you're doing this**

The monitoring dashboard shows what the attacker is trying to find. We can use this information to better secure our systems, stop the attacker and prevent this attack from occuring again.

---------------------------------------------------------------------------------------

#### Copy the latest URL that the attacker has tried to find and paste it below

Hint: The attacker is trying to access sensitive pages such as a "admin" page.

Answer: `https://fakebank.com/admin`

---------------------------------------------------------------------------------------

### Task 4: Stop the Attack

#### Stop the Attack

Now that the attack has been identified, defenders can take steps to stop it.

**You'll need to...**

1. Block the attacker's IP address
2. Apply rate limits, so any one else cannot overwhelm the system
3. Update security rules
4. Apply additional security measures to prevent this occuring again.

**Why you're doing this**

We can stop the attacker from continuing on immediately while we investigate and fix any security vulnerabilities. This is known as **containment**.

---------------------------------------------------------------------------------------

#### When the success message apears, copy the flag and paste it below

Answer: `THM{<REDACTED>}`

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [Digital forensics - Wikipedia](https://en.wikipedia.org/wiki/Digital_forensics)
- [Malware analysis - Wikipedia](https://en.wikipedia.org/wiki/Malware_analysis)
- [Security operations center - Wikipedia](https://en.wikipedia.org/wiki/Security_operations_center)
