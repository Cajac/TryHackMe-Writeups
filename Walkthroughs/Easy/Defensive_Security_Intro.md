# Defensive Security Intro

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Introducing defensive security and related topics, such as Threat Intelligence, 
SOC, DFIR, Malware Analysis, and SIEM.
```

Room link: [https://tryhackme.com/room/defensivesecurityintro](https://tryhackme.com/room/defensivesecurityintro)

## Solution

### Task 1 - Introduction to Defensive Security

Some of the tasks that are related to defensive security include:

- **User cyber security awareness**  
  Training users about cyber security helps protect against attacks targeting their systems.
- **Documenting and managing assets**  
  We need to know the systems and devices we must manage and protect adequately.
- **Updating and patching systems**  
  Ensuring that computers, servers, and network devices are correctly updated and patched.
- **Setting up preventative security devices**  
  Firewalls and intrusion prevention systems (IPS) are critical components of preventative security.
- **Setting up logging and monitoring devices**  
  Proper network logging and monitoring are essential for detecting malicious activities and intrusions.

There is much more to defensive security. Aside from the above, we will also cover the following related topics:

- Security Operations Center (SOC)
- Threat Intelligence
- Digital Forensics and Incident Response (DFIR)
- Malware Analysis

#### Which team focuses on defensive security?

Answer: Blue Team

### Task 2 - Areas of Defensive Security

#### Security Operations Center (SOC)

A Security Operations Center (SOC) is a team of cyber security professionals that monitors the network and its  
systems to detect malicious cyber security events.

#### Threat Intelligence

In this context, *intelligence* refers to information you gather about actual and potential enemies. A *threat* is any  
action that can disrupt or adversely affect a system. Threat intelligence collects information to help the company  
better prepare against potential adversaries. The purpose would be to achieve a *threat-informed defence*.

#### Digital Forensics and Incident Response (DFIR)

This section is about Digital Forensics and Incident Response (DFIR), and we will cover:

- Digital Forensics
- Incident Response
- Malware Analysis

Forensics is the application of science to investigate crimes and establish facts. With the use and spread of digital  
systems, such as computers and smartphones, a new branch of forensics was born to investigate related crimes: computer  
forensics, which later evolved into digital forensics.

An incident usually refers to a data breach or cyber attack; however, in some cases, it can be something less critical,  
such as a misconfiguration, an intrusion attempt, or a policy violation. Examples of a cyber attack include an attacker  
making our network or systems inaccessible, defacing (changing) the public website, and data breach (stealing company data).

Malware analysis aims to learn about such malicious programs using various means:

1. Static analysis works by inspecting the malicious program without running it.
2. Dynamic analysis works by running the malware in a controlled environment and monitoring its activities.

#### What would you call a team of cyber security professionals that monitors a network and its systems for malicious events?

Answer: Security Operations Center

#### What does DFIR stand for?

Answer: Digital Forensics and Incident Response

#### Which kind of malware requires the user to pay money to regain access to their files?

Answer: Ransomware

### Task 3 - Practical Example of Defensive Security

Inspect the alerts in your SIEM dashboard. Find the malicious IP address from the alerts, make a note of it,  
and then click on the alert to proceed.

`Unauthorized connection attempt detected from IP address 143.110.250.149 to port 22`

Input the IP-adress in `IP-SCANNER.THM` and get a `Malicious` rating.

Escalate to Will Griffin, the SOC Team Lead, and proceed to block the IP to receive the flag.

For additional information, please see the references below.

## References

- [Digital forensics - Wikipedia](https://en.wikipedia.org/wiki/Digital_forensics)
- [Malware analysis - Wikipedia](https://en.wikipedia.org/wiki/Malware_analysis)
- [Security operations center - Wikipedia](https://en.wikipedia.org/wiki/Security_operations_center)
