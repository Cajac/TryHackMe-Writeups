# Windows Fundamentals 3

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Info
OS: Windows
Subscription type: Free
Description: In part 3 of the Windows Fundamentals module, learn about the built-in Microsoft tools that help keep 
the device secure, such as Windows Updates, Windows Security, BitLocker, and more...
```

Room link: [https://tryhackme.com/room/windowsfundamentals3xzx](https://tryhackme.com/room/windowsfundamentals3xzx)

## Solution

### Task 1 - Introduction

We will continue our journey exploring the Windows operating system.

To summarize the previous two rooms:

- In Windows Fundamentals 1, we covered the desktop, the file system, user account control, the control panel, settings, and the task manager.
- In Windows Fundamentals 2, we covered various utilities, such as System Configuration, Computer Management, Resource Monitor, etc.

This module will attempt to provide an overview of the security features within the Windows operating system.

We start by connecting to the machine with `freerdp`. Install it with `sudo apt-get install freerdp2-x11` if needed.  
Alternatively, use the AttackBox.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Info/Windows_Fundamentals_3]
└─$ xfreerdp /v:10.10.233.229 /cert:ignore /u:administrator /p:'letmein123!' /h:960 /w:1500 +clipboard
[13:07:27:414] [88895:88896] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[13:07:27:414] [88895:88896] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
<---snip--->
```

### Task 2 - Windows Updates

Let's start things off with Windows Update.

Windows Update is a service provided by Microsoft to provide security updates, feature enhancements, and patches for the Windows operating system and other Microsoft products, such as Microsoft Defender.

Updates are typically released on the 2nd Tuesday of each month. This day is called Patch Tuesday. That doesn't necessarily mean that a critical update/patch has to wait for the next Patch Tuesday to be released. If the update is urgent, then Microsoft will push the update via the Windows Update service to the Windows devices.

#### There were two definition updates installed in the attached VM. On what date were these updates installed?

Check `View update history` and expand `Definition Updates`

Answer: 5/3/2021

### Task 3 - Windows Security

Per Microsoft, "*Windows Security is your home to manage the tools that protect your device and your data*".

In case you missed it, Windows Security is also available in Settings.

#### Checking the Security section on your VM, which area needs immediate attention?

Answer: Virus & threat protection

### Task 4 - Virus & threat protection

Virus & threat protection is divided into two parts:

- Current threats
- Virus & threat protection settings

#### Specifically, what is turned off that Windows is notifying you to turn on?

Answer: Real-time protection

### Task 5 - Firewall & network protection

What is a firewall?

Per Microsoft, "*Traffic flows into and out of devices via what we call ports. A firewall is what controls what is - and more importantly isn't - allowed to pass through those ports. You can think of it like a security guard standing at the door, checking the ID of everything that tries to enter or exit*".

#### If you were connected to airport Wi-Fi, what most likely will be the active firewall profile?

Hint: xyz network

Answer: Public network

### Task 6 -  App & browser control

In this section, you can change the settings for the Microsoft Defender SmartScreen.

Per Microsoft, "*Microsoft Defender SmartScreen protects against phishing or malware websites and applications, and the downloading of potentially malicious files*".

### Task 7 - Device security

What is the Trusted Platform Module (TPM)?

Per Microsoft, "*Trusted Platform Module (TPM) technology is designed to provide hardware-based, security-related functions. A TPM chip is a secure crypto-processor that is designed to carry out cryptographic operations. The chip includes multiple physical security mechanisms to make it tamper-resistant, and malicious software is unable to tamper with the security functions of the TPM*".

#### What is the TPM?

Answer: Trusted Platform Module

### Task 8 - BitLocker

What is BitLocker?

Per Microsoft, "*BitLocker Drive Encryption is a data protection feature that integrates with the operating system and addresses the threats of data theft or exposure from lost, stolen, or inappropriately decommissioned computers*".

On devices with TPM installed, BitLocker offers the best protection.

Per Microsoft, "*BitLocker provides the most protection when used with a Trusted Platform Module (TPM) version 1.2 or later. The TPM is a hardware component installed in many newer computers by the computer manufacturers. It works with BitLocker to help protect user data and to ensure that a computer has not been tampered with while the system was offline*".

#### We should use a removable drive on systems without a TPM version 1.2 or later. What does this removable drive contain?

Hint: Refer to the Microsoft documentation on BitLocker.

Answer: startup key

### Task 9 - Volume Shadow Copy Service

Per Microsoft, the Volume Shadow Copy Service (VSS) coordinates the required actions to create a consistent shadow copy (also known as a snapshot or a point-in-time copy) of the data that is to be backed up.

Volume Shadow Copies are stored on the System Volume Information folder on each drive that has protection enabled.

If VSS is enabled (System Protection turned on), you can perform the following tasks from within advanced system settings.

- Create a restore point
- Perform system restore
- Configure restore settings
- Delete restore points

From a security perspective, malware writers know of this Windows feature and write code in their malware to look for these files and delete them. Doing so makes it impossible to recover from a ransomware attack unless you have an offline/off-site backup.

#### What is VSS?

Answer: Volume Shadow Copy Service

## References

- [BitLocker - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
- [BitLocker - Wikipedia](https://en.wikipedia.org/wiki/BitLocker)
- [Microsoft Windows - Wikipedia](https://en.wikipedia.org/wiki/Microsoft_Windows)
- [Shadow Copy - Wikipedia](https://en.wikipedia.org/wiki/Shadow_Copy)
- [Trusted Platform Module - Wikipedia](https://en.wikipedia.org/wiki/Trusted_Platform_Module)
