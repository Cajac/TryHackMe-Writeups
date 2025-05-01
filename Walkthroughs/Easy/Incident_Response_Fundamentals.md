# Incident Response Fundamentals

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Premium
Description: Learn how to perform Incident Response in cyber security.
```

Room link: [https://tryhackme.com/room/incidentresponsefundamentals](https://tryhackme.com/room/incidentresponsefundamentals)

## Solution

### Task 1 - Introduction to Incident Response

Imagine living in a heavily insecure street with many expensive things in your home. You must be thinking of having a security guard and a few CCTV cameras in your home. Hiding the expensive material inside a hidden underground room is a good idea if any intruder successfully enters the house. These are the things that you plan for the safety of your home, even before any attack occurs.

Besides these proactive measures, did you ever consider how things would work if someone successfully bypassed your external security mechanisms and gained access to your home? You must also take several other measures after your home is attacked.

Let’s take the above into the Digital Realm. You may have heard about a cyber attack on any organization that caused them to lose thousands of dollars. Several such cases are reported daily on the internet. These are referred to as **Cyber Security Incidents**. Just as in the scenario above, where you planned for the security of your home, cyber security incidents also need some planning and resources to avoid huge losses.

Incident Response handles an incident from its start to end. From deploying security in several areas to prevent incidents to fighting with them, and minimizing their impact, incident response is a thorough guideline.

This room will help you understand the critical concepts of incident response and give you a chance to solve your first incident practically.

#### Learning Objectives

- Overview of what are incidents and their severity levels
- Common types of incidents
- Phases of Incident Response from SANS and NIST Frameworks
- Tools for Incident Detection and Response along with the role of PlayBooks
- Incident Response Plan

#### Room Pre-Requisites

- Intro to Defensive Security

### Task 2 - What are Incidents?

Several different processes run on your computing devices, e.g., laptops, mobile phones, etc. Some of these processes are interactive, meaning you perform the actions, e.g., playing a game or watching a video. There will also be some non-interactive processes running in the background that may not require your interaction with them. They are just necessary for your device. Both of these types of processes generate several events. Anything they do, an event is logged for what they have done.

Events are generated in huge numbers regularly. This is because many processes run on a device, each performing different routine tasks, generating numerous events. These events can sometimes point to something terrible going on in your device. How do we check these vast numbers of events and see if they point to some destructive activity? There are security solutions in place to solve this problem. These events are ingested into the security solutions as logs, and the security solutions can find harmful activities in them. This made our job way more easier! But wait a minute; the real challenge is after the security solution points these activities out.

So, when a security solution finds an event or group of events associated with a possible harmful activity, it triggers an alert. The security team then analyzes these alerts. Some of these alerts may be **False Positives**, while some would be **True Positives**. The alerts that point to something dangerous but are not harmful are referred to as false positives. In contrast, the alerts that point to something harmful and are actually dangerous are called true positives. You can get a better understanding of this from the example below:

- **False positive**: A security solution raised an alert on a high amount of data being transferred from one system to an external IP address. Upon analyzing this alert, the security team found that the subject system was undergoing a backup process to a cloud storage service, which caused this. This is known as a false positive.

- **True Positive**: A security solution raised an alert on a phishing attempt on one of the organization’s users. Upon analyzing this alert, the security team found that the email was a phishing email sent to this user to compromise the system. This is known as a true positive.

These true positive alerts are sometimes referred to as **Incidents**. Assuming the alert is now categorized as an incident, the next phase is to give a severity level to the incident. Imagine you are part of the security team and get multiple incidents simultaneously. Which incident would you choose first to respond to? This is where the idea of incident severity helps. Incidents can be categorized as low, medium, high, or critical based on the impact they can create. Critical Severity incidents are always the higher priority, followed by high severity, and so on.

#### What is triggered after an event or group of events point at a harmful activity?

Answer: Alert

#### If a security solution correctly identifies a harmful activity from a set of events, what type of alert is it?

Answer: True Positive

#### If a fire alarm is triggered by smoke after cooking, is it a true positive or a false positive?

Answer: False Positive

### Task 3 - Types of Incidents

People usually label every harmful activity associated with the digital world as a hacking attempt. This may be correct, but it is very generic in terms of cyber security. Security Incidents can be of different types. In the above tasks, we saw an example of a true positive alert, which became an incident after the analysis of the security team. This incident was related to the phishing email, which probably came with a malicious attachment. If downloaded into the system, this attachment may have harmful consequences. This is one type of incident. There are several other types of incidents. These types can occur independently or altogether within the same victim.

- **Malware Infections**: Malware is a malicious program that can damage a system, network, or application. The majority of incidents are associated with malware infections.  There are different types of malware, each with a unique potential to cause damage. Malware infections are mostly caused by files that can be text, documents, executables, etc.

- **Security Breaches**: Security Breaches arise when an unauthorized person gets access to confidential data (something we don’t want them to see or have).  Security Breaches are of the utmost importance as many businesses rely on their confidential data, which must only be accessible to authorized personnel.

- **Data Leaks**: Data leaks are incidents in which confidential information of an individual or an organization is exposed to unauthorized entities. Many attackers use data leaks for reputational damage to their victims or use this technique to threaten their victims and get what they need from them. Unlike Security Breaches, data leaks can also be unintentionally caused by human errors or misconfigurations.

- **Insider Attacks**: Incidents from within an organization are known as insider attacks. Think about a disgruntled employee infecting the whole network through a USB on his last day. This is an example of an insider attack. Someone within your organization intentionally initiating an attack comes under this category. These attacks can be hazardous, as an insider always has greater access to resources than an outsider.

- **Denial Of Service Attacks**: Availability is one of the three pillars of cyber security. Defensive security solutions and people constantly find ways to protect information; they ensure that the data is available to the people simultaneously. This is because there is no point in protecting something that is unavailable to us. Denial of Service attacks, or DoS attacks, are incidents where the attacker floods a system/network/application with false requests, eventually making it unavailable to legitimate users. This happens due to the exhaustion of resources available to entertain the requests.

All these incidents have their unique potential to impact the victim negatively. These incidents can not be compared in terms of the severity of the impact they create. This is because a particular incident can be disastrous for one organization while it can cause minor damage to another. For example, XYZ Corp. may not be heavily impacted by a data leak as the information it stores can be useless to anybody else. However, it can undergo a massive loss in case of a Denial of Service (DoS) attack on its primary website, as its services depend on that website.

#### A user's system got compromised after downloading a file attachment from an email. What type of incident is this?

Answer: malware infection

#### What type of incident aims to disrupt the availability of an application?

Answer: Denial of service

### Task 4 - Incident Response Process

In the above task, we saw different types of incidents. Sometimes, handling a variety of incidents in an environment can be difficult. Due to the distinct nature of incidents in organizations, there should be a structured process for incident response. Incident Response Frameworks help us in this regard. These are the generic approaches to follow in any incident for effective response. We will discuss the two widely used incident response frameworks: SANS and NIST.

SANS and NIST are popular organizations contributing to cyber security. SANS has offered various courses and certifications in cyber security, and NIST played its role in developing standards and guidelines for cyber security. Both SANS and NIST have quite similar incident response frameworks.

The SANS incident Response framework has 6 phases, which can be called 'PICERL' to remember them easily.

| Phase | Explanation | Example |
|----|----|----|
|Preparation|This is the first phase. The preparation phase includes building the necessary resources to handle an incident. These resources include developing incident response teams, having a proper incident response plan in place, and deploying necessary security solutions to combat the incidents.|Conducting awareness training for employees on phishing emails. Phishing emails are fraudulent emails sent by malicious attackers that can trick you into performing actions that can lead you to an incident.|
|Identification|The identification phase refers to looking for any abnormal behavior that may indicate an incident. This involves using various security solutions and techniques to monitor abnormal events.|The security team notices a huge amount of data being sent out from one of the hosts. Upon analysis, it was found to be compromised after a malicious file was downloaded from a phishing email attachment.|
|Containment|Once an incident has been identified, the next step should be to contain it. This means minimizing the impact of the attack. This is usually done by isolating the victim machine, disabling the compromised user accounts, etc.|The Security team isolates the host from the network to minimize the impact and not allow the attacker to jump to other systems, leveraging the compromised host.|
|Eradication|This phase, as its name suggests, involves removing the threat from the attacked environment. The threat may be of any kind. The eradication phase will ensure the subject environment is clean, and now we can move to the recovery phase.|A deep malware scan was executed on the system to remove the malicious software from the host.|
|Recovery|The recovery phase is very important in this chain. It involves recovering the affected systems from backup or rebuilding them. The recovered systems are then tested and are ready to use.|The compromised host was re-configured, and the exfiltrated data was restored from the backup.|
|Lessons Learned|This is also an important part of the incident response lifecycle. Gaps in the detection and analysis of the incident are identified and documented, helping to improve the overall process in future incidents.|Conducting a post-incident review meeting to analyze the incident's root cause and improve the security to prevent future attacks.|

![SANS Incident Response Cycle](Images/SANS_Incident_Response_Cycle.png)

The Incident Response Framework of NIST is similar to the SANS framework we studied above. The number of phases in this framework is reduced to 4.

![NIST Incident Response Framework](Images/NIST_Incident_Response_Framework.png)

Organizations may derive their incident response processes by following these frameworks. Every process has a formal document listing all the relevant organizational procedures. The formal incident response document is called the **Incident Response Plan**. This structured document underlines the approach during any incident. It is formally approved by senior management and consists of the procedures to be followed before, during, and after an incident has been completed.

The key components of this plan include (and are not limited to):

- Roles and Responsibilities
- Incident Response methodology
- Communication plan with stakeholders, including law enforcement
- Escalation path to be followed

#### The Security team disables a machine's internet connection after an incident. Which phase of the SANS IR lifecycle is followed here?

Answer: Containment

#### Which phase of NIST corresponds with the lessons learned phase of the SANS IR lifecycle?

Answer: Post Incident Activity

### Task 5 - Incident Response Techniques

Remember we studied the second phase of the incident response lifecycle, ‘Identification’ in SANS, and ‘Detection and Analysis’ in NIST. It is very hard to look for abnormal behavior and identify incidents manually. There are multiple security solutions that serve their own unique roles in detecting any incidents. Some of them even have the capability to respond to the incidents and execute the other phases of the lifecycle, such as containment, eradication, etc. A brief explanation of some of these solutions is given below:

- **SIEM**: The Security Information and Event Management Solution (SIEM) collects all important logs in one centralized location and correlates them to identify incidents.
- **AV**: Antivirus (AV) detects known malicious programs in a system and regularly scans your system for these.
- **EDR**: Endpoint Detection and Response (EDR) is deployed on every system, protecting it against some advanced-level threats. This solution can also contain and eradicate the threat.

After incidents are identified, certain procedures must be followed, including investigating the extent of the attack, taking necessary actions to prevent further damage and eliminate it from the root. These steps may be different for different kinds of incidents. In this scenario, having step-by-step instructions to deal with each kind of incident helps you save a lot of time. These types of instructions are known as **Playbooks**.

Playbooks are the guidelines for a comprehensive incident response.

Following is an example of a **Playbook** for an incident: Phishing Email

1. Notify all the stakeholders of the phishing email incident
2. Determine if the email was malicious by conducting header and body analysis of the email
3. Look for any attachments with the email and analyze them
4. Determine if anybody opened the attachments
5. Isolate the infected systems from the network
6. Block the email sender

**Runbooks**, on the other hand, are the detailed, step-by-step execution of specific steps during different incidents. These steps may vary depending on the resources available for investigation.

#### Step-by-step comprehensive guidelines for incident response are known as?

Answer: Playbooks

### Task 6 - Lab Work Incident Response

**Scenario**: In this task, you will initiate an incident by downloading an attachment from a phishing email. The attachment is malware. Once you download the file, an incident begins. You will now start investigating the incident. The first phase is to see how many hosts are infected with this same file, as there are many chances that a single phishing campaign targets multiple employees within the same organization. You will see some hosts on which this file was executed after getting downloaded and some hosts on which this file was only downloaded. You will perform the necessary actions on all these hosts and see a detailed timeline of events in the infected host.

Click on the **View Site** button below to display the lab on the right side of the screen.

You will perform a complete incident response after a phishing email hits multiple hosts in a network. You have to follow the steps given in the site and answer the questions below:

#### What was the name of the malicious email sender?

Answer: Jeff Johnson

#### What was the threat vector?

Hint: Email Attachment/URL

Answer: Email Attachment

#### How many devices downloaded the email attachment?

Answer: 3

#### How many devices executed the file?

Answer: 1

#### What is the flag found at the end of the exercise?

Answer: `THM{<REDACTED>}`

### Task 7 - Conclusion

In this room, we learned about the different concepts of incident response. We studied how and when an event is categorized as an incident and the priorities given to different incidents. We also looked into types of incidents and the frameworks of incident response: SANS and NIST, which guide us through handling an incident. Lastly, we saw some tools for incident response and carried out a realistic hands-on lab.

For additional information, please see the references below.

## References

- [Cybercrime - Wikipedia](https://en.wikipedia.org/wiki/Cyber_crime)
- [Digital forensics - Wikipedia](https://en.wikipedia.org/wiki/Digital_forensics)
- [Exif - Wikipedia](https://en.wikipedia.org/wiki/Exif)
- [Memory forensics - Wikipedia](https://en.wikipedia.org/wiki/Memory_forensics)
- [Metadata - Wikipedia](https://en.wikipedia.org/wiki/Metadata)
