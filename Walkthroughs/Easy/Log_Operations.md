# Log Operations

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Learn the operation process details.
```

Room link: [https://tryhackme.com/room/logoperations](https://tryhackme.com/room/logoperations)

## Solution

### Task 1 - Introduction

#### Log Operations

The first thing that comes to mind regarding log analysis is to open the door to the adventure of looking for a needle in a haystack. In case of an incident investigation, are you lost in the log space and wasting your precious time? If so, it's time to do something about log configuration.

In this room, you will learn the configuration approaches required to manage and analyse logs in an operational context and the log information you learned in the previous introductory room.

#### Learning Objectives

- Understanding the logic of log management and configuration
- Familiarise with log configuration approaches
- Experience the log configuration process

#### Room Prerequisites

- Working knowledge of MS Windows and Linux
- Working knowledge of network and endpoint log systems
- [Intro to Logs](https://tryhackme.com/room/introtologs)

### Task 2 - Log Configuration

#### Log Configuration Options

"Do you dare to configure your logs, or are you happy to be lost in the madness of the thousands of lines?" In log operations, there are multiple concerns about configuration approaches, and identifying the suitable configuration approach could be a pain point.

Log configuration is a multifaceted operation that addresses security, operational stability, regulatory compliance, and debugging needs. Adequately configured logs are crucial in cyber security, operational efficiency, regulatory compliance, and software development, providing organisations with comprehensive system, asset, and resource management statistics. Let's look at and understand the scopes and differences of common purposes of log configuration.

- SECURITY
- OPERATIONAL
- LEGAL
- DEBUG

#### Security Purposes

Logging and configuration for security purposes are typically planned to detect and respond to anomalies and security issues. For example, configuration to verify the authenticity of user activity to ensure authorisation control and timely detection of unauthorised access. The main focus areas of this approach are:

- Anomaly and threat detection
- Logging user authentication data
- Ensuring the system's integrity and data confidentiality

#### Operational Purposes

Logging and configuring for operational purposes is usually planned to detect and respond to system errors and identify action points to enhance the system's performance, continuity, and reliability. The main focus areas of this approach are:

- Proactively creating reports and notifications for on-system and component status
- Troubleshooting
- Capacity planning
- Service billing

#### Legal Purposes

Logging and configuring for legal purposes is similar to security purposes; it is usually planned to stay compliant and increase the alignment with regulations and obligations. Here, the laws, regulations, and compliance standards will vary depending on the work's scope, the data being processed, and the service area being provided. Therefore, each enrollment will come with a set of responsibilities and guidelines to follow. The main focus areas of this approach are:

- Alignment with standards, compliance, regulations, and laws
  - E.g. ISO 27001, COBIT, GDPR, PCI DSS, HIPAA, FISMA

Legal Compliance Example: A company must have an active central log management system, adequate log configuration, 12-month log retention for logs and affiliated system logs (last three months data must always be ready to search), system and component security checks, and overall yearly audit checks to meet PCI logging compliance.

#### Debug Purposes

Logging and configuring for debug purposes is usually planned to boost the system's reliability and enhance provided features by discovering the bugs and potential fault conditions. This configuration scope is not always implemented in the production environment and is mostly used for testing and developing purposes. The main focus areas of this approach are:

- Increasing visibility for the application debugging
- Enhancing efficiency
- Speeding up the development process

---------------------------------------------------------------

#### Which of the given log purposes would be suitable to measure the cost of using a service?

Hint: Billing is a method of measuring service usage.

Answer: Operational

#### Which of the given log purposes would be suitable for investigating application logs for enhancement and stability?

Answer: Debug

### Task 3 - Where To Start After Deciding the Logging Purpose

#### Where To Start and What To Do After Deciding the Log Purpose?

If you already have an objective and scope plan but need help knowing how and where to start, you can use the meeting and brainstorming methods with your team. The meeting might sound like a passive action, but it will start the ball rolling for brainstorming, which will help consider multiple aspects and create a draft plan.

Remember, each log configuration purpose is planned and implemented to fulfil a different goal. Questioning is one of the most common ways to identify needs and facilitate planning. Remember, each implementation is unique, but common base questions must be answered in almost any log configuration planning session. You can use the following questions as a starting point and broaden the list according to the answers. Remember, you will need additional steps like creating a detailed plan, choosing tools/technologies, establishing monitoring and review/analysis processes after answering the initial questions.

Questions To Ask In Planning Meeting/Session

- What will you log, and for what (asset scope and logging purpose)?
  - Is additional commitment or effort required to achieve the purpose (requirements related to the purpose)?
- How much are you going to log (detail scope)?
- How much do you need to log?
- How are you going to log (collection)?
- How are you going to store collected logs?
  - Is there a standard, process, legislation, or law that you must comply with due to the data you log?
- How are you going to protect the logs?
- How are you going to analyse collected logs?
- Do you have enough resources and workforce to do logging?
- Do you have enough budget to plan, implement and maintain logging?

---------------------------------------------------------------

You are a consultant working for a growing startup. As a consultant, you participated in a log configuration planning session. The company you work for is working to get compliant to process payment information. The given question set is being discussed.

#### Which question's answer can be "as much as mentioned in the PCI DSS requirements."?

Hint: Compliances have strict rules to meet, so it is a need.

Answer: How much do you need to log?

### Task 4 - Configuration Dilemma: Planning and Implementation

#### Configuration Dilemma: Requirements, Aspirations, Resources, and Investment

Configuration dilemma reflects the challenges of implementation. As highlighted in the previous task, each log configuration scope comes with responsibilities, guidelines, and challenges. This means that the log configuration and logging are more than a simple practice of enabling logging from the assets and surviving among thousands of lines.

Each log configuration plan results from a unique analysis of the scope, assets, objectives, requirements, and expectations to be applied. Expectations, requirements, and limits are determined with the involvement of system administrators, legal and financial advisors, and managers, if possible. In summary, the main source of the dilemma is finding the balance between requirements, scope, details, and price (financial and labour costs, risks, and investment). During the meeting, there might be some points where participants get off the point, but it is vital to keep in mind that the main objective of the meeting is:

- Meeting specific operational and security requirements (non-negotiable) while also considering the feasibility of improving the capability by implementing additional data and insights.

Last but not least, a comprehensive risk assessment, prioritising security, compliance, and legal needs will be helpful to navigate this dilemma. Finding the balance in "operational and management" level decisions and achieve secure, efficient, proactive, resilient, and sustainable outcomes in the ever-evolving threat/IT landscape and technical operations.

#### Translating "Requirements" and "Aspirations" To Operational Level

Let's take a closer look at exactly how the dilemma arose.

Base Requirements

- What happened?
- When did it happen?
  - With time data (if possible).
- Where did it happen?
  - Network, system, folder, path, interface.
- Who/What caused it to occur?
- From which log source?

Aspirations for Better Insights

- Is it possible to have more data?
  - More details.
- How sure can I be that this is true?
- What is affected?
- What will happen next?
- Is there anything else that requires attention?
- What should I do about the incident?

While the main focus is the same, two question sets represent two distinct dimensions of logging and analysis:

- The base part heavily relies on an incident detection mindset. Still, it provides a solid framework for logging and analysis but is reactive. The requirements are a good place to start, but it is primarily helpful against known threats.

- The aspirations part is more focused on a threat-hunting mindset. Therefore, it is proactive and requires more resources due to the need to go above and beyond. Therefore, this part is more helpful against advanced and sophisticated threats.

The baseline part is necessary for a solid incident detection and response scope foundation. However, adopting proactive aspirations by adding them to the operational vision is strongly recommended, given the ever-evolving threat landscape.

---------------------------------------------------------------

The session continues, and your teammates need your help; they will negotiate for logging budget and operation details. As a consultant, you must remind them of a vital point:

#### Which requirements are non-negotiable?

Answer: operational and security requirements

### Task 5 - Principles and Difficulties

#### Logging Principles

Logging is a critical aspect of the cyber-security and IT operations. It is a process that is as burdensome as functional and requires active resource utilisation. Therefore, it is crucial to implement a proper logging operation and ensure its effectiveness and efficiency. There are multiple principles which help achieve the mentioned goal. The table below highlights some of the essentials.

| Principle | Aspects |
|----|----|
|**Collection**|Define the logging purpose.<br>Collect what you will need and use.<br>Do not collect irrelevant data.<br>Avoid log noise.|
|**Format**|Log at the correct level and detail.<br>Implement a consistent log format.<br>Ensure that timestamps in logs are accurate and synchronised.|
|**Archiving and Accessibility**|Define log retention policies and implement them.<br>Store log data and make sure the important part is available for analysis.<br>Create backups of stored log data and used systems.|
|**Monitoring and Alerting**|Create alerts and notifications for important and noteworthy cases.<br>Focus on actionable alerts and avoid noise.|
|**Security**|Protect logs by implementing access controls.<br>Implement encryption if required.<br>Use a dedicated log management solution.|
|**Continuous Change**|Logging sources, types, and messages are constantly changing and being updated.<br>Be open to continuous change.<br>Train your personnel.|

#### Challenges

Challenges are as much a part of log management as principles. However, most of them can be addressed in the planning section. The table below highlights the main challenges of logging.

| Challenge | Aspects |
|----|----|
|**Data Volume and Noise**|Having multiple data sources to deal with.<br>Differences in the log volumes created by applications.<br>Some applications generate an insufficient amount of logs.<br>Large-scale applicants could generate massive log volumes.<br>Some logs can provide non-essential data and make the identifying process difficult.|
|**System Performance and Collection**|Log collection can slow down the system's performance.<br>Systems are not always "state of the art".<br>Some "sensitive" or "ancient" systems are impossible to touch.<br>Deployment and optimisation challenges.<br>Managing system and agent version updates and synchronisation in large-scale networks is overwhelming.|
|**Process and Archive**|Having multiple data formats to deal with it.<br>Parsing different data sources and formats is time-consuming and error-prone.<br>Balancing the log retention can be challenging.<br>Especially when dealing with many compliance regulations and standards.|
|**Security**|Ensuring data security is a task/challenge in itself.|
|**Analysis**|Combining, correlating, and analysing data from multiple sources to understand the context of an incident is a time-consuming process that requires significant computing resources and expertise.<br>Achieving this in real-time is also another challenge in the same scope.<br>Avoiding false positives/negatives is overwhelming.|
|**Misc**|Lack of planning and roadmap.<br>Lack of financial resources/budget.<br>Lack of implementation scenarios, playbooks, and exercises.<br>Lack of technical skills to implement, maintain, and analyse.<br>Focusing on log collection instead of the analysis phase.<br>Ignoring human factors and potential system errors.|

#### Where To Go From Here?

The mentioned principles and challenges are common and can vary according to your case. However, the main point is adhering to logging principles and proactively addressing challenges.

---------------------------------------------------------------

Your team is working on policies to decide which logs will be stored and which portion will be available for analysis.

#### Which of the given logging principles would be implemented and improved?

Answer: Archiving and Accessibility

Your team implemented a brand new API logging product. One of the team members has been tasked with collecting the logs generated by that new product. The team member reported continuous errors when transferring the logs to the review platform.

#### In this case, which of the given difficulties occurs?

Answer: Process and Archive

### Task 6 - Common Mistakes and Best Practices

#### Common Mistakes and Best Practices

Logging is a powerful and valuable tool for cyber security and IT operations. But harnessing this power and maximising it takes solid planning and implementation. Otherwise, logging will become inefficient, making things difficult to do, tedious to manage, and draining resources.

In addition to the high and low-level details, strategies and suggestions discussed until this point, a few more things require your attention. Logging is a continuous and live operation which needs continuous maintenance and improvement. Therefore, the infamous "if it works, don't touch it!" approach is unacceptable. The threats and computing technologies evolve and change; therefore, you must update your configurations and adapt the changes accordingly. Implementing the following actions is a good place to start the self-assessment and improvement process.

- Learn from mistakes and failures.
- Track the sectoral threat dynamics for the operated sector and conduct regular scope and resilience testing.
- Follow the best practices of industry leaders and experts.

If you ever think about how important to re-configure, update, or test your existing logging configurations is, please consider the following real-life experience faced by millions of people worldwide.

Experience

- Log analysis nightmare due to improper log configurations and/or lack of configuration maintenance/updates.

Storyline

- MS Windows 7 Operation System default logging configurations provided zero and/or insufficient logs when the system is compromised with the EternalBlue vulnerability (CVE-2017-0144) exploit.
- No significant event logs were created under System, Security, and Application logs.

Attack Details

- Damage: Full access to the victim system.
- Impact: High
- Score: NIST NVD Score (CVSS 3)= 8.1 High.

Notes

- MS Windows 7 SP1's official support date ends in 2020.
- The exploit was discovered and used in the wild in 2017.

Common Mistakes and Best Practices

First, you should use consultancy services if you are short on time and need a solution that directly fits your systems. Tailored-up solutions require comprehensive risk assessment practices, as highlighted in the previous tasks. However, avoiding some known pain points and deadlock cases is possible by considering the "dos" and "don'ts" in the planning and implementation steps. Therefore, the main point of this section is understanding "what does work" and "what doesn't".

| Mistakes "don'ts" | Best Practices "dos" |
|----|----|
|Logging sensitive information!|Create a suitable log configuration and plan according to your systems.|
|Creating logs by yourself.|Implement testing on scale, functionality, and operational stability.|
|Having uncollected logs.|Exclude logging sensitive information!|
|Collecting everything but not analysing.|Secure your logs.|
|Collecting logs without proper planning and configuration.|Create meaningful alerts/notifications.|
|Having systems that lack the planned/required log configuration.|Focus on having insights on actionable and impactful results.|
|Skipping the scale, testing, and functionality analysis.|Train your analysts and enhance their skills.|
|Focusing on edges and skipping the internal systems in analysis.|Update/maintain your operation plans and components/assets as needed.|
|"Searching for what you want to find" and "Not investigating what you see".| |
|Forgetting that the process takes the form of proper planning, management, and analysis.| |

---------------------------------------------------------------

As a consultant, you are doing a comprehensive risk assessment and noticed that one of the development teams implemented a custom script to generate logs for an old system, which omits loggings at some phases.

#### What you would call this? (Mistake or Practice?)

Answer: Mistake

### Task 7 - Conclusion

#### Congratulations!

You just finished the "Log Operations" room.

In this room, we dived deep into log operations and discovered the background and management side of the technical logging and log analysis operations by covering:

- Fundamentals of log configuration.
- Logging use cases.
- Common mistakes and learn best practices in logging.

Now, you have a solid understanding of the overall log operations and are ready to fly to the log universe, where you will experience the hands-on aspect of the log operations!

Proceed to the [Log Universe](https://tryhackme.com/r/room/loguniverse) room.

For additional information, please see the references below.

## References

- [Logging (computing) - Wikipedia](https://en.wikipedia.org/wiki/Logging_(computing))
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Security information and event management - Wikipedia](https://en.wikipedia.org/wiki/Security_information_and_event_management)
- [NIST Special Publication 800-92](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf)
