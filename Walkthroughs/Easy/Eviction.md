# Eviction

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: -
Subscription type: Premium
Description: Unearth the monster from under your bed.
```

Room link: [https://tryhackme.com/room/eviction](https://tryhackme.com/room/eviction)

## Solution

### Understand the adversary

Sunny is a SOC analyst at E-corp, which manufactures rare earth metals for government and non-government clients. She receives a classified intelligence report that informs her that an APT group (APT28) might be trying to attack organizations similar to E-corp. To act on this intelligence, she must use the MITRE ATT&CK Navigator to identify the TTPs used by the APT group, to ensure it has not already intruded into the network, and to stop it if it has.

Please visit [this link](https://static-labs.tryhackme.cloud/sites/eviction/) to check out the MITRE ATT&CK Navigator layer for the APT group and answer the questions below.

### What is a technique used by the APT to both perform recon and gain initial access?

The common technique for both Reconnaissance and Initial Access is [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/).

Answer: `Spearphishing Link`

### Sunny identified that the APT might have moved forward from the recon phase. Which accounts might the APT compromise while developing resources?

Checking the Resource Development tactic we find [Email Accounts](https://attack.mitre.org/techniques/T1586/002/) under Compromise Accounts.

Answer: `Email Accounts`

### E-corp has found that the APT might have gained initial access using social engineering to make the user execute code for the threat actor. Sunny wants to identify if the APT was also successful in execution. What two techniques of user execution should Sunny look out for? (Answer format: <technique 1> and <technique 2>)

Checking the [User Execution](https://attack.mitre.org/techniques/T1204/) technique we find that this APT uses Malicious File and Malicious Link.

Answer: `Malicious File and Malicious Link`

### If the above technique was successful, which scripting interpreters should Sunny search for to identify successful execution? (Answer format: <technique 1> and <technique 2>)

This APT uses two [Command and Scripting Interpreters](https://attack.mitre.org/techniques/T1059/): PowerShell and Windows Command Shell.

Answer: `PowerShell and Windows Command Shell`

### While looking at the scripting interpreters identified in Q4, Sunny found some obfuscated scripts that changed the registry. Assuming these changes are for maintaining persistence, which registry keys should Sunny observe to track these changes?

Hint: Use the exact text from the ATT&CK Navigator.

Checking the Persistence tactic we find that this APT uses [Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/).

Answer: `Registry Run Keys`

### Sunny identified that the APT executes system binaries to evade defences. Which system binary's execution should Sunny scrutinize for proxy execution?

This APT mainly uses one [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/) technique: Rundll32.

Answer: `Rundll32`

### Sunny identified tcpdump on one of the compromised hosts. Assuming this was placed there by the threat actor, which technique might the APT be using here for discovery?

Checking for network related Discovery techniques used by this APT we find [Network Sniffing](https://attack.mitre.org/techniques/T1040/).

Answer: `Network Sniffing`

### It looks like the APT achieved lateral movement by exploiting remote services. Which remote services should Sunny observe to identify APT activity traces?

This APT mainly uses on Remote Service for lateral movement: [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/).

Answer: `SMB/Windows Admin Shares`

### It looked like the primary goal of the APT was to steal intellectual property from E-corp's information repositories. Which information repository can be the likely target of the APT?

We can see that this APT collects Data from one Information Repository: [Sharepoint](https://attack.mitre.org/techniques/T1213/002/).

Answer: `Sharepoint`

### Although the APT had collected the data, it could not connect to the C2 for data exfiltration. To thwart any attempts to do that, what types of proxy might the APT use? (Answer format: <technique 1> and <technique 2>)

Checking the [Proxy](https://attack.mitre.org/techniques/T1090/) techniques used by this APT we find: External Proxy and Multi-hop Proxy.

Answer: `External Proxy and Multi-hop Proxy`

For additional information, please see the references below.

## References

- [APT28 - ATT&CK - Mitre](https://attack.mitre.org/groups/G0007/)
- [ATT&CK - Mitre](https://attack.mitre.org/)
- [ATT&CK Navigator - Mitre](https://mitre-attack.github.io/attack-navigator/)
