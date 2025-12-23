# Brim

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
Tags: -
Subscription type: Premium
Description:
Learn and practice log investigation, pcap analysis and threat hunting with Brim.
```

Room link: [https://tryhackme.com/room/brim](https://tryhackme.com/room/brim)

## Solution

### Task 1: Introduction

[BRIM](https://www.brimdata.io/) is an open-source desktop application that processes pcap files and logs files. Its primary focus is providing search and analytics. In this room, you will learn how to use Brim, process pcap files and investigate log files to find the needle in the haystack! This room expects you to be familiar with basic security concepts and processing Zeek log files. We suggest completing the "[Network Fundamentals](https://tryhackme.com/module/network-fundamentals)" path and the "[Zeek room](https://tryhackme.com/room/zeekbro)" before starting working in this room.

A VM is attached to this room. You don't need SSH or RDP; the room provides a "**Split View**" feature. Exercise files are located in the folder on the desktop.

**NOTE**: DO NOT directly interact with any domains and IP addresses in this room.

![Brim Exercise Files](Images/Brim_Exercise_Files.png)

### Task 2: What is Brim?

![Brim Zed Overview](Images/Brim_Zed_Overview.png)

#### What is Brim?

Brim is an open-source desktop application that processes pcap files and logs files, with a primary focus on providing search and analytics. It uses the Zeek log processing format. It also supports Zeek signatures and Suricata Rules for detection.

It can handle two types of data as an input;

- **Packet Capture Files**: Pcap files created with tcpdump, tshark and Wireshark like applications.
- **Log Files**: Structured log files like Zeek logs.

Brim is built on open-source platforms:

- **Zeek**: Log generating engine.
- **Zed Language**: Log querying language that allows performing keywoırd searches with filters and pipelines.
- **ZNG Data Format**: Data storage format that supports saving data streams.
- **Electron and React**: Cross-platform UI.

#### Why Brim?

Ever had to investigate a big pcap file? Pcap files bigger than one gigabyte are cumbersome for Wireshark. Processing big pcaps with tcpdump and Zeek is efficient but requires time and effort. Brim reduces the time and effort spent processing pcap files and investigating the log files by providing a simple and powerful GUI application.

#### Brim vs Wireshark vs Zeek

While each of them is powerful and useful, it is good to know the strengths and weaknesses of each tool and which one to use for the best outcome. As a traffic capture analyser, some overlapping functionalities exist, but each one has a unique value for different situations.

The common best practice is:

- handling medium-sized pcaps with Wireshark,
- creating logs and correlating events with Zeek, and
- processing multiple logs in Brim.

||Brim|Wireshark|Zeek|
|----|----|----|----|
|Purpose|Pcap processing; event/stream and log investigation.|Traffic sniffing. Pcap processing; packet and stream investigation.|Pcap processing; event/stream and log investigation.|
|GUI|✔|✔|✖|
|Sniffing|✖|✔|✔|
|Pcap processing|✔|✔|✔|
|Log processing|✔|✖|✔|
|Packet decoding|✖|✔|✔|
|Filtering|✔|✔|✔|
|Scripting|✖|✖|✔|
|Signature Support|✔|✖|✔|
|Statistics|✔|✔|✔|
|File Extraction|✖|✔|✔|
|Handling pcaps over 1GB|Medium performance|Low performance|Good performance|
|Ease of Management|4/5|4/5|3/5|

---------------------------------------------------------------------------------------

### The Basics

#### Landing Page

Once you open the application, the landing page loads up. The landing page has three sections and a file importing window. It also provides quick info on supported file formats.

- **Pools**: Data resources, investigated pcap and log files.
- **Queries**: List of available queries.
- **History**: List of launched queries.

#### Pools and Log Details

Pools represent the imported files. Once you load a pcap, Brim processes the file and creates Zeek logs, correlates them, and displays all available findings in a timeline, as shown in the image below.

![Brim GUI Overview](Images/Brim_GUI_Overview.png)

The timeline provides information about capture start and end dates. Brim also provides information fields. You can hover over fields to have more details on the field. The above image shows a user hovering over the Zeek's conn.log file and uid value. This information will help you in creating custom queries. The rest of the log details are shown in the right pane and provides details of the log file fields. Note that you can always export the results by using the export function located near the timeline.

You can correlate each log entry by reviewing the correlation section at the log details pane (shown on the below image). This section provides information on the source and destination addresses, duration and associated log files. This quick information helps you answer the "Where to look next?" question and find the event of interest and linked evidence.

![Brim Correlation Example](Images/Brim_Correlation_Example.png)

You can also right-click on each field to filter and accomplish a list of tasks.

- Filtering values
- Counting fields
- Sorting (A-Z and Z-A)
- Viewing details
- Performing whois lookup on IP address
- Viewing the associated packets in Wireshark

The image below demonstrates how to perform whois lookup and Wireshark packet inspection.

![Brim Wireshark VT Whois Example](Images/Brim_Wireshark_VT_Whois_Example.png)

#### Queries and History

Queries help us to correlate finding and find the event of the interest. History stores executed queries.

![Brim Queries and History](Images/Brim_Queries_and_History.png)

The image above demonstrates how to browse the queries and load a specific query from the library.

Queries can have names, tags and descriptions. Query library lists the query names, and once you double-click, it passes the actual query to the search bar.

You can double-click on the query and execute it with ease. Once you double-click on the query, the actual query appears on the search bar and is listed under the history tab.

The results are shown under the search bar. In this case, we listed all available log sources created by Brim. In this example, we only insert a pcap file, and it automatically creates nine types of Zeek log files.

Brim has 12 premade queries listed under the "Brim" folder. These queries help us discover the Brim query structure and accomplish quick searches from templates.  You can add new queries by clicking on the "+" button near the "Queries" menu.

![Brim Queries and History 2](Images/Brim_Queries_and_History_2.png)

---------------------------------------------------------------------------------------

Process the "**sample.pcap**" file and look at the details of the first DNS log that appear on the dashboard.

#### What is the "qclass_name"?

Hint: You can review the details of the log files by "right-click --> "Open details".

Find the first `dns` log entry and double-click on it to open the details view:

![Brim DNS Details Example](Images/Brim_DNS_Details_Example.png)

Answer: `C_INTERNET`

#### Look at the details of the first NTP log that appear on the dashboard. What is the "duration" value?

Hint: The correlation section provides the duration value.

![Brim NTP Details Example](Images/Brim_NTP_Details_Example.png)

Answer: `0.005`

#### Look at the details of the STATS packet log that is visible on the dashboard. What is the "reassem_tcp_size"?

![Brim Stats Details Example](Images/Brim_Stats_Details_Example.png)

Answer: `540`

### Task 4: Default Queries

#### Default Queries

We mentioned that Brim had 12 premade queries in the previous task. Let's see them in action! Now, open Brim, import the sample pcap (**task4-sample-b.pcap**) and go through the walkthrough.

**Reviewing Overall Activity**

This query provides general information on the pcap file. The provided information is valuable for accomplishing further investigation and creating custom queries. It is impossible to create advanced or case-specific queries without knowing the available log files.

The image below shows that there are 20 logs generated for the provided pcap file.

![Brim Activity Overview Query](Images/Brim_Activity_Overview_Query.png)

**Windows Specific Networking Activity**

This query focuses on Windows networking activity and details the source and destination addresses and named pipe, endpoint and operation detection. The provided information helps investigate and understand specific Windows events like SMB enumeration, logins and service exploiting.

![Brim Windows Networking Activity Query](Images/Brim_Windows_Networking_Activity_Query.png)

**Unique Network Connections** and **Connection Received Data**

These two queries provide information on unique connections and connection-data correlation. The provided info helps analysts detect weird and malicious connections and suspicious and beaconing activities. The uniq list provides a clear list of unique connections that help identify anomalies. The data list summarises the data transfer rate that supports the anomaly investigation hypothesis.

![Brim Unique Net Conns and Transferred Data Queries](Images/Brim_Unique_Net_Conns_and_Transferred_Data_Queries.png)

**Unique DNS Queries** and **HTTP Requests**

These queries provide the list of the DNS queries and HTTP methods. The provided information helps analysts to detect anomalous DNS and HTTP traffic. You can also narrow the search by viewing the "HTTP POST" requests with the available query and modifying it to view the "HTTP GET" methods.

![Brim Unique DNS and HTTP Requests Queries](Images/Brim_Unique_DNS_and_HTTP_Requests_Queries.png)

**File Activity**

This query provides the list of the available files. It helps analysts to detect possible data leakage attempts and suspicious file activity. The query provides info on the detected file MIME and file name and hash values (MD5, SHA1).

![Brim File Activity Query](Images/Brim_File_Activity_Query.png)

**Show IP Subnet** Statistics

This query provides the list of the available IP subnets. It helps analysts detect possible communications outside the scope and identify out of ordinary IP addresses.

![Brim Show IP Subnet Query](Images/Brim_Show_IP_Subnet_Query.png)

**Suricata Alerts**

These queries provide information based on Suricata rule results. Three different queries are available to view the available logs in different formats:

- Suricata Alerts by Category
- Suricata Alerts by Source and Destination
- Suricata Alerts by Subnet

**Note**: Suricata is an open-source threat detection engine that can act as a rule-based Intrusion Detection and Prevention System. It is developed by the Open Information Security Foundation (OISF). Suricata works and detects anomalies in a similar way to [Snort](https://tryhackme.com/room/snort) and can use the same signatures.

![Brim Suricata Alert Queries](Images/Brim_Suricata_Alert_Queries.png)

---------------------------------------------------------------------------------------

#### Investigate the files. What is the name of the detected GIF file?

Hint: Use task4 pcap file.

Using the query `File Activity` we find the answer:

![Brim File Activity GIF File](Images/Brim_File_Activity_GIF_File.png)

Answer: `cat01_with_hidden_text.gif`

#### Investigate the conn logfile. What is the number of the identified city names?

Hint: You can filter the conn logfile and then view the available sections by scrolling the horizontal bar.

`_path=="conn" | cut geo.resp.country_code, geo.resp.region, geo.resp.city`

1. Clear the search bar to view all log events
2. Right-click on a **Conn** icon/tag and select `Filter == value`
3. The query becomes `_path=="conn"` and only conn log events are shown
4. Scroll to the right and look City-related columns.
5. There are two related columns: `geo > orig > city` and `geo > resp > city` for source resp. destination.
6. Click on the column header to sort on that column/field.
7. Only the destination (`geo > resp > city`) have data.
8. The query is now `_path=="conn" | sort geo.resp.city`

![Brim Conn Log with City Geo Data](Images/Brim_Conn_Log_with_City_Geo_Data.png)

Answer: `2`

#### Investigate the Suricata alerts. What is the Signature id of the alert category "Potential Corporate Privacy Violation"?

1. Use the `Suricata Alerts by Category` query
2. Right-click on `Potential Corporate Privacy Violation` and select `New search with this value`.
3. There are two matching log entries.
4. Scroll to the right and look for a column that includes signature IDs (`alert > signature_id`)
5. Or double-click on one of the log entries to open the Details view.

![Brim Suricata Alert Details](Images/Brim_Suricata_Alert_Details.png)

Answer: `2,012,887`

### Task 5: Use Cases

#### Custom Queries and Use Cases

There are a variety of use case examples in traffic analysis. For a security analyst, it is vital to know the common patterns and indicators of anomaly or malicious traffic. In this task, we will cover some of them. Let's review the basics of the Brim queries before focusing on the custom and advanced ones.

**Brim Query Reference**

|Purpose|Syntax|Example Query|
|----|----|----|
|Basic search|You can search any string and numeric value.|Find logs containing an IP address or any value.<br>`10.0.0.1`|
|Logical operators|Or, And, Not.|Find logs contain three digits of an IP AND NTP keyword.<br>`192 and NTP`|
|Filter values|"field name" == "value"|Filter source IP.<br>`id.orig_h==192.168.121.40`|
|List specific log file contents|_path=="log name"|List the contents of the conn log file.<br>`_path=="conn"`|
|Count field values|count () by "field"|Count the number of the available log files.<br>`count () by _path`|
|Sort findings|sort|Count the number of the available log files and sort recursively.<br>`count () by _path \| sort -r`|
|Cut specific field from a log file|_path=="conn" \| cut "field name"|Cut the source IP, destination port and destination IP addresses from the conn log file.<br>`_path=="conn" \| cut id.orig_h, id.resp_p, id.resp_h`|
|List unique values|uniq|Show the unique network connections.<br>`_path=="conn" \| cut id.orig_h, id.resp_p, id.resp_h \| sort \| uniq`|

**Note**: It is highly suggested to use field names and filtering options and not rely on the blind/irregular search function. Brim provides great indexing of log sources, but it is not performing well in irregular search queries. The best practice is always to use the field filters to search for the event of interest.

**Communicated Hosts**

Identifying the list of communicated hosts is the first step of the investigation. Security analysts need to know which hosts are actively communicating on the network to detect any suspicious and abnormal activity in the first place. This approach will help analysts to detect possible access violations, exploitation attempts and malware infections.

**Query**: `_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq`

**Frequently Communicated Hosts**

After having the list of communicated hosts, it is important to identify which hosts communicate with each other most frequently. This will help security analysts to detect possible data exfiltration, exploitation and backdooring activities.

**Query**: `_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq -c | sort -r`

**Most Active Ports**

Suspicious activities are not always detectable in the first place. Attackers use multiple ways of hiding and bypassing methods to avoid detection. However, since the data is evidence, it is impossible to hide the packet traces. Investigating the most active ports will help analysts to detect silent and well-hidden anomalies by focusing on the data bus and used services.

**Query**: `_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count`

**Query**: `_path=="conn" | cut id.orig_h, id.resp_h, id.resp_p, service | sort id.resp_p | uniq -c | sort -r`

**Long Connections**

For security analysts, the long connections could be the first anomaly indicator. If the client is not designed to serve a continuous service, investigating the connection duration between two IP addresses can reveal possible anomalies like backdoors.

**Query**: `_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h, duration | sort -r duration`

**Transferred Data**

Another essential point is calculating the transferred data size. If the client is not designed to serve and receive files and act as a file server, it is important to investigate the total bytes for each connection. Thus, analysts can distinguish possible data exfiltration or suspicious file actions like malware downloading and spreading.

**Query**: `_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes`

**DNS and HTTP Queries**

Identifying suspicious and out of ordinary domain connections and requests is another significant point for a security analyst. Abnormal connections can help detect C2 communications and possible compromised/infected hosts. Identifying the suspicious DNS queries and HTTP requests help security analysts to detect malware C2 channels and support the investigation hypothesis.

**Query**: `_path=="dns" | count () by query | sort -r`

**Query**: `_path=="http" | count () by uri | sort -r`

**Suspicious Hostnames**

Identifying suspicious and out of ordinary hostnames helps analysts to detect rogue hosts. Investigating the DHCP logs provides the hostname and domain information.

**Query**: `_path=="dhcp" | cut host_name, domain`

**Suspicious IP Addresses**

For security analysts, identifying suspicious and out of ordinary IP addresses is essential as identifying weird domain addresses. Since the connection logs are stored in one single log file (conn), filtering IP addresses is more manageable and provides more reliable results.

**Query**: `_path=="conn" | put classnet := network_of(id.resp_h) | cut classnet | count() by classnet | sort -r`

**Detect Files**

Investigating transferred files is another important point of traffic investigation. Performing this hunt will help security analysts to detect the transfer of malware or infected files by correlating the hash values. This act is also valuable for detecting transferring of sensitive files.

**Query**: `filename!=null`

**SMB Activity**

Another significant point is investigating the SMB activity. This will help analysts to detect possible malicious activities like exploitation, lateral movement and malicious file sharing. When running an investigation, it is suggested to ask, "What is going on in SMB?".

**Query**: `_path=="dce_rpc" OR _path=="smb_mapping" OR _path=="smb_files"`

**Known Patterns**

Known patterns represent alerts generated by security solutions. These alerts are generated against the common attack/threat/malware patterns and known by endpoint security products, firewalls and IDS/IPS solutions. This data source highly relies on available signatures, attacks and anomaly patterns. Investigating available log sources containing alerts is vital for a security analyst.

Brim supports the Zeek and Suricata logs, so any anomaly detected by these products will create a log file. Investigating these log files can provide a clue where the analyst should focus.

**Query**: `event_type=="alert" or _path=="notice" or _path=="signatures"`

---------------------------------------------------------------------------------------

### Task 6: Exercise: Threat Hunting with Brim | Malware C2 Detection

#### Threat Hunting with Brim | Malware C2 Detection

It is just another malware campaign spread with CobaltStrike. We know an employee clicks on a link, downloads a file, and then network speed issues and anomalous traffic activity arises. Now, open Brim, import the sample pcap and go through the walkthrough.

Let's investigate the traffic sample (**task6-malware-c2.pcap**) to detect malicious C2 activities!

Let's look at the available logfiles first to see what kind of data artefact we could have. Use the `Activity Overview` query. The image below shows that we have many alternative log files we could rely on.

![Brim C2 Logs Overview](Images/Brim_C2_Logs_Overview.png)

Let's review the frequently communicated hosts before starting to investigate individual logs.

**Query**: `_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq -c | sort -r count`

![Brim C2 Communications Overview](Images/Brim_C2_Communications_Overview.png)

This query provides sufficient data that helped us decide where to focus. The IP addresses "10.22.xx" and "104.168.xx" draw attention in the first place. Let's look at the port numbers and available services before focusing on the suspicious IP address and narrowing our search.

**Query**: `_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count`

![Brim C2 Service Overview](Images/Brim_C2_Service_Overview.png)

Nothing extremely odd in port numbers, but there is a massive DNS record available. Let's have a closer look.

**Query**: `_path=="dns" | count() by query | sort -r`

![Brim C2 DNS Query Overview](Images/Brim_C2_DNS_Query_Overview.png)

There are out of ordinary DNS queries. Let's enrich our findings by using VirusTotal to identify possible malicious domains.

![Brim C2 VirusTotal Lookups](Images/Brim_C2_VirusTotal_Lookups.png)

We have detected two additional malicious IP addresses (we have the IP 45.147.xx from the log files and gathered the 68.138.xx and 185.70.xx from VirusTotal) linked with suspicious DNS queries with the help of external research. Let's look at the HTTP requests before narrowing down our investigation with the found malicious IP addresses.

**Query**: `_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort value.uri`

![Brim C2 HTTP Requests Overview](Images/Brim_C2_HTTP_Requests_Overview.png)

We detect a file download request from the IP address we assumed as malicious. Let's validate this idea with VirusTotal and validate our hypothesis.

![Brim C2 VirusTotal Lookups 2](Images/Brim_C2_VirusTotal_Lookups_2.png)

VirusTotal results show that the IP address "104.xx" is linked with a file. Once we investigate that file, we discover that these two findings are associated with CobaltStrike. Up to here, we've followed the abnormal activity and found the malicious IP addresses. Our findings represent the C2 communication. Now let's conclude our hunt by gathering the low hanging fruits with Suricata logs.

**Query**: `event_type=="alert" | count() by alert.severity,alert.category | sort count`

![Brim C2 Suricata Overview](Images/Brim_C2_Suricata_Overview.png)

Now we can see the overall malicious activities detected by Suricata. Note that you can investigate the rest of the IP addresses to identify the secondary C2 traffic anomaly without using the Suricata logs. This task demonstrates two different approaches to detecting anomalies.

Investigating each alarm category and signature to enhance the threat hunting activities and post-hunting system hardening operations is suggested. Please note, Adversaries using CobaltStrike are usually skilled threats and don't rely on a single C2 channel. Common experience and use cases recommend digging and keeping the investigation by looking at additional C2 channels.

This concludes our hunt for the given case. Now, repeat this exercise in the attached VM and ask the questions below.

---------------------------------------------------------------------------------------

#### What is the name of the file downloaded from the CobaltStrike C2 connection?

From the query: `_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort uri`

Answer: `4564.exe`

#### What is the number of CobaltStrike connections using port 443?

Hint: The IP starting with "104" is CobaltStrike.

From the query: `_path=="conn" and id.resp_p==443 and id.resp_h==104.168.44.45 | cut id.orig_h, id.resp_h, id.resp_p, service | sort | uniq -c | sort -r count`

Answer: `328`

#### There is an additional C2 channel in used the given case. What is the name of the secondary C2 channel?

Hint: `event_type=="alert" | cut alert.signature | sort -r | uniq -c | sort -r count`

If we list all Suricata alerts and exclude the first C2 IP (`104.168.44.45`) as both source and destination we get a list of "new" alerts:

![Brim C2 Alternate C2 Hunting](Images/Brim_C2_Alt_C2_Hunting.png)

The query is: `event_type=="alert" and src_ip!=104.168.44.45 and dest_ip!=104.168.44.45  | cut alert.signature,src_ip, dest_ip | sort -r | uniq -c | sort -r count`

**Note** the non-standard zeek field names `src_ip` and `dest_ip`.

In the second to last alert type `IcedID` is mentioned.

Answer: `IcedID`

### Task 7: Exercise: Threat Hunting with Brim | Crypto Mining

#### Threat Hunting with Brim | Crypto Mining

Cryptocurrencies are frequently on the agenda with their constantly rising value and legal aspect. The ability to obtain cryptocurrencies by mining other than purchasing is becoming one of the biggest problems in today's corporate environments. Attackers not only compromise the systems and ask for a ransom, but sometimes they also install mining tools (cryptojacking). Other than the attackers and threat actors, sometimes internal threats and misuse of trust and privileges end up installing coin miners in the corporate environment.

Usually, mining cases are slightly different from traditional compromising activities. Internal attacks don't typically contain major malware samples. However, this doesn't mean they aren't malicious as they are exploiting essential corporate resources like computing power, internet, and electricity. Also, crypto mining activities require third party applications and tool installations which could be vulnerable or create backdoors. Lastly, mining activities are causing network performance and stability problems. Due to these known facts, coin mining is becoming one of the common use cases of threat hunters.

Now, open Brim, import the sample pcap (**task7-crypto-mine.pcap**) and go through the walkthrough.

Let's investigate a traffic sample to detect a coin mining activity!

Let's look at the available logfiles first to see what kind of data artefact we could have through the query `Activity Overview`. The image below shows that we don't have many alternative log files we could rely on.

![Brim Crypto Log Overview](Images/Brim_Crypto_Log_Overview.png)

Let's review the frequently communicated hosts to see if there is an anomaly indicator.

**Query**: `cut id.orig_h, id.resp_p, id.resp_h | sort  | uniq -c | sort -r`

![Brim Crypto Communication Overview](Images/Brim_Crypto_Communication_Overview.png)

This query provided sufficient data that helped us decide where to focus. The IP address "192.168.xx" draws attention in the first place. Let's look at the port numbers and available services before focusing on the suspicious IP address and narrowing our search.

**Query**: `_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count`

![Brim Crypto Service Overview](Images/Brim_Crypto_Service_Overview.png)

There is multiple weird port usage, and this is not usual. Now, we are one step closer to the identification of the anomaly. Let's look at the transferred data bytes to support our findings and find more indicators.

**Query**: `_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes`

![Brim Crypto Bytes Transferred Overview](Images/Brim_Crypto_Bytes_Transferred_Overview.png)

The query result proves massive traffic originating from the suspicious IP address. The detected IP address is suspicious. However, we don't have many supportive log files to correlate our findings and detect accompanying activities. At this point, we will hunt the low hanging fruits with the help of Suricata rules. Let's investigate the Suricata logs.

**Query**: `event_type=="alert" | count() by alert.severity,alert.category | sort count`

![Brim Crypto Suricata Overview](Images/Brim_Crypto_Suricata_Overview.png)

Suricata rules have helped us conclude our hunt quickly, as the alerts tell us we are investigating a "Crypto Currency Mining" activity. Let's dig deeper and discover which data pool is used for the mining activity. First, we will list the associated connection logs with the suspicious IP, and then we will run a VirusTotal search against the destination IP.

**Query**: `_path=="conn" | 192.168.1.100`

![Brim Crypto IP Investigation](Images/Brim_Crypto_IP_Investigation.png)

![Brim Crypto VirusTotal Lookup](Images/Brim_Crypto_VirusTotal_Lookup.png)

We investigated the first destination IP address and successfully identified the mining server. In real-life cases, you may need to investigate multiple IP addresses to find the event of interest.

Lastly, let's use Suricata logs to discover mapped out MITRE ATT&CK techniques.

**Query**: `event_type=="alert" | cut alert.category, alert.metadata.mitre_technique_name, alert.metadata.mitre_technique_id, alert.metadata.mitre_tactic_name | sort | uniq -c`

![Brim Crypto Suricata Overview 2](Images/Brim_Crypto_Suricata_Overview_2.png)

Now we can identify the mapped out MITRE ATT&CK details as shown in the table below.

|Suricata Category|MITRE Technique Name|MITRE Technique Id|MITRE Tactic Name|
|----|----|----|----|
|Crypto Currency Mining|Resource_Hijacking|T1496|Impact|

This concludes our hunt for the given case. Now, repeat this exercise in the attached VM and ask the questions below.

---------------------------------------------------------------------------------------

#### How many connections used port 19999?

From query: `_path=="conn" AND (id.resp_p==19999 OR id.orig_p==19999) | count()`

Answer: `22`

#### What is the name of the service used by port 6666?

From query: `_path=="conn" AND id.resp_p==6666 | cut service | uniq`

Answer: `irc`

#### What is the amount of transferred total bytes to "101.201.172.235:8888"?

From query: `_path=="conn" id.resp_h==101.201.172.235 id.resp_p==8888 | put total_bytes := orig_bytes + resp_bytes  | cut total_bytes`

Answer: `3,729`

#### What is the detected MITRE tactic id?

Hint: Investigate the alert logs without filter and find the tactic id field.

From query: `event_type=="alert" alert.category=="Crypto Currency Mining Activity Detected" | cut alert.metadata.mitre_tactic_name, alert.metadata.mitre_tactic_id | uniq`

Answer: `TA0040`

### Task 8: Conclusion

**Congratulations**! You just finished the Brim room.

In this room, we covered Brim, what it is, how it operates, and how to use it to investigate threats.

Now, we invite you to complete the Brim challenge room: [Masterminds](https://tryhackme.com/room/mastermindsxlq)

For additional information, please see the references below.

## References

- [Brim - Homepage](https://www.brimdata.io/)
- [pcap - Wikipedia](https://en.wikipedia.org/wiki/Pcap)
- [Zed - Documentation](https://zed.brimdata.io/docs/)
- [Zed - GitHub](https://github.com/brimdata/zed-archive)
- [Zed - Homepage](https://www.brimdata.io/)
