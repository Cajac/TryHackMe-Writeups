# Windows PowerShell

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Premium
Description: Discover the "Power" in PowerShell and learn the basics.
```

Room link: [https://tryhackme.com/room/windowspowershell](https://tryhackme.com/room/windowspowershell)

## Solution

### Task 1 - Introduction

Ahoy there! If you’re here, you’ve either heard whispers of the marvels of PowerShell and want to discover more, or you’ve sailed over from the first room of the Command Line module — Windows Command Line. Either way, you’re about to embark on a journey to discover the marvels of this powerful shell, learning how to use it to uncover the secrets of any Windows system. Avast, then—on board!

#### Learning Objectives

This is the second room in the Command Line module. It is an introductory room to PowerShell, the second—only historically—command-line utility built for the Windows operating system.

- Learn what PowerShell is and its capabilities.
- Understand the basic structure of PowerShell’s language.
- Learn and run some basic PowerShell commands.
- Understand PowerShell’s many applications in the cyber security industry.

### Task 2 - What Is PowerShell

From the official Microsoft page: “*PowerShell is a cross-platform task automation solution made up of a command-line shell, a scripting language, and a configuration management framework.*”

PowerShell is a powerful tool from Microsoft designed for task automation and configuration management. It combines a command-line interface and a scripting language built on the .NET framework. Unlike older text-based command-line tools, PowerShell is object-oriented, which means it can handle complex data types and interact with system components more effectively. Initially exclusive to Windows, PowerShell has lately expanded to support macOS and Linux, making it a versatile option for IT professionals across different operating systems.

#### A Brief History of PowerShell

PowerShell was developed to overcome the limitations of existing command-line tools and scripting environments in Windows. In the early 2000s, as Windows was increasingly used in complex enterprise environments, traditional tools like `cmd.exe` and batch files fell short in automating and managing these systems. Microsoft needed a tool that could handle more sophisticated administrative tasks and interact with Windows’ modern APIs.

Jeffrey Snover, a Microsoft engineer, realised that Windows and Unix handled system operations differently — Windows used structured data and APIs, while Unix treated everything as text files. This difference made porting Unix tools to Windows impractical. Snover’s solution was to develop an object-oriented approach, combining scripting simplicity with the power of the .NET framework. Released in 2006, PowerShell allowed administrators to automate tasks more effectively by manipulating objects, offering deeper integration with Windows systems.

As IT environments evolved to include various operating systems, the need for a versatile automation tool grew. In 2016, Microsoft responded by releasing PowerShell Core, an open-source and cross-platform version that runs on Windows, macOS, and Linux.

#### The Power in PowerShell

To fully grasp the power of PowerShell, we first need to understand what an **object** is in this context.

In programming, an **object** represents an item with **properties** (characteristics) and **methods** (actions). For example, a `car` object might have properties like `Color`, `Model`, and `FuelLevel`, and methods like `Drive()`, `HonkHorn()`, and `Refuel()`.

Similarly, in PowerShell, objects are fundamental units that encapsulate data and functionality, making it easier to manage and manipulate information. An object in PowerShell can contain file names, usernames or sizes as data (**properties**), and carry functions (**methods**) such as copying a file or stopping a process.

The traditional Command Shell’s basic commands are text-based, meaning they process and output data as plain text. Instead, when a **cmdlet** (pronounced command-let) is run in PowerShell, it returns objects that retain their properties and methods. This allows for more powerful and flexible data manipulation since these objects do not require additional parsing of text.

We will explore more about PowerShell’s cmdlets and their capabilities in the upcoming sections.

#### What do we call the advanced approach used to develop PowerShell?

Answer: object-oriented

### Task 3 - PowerShell Basics

#### Connecting

We start by connecting to the machine using `ssh` and the credentials `captain:JollyR0ger#`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Windows_PowerShell]
└─$ ssh captain@10.10.246.17 
The authenticity of host '10.10.246.17 (10.10.246.17)' can't be established.
ED25519 key fingerprint is SHA256:WXNrzCBIhI0BbpO2+dlBbLRIlFimN8JzidezgFTQOM8.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:39: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.246.17' (ED25519) to the list of known hosts.
captain@10.10.246.17's password: 
Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

captain@THEBLACKPEARL C:\Users\captain> 
```

#### Launching PowerShell

PowerShell can be launched in several ways, depending on your needs and environment. If you are working on a Windows system from the graphical interface (GUI), these are some of the possible ways to launch it:

- **Start Menu**: Type `powershell` in the Windows Start Menu search bar, then click on `Windows PowerShell` or `PowerShell` from the results.
- **Run Dialog**: Press `Win + R` to open the `Run` dialog, type `powershell`, and hit `Enter`.
- **File Explorer**: Navigate to any folder, then type `powershell` in the address bar, and press `Enter`. This opens PowerShell in that specific directory.
- **Task Manager**: Open the Task Manager, go to `File > Run new task`, type `powershell`, and press `Enter`.

Alternatively, PowerShell can be launched from a Command Prompt (`cmd.exe`) by typing `powershell`, and pressing `Enter`.

```text
captain@THEBLACKPEARL C:\Users\captain>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\captain> 
```

#### Basic Syntax: Verb-Noun

As previously mentioned, PowerShell commands are known as `cmdlets` (pronounced command-lets). They are much more powerful than the traditional Windows commands and allow for more advanced data manipulation.

Cmdlets follow a consistent `Verb-Noun` naming convention. This structure makes it easy to understand what each cmdlet does. The Verb describes the action, and the Noun specifies the object on which action is performed. For example:

- `Get-Content`: Retrieves (gets) the content of a file and displays it in the console.
- `Set-Location`: Changes (sets) the current working directory.

#### Basic Cmdlets

To list all available cmdlets, functions, aliases, and scripts that can be executed in the current PowerShell session, we can use `Get-Command`. It’s an essential tool for discovering what commands one can use.

For each `CommandInfo` object retrieved by the cmdlet, some essential information (properties) is displayed on the console. It’s possible to filter the list of commands based on displayed property values. For example, if we want to display only the available commands of type “function”, we can use `-CommandType "Function"`.

Another essential cmdlet to keep in our tool belt is `Get-Help`: it provides detailed information about cmdlets, including usage, parameters, and examples. It’s the go-to cmdlet for learning how to use PowerShell commands.

As shown in the results above, `Get-Help` informs us that we can retrieve other useful information about a cmdlet by appending some options to the basic syntax. For example, by appending `-examples` to the command displayed above, we will be shown a list of common ways in which the chosen cmdlet can be used.

To make the transition easier for IT professionals, PowerShell includes aliases —which are shortcuts or alternative names for cmdlets — for many traditional Windows commands. Indispensable for users already familiar with other command-line tools, `Get-Alias` lists all aliases available. For example, `dir` is an alias for `Get-ChildItem`, and `cd` is an alias for `Set-Location`.

#### Where to Find and Download Cmdlets

Another powerful feature of PowerShell is the possibility of extending its functionality by downloading additional cmdlets from online repositories.

NOTE: Please note that the cmdlets listed in this section require a working internet connection to query online repositories. The attached machine doesn't have access to the internet, therefore these commands won't work in this environment.

To search for modules (collections of cmdlets) in online repositories like the PowerShell Gallery, we can use `Find-Module`. Sometimes, if we don’t know the exact name of the module, it can be useful to search for modules with a similar name. We can achieve this by filtering the `Name` property and appending a wildcard (`*`) to the module’s partial name, using the following standard PowerShell syntax: `Cmdlet -Property "pattern*"`.

Once identified, the modules can be downloaded and installed from the repository with `Install-Module`, making new cmdlets contained in the module available for use.

With these essential tools in our belt, we can now start exploring PowerShell’s capabilities.

#### How would you retrieve a list of commands that start with the verb Remove? [for the sake of this question, avoid the use of quotes (" or ') in your answer]

Hint: Read the last paragraph of the Where to Find and Download Cmdlets section that discusses using wildcards for patterns.

Answer: Get-Command -Name Remove*

#### What cmdlet has its traditional counterpart echo as an alias?

```powershell
PS C:\Users\captain> Get-Alias -Name echo 

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           echo -> Write-Output

```

Answer: Write-Output

#### What is the command to retrieve some example usage for the cmdlet New-LocalUser?

Answer: Get-Help New-LocalUser -Examples

### Task 4 - Navigating the File System and Working with Files

PowerShell provides a range of cmdlets for navigating the file system and managing files, many of which have counterparts in the traditional Windows CLI.

Similar to the `dir` command in Command Prompt (or ls in Unix-like systems), `Get-ChildItem` lists the files and directories in a location specified with the `-Path` parameter. It can be used to explore directories and view their contents. If no `Path` is specified, the cmdlet will display the content of the current working directory.

To navigate to a different directory, we can use the `Set-Location` cmdlet. It changes the current directory, bringing us to the specified path, akin to the `cd` command in Command Prompt.

While the traditional Windows CLI uses separate commands to create and manage different items like directories and files, PowerShell simplifies this process by providing a single set of cmdlets to handle the creation and management of both files and directories.

To create an item in PowerShell, we can use `New-Item`. We will need to specify the path of the item and its type (whether it is a file or a directory).

Similarly, the `Remove-Item` cmdlet removes both directories and files, whereas in Windows CLI we have separate commands `rmdir` and `del`.

We can copy or move files and directories alike, using respectively `Copy-Item` (equivalent to copy) and `Move-Item` (equivalent to move).

Finally, to read and display the contents of a file, we can use the `Get-Content` cmdlet, which works similarly to the `type` command in Command Prompt (or `cat` in Unix-like systems).

#### What cmdlet can you use instead of the traditional Windows command type?

Answer: Get-Content

#### What PowerShell command would you use to display the content of the "C:\Users" directory? [for the sake of this question, avoid the use of quotes (" or ') in your answer]

Answer: Get-ChildItem -Path C:\Users

#### How many items are displayed by the command described in the previous question?

```powershell
PS C:\Users\captain>  Get-ChildItem -Path C:\Users


    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          9/5/2024   4:34 AM                Administrator
d-----          9/4/2024  12:34 PM                captain
d-----          9/4/2024  10:40 AM                p1r4t3
d-r---         4/23/2024  10:05 AM                Public


PS C:\Users\captain>  Get-ChildItem -Path C:\Users | Measure-Object


Count    : 4
Average  :
Sum      :
Maximum  :
Minimum  :
Property :



PS C:\Users\captain> ( Get-ChildItem -Path C:\Users | Measure-Object).Count
4
```

Answer: 4

### Task 5 - Piping, Filtering, and Sorting Data

Piping is a technique used in command-line environments that allows the output of one command to be used as the input for another. This creates a sequence of operations where the data flows from one command to the next. Represented by the `|` symbol, piping is widely used in the Windows CLI, as introduced earlier in this module, as well as in Unix-based shells.

In PowerShell, piping is even more powerful because it passes **objects** rather than just text. These objects carry not only the data but also the properties and methods that describe and interact with the data.

For example, if you want to get a list of files in a directory and then sort them by size, you could use the following command in PowerShell:

```powershell
PS C:\Users\captain\Documents\captain-cabin> Get-ChildItem | Sort-Object Length


    Directory: C:\Users\captain\Documents\captain-cabin


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/4/2024  12:29 PM              0 captain-boots.txt
-a----          9/4/2024  12:14 PM            264 captain-hat.txt
-a----          9/4/2024  12:37 PM           2116 ship-flag.txt

```

Here, `Get-ChildItem` retrieves the files (as objects), and the pipe (`|`) sends those file objects to `Sort-Object`, which then sorts them by their `Length` (size) property. This object-based approach allows for more detailed and flexible command sequences.

In the example above, we have leveraged the `Sort-Object` cmdlet to sort objects based on specified properties. Beyond sorting, PowerShell provides a set of cmdlets that, when combined with piping, allow for advanced data manipulation and analysis.

To filter objects based on specified conditions, returning only those that meet the criteria, we can use the `Where-Object` cmdlet. For instance, to list only `.txt` files in a directory, we can use:

```powershell
PS C:\Users\captain\Documents\captain-cabin> Get-ChildItem | Where-Object -Property "Extension" -eq ".txt" 


    Directory: C:\Users\captain\Documents\captain-cabin


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/4/2024  12:29 PM              0 captain-boots.txt
-a----          9/4/2024  12:14 PM            264 captain-hat.txt
-a----          9/4/2024  12:37 PM           2116 ship-flag.txt   
```

Here, `Where-Object` filters the files by their `Extension` property, ensuring that only files with extension equal (`-eq`) to `.txt` are listed.

The operator `-eq` (i.e. "equal to") is part of a set of comparison operators that are shared with other scripting languages (e.g. Bash, Python). To show the potentiality of the PowerShell's filtering, we have selected some of the most useful operators from that list:

- `-ne`: "not equal". This operator can be used to exclude objects from the results based on specified criteria.
- `-gt`: "greater than". This operator will filter only objects which exceed a specified value. It is important to note that this is a strict comparison, meaning that objects that are equal to the specified value will be excluded from the results.
- `-ge`: "greater than or equal to". This is the non-strict version of the previous operator. A combination of `-gt` and `-eq`.
- `-lt`: "less than". Like its counterpart, "greater than", this is a strict operator. It will include only objects which are strictly below a certain value.
- `-le`: "less than or equal to". Just like its counterpart `-ge`, this is the non-strict version of the previous operator. A combination of `-lt` and `-eq`.

Below, another example shows that objects can also be filtered by selecting properties that match (`-like`) a specified pattern:

```powershell
PS C:\Users\captain\Documents\captain-cabin> Get-ChildItem | Where-Object -Property "Name" -like "ship*" 


    Directory: C:\Users\captain\Documents\captain-cabin


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/4/2024  12:37 PM           2116 ship-flag.txt   

```

The next filtering cmdlet, `Select-Object`, is used to select specific properties from objects or limit the number of objects returned. It’s useful for refining the output to show only the details one needs.

```powershell
PS C:\Users\captain\Documents\captain-cabin> Get-ChildItem | Select-Object Name, Length 

Name              Length
----              ------
captain-boots.txt      0
captain-hat.txt      264
ship-flag.txt       2116
```

The last in this set of filtering cmdlets is `Select-String`. This cmdlet searches for text patterns within files, similar to `grep` in Unix-based systems or `findstr` in Windows Command Prompt. It’s commonly used for finding specific content within log files or documents.

The Select-String cmdlet fully supports the use of regular expressions (regex). This advanced feature allows for complex pattern matching within files, making it a powerful tool for searching and analysing text data.

#### How would you retrieve the items in the current directory with size greater than 100? [for the sake of this question, avoid the use of quotes (" or ') in your answer]

Answer: Get-ChildItem | Where-Object -Property Length -gt 100

### Task 6 - System and Network Information

PowerShell was created to address a growing need for a powerful automation and management tool to help system administrators and IT professionals. As such, it offers a range of cmdlets that allow the retrieval of detailed information about system configuration and network settings.

The `Get-ComputerInfo` cmdlet retrieves comprehensive system information, including operating system information, hardware specifications, BIOS details, and more. It provides a snapshot of the entire system configuration in a single command. Its traditional counterpart `systeminfo` retrieves only a small set of the same details.

Essential for managing user accounts and understanding the machine’s security configuration, `Get-LocalUser` lists all the local user accounts on the system. The default output displays, for each user, username, account status, and description.

Similar to the traditional `ipconfig` command, the following two cmdlets can be used to retrieve detailed information about the system’s network configuration.

`Get-NetIPConfiguration` provides detailed information about the network interfaces on the system, including IP addresses, DNS servers, and gateway configurations.

In case we need specific details about the IP addresses assigned to the network interfaces, the `Get-NetIPAddress` cmdlet will show details for all IP addresses configured on the system, including those that are not currently active.

These cmdlets give IT professionals the ability to quickly access crucial system and network information directly from the command line, making it easier to monitor and manage both local and remote machines.

#### Other than your current user and the default "Administrator" account, what other user is enabled on the target machine?

```powershell
PS C:\Users\captain\Documents\captain-cabin> Get-LocalUser  

Name               Enabled Description                                                                                    
----               ------- -----------
Administrator      True    Built-in account for administering the computer/domain
captain            True    The beloved captain of this pirate ship.
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
p1r4t3             True    A merry life and a short one.
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scenarios.
```

Answer: p1r4t3

#### This lad has hidden his account among the others with no regard for our beloved captain! What is the motto he has so bluntly put as his account's description?

```powershell
PS C:\Users\captain\Documents\captain-cabin> Get-LocalUser -Name p1r4t3

Name   Enabled Description                  
----   ------- -----------
p1r4t3 True    A merry life and a short one.

```

Answer: A merry life and a short one.

#### Now a small challenge to put it all together. This shady lad that we just found hidden among the local users has his own home folder in the "C:\Users" directory. Can you navigate the filesystem and find the hidden treasure inside this pirate's home?

```powershell
PS C:\Users> Get-ChildItem


    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          9/5/2024   4:34 AM                Administrator
d-----          9/4/2024  12:34 PM                captain
d-----          9/4/2024  10:40 AM                p1r4t3
d-r---         4/23/2024  10:05 AM                Public


PS C:\Users> cd .\p1r4t3\
PS C:\Users\p1r4t3> Get-ChildItem -Recurse


    Directory: C:\Users\p1r4t3


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---         8/29/2024   3:53 PM                Desktop
d-r---         8/29/2024  11:33 AM                Documents
d-r---          5/8/2021   9:15 AM                Downloads
d-r---          5/8/2021   9:15 AM                Favorites
d-----         8/29/2024   1:15 PM                hidden-treasure-chest
d-r---          5/8/2021   9:15 AM                Links
d-r---          5/8/2021   9:15 AM                Music
d-r---          5/8/2021   9:15 AM                Pictures
d-----          5/8/2021   9:15 AM                Saved Games
d-r---          5/8/2021   9:15 AM                Videos


    Directory: C:\Users\p1r4t3\hidden-treasure-chest


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         8/29/2024   1:15 PM            322 big-treasure.txt


PS C:\Users\p1r4t3> Get-Content C:\Users\p1r4t3\hidden-treasure-chest\big-treasure.txt
            ___
        .-"; ! ;"-.
      .'!  : | :  !`.
     /\  ! : ! : !  /\
    /\ |  ! :|: !  | /\
   (  \ \ ; :!: ; / /  )
  ( `. \ | !:|:! | / .' )
  (`. \ \ \!:|:!/ / / .')
   \ `.`.\ |!|! |/,'.' /
    `._`.\\\!!!// .'_.'
       `.`.\\|//.'.'
        |`._`n'_.'|  hjw
        "----^----"

FLAG: THM{<REDACTED>}
PS C:\Users\p1r4t3>
```

Answer: `THM{<REDACTED>}`

### Task 7 - Real-Time System Analysis

To gather more advanced system information, especially concerning dynamic aspects like running processes, services, and active network connections, we can leverage a set of cmdlets that go beyond static machine details.

`Get-Process` provides a detailed view of all currently running processes, including CPU and memory usage, making it a powerful tool for monitoring and troubleshooting.

Similarly, `Get-Service` allows the retrieval of information about the status of services on the machine, such as which services are running, stopped, or paused. It is used extensively in troubleshooting by system administrators, but also by forensics analysts hunting for anomalous services installed on the system.

To monitor active network connections, `Get-NetTCPConnection` displays current TCP connections, giving insights into both local and remote endpoints. This cmdlet is particularly handy during an incident response or malware analysis task, as it can uncover hidden backdoors or established connections towards an attacker-controlled server.

Additionally, we are going to mention `Get-FileHash` as a useful cmdlet for generating file hashes, which is particularly valuable in incident response, threat hunting, and malware analysis, as it helps verify file integrity and detect potential tampering.

These cmdlets collectively provide a comprehensive set of tools for real-time system monitoring and analysis, proving especially useful to incident responders and threat hunters.

#### In the previous task, you found a marvellous treasure carefully hidden in the target machine. What is the hash of the file that contains it?

```powershell
PS C:\Users\p1r4t3> Get-FileHash C:\Users\p1r4t3\hidden-treasure-chest\big-treasure.txt

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          71FC5EC11C2497A32F8F08E61399687D90ABE6E204D2964DF589543A613F3E08       C:\Users\p1r4t3\hidden-treasure-chest\big-treasure.txt

```

Answer: 71FC5EC11C2497A32F8F08E61399687D90ABE6E204D2964DF589543A613F3E08

#### What property retrieved by default by Get-NetTCPConnection contains information about the process that has started the connection?

```powershell
PS C:\Users\p1r4t3> Get-NetTCPConnection

LocalAddress                        LocalPort RemoteAddress                       RemotePort State       AppliedSetting OwningProcess 
------------                        --------- -------------                       ---------- -----       -------------- -------------
::                                  49669     ::                                  0          Listen                     424
::                                  49668     ::                                  0          Listen                     660           
::                                  49666     ::                                  0          Listen                     380
::                                  49665     ::                                  0          Listen                     508
::                                  49664     ::                                  0          Listen                     684
::                                  47001     ::                                  0          Listen                     4
::                                  5985      ::                                  0          Listen                     4
::                                  3389      ::                                  0          Listen                     984           
::                                  445       ::                                  0          Listen                     4
::                                  135       ::                                  0          Listen                     900
::                                  22        ::                                  0          Listen                     1420
0.0.0.0                             49829     0.0.0.0                             0          Bound                      3672
10.10.159.242                       49829     23.217.74.14                        443        SynSent                    3672
0.0.0.0                             49669     0.0.0.0                             0          Listen                     424
0.0.0.0                             49668     0.0.0.0                             0          Listen                     660
0.0.0.0                             49666     0.0.0.0                             0          Listen                     380
0.0.0.0                             49665     0.0.0.0                             0          Listen                     508           
0.0.0.0                             49664     0.0.0.0                             0          Listen                     684
0.0.0.0                             3389      0.0.0.0                             0          Listen                     984
10.10.159.242                       139       0.0.0.0                             0          Listen                     4
0.0.0.0                             135       0.0.0.0                             0          Listen                     900           
10.10.159.242                       22        10.14.61.233                        45366      Established Internet       1420
0.0.0.0                             22        0.0.0.0                             0          Listen                     1420
```

Answer: OwningProcess

It's time for another small challenge. Some vital service has been installed on this pirate ship to guarantee that the captain can always navigate safely. But something isn't working as expected, and the captain wonders why. Investigating, they find out the truth, at last: the service has been tampered with! The shady lad from before has modified the service DisplayName to reflect his very own motto, the same that he put in his user description.

#### With this information and the PowerShell knowledge you have built so far, can you find the service name?

```powershell
PS C:\Users\p1r4t3> Get-Service | Where-Object Displayname -eq 'A merry life and a short one.'

Status   Name               DisplayName                           
------   ----               -----------
Running  p1r4t3-s-compass   A merry life and a short one.

```

Answer: p1r4t3-s-compass

### Task 8 - Scripting

Scripting is the process of writing and executing a series of commands contained in a text file, known as a script, to automate tasks that one would generally perform manually in a shell, like PowerShell.

Simply speaking, scripting is like giving a computer a to-do list, where each line in the script is a task that the computer will carry out automatically. This saves time, reduces the chance of errors, and allows to perform tasks that are too complex or tedious to do manually. As you learn more about shells and scripting, you’ll discover that scripts can be powerful tools for managing systems, processing data, and much more.

Before concluding this task about scripting, we can’t go without mentioning the `Invoke-Command` cmdlet.

`Invoke-Command` is essential for executing commands on remote systems, making it fundamental for system administrators, security engineers and penetration testers. `Invoke-Command` enables efficient remote management and—combining it with scripting—automation of tasks across multiple machines. It can also be used to execute payloads or commands on target systems during an engagement by penetration testers—or attackers alike.

#### What is the syntax to execute the command Get-Service on a remote computer named "RoyalFortune"? Assume you don't need to provide credentials to establish the connection. [for the sake of this question, avoid the use of quotes (" or ') in your answer]

Answer: Invoke-Command -ComputerName RoyalFortune -ScriptBlock { Get-Service }

For additional information, please see the references below.

## References

- [Approved Verbs for PowerShell Commands](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-5.1)
- [Copy-Item - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/copy-item?view=powershell-5.1)
- [Find-Module - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/powershellget/find-module?view=powershellget-1.x)
- [Get-Alias- Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-alias?view=powershell-5.1)
- [Get-ChildItem - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem?view=powershell-5.1)
- [Get-Command - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-command?view=powershell-5.1)
- [Get-ComputerInfo - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-computerinfo?view=powershell-5.1)
- [Get-Content - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-5.1)
- [Get-FileHash - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-5.1)
- [Get-Help - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-help?view=powershell-5.1)
- [Get-LocalUser - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser?view=powershell-5.1)
- [Get-NetIPAddress - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress?view=windowsserver2019-ps)
- [Get-NetIPConfiguration - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipconfiguration?view=windowsserver2019-ps)
- [Get-NetTCPConnection - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=windowsserver2019-ps)
- [Get-Process - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-5.1)
- [Get-Service - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-5.1)
- [Invoke-Command - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-5.1)
- [Move-Item - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/move-item?view=powershell-5.1)
- [New-Item- Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-item?view=powershell-5.1)
- [PowerShell - Wikipedia](https://en.wikipedia.org/wiki/PowerShell)
- [Remove-Item - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item?view=powershell-5.1)
- [Select-Object - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Utility/Select-Object?view=powershell-5.1)
- [Select-String - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string?view=powershell-5.1)
- [Set-Location - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-location?view=powershell-5.1)
- [Sort-Object - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/sort-object?view=powershell-5.1)
- [Where-Object - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object?view=powershell-5.1)
