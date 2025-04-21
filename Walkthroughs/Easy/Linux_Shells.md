# Linux Shells

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: Linux
Subscription type: Premium
Description: Learn about scripting and the different types of Linux shells.
```

Room link: [https://tryhackme.com/room/linuxshells](https://tryhackme.com/room/linuxshells)

## Solution

### Task 1 - Introduction to Linux Shells

As regular users of operating systems, we all extensively use the Graphical User Interface (GUI) to carry out most operations. It takes a few clicks on different options, and your task is done. However, you can perform almost every task by writing commands in the CLI of your operating system rather than using the GUI. The shells give you some great features for the commands you write in your CLI. This way of interacting with the OS is more efficient and resource-friendly.

You may have seen hacking scenes in movies that show cool terminals with many commands getting executed. This is because most Linux users prefer to perform operations by writing commands on the CLI using shells instead of using the GUI. This room will teach us how to interact with a Linux shell. We will also explore different shells available in Linux and write some shell scripts in the end.

#### Learning Objectives

- Learn interaction with Linux shell
- Use basic shell commands
- Explore the types of Linux shells available
- Write some shell scripts

#### Who is the facilitator between the user and the OS?

Answer: Shell

### Task 2 - How To Interact With a Shell?

#### Connecting

We start by connecting to the machine with `ssh`. Alternatively, use the AttackBox.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Linux_Shells]
└─$ ssh user@10.10.48.155         
The authenticity of host '10.10.48.155 (10.10.48.155)' can't be established.
ED25519 key fingerprint is SHA256:zhc06GVc9aGeMl+Q6NcZ7yzVQgswtOkaeeoi3rEEtsA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.48.155' (ED25519) to the list of known hosts.
user@10.10.48.155's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-1068-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Mon Apr 21 06:01:38 UTC 2025

  System load:  0.08               Processes:             189
  Usage of /:   12.6% of 58.09GB   Users logged in:       1
  Memory usage: 44%                IPv4 address for ens5: 10.10.48.155
  Swap usage:   0%

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

Expanded Security Maintenance for Applications is not enabled.

91 updates can be applied immediately.
60 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

21 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Apr 21 05:56:32 2025 from 10.100.1.74
user@tryhackme:~$ 
```

Most Linux distributions use `Bash` (Bourne Again Shell) as their default shell. However, the default shell displayed when you open the terminal depends on your Linux distribution.

Note: In the upcoming task, we will discuss different types of shells.

You would have already explored the basic Linux commands in the Linux Fundamentals module mentioned in this room’s prerequisites. Let’s briefly discuss some of the most important ones we use in the shell.

When interacting with a shell, you must be in the directory where you want to perform operations. By default, when you open a shell in most of the Linux distributions, you will be in your home directory. To see your current working directory, you can execute `pwd`, which stands for Print Working Directory.

However, you can change your directory as well. To do that, you can use `cd` (short for Change Directory).

The `grep` command is a very popular command among Linux users. This powerful command can search for any word or pattern inside a file. Suppose you want to search for specific entries in a huge file. You can use the grep command along with the pattern of those entries, which will extract them for you. It also helps you to search for a specific keyword in a big file.

#### What is the default shell in most Linux distributions?

Answer: Bash

#### Which command utility is used to list down the contents of a directory?

Answer: ls

#### Which command utility can help you search for anything in a file?

Answer: grep

### Task 3 - Types of Linux Shells

Like the Command Prompt and PowerShell in Windows OS, Linux has different types of shells available, each with its own features and characteristics.

Multiple shells are installed in different Linux distributions. To see which shell you are using, type the following command:

```bash
user@tryhackme:~$ echo $SHELL
/bin/bash
```

You can also list down the available shells in your Linux OS. The file `/etc/shells` contains all the installed shells on a Linux system.

```bash
user@tryhackme:~$ cat /etc/shells
# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/bin/dash
/usr/bin/dash
/usr/bin/tmux
/usr/bin/screen
/bin/zsh
/usr/bin/zsh
```

To switch between these shells, you can type the shell name that is present on your OS, and it will open for you, as can be seen below:

```bash
user@ubuntu:~$ zsh
user@ubuntu ~ $
```

If you want to permanently change your default shell, you can use the command: `chsh -s /usr/bin/zsh`. This will make this shell as the default shell for your terminal.

There are many types of Linux shells. We will discuss a few of them and their features.

#### Bourne Again Shell

Bourne Again Shell (`Bash`) is the default shell for most Linux distributions. When you open the terminal, `bash` is present for you to enter commands. Before bash, some shells like `sh`, `ksh`, and `csh` had different capabilities. `Bash` came as an enhanced replacement for these shells, borrowing capabilities from all of them. This means that it has many of the features of these old shells and some of its unique abilities. Some of the key features provided by bash are listed below:

- `Bash` is a widely used shell with scripting capabilities.
- It offers a tab completion feature, which means if you are in the middle of completing a command, you can press the tab key on your keyboard. It will automatically complete the command based on a possible match or give you multiple suggestions for completing it.
- `Bash` keeps a history file and logs all of your commands. You can use the up and down arrow keys to use the previous commands without typing them again. You can also type `history` to display all your previous commands.

#### Friendly Interactive Shell

Friendly Interactive Shell (`Fish`) is also not default in most Linux distributions. As its name suggests, it focuses more on user-friendliness than other shells. Some of the key features provided by `fish` are listed below:

- It offers a very simple syntax, which is feasible for beginner users.
- Unlike `bash`, it has auto spell correction for the commands you write.
- You can customize the command prompt with some cool themes using `fish`.
- The syntax highlighting feature of `fish` colors different parts of a command based on their roles, which can improve the readability of commands. It also helps us to spot errors with their unique colors.
- `Fish` also provides scripting, tab completion, and command history functionality like the shells mentioned in this task.

#### Z Shell

Z Shell (`Zsh`) is not installed by default in most Linux distributions. It is considered a modern shell that combines the functionalities of some previous shells. Some of the key features provided by `zsh` are listed below:

- `Zsh` provides advanced tab completion and is also capable of writing scripts.
- Just like `fish`, it also provides auto spell correction for the commands.
- It offers extensive customization that may make it slower than other shells.
- It also provides tab completion, command history functionality, and several other features.

| Feature | Bash | Fish | Zsh |
|----|----|----|----|
|Full Name|The full form of Bash is Bourne Again Shell.|The full form of Fish is Friendly Interactive Shell.|The full form of Zsh is Z Shell.|
|Scripting|It offers widely compatible scripting with extensive documentation available.|It has limited scripting features as compared to the other two shells.|It offers an excellent level of scripting, combining the traditional capabilities of Bash shell with some extra features.|
|Tab completion|It has a basic tab completion feature.|It offers advanced tab completion by giving suggestions based on your previous commands.|Its tab completion capability can be extended heavily by using plugins.|
|Customization|Basic level of customization.|It offers some good customization through interactive tools.|Advanced customization through oh-my-zsh framework.|
|User friendliness|It is less user-friendly, but being a traditional and widely used shell, its users are quite familiar and comfortable with it.|It is the most user-friendly shell.|It can be highly user-friendly with proper customization.|
|Syntax highlighting|The syntax highlighting feature is not available in this shell.|The syntax highlighting is built-in to this shell.|The syntax highlighting can be used with this shell by introducing some plugins.|

Selecting the best Linux shell depends on your usage and its features. The shells discussed in this task are some of the many different shells available in Linux. You can compare the features of these different shells and choose the best one based on your tasks.

#### Which shell comes with syntax highlighting as an out-of-the-box feature?

Answer: Fish

#### Which shell does not have auto spell correction?

Answer: Bash

#### Which command displays all the previously executed commands of the current session?

Answer: history

### Task 4 - Shell Scripting and Components

A shell script is nothing but a set of commands. Suppose a repetitive task requires you to enter multiple commands using a shell. Instead of entering them one after one on every repetition of that task, which may take more of your time, you can combine them into a script. To execute all those commands, you will only execute the script, and all the commands will be executed. All the shells mentioned in the previous tasks have scripting capabilities. Scripting helps us to automate tasks. Before learning how to write a script, we need to know that even though Linux shells have scripting capabilities, this does not mean that you can only make a script using a shell. Scripting can be done in various programming languages as well. However, the scope of this room is to cover scripting using a shell.

Unlike the other commands we type in the shell, we first need to create a file using any text editor for the script. The file must be named with an extension .sh, the default extension for bash scripts. The following terminal shows the script file creation:

```bash
user@ubuntu:~$ nano first_script.sh
```

Every script should start from shebang. Shebang is a combination of some characters that are added at the beginning of a script, starting with #! followed by the name of the interpreter to use while executing the script. As we are writing our script in bash, let’s define it as the interpreter in the shebang.

```bash
#!/bin/bash
```

We are all set to write our first script now. There are some fundamental building blocks of a script that together make an efficient script. Let’s learn and utilize these script constructs to write one script ourselves.

#### Variables

A variable stores a value inside it. Suppose you need to use some complex values, like a URL, a file path, etc., several times in your script. Instead of memorizing and writing them repeatedly, you can store them in a variable and use the variable name wherever you need it.

The script below displays a string on the screen: "Hey, what’s your name?” This is done by `echo` command. The second line of the script contains the code `read name`. `read` is used to take input from the user, and `name` is the variable in which the input would be stored. The last line uses `echo` to display the welcome line for the user, along with its name stored in the variable.

```bash
# Defining the Interpreter 
#!/bin/bash
echo "Hey, what’s your name?"
read name
echo "Welcome, $name"
```

To execute the script, we first need to make sure that the script has execution permissions. To give these permissions to the script, we can type the following command in our terminal:

```bash
user@ubuntu:~$ chmod +x variable_script.sh
```

Now that the script has execution permissions use `./` before the script name to execute it. We use `./` before the script to run rather than typing the script name directly because `./` tells the shell to execute the file that is present in the current directory. If you don't define `./` before the script name, the shell will search the script in the `PATH` environment variable (that contains all the directories except the current one), and it will not find the defined script in any of those directories and generate an error. The below terminal shows the script in which we utilized the variables:

```bash
user@ubuntu:~$ ./variable_script.sh
Hey, What's your name?
John
Welcome, John
```

#### Loops

Loop, as the name suggests, is something that is repeating. For example, you have a list of many friends, and you want to send them the same message. Instead of sending them individually, you can make a loop in your script, give your friend list to the loop and the message, and it will send that message to all your friends.

For a general explanation of loops, let’s write a loop that will display all numbers starting from 1 to 10 on the screen:

```bash
# Defining the Interpreter 
#!/bin/bash
for i in {1..10};
do
echo $i
done
```

The first line has the variable i that will iterate from 1 to 10 and execute the below code every time. `do` indicates the start of the loop code, and `done` indicates the end. In between them, the code we want to execute in the loop is to be written. The for loop will take each number in the brackets and assign it to the variable `i` in each iteration. The `echo $i` will display this variable’s value every iteration.

#### Conditional Statements

Conditional statements are an essential part of scripting. They help you execute a specific code only when a condition is satisfied; otherwise, you can execute another code. Suppose you want to make a script that shows the user a secret. However, you want it to be shown to only some users, only to the high-authority user. You will create a conditional statement that will first ask the user their name, and if that name matches the high authority user’s name, it will display the secret.

```bash
# Defining the Interpreter 
#!/bin/bash
echo "Please enter your name first:"
read name
if [ "$name" = "Stewart" ]; then
        echo "Welcome Stewart! Here is the secret: THM_Script"
else
        echo "Sorry! You are not authorized to access the secret."
fi
```

The above script takes the user’s name as input and stores it into a variable (studied in the Variables section). The conditional statement starts with `if` and compares the value of that variable with the string `Stewart`; if it’s a match, it will display the secret to the user, or else it will not. The `fi` is used to end the for loop.

#### Comments

Sometimes, the code can be very lengthy. In this scenario, the code might confuse you when you look at it after some time or share it with somebody. An easy way to resolve this problem is to use comments in different parts of the code. A comment is a sentence that we write in our code just for the sake of our understanding. It is written with a `#` sign followed by a space and the sentence you need to write. For example, let’s rewrite the script we discussed in the conditional statements section and add comments to it.

```bash
# Defining the Interpreter
#!/bin/bash

# Asking the user to enter a value.
echo "Please enter your name first:"

# Storing the user input value in a variable.
read name

# Checking if the name the user entered is equal to our required name.
if [ "$name" = "Stewart" ]; then

# If it equals the required name, the following line will be displayed.
echo "Welcome Stewart! Here is the secret: THM_Script"

# Defining the sentence to be displayed if the condition fails.
else
        echo "Sorry! You are not authorized to access the secret."
fi
```

See how easy a script looks with comments. Comments don’t affect the working of any script. A good script always has some comments. The example shown above contains a comment for each line. This is just a better explanation of its concept. However, the best way to include comments is to define them in the major and complex areas of the script.

Note: Other types of variables, loops, and conditional statements can also be used to achieve different tasks. Moreover, multiple lines of comments can also be added within a single comment. However, it is not the scope of this room.

#### What is the shebang used in a Bash script?

Answer: #!/bin/bash

#### Which command gives executable permissions to a script?

Answer: chmod +x

#### Which scripting functionality helps us configure iterative tasks?

Answer: loops

### Task 5 - The Locker Script

In the previous task, we studied variables, loops, and conditional statements in shell scripting. Let’s use that knowledge to create a shell script that utilizes all these components.

#### Requirement

A user has a locker in a bank. To secure the locker, we have to have a script in place that verifies the user before opening it. When executed, the script should ask the user for their name, company name, and PIN. If the user enters the following details, they should be allowed to enter, or else they should be denied access.

- Username: John
- Company name: Tryhackme
- PIN: 7385

#### Script

```bash
# Defining the Interpreter 
#!/bin/bash 

# Defining the variables
username=""
companyname=""
pin=""

# Defining the loop
for i in {1..3}; do
# Defining the conditional statements
        if [ "$i" -eq 1 ]; then
                echo "Enter your Username:"
                read username
        elif [ "$i" -eq 2 ]; then
                echo "Enter your Company name:"
                read companyname
        else
                echo "Enter your PIN:"
                read pin
        fi
done

# Checking if the user entered the correct details
if [ "$username" = "John" ] && [ "$companyname" = "Tryhackme" ] && [ "$pin" = "7385" ]; then
        echo "Authentication Successful. You can now access your locker, John."
else
        echo "Authentication Denied!!"
fi
```

#### Script Execution

```bash
Executing the Locker Script
user@ubuntu:~$ ./locker_script.sh
Enter your Username:
John
Enter your Company name:
Tryhackme
Enter your PIN:
1349
Authentication Denied!!
```

#### What would be the correct PIN to authenticate in the locker script?

Answer: 7385

### Task 6 -  Practical Exercise

We have placed a script on the default user directory `/home/user` of the attached Ubuntu machine. This script searches for a specific keyword in all the files (with .log extension) in a specific directory.

Note: Some changes are required inside the script file before you execute it. When you open the machine according to the instructions in task #2, you will be able to gain the session as a normal user. However, we recommend you to become the `root` user in order to search for the flag in all the files of the given directory.

```bash
user@tryhackme:~$ sudo su
[sudo] password for user: 
root@tryhackme:/home/user# 
```

You can make the changes in the script file by keeping in view the following details:

- Flag: thm-flag01-script
- Directory: /var/log

Hint: Look for empty double quotes " " inside the script file and fill them. Make sure not to leave any space between them.

Fixed script:

```bash
#!/bin/bash

# Defining the directory to search our flag
directory="/var/log"

# Defining the flag to search
flag="thm-flag01-script"

echo "Flag search in directory: $directory in progress..."

# Defining for loop to iterate over all the files with .log extension in the defined directory
for file in $directory/*.log; do
    # Check if the file contains the flag
    if grep -q "$flag" "$file"; then
        # Print the filename
        echo "Flag found in: $(basename "$file")"
    fi
done
```

#### Which file has the keyword?

Hint: There are 3 changes to be made in the script file in order to execute it properly.

```bash
root@tryhackme:/home/user# ./flag_hunt.sh 
Flag search in directory: /var/log in progress...
Flag found in: authentication.log
```

Answer: authentication.log

#### Where is the cat sleeping?

Hint: Open the file that contains the flag.

```bash
root@tryhackme:/home/user# cat /var/log/authentication.log 
the cat is sleeping under the table
thm-flag01-script
```

Answer: under the table

For additional information, please see the references below.

## References

- [Bash (Unix shell) - Wikipedia](https://en.wikipedia.org/wiki/Bash_(Unix_shell))
- [cat - Linux manual page](https://man7.org/linux/man-pages/man1/cat.1.html)
- [cd - Linux manual page](https://man7.org/linux/man-pages/man1/cd.1p.html)
- [chsh - Linux manual page](https://www.man7.org/linux/man-pages/man1/chsh.1.html)
- [Command-line completion - Wikipedia](https://en.wikipedia.org/wiki/Command-line_completion)
- [echo - Linux manual page](https://man7.org/linux/man-pages/man1/echo.1.html)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [Fish (Unix shell) - Wikipedia](https://en.wikipedia.org/wiki/Fish_(Unix_shell))
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [history - Linux manual page](https://www.man7.org/linux/man-pages/man3/history.3.html)
- [Linux - Wikipedia](https://en.wikipedia.org/wiki/Linux)
- [ls - Linux manual page](https://man7.org/linux/man-pages/man1/ls.1.html)
- [pwd - Linux manual page](https://man7.org/linux/man-pages/man1/pwd.1.html)
- [read(1) - Linux manual page](https://www.man7.org/linux/man-pages/man1/read.1p.html)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [Shebang (Unix) - Wikipedia](https://en.wikipedia.org/wiki/Shebang_(Unix))
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [wc - Linux manual page](https://man7.org/linux/man-pages/man1/wc.1.html)
- [whoami - Linux manual page](https://man7.org/linux/man-pages/man1/whoami.1.html)
- [Z shell - Wikipedia](https://en.wikipedia.org/wiki/Z_shell)
