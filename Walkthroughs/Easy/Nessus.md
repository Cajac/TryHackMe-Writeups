# Nessus

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: -
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
Learn how to set up and use Nessus, a popular vulnerability scanner.
```

Room link: [https://tryhackme.com/room/rpnessusredux](https://tryhackme.com/room/rpnessusredux)

## Solution

### Task 1: Introduction

![Nessus Logo](Images/Nessus_Logo.png)

Nessus vulnerability scanner is exactly what you think is its! A vulnerability scanner!

It uses techniques similar to Nmap to find and report vulnerabilities, which are then, presented in a nice GUI for us to look at.
Nessus is different from other scanners as it doesn't make assumptions when scanning,
like assuming the web application is running on port 80 for instance.

Nessus offers a free and paid service, in which some features are left out from the free to make you more inclined to buy the paid service.
Their pricing is similar to Burp Suite, so unless you got some spare change, we will be just be using their free version.

You can check out their pricing options here: [https://www.tenable.com/products/nessus](https://www.tenable.com/products/nessus)

---------------------------------------------------------------------------

### Task 2: Installation

![Nessus Essentials Logo](Images/Nessus_Essentials_Logo.png)

We will be installing Nessus on a Local Kali VM.

**Warning**: Do not install Nessus on the **THM AttackBox**. It will **not** work, as there's no sufficient space!

Other OS's will not be covered in this walkthrough, in which case the official installation guide can be found below.

[https://docs.tenable.com/nessus/Content/GettingStarted.htm](https://docs.tenable.com/nessus/Content/GettingStarted.htm)

#### Step 1 - Registration

![Nessus Essentials Registration](Images/Nessus_Essentials_Registration.png)

Goto [https://www.tenable.com/products/nessus/nessus-essentials](https://www.tenable.com/products/nessus/nessus-essentials) and register an account.

You will need to do this for an **activation code**.

#### Step 2 - Downloading

![Nessus Essentials Download](Images/Nessus_Essentials_Download.png)

We will then download the Nessus-#.##.#-debian6_**amd64**.deb file

Save it to your **/Downloads/** folder

#### Step 3 - Installation

In the terminal we will navigate to that folder and run the following command:

`sudo dpkg -i package_file.deb`

Remember to replace **package_file.deb** with the file name you downloaded.

![Nessus Essentials Installation](Images/Nessus_Essentials_Installation.png)

#### Step 4 - Start service

We will now start the Nessus Service with the command:

`sudo /bin/systemctl start nessusd.service`

![Nessus Essentials Start Service](Images/Nessus_Essentials_Start_Service.png)

#### Step 5 - Connect

Open up Firefox and goto the following URL:

[https://localhost:8834/](https://localhost:8834/)

You may be prompted with a security risk alert.

Click `Advanced...` -> `Accept the Risk and Continue`

![Nessus Essentials Cert Warning](Images/Nessus_Essentials_Cert_Warning.png)

#### Step 6 - Choose Type

Next, we will set up the scanner.

Select the option Nessus Essentials

![Nessus Essentials Choose Type](Images/Nessus_Essentials_Choose_Type.png)

Clicking the Skip button will bring us to a page, which we will input that code we got in the email from Nessus.

![Nessus Essentials Activate](Images/Nessus_Essentials_Activate.png)

#### Step 7 - Create Account

Fill out the **Username** and **Password** fields. Make sure to use a strong password!

![Nessus Essentials Account](Images/Nessus_Essentials_Account.png)

#### Step 8 - Plugin Installation

Nessus will now install the plugins required for it to function.

![Nessus Essentials Plugins](Images/Nessus_Essentials_Plugins.png)

This will take some time, which will depend on your internet connection and the hardware attached to your VM.

If the progress bar appears to be not moving, it means you do not have **enough space** on the VM to install.  

#### Step 9 - Login

Log in with the account credentials you made earlier.

![Nessus Essentials Login](Images/Nessus_Essentials_Login.png)

#### Step 10 - Start using Nessus

You have now successfully installed Nessus!

![Nessus Essentials Ready](Images/Nessus_Essentials_Ready.png)

---------------------------------------------------------------------------

### Task 3: Navigation and Scans

![Nessus Essentials Scan Types](Images/Nessus_Essentials_Scan_Types.png)

---------------------------------------------------------------------------

#### What is the name of the button which is used to launch a scan?

Hint: Top right blue button

Answer: `New Scan`

#### What side menu option allows us to create custom templates?

Hint: One of the options under "Resources"

Answer: `Policies`

#### What menu allows us to change plugin properties such as hiding them or changing their severity?

Hint: One of the options under "Resources"

Answer: `Plugin Rules`

#### In the 'Scan Templates' section after clicking on 'New Scan', what scan allows us to see simply what hosts are alive?

Answer: `Host Discovery`

#### One of the most useful scan types, which is considered to be 'suitable for any host'?

Answer: `Basic Network Scan`

#### What scan allows you to 'Authenticate to hosts and enumerate missing updates'?

Answer: `Credentialed Patch Audit`

#### What scan is specifically used for scanning Web Applications?

Answer: `Web Application Tests`

---------------------------------------------------------------------------

### Task 4: Scanning

![Nessus Essentials Scan Types](Images/Nessus_Essentials_Scan_Types.png)

---------------------------------------------------------------------------

![Nessus Essentials Basic Scan](Images/Nessus_Essentials_Basic_Scan.png)

#### Create a new 'Basic Network Scan' targeting the deployed VM. What option can we set under 'BASIC' (on the left) to set a time for this scan to run?

This can be very useful when network congestion is an issue.

Answer: `Schedule`

#### Under 'DISCOVERY' (on the left) set the 'Scan Type' to cover ports 1-65535. What is this type called?

Answer: `Port scan (all ports)`

#### What 'Scan Type' can we change to under 'ADVANCED' for lower bandwidth connection?

Answer: `Scan low bandwidth links`

With these options set, launch the scan.

![Nessus Essentials Launch Scan](Images/Nessus_Essentials_Launch_Scan.png)

#### After the scan completes, which 'Vulnerability' in the 'Port scanners' family can we view the details of to see the open ports on this host?

Answer: `Nessus SYN scanner`

#### What Apache HTTP Server Version is reported by Nessus?

Hint: Wait for the scan to complete. This will take 1-5 minutes.

Answer: `2.4.41`

---------------------------------------------------------------------------

### Task 5: Scanning a Web Application

Run a Web Application scan on the VM!

![Nessus Essentials Web Scan](Images/Nessus_Essentials_Web_Scan.png)

Running this Scan will take some time to complete, please be patient

---------------------------------------------------------------------------

#### What is the plugin id of the plugin that determines the HTTP server type and version?

Hint: Found on the right after clicking 'HTTP Server Type and Version'

Answer: `10107`

#### What authentication page is discovered by the scanner that transmits credentials in cleartext?

Hint: It has the Severity of Low

Answer: `login.php`

#### What is the file extension of the config backup?

Hint: It has the Severity of Medium

Answer: `.bak`

#### Which directory contains example documents? (This will be in a php directory)

Hint: In the Browsable Web Directories tab

Answer: `/external/phpids/0.6/docs/examples/`

#### What vulnerability is this application susceptible to that is associated with X-Frame-Options?

Hint: It has the Severity of Medium

Answer: `Clickjacking`

---------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [Nessus - Docs](https://docs.tenable.com/nessus/Content/GettingStarted.htm)
- [Nessus - Homepage](https://www.tenable.com/products/nessus)
- [Nessus Essentials - Homepage](https://www.tenable.com/products/nessus/nessus-essentials)
- [Nessus (software) - Wikipedia](https://en.wikipedia.org/wiki/Nessus_(software))
- [Vulnerability scanner - Wikipedia](https://en.wikipedia.org/wiki/Vulnerability_scanner)
