# HTTP in Detail

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Learn about how you request content from a web server using the HTTP protocol
```

Room link: [https://tryhackme.com/room/httpindetail](https://tryhackme.com/room/httpindetail)

## Solution

### Task 1: What is HTTP(S)?

#### What is HTTP? (HyperText Transfer Protocol)

HTTP is what's used whenever you view a website, developed by Tim Berners-Lee and his team between 1989-1991.  
HTTP is the set of rules used for communicating with web servers for the transmitting of webpage data, whether  
that is HTML, Images, Videos, etc.

#### What is HTTPS? (HyperText Transfer Protocol Secure)

HTTPS is the secure version of HTTP. HTTPS data is encrypted so it not only stops people from seeing the data  
you are receiving and sending, but it also gives you assurances that you're talking to the correct web server  
and not something impersonating it.

#### What does HTTP stand for?

Answer: HyperText Transfer Protocol

#### What does the S in HTTPS stand for?

Answer: Secure

#### On the mock webpage on the right there is an issue, once you've found it, click on it. What is the challenge flag?

Answer: `THM{<REDACTED>}`

### Task 2: Requests And Responses

#### What is a URL? (Uniform Resource Locator)

If you’ve used the internet, you’ve used a URL before. A URL is predominantly an instruction on how to access a  
resource on the internet.

The below image shows what a URL looks like with all of its features (it does not use all features in every request).

![URL Example](Images/URL_Example.png)

**Scheme**: This instructs on what protocol to use for accessing the resource such as HTTP, HTTPS, FTP (File  
Transfer Protocol).

**User**: Some services require authentication to log in, you can put a username and password into the URL to log in.

**Host**: The domain name or IP address of the server you wish to access.

**Port**: The Port that you are going to connect to, usually 80 for HTTP and 443 for HTTPS, but this can be hosted on  
any port between 1 - 65535.

**Path**: The file name or location of the resource you are trying to access.

**Query String**: Extra bits of information that can be sent to the requested path. For example, /blog? id=1 would tell  
the blog path that you wish to receive the blog article with the id of 1.

**Fragment**: This is a reference to a location on the actual page requested. This is commonly used for pages with long  
content and can have a certain part of the page directly linked to it, so it is viewable to the user as soon as they  
access the page.

#### Making a Request

It's possible to make a request to a web server with just one line `GET / HTTP/1.1`.

But for a much richer web experience, you’ll need to send other data as well. This other data is sent in what is  
called headers, where headers contain extra information to give to the web server you’re communicating with, but  
we’ll go more into this in the Header task.

```text
GET / HTTP/1.1
Host: tryhackme.com
User-Agent: Mozilla/5.0 Firefox/87.0
Referer: https://tryhackme.com/
```

Example response:

```text
HTTP/1.1 200 OK
Server: nginx/1.15.8
Date: Fri, 09 Apr 2021 13:34:03 GMT
Content-Type: text/html
Content-Length: 98

<html>
<head>
    <title>TryHackMe</title>
</head>
<body>
    Welcome To TryHackMe.com
</body>
</html>
```

#### What HTTP protocol is being used in the above example?

Answer: HTTP/1.1

#### What response header tells the browser how much data to expect?

Answer: Content-Length

### Task 3: HTTP Methods

HTTP methods are a way for the client to show their intended action when making an HTTP request.  
There are a lot of HTTP methods but we'll cover the most common ones, although mostly you'll  
deal with the GET and POST method.

#### GET Request

This is used for getting information from a web server.

#### POST Request

This is used for submitting data to the web server and potentially creating new records

#### PUT Request

This is used for submitting data to a web server to update information

#### DELETE Request

This is used for deleting information/records from a web server.

#### What method would be used to create a new user account?

Answer: POST

#### What method would be used to update your email address?

Answer: PUT

#### What method would be used to remove a picture you've uploaded to your account?

Answer: DELETE

#### What method would be used to view a news article?

Answer: GET

### Task 4: HTTP Status Codes

#### HTTP Status Codes

In the previous task, you learnt that when a HTTP server responds, the first line always contains a status code  
informing the client of the outcome of their request and also potentially how to handle it. These status codes  
can be broken down into 5 different ranges:

**100-199 - Information Response**:  
These are sent to tell the client the first part of their request has been accepted and they should continue  
sending the rest of their request. These codes are no longer very common.

**200-299 - Success**:  
This range of status codes is used to tell the client their request was successful.

**300-399 - Redirection**:  
These are used to redirect the client's request to another resource. This can be either to a different webpage  
or a different website altogether.

**400-499 - Client Errors**:  
Used to inform the client that there was an error with their request.

**500-599 - Server Errors**:  
This is reserved for errors happening on the server-side and usually indicate quite a major problem with the  
server handling the request.

#### Common HTTP Status Codes

| Status code | Description |
|----|----|
|200 - OK|The request was completed successfully.|
|201 - Created|A resource has been created (for example a new user or new blog post).|
|301 - Moved Permanently|This redirects the client's browser to a new webpage or tells search engines that the page has moved somewhere else.|
|302 - Found|Similar to the above permanent redirect, but as the name suggests, this is only a temporary change.|
|400 - Bad Request|This tells the browser that something was either wrong or missing in their request.|
|401 - Not Authorised|You are not currently allowed to view this resource until you have authorised with the web application.|
|403 - Forbidden|You do not have permission to view this resource whether you are logged in or not.|
|405 - Method Not Allowed|The resource does not allow this method request.|
|404 - Page Not Found|The page/resource you requested does not exist.|
|500 - Internal Service Error|The server has encountered some kind of error with your request that it doesn't know how to handle properly.|
|503 - Service Unavailable|This server cannot handle your request as it's either overloaded or down for maintenance.|

#### What response code might you receive if you've created a new user or blog post article?

Answer: 201

#### What response code might you receive if you've tried to access a page that doesn't exist?

Answer: 404

#### What response code might you receive if the web server cannot access its database and the application crashes?

Answer: 503

#### What response code might you receive if you try to edit your profile without logging in first?

Answer: 401

### Task 5: Headers

Headers are additional bits of data you can send to the web server when making requests.

Although no headers are strictly required when making a HTTP request, you’ll find it difficult to view a website properly.

#### Common Request Headers

These are headers that are sent from the client (usually your browser) to the server.

**Host**: Some web servers host multiple websites so by providing the host headers you can tell it which one you require,  
otherwise you'll just receive the default website for the server.

**User-Agent**: This is your browser software and version number, telling the web server your browser software helps it  
format the website properly for your browser and also some elements of HTML, JavaScript and CSS are only available in  
certain browsers.

**Content-Length**: When sending data to a web server such as in a form, the content length tells the web server how much  
data to expect in the web request. This way the server can ensure it isn't missing any data.

**Accept-Encoding**: Tells the web server what types of compression methods the browser supports so the data can be made  
smaller for transmitting over the internet.

**Cookie**: Data sent to the server to help remember your information (see cookies task for more information).

#### Common Response Headers

These are the headers that are returned to the client from the server after a request.

**Set-Cookie**: Information to store which gets sent back to the web server on each request (see cookies task for more  
information).

**Cache-Control**: How long to store the content of the response in the browser's cache before it requests it again.

**Content-Type**: This tells the client what type of data is being returned, i.e., HTML, CSS, JavaScript, Images, PDF,  
Video, etc. Using the content-type header the browser then knows how to process the data.

**Content-Encoding**: What method has been used to compress the data to make it smaller when sending it over the internet.

#### What header tells the web server what browser is being used?

Answer: User-Agent

#### What header tells the browser what type of data is being returned?

Answer: Content-Type

#### What header tells the web server which website is being requested?

Answer: Host

### Task 6: Cookies

You've probably heard of cookies before, they're just a small piece of data that is stored on your computer. Cookies are  
saved when you receive a "Set-Cookie" header from a web server. Then every further request you make, you'll send the cookie  
data back to the web server. Because HTTP is stateless (doesn't keep track of your previous requests), cookies can be used  
to remind the web server who you are, some personal settings for the website or whether you've been to the website before.

Cookies can be used for many purposes but are most commonly used for website authentication.

#### Which header is used to save cookies to your computer?

Answer: Set-Cookie

### Task 7: Making Requests

#### Make a GET request to /room

Hint: The answer is the text starting with the letters THM{...

Request:

```text
GET /room HTTP/1.1
Host: tryhackme.com
User-Agent: Mozilla/5.0 Firefox/87.0
Content-Length: 0
```

Rewsponse:

```text
HTTP/1.1 200 Ok
Server: nginx/1.15.8
Fri, 18 Apr 2025 17:26:25 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 252
Last-Modified: Fri, 18 Apr 2025 17:26:25 GMT

<html>
<head>
    <title>TryHackMe</title>
</head>
<body>
    Welcome to the Room page THM{<REDACTED>}
</body>
</html>
```

Answer: `THM{<REDACTED>}`

#### Make a GET request to /blog and using the gear icon set the id parameter to 1 in the URL field

Request:

```text
GET /blog HTTP/1.1
Host: tryhackme.com
User-Agent: Mozilla/5.0 Firefox/87.0
Content-Length: 0
```

Rewsponse:

```text
HTTP/1.1 200 Ok
Server: nginx/1.15.8
Fri, 18 Apr 2025 17:29:5 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 250
Last-Modified: Fri, 18 Apr 2025 17:29:5 GMT

<html>
<head>
    <title>TryHackMe</title>
</head>
<body>
    Viewing Blog article 1 THM{<REDACTED>}
</body>
</html>
```

Answer: `THM{<REDACTED>}`

#### Make a DELETE request to /user/1

Request:

```text
DELETE /user/1 HTTP/1.1
Host: tryhackme.com
User-Agent: Mozilla/5.0 Firefox/87.0
Content-Length: 0
```

Response:

```text
HTTP/1.1 200 Ok
Server: nginx/1.15.8
Fri, 18 Apr 2025 17:30:57 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 250
Last-Modified: Fri, 18 Apr 2025 17:30:57 GMT

<html>
<head>
    <title>TryHackMe</title>
</head>
<body>
    The user has been deleted THM{<REDACTED>}
</body>
</html>
```

Answer: `THM{<REDACTED>}`

#### Make a PUT request to /user/2 with the username parameter set to admin

Hint: Click the settings cog to add a parameter to the PUT request

Request:

```text
PUT /user/2 HTTP/1.1
Host: tryhackme.com
User-Agent: Mozilla/5.0 Firefox/87.0
Content-Length: 0
```

Response:

```text
HTTP/1.1 200 Ok
Server: nginx/1.15.8
Fri, 18 Apr 2025 17:32:39 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 251
Last-Modified: Fri, 18 Apr 2025 17:32:39 GMT

<html>
<head>
    <title>TryHackMe</title>
</head>
<body>
    Username changed to admin THM{<REDACTED>}
</body>
</html>
```

Answer: `THM{<REDACTED>}`

#### POST the username of thm and a password of letmein to /login

Hint: Delete the parameter requests from the last task, and add two more (username & password).

Request:

```text
POST /login HTTP/1.1
Host: tryhackme.com
User-Agent: Mozilla/5.0 Firefox/87.0
Content-Length: 0
```

Response:

```text
HTTP/1.1 200 Ok
Server: nginx/1.15.8
Fri, 18 Apr 2025 17:35:22 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 256
Last-Modified: Fri, 18 Apr 2025 17:35:22 GMT

<html>
<head>
    <title>TryHackMe</title>
</head>
<body>
    You logged in! Welcome Back THM{<REDACTED>}
</body>
</html>
```

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [HTTP - Wikipedia](https://en.wikipedia.org/wiki/HTTP)
- [HTTP headers - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers)
- [HTTP request methods - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods)
- [HTTP Request methods - Wikipedia](https://en.wikipedia.org/wiki/HTTP#Request_methods)
- [HTTP response status codes - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status)
- [List of HTTP status codes - Wikipedia](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)
