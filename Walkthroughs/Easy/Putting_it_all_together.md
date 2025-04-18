# Putting it all together

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Learn how all the individual components of the web work together to bring you access to your 
favourite web sites.
```

Room link: [https://tryhackme.com/room/puttingitalltogether](https://tryhackme.com/room/puttingitalltogether)

## Solution

### Task 1: Putting It All Together

From the previous modules, you'll have learned that quite a lot of things go on behind the scenes when you  
request a webpage in your browser.

To summarise, when you request a website, your computer needs to know the server's IP address it needs to  
talk to; for this, it uses DNS. Your computer then talks to the web server using a special set of commands  
called the HTTP protocol; the webserver then returns HTML, JavaScript, CSS, Images, etc., which your browser  
then uses to correctly format and display the website to you.

There are also a few other components that help the web run more efficiently and provide extra features.

### Task 2: Other Components

#### Load Balancers

When a website's traffic starts getting quite large or is running an application that needs to have high  
availability, one web server might no longer do the job. Load balancers provide two main features, ensuring  
high traffic websites can handle the load and providing a failover if a server becomes unresponsive.

#### CDN (Content Delivery Networks)

A CDN can be an excellent resource for cutting down traffic to a busy website. It allows you to host static  
files from your website, such as JavaScript, CSS, Images, Videos, and host them across thousands of servers  
all over the world. When a user requests one of the hosted files, the CDN works out where the nearest server  
is physically located and sends the request there instead of potentially the other side of the world.

#### Databases

Often websites will need a way of storing information for their users. Webservers can communicate with  
databases to store and recall data from them. Databases can range from just a simple plain text file up to  
complex clusters of multiple servers providing speed and resilience. You'll come across some common databases:  
MySQL, MSSQL, MongoDB, Postgres, and more; each has its specific features.

#### WAF (Web Application Firewall)

A WAF sits between your web request and the web server; its primary purpose is to protect the webserver from  
hacking or denial of service attacks. It analyses the web requests for common attack techniques, whether the  
request is from a real browser rather than a bot. It also checks if an excessive amount of web requests are  
being sent by utilising something called rate limiting, which will only allow a certain amount of requests from  
an IP per second. If a request is deemed a potential attack, it will be dropped and never sent to the webserver.

#### What can be used to host static files and speed up a clients visit to a website?

Answer: CDN

#### What does a load balancer perform to make sure a host is still alive?

Answer: health check

#### What can be used to help against the hacking of a website?

Answer: WAF

### Task 3: How Web Servers Work

#### What is a Web Server?

A web server is a software that listens for incoming connections and then utilises the HTTP protocol to deliver  
web content to its clients. The most common web server software you'll come across is Apache, Nginx, IIS and  
NodeJS. A Web server delivers files from what's called its root directory, which is defined in the software  
settings. For example, Nginx and Apache share the same default location of /var/www/html in Linux operating  
systems, and IIS uses C:\inetpub\wwwroot for the Windows operating systems.

#### Virtual Hosts

Web servers can host multiple websites with different domain names; to achieve this, they use virtual hosts.  
The web server software checks the hostname being requested from the HTTP headers and matches that against its  
virtual hosts (virtual hosts are just text-based configuration files). If it finds a match, the correct  
website will be provided. If no match is found, the default website will be provided instead.

#### Static Vs Dynamic Content

Static content, as the name suggests, is content that never changes. Common examples of this are pictures,  
javascript, CSS, etc., but can also include HTML that never changes. Furthermore, these are files that are  
directly served from the webserver with no changes made to them.

Dynamic content, on the other hand, is content that could change with different requests. Take, for example,  
a blog. On the homepage of the blog, it will show you the latest entries. If a new entry is created, the home  
page is then updated with the latest entry, or a second example might be a search page on a blog. Depending  
on what word you search, different results will be displayed.

#### Scripting and Backend Languages

There's not much of a limit to what a backend language can achieve, and these are what make a website  
interactive to the user. Some examples of these languages (in no particular order :p) are PHP, Python, Ruby,  
NodeJS, Perl and many more. These languages can interact with databases, call external services, process  
data from the user, and so much more.

#### What does web server software use to host multiple sites?

Answer: Virtual Hosts

#### What is the name for the type of content that can change?

Answer: Dynamic

#### Does the client see the backend code? Yay/Nay

Answer: Nay

### Task 4: Quiz

Using everything you've learnt from the other modules, drag and drop the tiles into the correct order of how  
a request to a website works to reveal the flag.

1. Request tryhackme.com in your browser
2. Check Local Cache for IP Address
3. Check your recursive DNS Server for Address
4. Query root server to find authorative DNS server
5. Authorative DNS server advices the IP address for the website
6. Request passes through a Web Application Firewall
7. Request passes through a Load Balancer
8. Connect to Wbserver on port 80 or 443
9. Web server receives the GET request
10. Web Application talks to Database
11. Your Browser renders the HTML into a viewable website

Answer: `THM{<REDACTED>}`

For additional information, please see the references below.

## References

- [Domain Name System - Wikipedia](https://en.wikipedia.org/wiki/Domain_Name_System)
- [HTML - Wikipedia](https://en.wikipedia.org/wiki/HTML)
- [HTTP - Wikipedia](https://en.wikipedia.org/wiki/HTTP)
- [JavaScript - Wikipedia](https://en.wikipedia.org/wiki/JavaScript)
- [Load balancing (computing) - Wikipedia](https://en.wikipedia.org/wiki/Load_balancing_(computing))
- [Web application firewall - Wikipedia](https://en.wikipedia.org/wiki/Web_application_firewall)
