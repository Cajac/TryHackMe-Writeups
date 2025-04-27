# How Websites Work

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: To exploit a website, you first need to know how they are created.
```

Room link: [https://tryhackme.com/room/howwebsiteswork](https://tryhackme.com/room/howwebsiteswork)

## Solution

### Task 1: How websites work

When you visit a website, your browser (like Safari or Google Chrome) makes a request to a web server asking  
for information about the page you're visiting. It will respond with data that your browser uses to show you  
the page; a web server is just a dedicated computer somewhere else in the world that handles your requests.

There are two major components that make up a website:

1. Front End (Client-Side) - the way your browser renders a website.
2. Back End (Server-Side) - a server that processes your request and returns a response.

#### What term best describes the component of a web application rendered by your browser?

Hint: This component is also often called "client-side".

Answer: Front End

### Task 2: HTML

Websites are primarily created using:

- HTML, to build websites and define their structure
- CSS, to make websites look pretty by adding styling options
- JavaScript, implement complex features on pages using interactivity

HyperText Markup Language (HTML) is the language websites are written in. Elements (also known as tags) are the  
building blocks of HTML pages and tells the browser how to display content.

#### One of the images on the cat website is broken - fix it, and the image will reveal the hidden text answer!

```html
<!DOCTYPE html>
<html>
    <head>
        <title>TryHackMe HTML Editor</title>
    </head>
    <body>
        <h1>Cat Website!</h1>
        <p>See images of all my cats!</p>
        <img src='img/cat-1.jpg'>
        <img src='img/cat-2.jpg'>
        <!-- Add dog image here -->
    </body>
</html>
```

Answer: HTMLHERO

#### Add a dog image to the page by adding another img tag (<img>) on line 11. The dog image location is img/dog-1.png. What is the text in the dog image?

```html
<!DOCTYPE html>
<html>
    <head>
        <title>TryHackMe HTML Editor</title>
    </head>
    <body>
        <h1>Cat Website!</h1>
        <p>See images of all my cats!</p>
        <img src='img/cat-1.jpg'>
        <img src='img/cat-2.jpg'>
        <img src='img/dog-1.png'>
    </body>
</html>
```

Answer: DOGHTML

### Task 3: JavaScript

JavaScript (JS) is one of the most popular coding languages in the world and allows pages to become interactive.  
HTML is used to create the website structure and content, while JavaScript is used to control the functionality  
of web pages - without JavaScript, a page would not have interactive elements and would always be static.

JavaScript is added within the page source code and can be either loaded within `<script>` tags or can be included  
remotely with the src attribute: `<script src="/location/of/javascript_file.js"></script>`.

#### On the right-hand side, add JavaScript that changes the demo element's content to "Hack the Planet"

Hint: Add your JavaScript to line 9 and click the "Render HTML+JS Code" button.

```html
<!DOCTYPE html>
<html>
    <head>
        <title>TryHackMe Editor</title>
    </head>
    <body>
        <div id="demo">Hi there!</div>
        <script type="text/javascript">
            document.getElementById("demo").innerHTML = "Hack the Planet";
        </script>
    </body>
</html>
```

Answer: JSISFUN

#### Add the button HTML from this task that changes the element's text to "Button Clicked" on the editor on the right

Hint: Put the following on the HTML Editor (between lines 7 and 8):
`<button onclick='document.getElementById("demo").innerHTML = "Button Clicked";'>Click Me!</button>`

```html
<!DOCTYPE html>
<html>
    <head>
        <title>TryHackMe Editor</title>
    </head>
    <body>
        <div id="demo">Hi there!</div>
        <button onclick='document.getElementById("demo").innerHTML = "Button Clicked";'>Click Me!</button>
        <script type="text/javascript">
            document.getElementById("demo").innerHTML = "Hack the Planet";
        </script>
    </body>
</html>
```

### Task 4: Sensitive Data Exposure

Sensitive Data Exposure occurs when a website doesn't properly protect (or remove) sensitive clear-text information to  
the end-user; usually found in a site's frontend source code.

We now know that websites are built using many HTML elements (tags), all of which we can see simply by "viewing the page  
source". A website developer may have forgotten to remove login credentials, hidden links to private parts of the website  
or other sensitive data shown in HTML or JavaScript.

#### View the website on this link. What is the password hidden in the source code?

```html
<!DOCTYPE html>
<html>
<head>
    <title>How websites work</title>
    <link rel="stylesheet" href="css/style.css"></link>
</head>

<body>
    <div id='html-code-box'>
        <div id='html-bar'>
            <span id='html-url'>https://vulnerable-site.com</span>
        </div>
        <div class='theme' id='html-code'>
            <div class='logo-pos'><img src='img/logo_white.png'></div>
            <p id='login-msg'></p>
            <form method='post' id='form' autocomplete="off">
                <div class='form-field'>
                    <input class="input-text" type="text" name="username" placeholder="Username..">
                </div>
                <div class='form-field'>
                    <input class="input-text" type="password" name="password" placeholder="Password..">
                </div>
                <button onclick="login()" type='button' class='login'>Login</button>
                <!--
                    TODO: Remove test credentials!
                        Username: admin
                        Password: testpasswd
                -->
            </form>
            <div class="footer">Copyright Â© Vulnerable Website</div>
        </div>
    </div>
    <script src='js/script.js'></script>
</body>

</html>
```

Answer: testpasswd

### Task 5: HTML Injection

HTML Injection is a vulnerability that occurs when unfiltered user input is displayed on the page. If a website  
fails to sanitise user input (filter any "malicious" text that a user inputs into a website), and that input is  
used on the page, an attacker can inject HTML code into a vulnerable website.

#### View the website on this task and inject HTML so that a malicious link to http://hacker.com is shown.

Enter the name `<a href="http://hacker.com">Click Me!</a>`

Answer: HTML_INJ3CTI0N

For additional information, please see the references below.

## References

- [CSS - Wikipedia](https://en.wikipedia.org/wiki/CSS)
- [HTML - Wikipedia](https://en.wikipedia.org/wiki/HTML)
- [HTTP - Wikipedia](https://en.wikipedia.org/wiki/HTTP)
- [JavaScript - Wikipedia](https://en.wikipedia.org/wiki/JavaScript)
