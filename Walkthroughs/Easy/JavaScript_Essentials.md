# JavaScript Essentials

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Premium
Description: Learn how to use JavaScript to add interactivity to a website and understand 
associated vulnerabilities.
```

Room link: [https://tryhackme.com/room/javascriptessentials](https://tryhackme.com/room/javascriptessentials)

## Solution

### Task 1: Introduction

JavaScript (JS) is a popular scripting language that allows web developers to add interactive features to websites containing HTML and CSS (styling). Once the HTML elements are created, you can add interactiveness like validation, onClick actions, animations, etc, through JS. Learning the language is equally important as that of HTML and CSS. The JS scripts are used primarily with HTML.

This room is designed as an introductory overview of JS, specifically tailored for beginners with limited JS experience. The primary focus is on teaching the fundamentals of JS from a cyber perspective and how hackers utilise legitimate functionalities to achieve malicious results.

#### Room Prerequisites

- Linux Fundamentals Module
- Web Application Basics
- How Websites Work

#### Learning Objectives

- Understand the basics of JS
- Integrating JS in HTML
- Abusing Dialogue Function
- Bypassing Control Flow Statements
- Exploring Minified Files

#### Connecting

Start the virtual machine by clicking `Start Machine`. The machine will start in a split-screen view.

### Task 2: Essential Concepts

#### Variables

Variables are containers that allow you to store data values in them. Like any other language, variables in JS are similar to containers to store data. When you store something in a bucket, you also need to label it so that it can be referenced later on easily. Similarly, in JS, each variable has a name; when we store a certain value in a variable, we assign a name to it to reference it later. There are three ways to declare variables in JS: `var`, `let`, and `const`. While `var` is function-scoped, both `let`, and `const` are block-scoped, offering better control over variable visibility within specific code blocks.

#### Data Types

In JS, data types define the type of value a variable can hold. Examples include `string` (text), `number`, `boolean` (true/false), null, undefined, and object (for more complex data like arrays or objects).

#### Functions

A function represents a block of code designed to perform a specific task. Inside a function, you group code that needs to perform a similar task. For example, you are developing a web application in which you need to print students' results on the web page. The ideal case would be to create a function `PrintResult(rollNum)` that would accept the roll number of the user as an argument.

```javascript
   <script>
        function PrintResult(rollNum) {
            alert("Username with roll number " + rollNum + " has passed the exam");
            // any other logic to display the result
        }

        for (let i = 0; i < 100; i++) {
            PrintResult(rollNumbers[i]);
        }
    </script>
```

So, instead of writing the same print code for all the students, we will use a simple function to print the result.

#### Loops

Loops allow you to run a code block multiple times as long as a condition is `true`. Common loops in JS are `for`, `while`, and `do...while`, which are used to repeat tasks, like going through a list of items. For example, if we want to print the results of 100 students, we can call the PrintResult(rollNum) function 100 times by writing it 100 times, or we can create a loop that will be iterated through 1 to 100 and will call the PrintResult(rollNum) function as shown below.

```javascript
   <script>
        function PrintResult(rollNum) {
            alert("Username with roll number " + rollNum + " has passed the exam");
            // any other logic to display the result
        }

        for (let i = 0; i < 100; i++) {
            PrintResult(rollNumbers[i]);
        }
    </script>
```

#### Request-Response Cycle

In web development, the request-response cycle is when a user's browser (the client) sends a request to a web server, and the server responds with the requested information. This could be a webpage, data, or other resources.

#### What term allows you to run a code block multiple times as long as it is a condition?

Answer: loop

### Task 3: JavaScript Overview

In this task, we’ll use JS to create our first program. JS is an **interpreted** language, meaning the code is executed directly in the browser without prior compilation. Below is a sample JS code demonstrating key concepts, such as defining a variable, understanding data types, using control flow statements, and writing simple functions. These essential building blocks help create more dynamic and interactive web apps. Don’t worry if it looks a bit new now - we will discuss each of these concepts in detail later on.

```javascript
 // Hello, World! program
console.log("Hello, World!");

// Variable and Data Type
let age = 25; // Number type

// Control Flow Statement
if (age >= 18) {
    console.log("You are an adult.");
} else {
    console.log("You are a minor.");
}

// Function
function greet(name) {
    console.log("Hello, " + name + "!");
}

// Calling the function
greet("Bob");
```

JS is primarily executed on the client side, which makes it easy to inspect and interact with HTML directly within the browser. We’ll use the `Google Chrome Console` feature to run our first JS program, allowing us to write and execute JS code easily without additional tools. Follow these steps to get started:

Open `Google Chrome` by clicking the `Google Chrome` icon on the Desktop of the VM.

Once Chrome is open, press `Ctrl + Shift + I` to open the `Console` or right-click anywhere on the page and select `Inspect`.

Then, click on the `Console` tab. This console allows you to run JS code directly in the browser without installing additional software.

Let's create a simple JS program that adds two numbers and displays the result. Below is the code:

```javascript
let x = 5;
let y = 10;
let result = x + y;
console.log("The result is: " + result);
```

In the code above, `x` and `y` are variables holding the numbers. `x + y` is an expression that adds the two numbers together, whereas `console.log`  is a function used to print the result to the console.

Copy the above code and paste it into the console by pressing the key `Ctrl + V`. Once pasted, press `Enter`.

Congratulations! You’ve successfully created your first program in JS. This is just the beginning, and there’s much more to explore as we dive deeper into JS in this room.

#### What is the code output if the value of x is changed to 10?

Answer: The result is: 20

#### Is JavaScript a compiled or interpreted language?

Answer: interpreted

### Task 4: Integrating JavaScript in HTML

This task assumes you have a basic understanding of HTML and its structure. This section will explore how JS can be integrated into HTML. Usually, JS is not used to render content; it works with HTML and CSS to create dynamic and interactive web pages. If you're unfamiliar with HTML, reviewing it through the provided link is recommended. There are two main ways to integrate JS into HTML: internally and externally.

#### Internal JavaScript

Internal JS refers to embedding the JS code directly within an HTML document. This method is preferable for beginners because it allows them to see how the script interacts with the HTML. The script is inserted between `<script>` tags. These tags can be placed inside the `<head>` section, typically used for scripts that need to be loaded before the page content is rendered, or inside the `<body>` section, where the script can be utilised to interact with elements as they are loaded on the web page.

Example

To create an HTML document with internal JS, right-click on the `Desktop` and select `Create Document` > `Empty File`. Name the file `internal.html`. Next, right-click the `internal.html` file and choose `Open with Pluma` to open it in a text editor.

Once the editor is open, paste the following code:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Internal JS</title>
</head>
<body>
    <h1>Addition of Two Numbers</h1>
    <p id="result"></p>

    <script>
        let x = 5;
        let y = 10;
        let result = x + y;
        document.getElementById("result").innerHTML = "The result is: " + result;
    </script>
</body>
</html>
```

After pasting the code, click `File` and select `Save`, which will save the file to `internal.html`. Double-click the file to open it in Chrome browser, where you will see the following output:

```text
Addition of Two Numbers

The result is: 15
```

In this HTML document, we are using internal JS, meaning the code is placed directly inside the HTML file within the `<script>` tag. The script performs a simple task: it adds two numbers (x and y) and then displays the result on the web page. The JS interacts with the HTML by selecting an element (`<p>` with id="result") and updating its content using `document.getElementById("result").innerHTML`. This internal JS is executed when the browser loads the HTML file.

#### External JavaScript

External JS involves creating and storing JS code in a separate file ending with a `.js` file extension. This method helps developers keep the HTML document clean and organised. The external JS file can be stored or hosted on the same web server as the HTML document or stored on an external web server such as the cloud.

We will use the same example for external JS but separate the JS code into a different file.

First, create a new file named `script.js` and save it on the `Desktop` with the following code:

```javascript
let x = 5;
let y = 10;
let result = x + y;
document.getElementById("result").innerHTML = "The result is: " + result;
```

Next, create a new file named `external.html` and paste the following code (notice that the HTML code is the same as that of the previous example):

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>External JS</title>
</head>
<body>
    <h1>Addition of Two Numbers</h1>
    <p id="result"></p>

    <!-- Link to the external JS file -->
    <script src="script.js"></script>
</body>
</html>
```

Now, double-click the external.html file and check the results. Do you see any difference? No, the output remains the same as in the previous example.

What we did differently is use the src attribute in the `<script>` tag to load the JS from an external file. When the browser loads the page, it looks for the `script.js` file and loads its content into the HTML document. This approach allows us to keep the JS code separate from the HTML, making the code more organised and easier to maintain, especially when working on larger projects.

#### Verifying Internal or External JS

When pen-testing a web application, it is important to check whether the website uses internal or external JS. This can be easily verified by viewing the page's source code. To do this, open the page `external_test.html` located in the `exercise` folder in `Chrome`, right-click anywhere on the page, and select `View Page Source`.

This will display the HTML code of the rendered page. Inside the source code, any JS written directly on the page will appear between `<script>` tags without the `src` attribute. If you see a `<script>` tag with a src attribute, it indicates that the page is loading external JS from a separate file.

For a practical example, visit [https://tryhackme.com](https://tryhackme.com) in your browser and inspect the source code to identify how the website loads the JS internally and from external sources.

#### Which type of JavaScript integration places the code directly within the HTML document?

Answer: Internal

#### Which method is better for reusing JS across multiple web pages?

Answer: External

#### What is the name of the external JS file that is being called by external_test.html?

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>External JS</title>
</head>
<body>
    <h1>Can you verify the JS?</h1>
    <p id="result"></p>

    <!-- Link to the external JS file -->
    <script src="thm_external.js"></script>
</body>
</html>
```

Answer: thm_external.js

#### What attribute links an external JS file in the <script> tag?

Answer: src

### Task 5: Abusing Dialogue Functions

One of the main objectives of JS is to provide dialogue boxes for interaction with users and dynamically update content on web pages. JS provides built-in functions like `alert`, `prompt`, and `confirm` to facilitate this interaction. These functions allow developers to display messages, gather input, and obtain user confirmation. However, if not implemented securely, attackers may exploit these features to execute attacks like Cross-Site Scripting (XSS), which you will cover later in this module.

We will be using the `Google Chrome console` in the upcoming exercises.

#### Alert

The `alert` function displays a message in a dialogue box with an "`OK`" button, typically used to convey information or warnings to users. For example, if we want to display "`Hello THM`" to the user, we would use an `alert("HelloTHM");`. To try it out, open the Chrome console, type `alert("Hello THM"`), and press Enter. A dialogue box with the message will appear on the screen.

#### Prompt

The `prompt` function displays a dialogue box that asks the user for input. It returns the entered value when the user clicks "`OK`", or null if the user clicks "`Cancel`". For example, to ask the user for their name, we would use `prompt("What is your name?");`.

To test this, open the Chrome console and paste the following that asks for a username and then greets him.

```javascript
name = prompt("What is your name?");
alert("Hello " + name);
```

Once you paste the code and hit `Enter`, a dialogue box will appear, and the value entered by the user will be returned to the console.

#### Confirm

The `confirm` function displays a dialogue box with a message and two buttons: "`OK`" and "`Cancel`". It returns true if the user clicks "OK" and false if the user clicks "Cancel". For example, to ask the user for confirmation, we would use `confirm("Are you sure?");`. To try this out, open the Chrome console, type `confirm("Do you want to proceed?")`, and press `Enter`.

A dialogue box will appear, and depending on whether the user clicks "`OK`" or "`Cancel`", the value true or false will be returned to the console.

#### How Hackers Exploit the Functionality

Imagine receiving an email from a stranger with an attached HTML file. The file looks harmless, but when you open it, it contains JS that disrupts your browsing experience. For example, the following code will show an alert box with the message "Hacked" three times:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Hacked</title>
</head>
<body>
    <script>
        for (let i = 0; i < 3; i++) {
            alert("Hacked");
        }
    </script>
</body>
</html>
```

On the Desktop of the attached VM, create a file called `invoice.html` and paste the above code. Double-click the file to open it, and the alert message will pop up three times, causing an undesired experience.

Imagine if a bad actor sent you a similar file, but instead of displaying the alert three times, the number is set to **500**. You would be forced to keep closing the alert boxes one after another. This is a simple example of how malicious JS can be used to create an inconvenience or worse. Therefore, ensuring you only execute JS files from trusted sources is crucial to avoid such an undesired experience.

#### In the file invoice.html, how many times does the code show the alert Hacked?

Hint: You need to check the invoice.html file on the attached VM.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Hacked</title>
</head>
<body>
    <script>
        for (let i = 0; i < 5; i++) {
            alert("Hacked");
        }
    </script>
</body>
</html>
```

Answer: 5

#### Which of the JS interactive elements should be used to display a dialogue box that asks the user for input?

Answer: prompt

#### If the user enters Tesla, what value is stored in the carName= prompt("What is your car name?")? in the carName variable?

Answer: Tesla

### Task 6: Bypassing Control Flow Statements

Control flow in JS refers to the order in which statements and code blocks are executed based on certain conditions. JS provides several control flow structures such as `if-else`, `switch` statements to make decisions, and loops like `for`, `while`, and `do...while` to repeat actions. Proper use of control flow ensures that a program can handle various conditions effectively.

#### Conditional Statements in Action

One of the most used conditional statements is the `if-else` statements, which allows you to execute different blocks of code depending on whether a condition evaluates to true or false.

To test this practically, let's create a file `age.html` on the Desktop of the attached VM and paste the following code:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Age Verification</title>
</head>
<body>
    <h1>Age Verification</h1>
    <p id="message"></p>

    <script>
        age = prompt("What is your age")
        if (age >= 18) {
            document.getElementById("message").innerHTML = "You are an adult.";
        } else {
            document.getElementById("message").innerHTML = "You are a minor.";
        }
    </script>
</body>
</html>
```

In the above code, a prompt will ask for your age. If your age is greater than or equal to 18, it will display a message saying, "`You are an adult.`" Otherwise, it will show a different message. This behaviour is controlled by the if-else statement, which checks the value of the age variable and displays the appropriate message based on the condition.

#### Bypassing Login Forms

Suppose a developer has implemented authentication functionality in JS, where only users with the username "`admin`" and passwords matching a specific value are allowed to log in. To see this in action, open the `login.html` file in the exercises folder.

When you double-click the file and open it in your browser, it will prompt you for a username and password. If the correct credentials are entered, it will display a message confirming that you are logged in.

#### What is the message displayed if you enter the age less than 18?

```javascript
        age = prompt("What is your age")
        if (age >= 18) {
            document.getElementById("message").innerHTML = "You are an adult.";
        } else {
            document.getElementById("message").innerHTML = "You are a minor.";
        }
```

Answer: You are a minor.

#### What is the password for the user admin?

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Login Page</title>
</head>
<body>
    <h2>Login Authentication</h2>

    <script>
        let username = prompt("Enter your username:");
        let password = prompt("Enter your password:");

        if (username === "admin" && password === "ComplexPassword") {
            document.write("You are successfully authenticated!");
        } else {
            document.write("Authentication failed. Incorrect username or password.");
        }
    </script>
</body>
</html>
```

Answer: ComplexPassword

### Task 7: Exploring Minified Files

We have understood how JS works and how we can read it until now, but what if the file is not human-readable and has been minified?

Minification in JS is the process of compressing JS files by removing all unnecessary characters, such as spaces, line breaks, comments, and even shortening variable names. This helps reduce the file size and improves the loading time of web pages, especially in production environments. Minified files make the code more compact and harder to read for humans, but they still function exactly the same.

Similarly, **obfuscation** is often used to make JS harder to understand by adding undesired code, renaming variables and functions to meaningless names, and even inserting dummy code.

#### Practical  Example

Create a file on the Desktop of the attached VM with the name hello.html and paste the following HTML code:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Obfuscated JS Code</title>
</head>
<body>
    <h1>Obfuscated JS Code</h1>
    <script src="hello.js"></script>
</body>
</html>
```

Then, create another file with the name `hello.js` and add the following code:

```javascript
function hi() {
  alert("Welcome to THM");
}
hi();
```

Now, double-click the `hello.html` file to open it in Google Chrome. Once the file is opened, you will see an alert greeting you with "`Welcome to THM`".

Click `OK` to close the alert dialogue box. Right-click anywhere on the page and click on `Inspect` to open the developer tools. In the developer tools, navigate to the `Sources` tab and click on the `hello.js` file to view the source code. You will see that the JS code is easily accessible and viewable.

#### Obfuscation in Action

Now, we will try to minify and obfuscate the JS code using an online tool. Visit the [website](https://codebeautify.org/javascript-obfuscator) and copy the contents of `hello.js`, and paste them into the dialogue box on the website. The tool will minify and obfuscate the code, turning it into a string of gibberish characters.

```javascript
function _0x3cde(_0x5d830b,_0x400ca3){var _0x37d47b=_0x4f48();return _0x3cde=function(_0x4a8b4b,_0x961574){_0x4a8b4b=_0x4a8b4b-(0x4f*-0x6d+0x156d+0x1*0xe19);var _0x1a6610=_0x37d47b[_0x4a8b4b];return _0x1a6610;},_0x3cde(_0x5d830b,_0x400ca3);}(function(_0x47f31b,_0x3c4a0){var _0x54d54d=_0x3cde,_0x13aed3=_0x47f31b();while(!![]){try{var _0x2ffb5e=parseInt(_0x54d54d(0x1f0))/(0x1d03+-0x2a0+-0xd31*0x2)+-parseInt(_0x54d54d(0x1e9))/(-0x3*0x76a+-0x1ae1+0x3121)+-parseInt(_0x54d54d(0x1ea))/(0x6e*0x1+-0x2ee+0x283)*(parseInt(_0x54d54d(0x1e3))/(0x347*0xa+0x1633*0x1+-0x36f5*0x1))+parseInt(_0x54d54d(0x1ef))/(-0xc5*-0x26+0x150c+-0x3245)*(parseInt(_0x54d54d(0x1e5))/(-0x1*0xc59+-0x1b3+0xe12))+parseInt(_0x54d54d(0x1f1))/(0x6a*-0x3a+-0x168e+0x4f*0x97)*(parseInt(_0x54d54d(0x1e8))/(0x77*-0x4+0x243+-0x5f*0x1))+-parseInt(_0x54d54d(0x1e6))/(0x1022*0x1+-0x5*-0x113+-0x55e*0x4)*(parseInt(_0x54d54d(0x1ee))/(0x1f7b+0x1*-0x1843+-0x1*0x72e))+parseInt(_0x54d54d(0x1ec))/(-0xffe*0x1+-0x111*-0x1d+0x2*-0x772);if(_0x2ffb5e===_0x3c4a0)break;else _0x13aed3['push'](_0x13aed3['shift']());}catch(_0x4afc47){_0x13aed3['push'](_0x13aed3['shift']());}}}(_0x4f48,-0x2*0xdbdbb+0xe0*0x685+0x24664b));function hi(){var _0xfc97e=_0x3cde,_0x208843={'friro':function(_0x4b2c06,_0x311ec9){return _0x4b2c06(_0x311ec9);},'jlfYb':_0xfc97e(0x1e4)+_0xfc97e(0x1eb)};_0x208843[_0xfc97e(0x1ed)](alert,_0x208843[_0xfc97e(0x1e7)]);}hi();function _0x4f48(){var _0x224751=['625113LgrpOT','jlfYb','965880uwNLCu','1677732DZXuQN','813YiTZsw','\x20THM','7228364FBSayM','friro','50jzbfdW','8010ZuMitJ','1435141MjEpxx','63mUEXsi','16664rleGHr','Welcome\x20to','354QYBdrQ'];_0x4f48=function(){return _0x224751;};return _0x4f48();}
```

But what if we tell you that these gibberish characters are still fully functional code? The only difference is that they are not human-readable, but the browser can still execute them correctly.

Click the `Copy to Clipboard`-button as shown on the website. Then, remove the current content of `hello.js` on the attached VM and paste the obfuscated content into the file.

Reload the `hello.html` file in Google Chrome and inspect the source code again under the `Sources` tab. You will notice that the code is now obfuscated but still functions exactly the same as before.

#### Deobfuscating a Code

We can also deobfuscate an obfuscated code using an online tool. Visit the [website](https://obf-io.deobfuscate.io/), then paste the obfuscated code into the provided dialogue box. The website will generate the equivalent, human-readable JS code for you, making it easier to understand and analyze the original script.

You have seen how easily we deobfuscated and retrieved our original code.

#### What is the alert message shown after running the file hello.html?

Answer: Welcome to THM

#### What is the value of the age variable in the following obfuscated code snippet?

`age=0x1*0x247e+0x35*-0x2e+-0x1ae3;`

Answer: 21

### Task 8: Best Practices

This task outlines the best practices for evaluating a website or writing code for a website. If you are developing a web application, you will likely end up using JS on your website. The practices below will assist you in reducing the attack surface and minimizing the chances of attack.

#### Avoid Relying on Client-Side Validation Only

One of JS's primary functions is performing client-side validation. Developers sometimes use it for validating forms and rely entirely on it, which is not a good practice. Since a user can **disable/manipulate** JS on the client side, performing validation on the server side is also essential.

#### Refrain from Adding Untrusted Libraries

As discussed in earlier tasks, JS allows you to include any other JS scripts using the `src` attribute inside a `<script>` tag. But have you considered whether the library we include is from a trusted source? Bad actors have uploaded a bundle of libraries on the internet with names that resemble legitimate ones. So, if you blindly include a malicious library, you will expose your web application to threats.

#### Avoid Hardcoded Secrets

Never hardcode sensitive data like API keys, access tokens, or credentials into your JS code, as the user can easily check the source code and get the password.

```javascript
// Bad Practice
const privateAPIKey = 'pk_TryHackMe-1337'; 
```

#### Minify and Obfuscate Your JavaScript Code

Minifying and obfuscating JS code reduces its size, improves load time, and makes it harder for attackers to understand the logic of the code. Therefore, always **minify** and **obfuscate** the code when using code in production. The attacker can eventually reverse engineer it, but getting the original code will take at least some effort.

#### Is it a good practice to blindly include JS in your code from any source (yea/nay)?

Answer: nay

### Task 9: Conclusion

Congratulations on completing the JavaScript Essentials room!

We've covered important topics like the basics of JS, creating our first JS code and **integrating JS in HTML**. Moving forward, we discussed other interactive elements of JS, like **prompts** and how attackers can abuse them. Then, the room highlighted the usage of **control flow statements** and how they can be bypassed in JS.

We then explored how to use **minify and obfuscate** a JS file and learned the other way around. Lastly, we touched upon some best practices that you can follow to keep your web app safe from cyber threats.

Keep learning and stay vigilant against security threats; your journey as a JS developer has just begun!

For additional information, please see the references below.

## References

- [HTML - Wikipedia](https://en.wikipedia.org/wiki/HTML)
- [JavaScript - MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
- [JavaScript - Wikipedia](https://en.wikipedia.org/wiki/JavaScript)
- [JavaScript Obfuscator - Code Beautify](https://codebeautify.org/javascript-obfuscator)
- [Minification (programming) - - Wikipedia](https://en.wikipedia.org/wiki/Minification_(programming))
- [Obfuscation (software) - Wikipedia](https://en.wikipedia.org/wiki/Obfuscation_(software))
- [Obfuscator.io Deobfuscator](https://obf-io.deobfuscate.io/)
