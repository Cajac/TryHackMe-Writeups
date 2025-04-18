# Python Basics

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Using a web-based code editor, learn the basics of Python and put your knowledge 
into practice by eventually coding a short Bitcoin investment project.
```

Room link: [https://tryhackme.com/room/pythonbasics](https://tryhackme.com/room/pythonbasics)

## Solution

### Task 2 - Hello World

Output to the screen (stdout) is done in Python with the `print` statement

```python
print("Hello World")
```

### Task 3 - Mathematical Operators

Most operators are as expacted in Python

| Operator | Syntax | Example |
|----|----|----|
|Addition|+|1 + 1 = 2|
|Subtraction|-|5 - 1 = 4|
|Multiplication|*|10 * 10 = 100|
|Division|/|10 / 2 = 5|
|Modulus|%|10 % 2 = 0|
|Exponent|**|5**2 = 25|

#### Addition

```python
print(21 + 43)
```

#### Subtraction

```python
print(142 - 52)
```

#### Multiplication

```python
print(10 * 342)
```

#### Squared/Exponent

```python
print(5 ** 2)
```

### Task 4 - Variables and Data Types

Now we introduce variables. There is no special syntax or prefix for variables.

```python
height = 200
height += 50
print(height)
```

### Task 5 - Logical and Boolean Operators

Logical operators allow assignment and comparisons to be made and are used in conditional testing (such as if statements).

| Logical Operation| Operator | Example |
|----|----|----|
|Equivalence|==|if x == 5|
|Less than|<|if x < 5|
|Less than or equal to|<=|if x <= 5|
|Greater than|>|if x > 5|
|Greater than or equal to|>=|if x >= 5|

Boolean operators are used to connect and compare relationships between statements.  
Like an if statement, conditions can be true or false.

| Boolean Operation | Operator | Example |
|----|----|----|
|Both conditions must be true for the statement to be true|AND|if x >= 5 AND x <= 100Returns TRUE if x isa number between 5 and 100|
|Only one condition of the statement needs to be true|OR|if x == 1 OR x == 10Returns TRUE if X is 1 or 10|
|If a condition is the opposite of an argument|NOT|if NOT yReturns TRUE if the y value is False|

### Task 6 -  Introduction to If Statements

Project description

```text
    In this project, you'll create a program that calculates the total
    cost of a customers shopping basket, including shipping.

    - If a customer spends over $100, they get free shipping
    - If a customer spends < $100, the shipping cost is $1.20 per kg of the baskets weight

    Print the customers total basket cost (including shipping) to complete this exercise.
```

Python code

```python
customer_basket_cost = 34
customer_basket_weight = 44

# Write if statement here to calculate the total cost
if customer_basket_cost <= 100:
  shipping = customer_basket_weight * 1.2
  total_cost = customer_basket_cost + shipping
else:
  total_cost = customer_basket_cost

print(total_cost)
```

### Task 7 -  Loops

#### While Loops

While loop example

```python
i = 1
while i <= 10:
     print(i)
     i = i + 1
```

#### For Loops

For loop example

```python
websites = ["facebook.com", "google.com", "amazon.com"]
for site in websites:
     print(site)
```

Code

```python
for i in range(51):
     print(i)
```

### Task 8 -  Introduction to Functions

Function examples

```python
def sayHello(name):
     print("Hello " + name + "! Nice to meet you.")

sayHello("ben") # Output is: Hello Ben! Nice to meet you
```

and

```python
def calcCost(item):
     if(item == "sweets"):
          return 3.99
     elif (item == "oranges"):
          return 1.99
     else:
          return 0.99

spent = 10
spent = spent + calcCost("sweets")
print("You have spent:" + str(spent))
```

Project description

```text
    In this project, you'll create a program that that tells
    you when the value of your Bitcoin falls below $30,000.

    You will need to:
    - Create a function to convert Bitcoin to USD
    - If your Bitcoin falls below $30,000, print a message.

    You can assume that 1 Bitcoin is worth $40,000
```

Python code

```python
investment_in_bitcoin = 1.2
bitcoin_to_usd = 40000

# 1) write a function to calculate bitcoin to usd
def bitcoinToUSD(bitcoin_amount, bitcoin_value_usd):
  usd_value = bitcoin_amount * bitcoin_value_usd
  return usd_value

investment_in_usd = bitcoinToUSD(investment_in_bitcoin, bitcoin_to_usd)
if investment_in_usd <= 30000:
  print("Investment below $30,000! SELL!")
else:
  print("Investment above $30,000")
```

Note that you must use their template litterly. You cannot change the variable or function names to something different!

### Task 9 -  Files

To read the entire contents of a file (all at once)

```python
f = open("file_name", "r")
print(f.read())
```

To append to an existing file

```python
f = open("demofile1.txt", "a") # Append to an existing file
f.write("The file will include more text..")
f.close()
```

To create and write to a new file

```python
f = open("demofile2.txt", "w") # Creating and writing to a new file
f.write("demofile2 file created, with this content in!")
f.close()
```

Code

```python
f = open("flag.txt", "r")
print(f.read())
```

### Task 10 -  Imports

To import and use libraries

```python
import datetime
current_time = datetime.datetime.now()
print(current_time)
```

For additional information, please see the references below.

## References

- [python - Linux manual page](https://linux.die.net/man/1/python)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [pwntools - Documentation](https://docs.pwntools.com/en/stable/index.html)
- [Scapy - Documentation](https://scapy.readthedocs.io/en/latest/)
- [Scapy - Homepage](https://scapy.net/)
- [Scapy - GitHub](https://github.com/secdev/scapy/)
