# W1seGuy

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
Tags: Linux
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Free
Description:
A w1se guy 0nce said, the answer is usually as plain as day.
```

Room link: [https://tryhackme.com/room/w1seguy](https://tryhackme.com/room/w1seguy)

## Solution

### Task 1: Source Code

Yes, it's me again with another crypto challenge!

Have a look at the source code before moving on to Task 2.

You can review the source code by clicking on the **Download Task Files** button at the top of this task to download the required file.

```python
import random
import socketserver 
import socket, os
import string

flag = open('flag.txt','r').read().strip()

def send_message(server, message):
    enc = message.encode()
    server.send(enc)

def setup(server, key):
    flag = 'THM{thisisafakeflag}' 
    xored = ""

    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))

    hex_encoded = xored.encode().hex()
    return hex_encoded

def start(server):
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    key = str(res)
    hex_encoded = setup(server, key)
    send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")
    
    send_message(server,"What is the encryption key? ")
    key_answer = server.recv(4096).decode().strip()

    try:
        if key_answer == key:
            send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")
            server.close()
        else:
            send_message(server, 'Close but no cigar' + "\n")
            server.close()
    except:
        send_message(server, "Something went wrong. Please try again. :)\n")
        server.close()

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start(self.request)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    server.serve_forever()
```

We can see that this is an XOR-cipher:

```python
    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))
```

And that the key is 5 characters long.

```python
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
```

The server is listening on port `1337`.

---------------------------------------------------------------------------------------

### Task 2: Get those flags

#### Set up your virtual environment

To successfully complete this room, you'll need to set up your virtual environment. This involves starting both your AttackBox (if you're not using your VPN) and Lab Machines, ensuring you're equipped with the necessary tools and access to tackle the challenges ahead.

Your friend told me you were wise, but I don't believe them. Can you prove me wrong?

When you are ready, click the **Start Lab Machine** button to fire up the Lab Machine. Please allow 3-5 minutes for the VM to start fully.

The server is listening on port **1337 via TCP**. You can connect to it using Netcat or any other tool you prefer.

---------------------------------------------------------------------------------------

#### What is the first flag?

We start by connecting to the service on port 1337 with netcat.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/W1seGuy]
└─$ export TARGET_IP=10.113.189.148

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/W1seGuy]
└─$ nc $TARGET_IP 1337
This XOR encoded text has flag 1: 18323d301b7d1b1c251f0902040a1f384e1320080d1402780a203609233e3e0e097b1e3e023f3916
What is the encryption key? 
```

We get an encrypted flag to decode.

Since the key is only 5 characters long and we know the first 4 characters of the flag (`THM{}`) we can bruteforce the 5th character.

The script is fully automated with the help of [PwnTools](https://docs.pwntools.com/en/stable/index.html).

```python
#!/usr/bin/env python3

import string
from pwn import *

charset = string.ascii_letters + string.digits

# Connection details
SERVER = '10.113.189.148'
PORT = 1337

# Set output level (critical, error, warning, info (default), debug)
context.log_level = "info"

io = remote(SERVER, PORT)
banner = io.recvuntil(b'flag 1: ')
enc_flag = bytes.fromhex(io.recvlineS().strip())

known_flag = b'THM{'
part_key = xor(enc_flag[:4], known_flag)

for c in charset:
    key = part_key + c.encode()
    dec_flag = xor(enc_flag, key).decode()
    
    if dec_flag[-1] == '}':
        print(f"Flag: {dec_flag}")
        print(f"Key: {key.decode()}")
        break

io.sendlineafter(b'encryption key? ', key)
banner = io.recvuntil(b'flag 2: ')
flag_2 = io.recvlineS().strip()
print(f"Flag 2: {flag_2}")
```

Then we execute the script to get all we need.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Challenges/Easy/W1seGuy]
└─$ ./solve.py
[+] Opening connection to 10.113.189.148 on port 1337: Done
Flag: THM{<REDACTED>}
Key: vKHDC
Flag 2: THM{<REDACTED>}
[*] Closed connection to 10.113.189.148 port 1337
```

Answer: `THM{<REDACTED>}`

### What is the second and final flag?

See the output above.

Answer: `THM{<REDACTED>}`

---------------------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [nc - Linux manual page](https://linux.die.net/man/1/nc)
- [netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
- [Python (programming language) - Wikipedia](https://en.wikipedia.org/wiki/Python_(programming_language))
- [pwntools - Documentation](https://docs.pwntools.com/en/stable/index.html)
- [pwntools - GitHub](https://github.com/Gallopsled/pwntools)
- [XOR cipher - Wikipedia](https://en.wikipedia.org/wiki/XOR_cipher)
