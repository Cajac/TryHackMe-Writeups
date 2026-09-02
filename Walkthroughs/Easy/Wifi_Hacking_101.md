# Wifi Hacking 101

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
Learn to attack WPA(2) networks! Ideally you'll want a smartphone with you for this, preferably one 
that supports hosting wifi hotspots so you can follow along.
```

Room link: [https://tryhackme.com/room/wifihacking101](https://tryhackme.com/room/wifihacking101)

## Solution

### Task 1: The basics - An Intro to WPA

Key Terms

- **SSID**: The network "name" that you see when you try and connect
- **ESSID**: An SSID that *may* apply to multiple access points, eg a company office, normally forming a bigger network. For Aircrack they normally refer to the network you're attacking.
- **BSSID**: An access point MAC (hardware) address
- **WPA2-PSK**: Wifi networks that you connect to by providing a pre-shared password that's the same for everyone
- **WPA2-EAP**: Wifi networks that you authenticate to by providing a username and password, which is sent to a RADIUS server.
- **RADIUS**: A server for authenticating clients, not just for wifi.

The core of WPA(2) authentication is the 4 way handshake.

Most home WiFi networks, and many others, use WPA(2) personal. If you have to log in with a password and it's not WEP, then it's WPA(2) personal. WPA2-EAP uses RADIUS servers to authenticate, so if you have to enter a username and password in order to connect then it's probably that.

Previously, the **WEP** (Wired Equivalent Privacy) standard was used. This was shown to be insecure and can be broken by capturing enough packets to guess the key via statistical methods.

The 4 way handshake allows the client and the AP to both prove that they know the key, without telling each other. WPA and WPA2 use practically the same authentication method, so the attacks on both are the same.

The keys for WPA are derived from both the ESSID and the password for the network. The ESSID acts as a salt, making dictionary attacks more difficult. It means that for a given password, the key will still vary for each access point. This means that unless you precompute the dictionary for just that access point/MAC address, you will need to try passwords until you find the correct one.

Room Banner by [Frank Wang](https://unsplash.com/@nicetomeetyou) on [Unsplash](https://unsplash.com/s/photos/wifi)

---------------------------------------------------------------------------

#### What type of attack on the encryption can you perform on WPA(2) personal?

Hint: Trying passwords until you find the right one.

Answer: `brute force`

#### Can this method be used to attack WPA2-EAP handshakes? (Yea/Nay)

Answer: `Nay`

#### What is the three-letter abbreviation for the pre-shared key used in Wi-Fi security?

Answer: `PSK`

#### What's the minimum length of a WPA2 Personal password?

See [https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access#WPA-Personal](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access#WPA-Personal)

Answer: `8`

---------------------------------------------------------------------------

### Task 2: You're being watched - Capturing packets to attack

Using the Aircrack-ng suite, we can start attacking a wifi network. This will walk you through attacking a network yourself, assuming you have a monitor mode enabled NIC.

The aircrack-ng suite consists of:

- aircrack-ng
- airdecap-ng
- airmon-ng
- aireplay-ng
- airodump-ng
- airtun-ng
- packetforge-ng
- airbase-ng
- airdecloak-ng
- airolib-ng
- airserv-ng
- buddy-ng
- ivstools
- easside-ng
- tkiptun-ng
- wesside-ng

We'll want to use aircrack-ng, airodump-ng and airmon-ng to attack WPA networks.

The aircrack tools come by default with Kali, or can be installed with a package manager or from [https://www.aircrack-ng.org/](https://www.aircrack-ng.org/)

I suggest creating a hotspot on a phone/tablet, picking a weak password (From rockyou.txt) and following along with every stage. To generate 5 random passwords from rockyou, you can use this command on Kali:

`head /usr/share/wordlists/rockyou.txt -n 10000 | shuf -n 5 -`

You will need a monitor mode NIC in order to capture the 4 way handshake. Many wireless cards support this, but it's important to note that not all of them do.

Injection mode helps, as you can use it to deauth a client in order to force a reconnect which forces the handshake to occur again. Otherwise, you have to wait for a client to connect normally.

---------------------------------------------------------------------------

#### How do you put the interface “wlan0” into monitor mode with Aircrack tools? (Full command)

Answer: `airmon-ng start wlan0`

#### What is the new interface name likely to be after you enable monitor mode?

Answer: `wlan0mon`

#### What do you do if other processes are currently trying to use that network adapter?

Hint: [https://www.aircrack-ng.org/doku.php?id=airmon-ng](https://www.aircrack-ng.org/doku.php?id=airmon-ng)

Answer: `airmon-ng check kill`

#### What tool from the aircrack-ng suite is used to create a capture?

Answer: `airodump-ng`

#### What flag do you use to set the BSSID to monitor?

Hint: --help

Answer: `--bssid`

#### And to set the channel?

Hint: --help

Answer: `--channel`

#### And how do you tell it to capture packets to a file?

Hint: --help

Answer: `-w`

---------------------------------------------------------------------------

### Task 3: Aircrack-ng - Let's Get Cracking

I will attach a capture for you to practice cracking on. If you are spending more than 3 mins cracking, something is likely wrong. (A single core VM on my laptop took around 1min).

In order to crack the password, we can either use aircrack itself or create a hashcat file in order to use GPU acceleration. There are two different versions of hashcat output file, most likely you want 3.6+ as that will work with recent versions of hashcat.

#### Useful Information

- **BSSID**: `02:1A:11:FF:D9:BD`
- **ESSID**: `James Honor 8`

---------------------------------------------------------------------------

#### What flag do we use to specify a BSSID to attack?

Hint: aircrack-ng --help

Answer: `-b`

#### What flag do we use to specify a wordlist?

Hint: aircrack-ng --help

Answer: `-w`

#### How do we create a HCCAPX in order to use hashcat to crack the password?

Hint: aircrack-ng --help

Answer: `-j`

#### Using the rockyou wordlist, crack the password in the attached capture. What's the password?

Hint: Use aircrack and rockyou, or export a hashcat file and attack in on GPU with rockyou as the wordlist

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/Walkthroughs/Easy/Wifi_Hacking_101]
└─$ aircrack-ng -b '02:1A:11:FF:D9:BD' -w /usr/share/wordlists/rockyou.txt NinjaJc01-01.cap 
Reading packets, please wait...
Opening NinjaJc01-01.cap
Read 589 packets.

1 potential targets


                               Aircrack-ng 1.7 

      [00:00:21] 130457/14344392 keys tested (6074.65 k/s) 

      Time left: 38 minutes, 59 seconds                          0.91%

                        KEY FOUND! [ greeneggsandham ]


      Master Key     : 71 5F 17 D1 D7 9E 70 4D 6E 2E 9C AD 46 F5 45 F5 
                       AF 5E 43 48 16 F9 5B AA 14 8F 39 AA FC 5E EB 3B 

      Transient Key  : 3A E9 E7 C2 EC 1F BC 15 CC E1 E3 6F 8C DF 9C 6C 
                       69 BF D9 0A 1E 54 02 BE 4B 99 48 77 65 53 42 7E 
                       A8 10 F4 83 CD F0 B9 F6 A8 68 1A 85 C3 1C 16 30 
                       0E 57 1A 6B B2 08 B4 5B 3F A4 86 13 3B 2D E2 00 

      EAPOL HMAC     : 9A 6A 56 EE E4 4E 42 A3 14 71 26 9F E0 E2 93 04 
```

Answer: `greeneggsandham`

#### Where is password cracking likely to be fastest, CPU or GPU?

Answer: `GPU`

---------------------------------------------------------------------------

For additional information, please see the references below.

## References

- [Aircrack-ng - Docs](https://www.aircrack-ng.org/doku.php?id=Main)
- [Aircrack-ng - Homepage](https://aircrack-ng.org/)
- [Aircrack-ng - Kali Tools](https://www.kali.org/tools/aircrack-ng/)
- [Hashcat - Homepage](https://hashcat.net/hashcat/)
- [Hashcat - Kali Tools](https://www.kali.org/tools/hashcat/)
- [Hashcat - Wiki](https://hashcat.net/wiki/)
- [rockyou.txt wordlist - GitHub](https://github.com/zacheller/rockyou)
- [SSID - Wikipedia](https://en.wikipedia.org/wiki/Service_set_(802.11_network)#SSID)
- [Wi-Fi - Wikipedia](https://en.wikipedia.org/wiki/Wi-Fi)
- [Wi-Fi Protected Access - Wikipedia](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access)
- [Wired Equivalent Privacy - Wikipedia](https://en.wikipedia.org/wiki/Wired_Equivalent_Privacy)
