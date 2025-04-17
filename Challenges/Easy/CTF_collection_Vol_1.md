# CTF collection Vol.1

- [Room information](#room-information)
- [Solution](#solution)
- [References](#references)

## Room information

```text
Type: Challenge
Difficulty: Easy
OS: N/A
Subscription type: Free
Description: Sharpening up your CTF skill with the collection. The first volume is designed for beginner.
```

Room link: [https://tryhackme.com/r/room/ctfcollectionvol1](https://tryhackme.com/r/room/ctfcollectionvol1)

## Solution

### What does the base said?

`Description: Can you decode the following?`

This is [base64](https://en.wikipedia.org/wiki/Base64) and you can convert it to ASCII with [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)), `base64` in bash, or with the base64 module in Python.

Convert using bash

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ echo 'VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ==' | base64 -d                            
THM{<REDACTED>}   
```

Convert with a simple python script

```python
#!/usr/bin/python
# -*- coding: latin-1 -*-

import base64

encoded_flag = b'VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ=='

print(base64.b64decode(encoded_flag).decode())
```

Then run the script to get the flag

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ python task2.py 
THM{<REDACTED>}
```

### Meta meta

`Description: Meta! meta! meta! meta...................................`

After downloading the file, we check for [metadata](https://en.wikipedia.org/wiki/Metadata) with `exiftool`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ exiftool Findme.jpg 
ExifTool Version Number         : 12.52
File Name                       : Findme.jpg
Directory                       : .
File Size                       : 35 kB
File Modification Date/Time     : 2020:10:07 08:06:58+02:00
File Access Date/Time           : 2024:09:28 09:05:54+02:00
File Inode Change Date/Time     : 2020:10:07 08:06:58+02:00
File Permissions                : -rwxrwxrwx
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 96
Y Resolution                    : 96
Exif Byte Order                 : Big-endian (Motorola, MM)
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
Flashpix Version                : 0100
Owner Name                      : THM{<REDACTED>}
Comment                         : CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), quality = 60.
Image Width                     : 800
Image Height                    : 480
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 800x480
Megapixels                      : 0.384
```

And there in the `Owner Name` field, we have the flag.

### Mon, are we going to be okay?

`Description: Something is hiding. That's all you need to know.`

The description `Something is hiding` likely points to [steganography](https://en.wikipedia.org/wiki/Steganography).  
One commonly used program for this is `steghide`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ steghide extract -sf Extinction.jpg          
Enter passphrase: 
wrote extracted data to "Final_message.txt".

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ cat Final_message.txt 
It going to be over soon. Sleep my child.

THM{<REDACTED>}
```

### Erm......Magick

`Description: Huh, where is the flag?`

The flag is written in white text above and after the periods in the description.  
One easy way to see it is to select all text in the browser with `CTRL + A`.

### QRrrrr

`Description: Such technology is quite reliable.`

The image is a [QR code](https://en.wikipedia.org/wiki/QR_code) and you can convert it with an online service such as [CyberChef](https://gchq.github.io/CyberChef/#recipe=Parse_QR_Code(false)) or [ZXing Decoder Online](https://zxing.org/w/decode.jspx), or  
with the `zbarimg` tool from the `zbar-tools` package.

Decode with `zbarimg`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ zbarimg QR.png 
QR-Code:THM{<REDACTED>}
scanned 1 barcode symbols from 1 images in 0.01 seconds
```

### Reverse it or read it?

`Description: Both works, it's all up to you.`

We start by checking the file type with `file`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ file hello.hello 
hello.hello: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=02900338a56c3c8296f8ef7a8cf5df8699b18696, for GNU/Linux 3.2.0, not stripped
```

We have an 64-bit [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) binary.

Let's check for [strings](https://en.wikipedia.org/wiki/String_(computer_science)) and `grep` for the flag

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ strings -n 8 hello.hello | grep THM
THM{<REDACTED>}
```

### Another decoding stuff

`Description: Can you decode it?`

This is Base58 and you can decode it with online services such as [Code Beautify](https://codebeautify.org/base58-decode) or [CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Base58('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')).

Or we can use the `base58` tool from the `base58` package

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ echo '3agrSy1CewF9v8ukcSkPSYm3oKUoByUpKG4L' | base58 -d
THM{<REDACTED>}
```

### Left or right

`Description: Left, right, left, right... Rot 13 is too mainstream. Solve this`

The text is rotated 7 steps (ROT-7) rather than the common 3 steps as in a caesar cipher or 13 steps as in ROT13.

You can decode the text with [CyberChef](https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,7)).

Alternatively, you can brute-force the number of steps with the `caesar` tool from the [bsdgames](https://wiki.linuxquestions.org/wiki/BSD_games) package.

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ for i in $(seq 1 25); do echo -n "$i: "; echo 'MAF{atbe_max_vtxltk}' | caesar $i; done
1: NBG{bucf_nby_wuymul}
2: OCH{cvdg_ocz_xvznvm}
3: PDI{dweh_pda_ywaown}
4: QEJ{exfi_qeb_zxbpxo}
5: RFK{fygj_rfc_aycqyp}
6: SGL{gzhk_sgd_bzdrzq}
7: THM{<REDACTED>}
8: UIN{ibjm_uif_dbftbs}
9: VJO{jckn_vjg_ecguct}
10: WKP{kdlo_wkh_fdhvdu}
11: XLQ{lemp_xli_geiwev}
12: YMR{mfnq_ymj_hfjxfw}
13: ZNS{ngor_znk_igkygx}
14: AOT{ohps_aol_jhlzhy}
15: BPU{piqt_bpm_kimaiz}
16: CQV{qjru_cqn_ljnbja}
17: DRW{rksv_dro_mkockb}
18: ESX{sltw_esp_nlpdlc}
19: FTY{tmux_ftq_omqemd}
20: GUZ{unvy_gur_pnrfne}
21: HVA{vowz_hvs_qosgof}
22: IWB{wpxa_iwt_rpthpg}
23: JXC{xqyb_jxu_squiqh}
24: KYD{yrzc_kyv_trvjri}
25: LZE{zsad_lzw_uswksj}
```

### Make a comment

`Description: No downloadable file, no ciphered or encoded text. Huh .......`

The flag is hidden in the HTML-code.

Select the `Huh .......` text in the browser, right-click and select `Inspect` and then expand the `<p style="display:none;">` tag to view the flag which is broken up in two parts.

### Can you fix it?

`Description: I accidentally messed up with this PNG file. Can you help me fix it? Thanks, ^^`

Let's view the file header with `xxd`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ xxd -l 48 spoil.png 
00000000: 2333 445f 0d0a 1a0a 0000 000d 4948 4452  #3D_........IHDR
00000010: 0000 0320 0000 0320 0806 0000 00db 7006  ... ... ......p.
00000020: 6800 0000 0173 5247 4200 aece 1ce9 0000  h....sRGB.......
```

If we check [this list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) we can see that the first 4 bytes of PNG-images should be the text `‰PNG` or `89 50 4E 47` in hexadecimal.

So we fix the file with `echo` and `dd`

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ echo -en '\x89\x50\x4e\x47' > fixed_spoil.png 

┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ dd skip=4 bs=1 if=spoil.png >> fixed_spoil.png
70755+0 records in
70755+0 records out
70755 bytes (71 kB, 69 KiB) copied, 15.7077 s, 4.5 kB/s
```

Then we can view the fixed image with `eog`, `feh` or any other tool of our choice.

### Read it

`Description: Some hidden flag inside Tryhackme social account.`

The hint says `reddit` so we can Google for `"THM{" site:www.reddit.com/r/tryhackme/`.  
Because a lot of time has passed since this room was released we might need to limit the dates with  
`"THM{" before:2020-12-31 after:2020-01-01 site:www.reddit.com/r/tryhackme/`

You will find the flag under the image in this post:
`https://www.reddit.com/r/tryhackme/comments/eizxaq/new_room_coming_soon/`

### Spin my head

`Description: What is this?`

This is an [esoteric programming language](https://en.wikipedia.org/wiki/Esoteric_programming_language) called [Brainfuck](https://en.wikipedia.org/wiki/Brainfuck).

You can decode/execute Brainfuck you with online services such as [dcode.fr](https://www.dcode.fr/brainfuck-language), [copy.sh](https://copy.sh/brainfuck/), or [md5decrypt.net](https://md5decrypt.net/en/Brainfuck-translator/).

### An exclusive!

`Description: Exclusive strings for everyone!`

Both strings are hexadecimal numbers. The `S1` string is the [ASCII](https://en.wikipedia.org/wiki/ASCII) characters that [XORed](https://en.wikipedia.org/wiki/Exclusive_or) with `S2` produces the flag.

You can decode the `S1` string with [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'10'%7D,'Standard',false)) to get the flag.

Alternatively, you can write a small Python script to decode it

```python
#!/usr/bin/python
# -*- coding: latin-1 -*-

def xor(var, key):
    return bytes(a ^ b for a, b in zip(var, key))

S1 = bytes.fromhex("44585d6b2368737c65252166234f20626d")
S2 = bytes.fromhex("1010101010101010101010101010101010")

print(xor(S1, S2).decode())
```

Then run the script to get the flag

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ python task14.py
THM{<REDACTED>}
```

### Binary walk

`Description: Please exfiltrate my file :)`

The challenge name referes to the [binwalk](https://github.com/ReFirmLabs/binwalk) tool.

We can use `binwalk` to recursively extract embedded files from the image

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ binwalk -Me hell.jpg 

Scan Time:     2024-09-28 13:50:57
Target File:   /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1/hell.jpg
MD5 Checksum:  70274357b4c2eb0d1500b42716e713ed
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.02
30            0x1E            TIFF image data, big-endian, offset of first image directory: 8
265845        0x40E75         Zip archive data, at least v2.0 to extract, uncompressed size: 69, name: hello_there.txt
266099        0x40F73         End of Zip archive, footer length: 22


Scan Time:     2024-09-28 13:50:57
Target File:   /mnt/hgfs/Wargames/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1/_hell.jpg.extracted/hello_there.txt
MD5 Checksum:  cff37a0b9c256750fa19ad3ae5f5ff2b
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
```

Then we check the text file

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ cat _hell.jpg.extracted/hello_there.txt 
Thank you for extracting me, you are the best!

THM{<REDACTED>}
```

### Darkness

`Description: There is something lurking in the dark.`

The description `lurking in the dark` likely points to another [steganography](https://en.wikipedia.org/wiki/Steganography) challenge.  
Another commonly used stego-program is `stegsolve`.

Open the image in `stegsolve` and step left/back with the buttons at the bottom of the tool.  
With the `Gray bits` mode you should see the flag.

### A sounding QR

`Description: How good is your listening skill?`

First we decode the QR-image to text

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ zbarimg QRCTF.png 
QR-Code:https://soundcloud.com/user-86667759/thm-ctf-vol1
scanned 1 barcode symbols from 1 images in 0.01 seconds
```

Then we visit the SoundCloud site (`https://soundcloud.com/user-86667759/thm-ctf-vol1`) and listen to the message.

It's very hard to hear but fortunately someone has posted the flag in the comments.  
Just convert it to uppercase and wrap it in `THM{<the_flag>}`.

### Dig up the past

`Description: Sometimes we need a 'machine' to dig the past`

The description is referring to [Wayback Machine](https://web.archive.org/) where you can search and read old archived web pages.

Search for `https://www.embeddedhacker.com/` and select 2020 on the timeline.  
Then select `January 2, 2000` and select the only snapshot time available.  

You will be redirected to `https://web.archive.org/web/20200102131252/https://www.embeddedhacker.com/` where you will find the flag in the `THM flag` post.

### Uncrackable!

`Description: Can you solve the following? By the way, I lost the key. Sorry >.<`

This is a substitution cipher called [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher).

The easiest way to solve this is to use the [Guballa.de Vigenère Solver](https://www.guballa.de/vigenere-solver).  
You can use the default setting on the service to get the flag.

### Small bases

`Description: Decode the following text.`

The "text" is a large deciaml number and you can get the flag by converting the number to hexadecimal and then to ASCII-characters.

One way to do it is to use the tools `bc` and `xxd` in bash

```bash
┌──(kali㉿kali)-[~]
└─$ echo "ibase=10;obase=16;581695969015253365094191591547859387620042736036246486373595515576333693" | bc | xxd -r -p
THM{<REDACTED>}   
```

Another way is to write a small Python script

```python
#!/usr/bin/python
# -*- coding: latin-1 -*-

dec = 581695969015253365094191591547859387620042736036246486373595515576333693
hex = hex(dec)[2:]

print(bytearray.fromhex(hex).decode())
```

Then we run the script to get the flag

```bash
┌──(kali㉿kali)-[/mnt/…/TryHackMe/CTFs/Easy/CTF_Collection_Vol.1]
└─$ python task20.py                                       
THM{<REDACTED>}
```

### Read the packet

`Description: I just hacked my neighbor's WiFi and try to capture some packet. He must be up to no good. Help me find it.`

Open the PCAPNG-file in [Wireshark](https://www.wireshark.org/).  
Apply a display filter of `frame contains "flag"` and you will get only one matching packet.

Right-click on the packet and select `Follow` and then `HTTP Stream`.  
A new windows pops up and include the flag at the end of the conversation

```text
GET /flag.txt HTTP/1.1
Host: 192.168.247.140
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Fri, 03 Jan 2020 04:36:45 GMT
If-None-Match: "e1bb7-15-59b34db67925a"
Cache-Control: max-age=0


HTTP/1.1 200 OK
Date: Fri, 03 Jan 2020 04:43:14 GMT
Server: Apache/2.2.22 (Ubuntu)
Last-Modified: Fri, 03 Jan 2020 04:42:12 GMT
ETag: "e1bb7-20-59b34eee33e0c"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 52
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/plain

THM{<REDACTED>}

Found me!
```

For additional information, please see the references below.

## References

- [ASCII - Wikipedia](https://en.wikipedia.org/wiki/ASCII)
- [base64 - Linux manual page](https://man7.org/linux/man-pages/man1/base64.1.html)
- [Base64 - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [bc - Linux manual page](https://man7.org/linux/man-pages/man1/bc.1p.html)
- [Binwalk - Github](https://github.com/ReFirmLabs/binwalk)
- [Binwalk - Kali Tools](https://www.kali.org/tools/binwalk/)
- [Brainfuck - Wikipedia](https://en.wikipedia.org/wiki/Brainfuck)
- [CyberChef - Homepage](https://gchq.github.io/CyberChef/)
- [dd - Linux manual page](https://man7.org/linux/man-pages/man1/dd.1.html)
- [echo - Linux manual page](https://man7.org/linux/man-pages/man1/echo.1.html)
- [Esoteric programming language - Wikipedia](https://en.wikipedia.org/wiki/Esoteric_programming_language)
- [Exclusive or - Wikipedia](https://en.wikipedia.org/wiki/Exclusive_or)
- [Executable and Linkable Format - Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [exiftool - Linux manual page](https://linux.die.net/man/1/exiftool)
- [ExifTool - Wikipedia](https://en.wikipedia.org/wiki/ExifTool)
- [file - Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [grep - Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [Hexadecimal - Wikipedia](https://en.wikipedia.org/wiki/Hexadecimal)
- [List of file signatures - Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)
- [Metadata - Wikipedia](https://en.wikipedia.org/wiki/Metadata)
- [QR code - Wikipedia](https://en.wikipedia.org/wiki/QR_code)
- [ROT13 - Wikipedia](https://en.wikipedia.org/wiki/ROT13)
- [Steganography - Wikipedia](https://en.wikipedia.org/wiki/Steganography)
- [steghide - Homepage](https://steghide.sourceforge.net/)
- [steghide - Kali Tools](https://www.kali.org/tools/steghide/)
- [stegsolve 1.3 - Homepage](http://www.caesum.com/handbook/stego.htm)
- [stegsolve 1.4 - Github](https://github.com/Giotino/stegsolve)
- [String (computer science) - Wikipedia](https://en.wikipedia.org/wiki/String_(computer_science))
- [strings - Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [Vigenère cipher - Wikipedia](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
- [Wireshark - Homepage](https://www.wireshark.org/)
- [xxd - Linux manual page](https://linux.die.net/man/1/xxd)
- [zbarimg - Linux manual page](https://linux.die.net/man/1/zbarimg)
