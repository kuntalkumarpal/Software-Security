# Software-Security

strncpy Issue :
https://blogs.msdn.microsoft.com/oldnewthing/20050107-00/?p=36773/




Resources:
[Adam Doupe](https://github.com/adamdoupe)




FORENSICS

* https://medium.com/@thereallulz/write-up-codebattle-2018-forensics-and-web-final-round-by-thereallulz-dfe05601e0ea
* https://github.com/DominicBreuker/stego-toolkit
* https://medium.com/@FourOctets/ctf-tidbits-part-1-steganography-ea76cc526b40
* [ZipCracker](https://github.com/hyc/fcrackzip)(http://oldhome.schmorp.de/marc/fcrackzip.html)
* https://www.aldeid.com/wiki/Xortool#Installationhttps://www.aldeid.com/wiki/Xortool#Installation
* https://ctfs.github.io/resources/topics/steganography/invisible-text/README.html



BINARY ANALYSIS

Disassemblers
* [Binary Ninja](https://binary.ninja/)
* [IDA](https://www.hex-rays.com/products/ida/)
* [Angr Management](https://github.com/angr/angr-management)
* [GDB-Peda](https://github.com/longld/peda)
Decompilers
* [Snowman](https://derevenets.com/)
* [Retargetable Decompiler](https://retdec.com/)
* Binary Ninja has a medium-level IL

Online x86 assembler
* [Defuse](https://defuse.ca/online-x86-assembler.htm)
Security feature checker
* [Checksec.sh](https://github.com/slimm609/checksec.sh)

Techniques :
* The very first step: Figure out the nature of the challenge. Is the stack executable? Is there [ASLR](https://searchsecurity.techtarget.com/definition/address-space-layout-randomization-ASLR) (or [PIE](https://eklitzke.org/position-independent-executables)) involved?


CTF:

* [SSH SOCKS proxy](https://www.digitalocean.com/community/tutorials/how-to-route-web-traffic-securely-without-a-vpn-using-a-socks-tunnel) An example command is listed here: ssh -D 8888 -C -q -N -i <path_to_your_private_key> ctf@<ip_of_your_game_box>, which will create a SOCKS proxy listening at localhost TCP port 8888. You may then setup the SOCKS proxy for your browser.



WEB EXPLOITATION

* Php
* JavaScript
* C
* Sqlite
* MySql
* cUrl

* https://null-byte.wonderhowto.com/how-to/exploit-php-file-inclusion-web-apps-0179955/
* (Php Security)[http://phpsec.org/projects/guide/]

[User-Agent Based](https://betanews.com/2017/03/22/user-agent-based-attacks-are-a-low-key-risk-that-shouldnt-be-overlooked/)
[Setting User-Agent](https://www.cyberciti.biz/faq/curl-set-user-agent-command-linux-unix/)

* XPATH Injection
* SQL Injection
* [XSS Injection](https://www.youtube.com/playlist?list=PL1A2CSdiySGIRec2pvDMkYNi3iRO89Zot)
      *Using Webhooks: Requestbin, 
* 
