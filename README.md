# Software-Security

strncpy Issue :
https://blogs.msdn.microsoft.com/oldnewthing/20050107-00/?p=36773/




Resources:
[Adam Doupe](https://github.com/adamdoupe)




## FORENSICS

* https://medium.com/@thereallulz/write-up-codebattle-2018-forensics-and-web-final-round-by-thereallulz-dfe05601e0ea
* https://github.com/DominicBreuker/stego-toolkit
* https://medium.com/@FourOctets/ctf-tidbits-part-1-steganography-ea76cc526b40
* [ZipCracker](https://github.com/hyc/fcrackzip)(http://oldhome.schmorp.de/marc/fcrackzip.html)
* https://www.aldeid.com/wiki/Xortool#Installationhttps://www.aldeid.com/wiki/Xortool#Installation
* https://ctfs.github.io/resources/topics/steganography/invisible-text/README.html



## BINARY ANALYSIS

### Tools
#### Disassemblers
* [Binary Ninja](https://binary.ninja/)
* [IDA](https://www.hex-rays.com/products/ida/)
* [Angr Management](https://github.com/angr/angr-management)
* [GDB-Peda](https://github.com/longld/peda)

#### Decompilers
* [Snowman](https://derevenets.com/)
* [Retargetable Decompiler](https://retdec.com/)
* Binary Ninja has a medium-level IL

#### Online x86 assembler
* [Defuse](https://defuse.ca/online-x86-assembler.htm)

#### Security feature checker
* [Checksec.sh](https://github.com/slimm609/checksec.sh)

### Techniques :
* The very first step: Figure out the nature of the challenge. Is the stack executable? Is there [ASLR](https://searchsecurity.techtarget.com/definition/address-space-layout-randomization-ASLR) (or [PIE](https://eklitzke.org/position-independent-executables)) involved?
* SUID problems, Privilege escalation
- Look for system calls, array with hard-coded array sizes or offsets, excessive number of type castings
- Symlink Creation
- Memory Corruption
- Environment Variable Tampering
* HOME variable - If a binary is using HOME variable to create a path of a file, then the HOME variable can be tampered to call a different file with same name but malicious content.
* PATH variable - Whenever system files like ls, tidy is called in a binary it first check the PATH variable, if there is a match it calls the file with the matched path. If a path can be appended in the beginning of the PATH variable then the first match would be the path to the malicious file with same name. Also system functions like *execlp* uses PATH variable

- Dot Dot Slash (../) Attack
In this attack using the ../ in a series, one can reach the root directory. The number of ../ doesn't matter to reach the root. Then one can append the path to a malicious file.

- Egg Environment Variable Usage
Using putenv() one can add a shellcode to an environment variable. It is called planting an egg in the environment. Then get the address of the environment variable and somehow use this address to invoke the shell. This can be done in two ways. 1) If an integer array you can directly store address of EGG

     `int main(int argc, char *argv[]
     {
          int array[8];
          ...
          //Both index and value is being calculated from argv
          array[index] = value;
     }`

Here you can store the address of EGG to the 11th index and execute the shellcode when main returns 
FACT : Environment variables are present in the same stack area as the binary if one can create generate a shell with an EGG and in that shell run the binary

- TOCTOU (Time to Check Time to Use) Attack
`//piece of code where access permission of file is checked
//Some amount of time in between access granted and file read 
//piece of code where file is read `
If, in this time between file access granted and actually read, a symlink is created for the file sensitive information like /etc/passwd or /etc/shadow then it can be read. Again it can be used to invoke shell if code for file execution is present instead of reading 
FACT : The system does not check whether it is file or symlink

## WEB EXPLOITATION

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


## CTF:

* [SSH SOCKS proxy](https://www.digitalocean.com/community/tutorials/how-to-route-web-traffic-securely-without-a-vpn-using-a-socks-tunnel) An example command is listed here: ssh -D 8888 -C -q -N -i <path_to_your_private_key> ctf@<ip_of_your_game_box>, which will create a SOCKS proxy listening at localhost TCP port 8888. You may then setup the SOCKS proxy for your browser.

## Various Attacks
* XPATH Injection
* SQL Injection
* [XSS Injection](https://www.youtube.com/playlist?list=PL1A2CSdiySGIRec2pvDMkYNi3iRO89Zot)
      * Using Webhooks: [requestbin](https://requestbin.fullcontact.com/), [hookb](https://hookbin.com/)
* 
