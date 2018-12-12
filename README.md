# Software-Security

## NETWORK SECURITY
[SCAPY for sending forged packets](https://scapy.readthedocs.io/en/latest/usage.html#starting-scapy)

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
* [GDB-Peda](https://github.com/longld/peda) [Cheatsheet](https://github.com/ebtaleb/peda_cheatsheet/blob/master/peda.md)

#### Decompilers
* [Snowman](https://derevenets.com/)
* [Retargetable Decompiler](https://retdec.com/)
* Binary Ninja has a medium-level IL

#### Online x86 assembler
* [Defuse](https://defuse.ca/online-x86-assembler.htm)

#### Security feature checker
* [Checksec.sh](https://github.com/slimm609/checksec.sh)

### Types of Attacks
#### Environment Variable Tampering
* HOME variable - If a binary is using HOME variable to create a path of a file, then the HOME variable can be tampered to call a different file with same name but malicious content.
* PATH variable - Whenever system files like ls, tidy is called in a binary it first check the PATH variable, if there is a match it calls the file with the matched path. If a path can be appended in the beginning of the PATH variable then the first match would be the path to the malicious file with same name. Also system functions like *execlp* uses PATH variable

#### Dot Dot Slash (../) Attack
In this attack using the ../ in a series, one can reach the root directory. The number of ../ doesn't matter to reach the root. Then one can append the path to a malicious file.

#### Egg Environment Variable Usage
Using putenv() one can add a shellcode to an environment variable. It is called planting an egg in the environment. Then get the address of the environment variable and somehow use this address to invoke the shell. This can be done in two ways. 
* Directly giving address of EGG If an integer array you can directly store address of EGG

```C
int main(int argc, char *argv[]
{
     int array[8];
     ...
     //Both index and value is being calculated from argv
     array[index] = value;
}
```

Here you can store the address of EGG to the 11th index and execute the shellcode when main returns 

* Address of Shellcode is prepended with NOP and appended with fillers and then with address of the NOPs so that it goes back to the shellcode

```Python
msg = "\x90"*100 + shellcode + "A"*65416 + "\xb8\xd6\xfd\xff"
```

FACT : Environment variables are present in the same stack area as the binary if one can create generate a shell with an EGG and in that shell run the binary
* Shellcodes are readily available [here](http://shell-storm.org/) but they depends on the system.

#### TOCTOU (Time to Check Time to Use) Attack
```C
//piece of code where access permission of file is checked
//Some amount of time in between access granted and file read 
//piece of code where file is read 
```
If, in this time between file access granted and actually read, a symlink is created for the file sensitive information like `/etc/passwd` or `/etc/shadow` then it can be read. Again it can be used to invoke shell if code for file execution is present instead of reading 
* Implementation : Run the binary in background using & and in foreground create a symlink of same name to a malicious file 
* FACT : The system does not check whether it is file or symlink

#### Overflowing char array
```C
#define BUFSIZE 512
  int main (int argc, char *argv[]) 
  { 
  char username[BUFSIZE]; 
  char password[BUFSIZE]; 
  ...
  strncpy(password, argv[1], BUFSIZE); 
  strncpy(username, argv[2], BUFSIZE);
  ...
  }
```
This can be overflowed using 
```Python
<name of binary> `python -c 'print "A"*512'` `python -c 'print "B"*8 +"\xdf\xd6\xff\xff"'
```
[Helpful Link](http://www.ouah.org/readmeneu.htm)
#### Overflowing a short variable
 ```C
 int main(int argc, char *argv[])
{
  char filename[256];
  long max;
  short len;
  ...
  len = strlen(argv[1]);
}
 ```
 Here the len variable is short(2B) can be overflowed. But we can improve it by repeating a series of NOPs followed by address of EGG variable 4096 times
 ```Python
 <name of binary> `python -c 'print "\x90\x90"+"\x90\x90\x90\x90\xdf\xd6\xff\xff"*4096'` <other arguments> 
 ```
 #### Format String Attacks
 [Resource](https://gbmaster.wordpress.com/2015/12/08/x86-exploitation-101-format-strings-ill-tell-ya-what-to-say/)

### Few Important Points to Note
* The very first step: Figure out the nature of the challenge. Is the stack executable? Is there [ASLR](https://searchsecurity.techtarget.com/definition/address-space-layout-randomization-ASLR) (or [PIE](https://eklitzke.org/position-independent-executables)) involved?
* Look for system calls, array with hard-coded array sizes or offsets, excessive number of type castings
* Eggcode compilation to enable hacking
 ```C
 gcc -Wall -O0 -g -fno-omit-frame-pointer -Wno-deprecated-declarations -D_FORTIFY_SOURCE=0 -fno-pie -Wno-format -Wno-format-security -z norelro -z execstack -fno-stack-protector -m32 -mpreferred-stack-boundary=2 -o eggcodefish eggcodefish.c
 ```

* [How to keep argc = 0](https://stackoverflow.com/questions/8113786/executing-a-process-with-argc-0) or How to keep argc = 0 but pass argv ?
```C
char *argv[]={ NULL};
char *envp[]={"b","c","d",payload,value,NULL};
execve("<path to binary>", argv,envp );
```

* If the address of the EGG variable is "\xff\xff\xd6\xdf" then it should be written as "\xdf\xd6\xff\xff"
* Tips to find which part of string is being taken as EIP. Pass a string like "AAAABBBBCCCCDDDD...." and use gdb-peda to see what is the EIP value when there is segmentation fault. Then replace the EGG variable addresss in place of that part of string. 

* [strncpy Issue](https://blogs.msdn.microsoft.com/oldnewthing/20050107-00/?p=36773/) - Checks \0 at end and so can be overflowed
* [snprintf Issue](https://access.redhat.com/blogs/766093/posts/1976193)
* Some good resources : 
[Exploit stack-based buffer overflow using NOP-sled technique](https://lthieu.wordpress.com/2012/11/10/exploit-stack-based-buffer-overflow-using-nop-sled-technique/) 
[Shellcode Injection](https://dhavalkapil.com/blogs/Shellcode-Injection/) 
[Shellcode and EGG](https://www.tenouk.com/Bufferoverflowc/bufferoverflowvulexploitdemo32.html) 
[Buffer Overflow](https://www.tenouk.com/Bufferoverflowc/Bufferoverflow6.html) 
[EGG and its address](https://stackoverflow.com/questions/14885716/getting-address-of-environmental-variable)
[GDB Stack Prints](https://shankaraman.wordpress.com/tag/finding-environment-variable-address-on-stack/)
[Very nice deta)iled Stack Smashing](https://insecure.org/stf/smashstack.html)
[Linux Privilege Escalation](https://www.hackingarticles.in/linux-privilege-escalation-via-automated-script/)
[captf](http://captf.com/practice-ctf/)


## WEB EXPLOITATION

* Php
* JavaScript
* C
* Sqlite
* MySql
* cUrl

* https://null-byte.wonderhowto.com/how-to/exploit-php-file-inclusion-web-apps-0179955/
* [Php Security](http://phpsec.org/projects/guide/)

[User-Agent Based](https://betanews.com/2017/03/22/user-agent-based-attacks-are-a-low-key-risk-that-shouldnt-be-overlooked/)
[Setting User-Agent](https://www.cyberciti.biz/faq/curl-set-user-agent-command-linux-unix/)


## CTF:

* [SSH SOCKS proxy](https://www.digitalocean.com/community/tutorials/how-to-route-web-traffic-securely-without-a-vpn-using-a-socks-tunnel) An example command is listed here: ssh -D 8888 -C -q -N -i <path_to_your_private_key> ctf@<ip_of_your_game_box>, which will create a SOCKS proxy listening at localhost TCP port 8888. You may then setup the SOCKS proxy for your browser.

* [Port Forwarding](https://askubuntu.com/questions/414930/access-webpage-through-ssh)
```
ssh root@<GAMEBOXIP> -p1338 -i<sshprivatekey> -L20001:localhost:20001 -L20002:localhost:20002 -L20003:localhost:20003
open in browser : localhost:20001-3
Each of the numbers(20001,20002,20003) are the ports of the services on the gamebox
```

* TCP Dump
There should always be one person to take tcpdump and analyze the traffic to see the exploit on themselves and replicate them. Might be a good idea to customize the analyzer for pcap files generated by tcpdump to read per port and ip traffic since the services will be running per port 
* Monitor the hack scripts
Always check that the hacks, backdoors created are still running even if executed with a nohup
* SUID problems are where one can get access of shellwith the permission same as that of the binary. This is also called privilege escalation
* [CTF-Training by Adam Doupe](https://github.com/adamdoupe/ctf-training)
* [CTF-Writeups](https://github.com/ctfs)
* [Web-CTF](https://www.youtube.com/watch?v=XJTYramNfEw)
* [CTF Resources](https://resources.infosecinstitute.com/tools-of-trade-and-resources-to-prepare-in-a-hacker-ctf-competition-or-challenge/#gref)
* [CTF Repository](http://captf.com/)


## Various Attack Types
* *XPATH Injection*
* *SQL Injection*: [Sqlite3 Injection](http://atta.cked.me/home/sqlite3injectioncheatsheet)
* *[XSS Injection](https://www.youtube.com/playlist?list=PL1A2CSdiySGIRec2pvDMkYNi3iRO89Zot)*
      : *Using Webhooks* like [requestbin](https://requestbin.fullcontact.com/), [hookb](https://hookbin.com/), [Webhook](https://webhook.site)
* *Privilege Escalation* 

## Other Resources
[Adam Doupe](https://github.com/adamdoupe)
[Pwndevils](https://pwndevils.com/hacking/howtwohack.html)
[Awesome-Hacking-Resources](https://github.com/vitalysim/Awesome-Hacking-Resources)
[Overthewire Bandit](http://overthewire.org/wargames/bandit/)
