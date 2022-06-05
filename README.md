# Head against wall writeup for tryhackme

1) Let's start by scanning with nmap!!
command :
nmap -sC -sT -A TAGRET_IP
output:

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 2c:25:1c:4b:b4:15:1b:07:32:97:84:f3:04:88:a1:9d (RSA)
|_  256 bf:ef:ca:99:aa:de:3d:5e:9c:4d:e7:2b:9f:73:45:86 (ECDSA)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.54 seconds
'''
# We can see that anonymous login for ftp is allowed, so let's check it out by command "ftp TARGET_IP"
	username: anonymous
	password: <BLANK>
# There is no file in there, but two files are hidden we can use "ls -la" command to see that
	ftp> ls -la
	200 PORT command successful. Consider using PASV.
	150 Here comes the directory listing.
	drwxr-xr-x    2 1001     118          4096 May 31 07:56 .
	drwxr-xr-x    2 1001     118          4096 May 31 07:56 ..
	-rw-r--r--    1 0        0              80 May 31 07:54 .password
	-rw-r--r--    1 0        0              72 May 31 07:56 .username
	226 Directory send OK.

let's get that two files by command "get .username" and then "get .password"
exit out of the server and looking at the files


command 
'''bash
"cat .username" :
	hello my friend,
                for username please visit our website at $port(80)

'''
command 
'''bash
"cat .password"
	4a564b45344d44434b5247585159544d484641555552525a504648454f53544a4a564d464350493d

password seems to be in hex format decrypting that gives you a base32 and that gives base64 string

decrytping the base64 string gives you the password for particular user
'''
 we can ssh bruteforce the username, but as .username says let's check out the web server


# Bruteforcing web directories by command :
	gobuster dir -u http://TARGET_IP -w PATH_TO_dirbuster_medium-2.3.txt 

output:
	login.php
	robots.txt
	user
	pass
	id_rsa
	public

I know some of these are rabbit holes, because I intentionally made that way

file "user" gives us a strange strins, which is sha1 hash
	you can decrypt here https://hashtoolkit.com/decrypt-sha1-hash/

ssh to username and password that you got above

you can see flag1.txt is present but, you can't see
try command : cat * ( to see every files present in that directory ) or 
there you will get flag THM{REDACTED}

and you can see the fernet__key.txt and fernet__token.txt, Which is a cryptography module in python

write a simple python script in your local machine
'''python
#!/usr/bin/env python3

from cryptography.fernet import Fernet

key = b'[fernet__key]'

token = b'[fernet__token]'

f = Fernet(key)
d = f.decrypt(token)
print(d)
'''


This gives us the password for holi user
b'The password for holi is [REDACTED]'

switching user to holi with that password

su holi

Then you can see user.txt in home directory

command : sudo -l

gives that user holi can run any commands with sudo
so, typing "sudo su root" gives us quick root shell


# Finding and getting root's flag

the file named hint.txt says that we should see the file named "-"
Which is a $OLDPWD you cannot cat that file, so specifying the filename in the current directorygives us another hint

command : cat ./-

it says we should find the root flag

command : find / -type f -name root.txt

output: /opt/.root_flag/root.txt

where it says b'\x80\x04\x95\x1b\x00\x00\x00\x00\x00\x00\x00\x8c\x17T\x90HM\x90{-\x90_1s\x90_@w\x90som3_468256}\x94.'

as per the hint.txt we should first remove the \x90 and we unpickle the object

# remove '\x90' in that string and you will get flag at very end 

THM[REDACTED]

hope this room was fun.....
Thankyou




