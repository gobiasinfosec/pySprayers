# rpcSpray/Password Spraying
This python script uses rpcclient to attempt to connect to an rpcserver and spray simple passwords. 

### Usage:
python3 rpcSpray.py -u user -p password -t 127.0.0.1 -o output.txt

python3 rpcSpray.py -U userlist.txt -P passwordlist.txt -t 127.0.0.1 -o output.txt

-------------------------------------------------------------------------------------------------------

# imapBruteForce/Password Spraying
This python script can be used to brute force imap logins where account lockout has not been turned off or disabled for imap logins.

It may also be used as a password spraying script.


This script is just designed to be a proof of concept and will download and print the first email in the mailbox within the python shell.

It has not (yet) been optimized for threading. 

### Notes/Dependencies:
-Written for Python3.5
-Requires the imapclient library (pip3 install imapclient)

-------------------------------------------------------------------------------------------------------

### Disclaimer:
-This tool has been provided for testing and academic purposes only. Do not use this tool on accounts that you do not own or have express/strict written consent to test against. Do not use for illegal purposes!
