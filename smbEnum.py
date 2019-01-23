#! python3
# smbEnum.py -v 1.0
# Author- David Sullivan
#
# enumerate smb shares with valid creds (or sprayed ones, it doesn't matter!)

import subprocess, argparse


def write_output(answer, user, target_ip, output):
    file = open(output, 'a+')
    file.write("Connecting with %s on %s" % (user, target_ip))
    file.write(answer)
    file.write('\n---------------------------------\n')
    file.close()


def smb_login(domain, creds, targets, output):
    print("Running")
    for target_ip in targets:
        print("Running against %s" % target_ip)
        for cred in creds:
            user, password = cred.split(':')
            password = password.replace("\n", "")
            arguments = 'smbclient -U "%s\%s%%%s" -L %s' % (domain, user, password, target_ip)
            response = subprocess.Popen(arguments, shell=True, stdout=subprocess.PIPE).stdout
            answer = (response.read()).decode()
            write_output(answer, user, target_ip, output)
    print("Complete")


def main():
    parser = argparse.ArgumentParser(description='Enumerate SMB Shares with Valid Creds')
    parser.add_argument('-d', '--domain', help='Domain name')
    parser.add_argument('-c', '--creds', help="Working creds in 'user:pass' format")
    parser.add_argument('-C', '--creds_file', help="Location of file containing working creds")
    parser.add_argument('-t', '--target', help="Target IP Address")
    parser.add_argument('-T', '--target_list', help="Location of file containing list of targets")
    parser.add_argument('-o', '--output', help="Output file name")
    args = parser.parse_args()

    creds = []
    if args.creds_file is not None:
        creds_doc = args.creds_file
        creds_import = open(creds_doc, 'r')
        for cred in creds_import:
            creds.append(cred)
    if args.creds is not None:
        creds.append(args.creds)

    targets = []
    if args.target_list is not None:
        target_doc = args.target_list
        target_import = open(target_doc, 'r')
        for target in target_import:
            targets.append(target)
    if args.target is not None:
        targets.append(args.target)

    domain = args.domain

    if args.output is not None:
        output = args.output
    else:
        output = None

    smb_login(domain, creds, targets, output)


main()
