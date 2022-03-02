#!/usr/bin/python

import getpass
import ipaddress
import os
import time

from impacket.smb import SMB_DIALECT
from slugify import slugify

from arg_parser import setup_command_line_args, Options
from print import printStatus, Colors
from scan import scanRange, scanSingle

class User:
    def __init__(self, username="Guest", password="", domain="", lmhash="", nthash=""):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.results = []


def validIP(addr):
    try:
        ipaddress.IPv4Network(str(addr))
        return True
    except ipaddress.AddressValueError:
        return False


def main():
    args = setup_command_line_args()
    os.makedirs("logs", exist_ok=True)

    options = Options()
    options.jitter = args.jitter
    options.timeout = args.timeout
    options.logFileName = args.logFileName
    options.outputLogFileName = (
        "logs/smbscan-" + time.strftime("%Y%m%d-%H%M%S") + ".log"
    )
    options.crawlShares = not args.shares
    options.maximumDepth = args.maximumDepth
    if str(args.inclusionList) != "None":
        options.inclusionList = str(args.inclusionList).split(",")
    if str(args.exclusionList) != "None":
        options.exclusionList = str(args.exclusionList).split(",")

    user = User()
    if args.user:
        user.username = args.user
        user.password = args.password if args.password else getpass.getpass()
        user.domain = args.domain if args.domain else ""

    if args.target:
        printStatus(None, Colors.OKGREEN, "Scanning %1s" % (args.target), options)
        if validIP(args.target):
            scanRange(args.target, user, options)
        else:
            scanSingle(args.target, user, options)
    else:
        with args.file as file:
            target = file.readline().strip()
            while target:
                printStatus(None, Colors.OKGREEN, "Scanning %1s" % (target), options)
                if validIP(target):
                    scanRange(target, user, options)
                else:
                    scanSingle(target, user, options)
                target = file.readline().strip()

    printStatus(None, Colors.OKGREEN, "FINISHED", options)


if __name__ == "__main__":
    main()
