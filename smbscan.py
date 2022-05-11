#!/usr/bin/python
__author__ = "jeffhacks"

import getpass
import ipaddress
import logging
import os
import sys
import time

from impacket.smb import SMB_DIALECT
from slugify import slugify
from logging import handlers #import logging.handlers as handlers

from arg_parser import setup_command_line_args, Options
from scan import scan_range, scan_single, User


def valid_ip(addr):
    try:
        ipaddress.IPv4Network(str(addr))
        return True
    except ipaddress.AddressValueError:
        return False

def main():
    args = setup_command_line_args()
    os.makedirs("logs", exist_ok=True)

    # Refactor Options - config file?
    options = Options()
    options.jitter            = args.jitter
    options.timeout           = args.timeout
    options.logFileName       = args.logFileName
    options.outputLogFileName = (
        "logs/smbscan-" + time.strftime("%Y%m%d-%H%M%S") + ".log"
    )
    options.crawlShares       = not args.shares
    options.maximumDepth      = args.maximumDepth
    options.keywordsFileName  = args.keywordsFileName
    options.downloadFiles     = args.downloadFiles
    
    if str(args.inclusionList) != "None":
        options.inclusionList = str(args.inclusionList).split(",")
    if str(args.exclusionList) != "None":
        options.exclusionList = str(args.exclusionList).split(",")

    with open(options.keywordsFileName, "r") as k_file:
        for line in k_file:
            options.keywords.append(line.strip().casefold())

    user = User()
    if args.user:
        user.username = args.user
        user.password = args.password if args.password else getpass.getpass()
        user.domain   = args.domain if args.domain else ""

    logger = logging.getLogger('smbscan')
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("[%(asctime)s %(levelname)s] %(message)s",
                                "%Y-%m-%d %H:%M:%S")

    logFileHandler = handlers.RotatingFileHandler(options.outputLogFileName,
                                            maxBytes=1024 * 1024 * 5,
                                            backupCount=2)
    logFileHandler.setLevel(logging.DEBUG)
    logFileHandler.setFormatter(formatter)
    logger.addHandler(logFileHandler)

    stdoutHandler = logging.StreamHandler(sys.stdout)
    stdoutHandler.setLevel(logging.DEBUG)
    stdoutHandler.setFormatter(formatter)
    logger.addHandler(stdoutHandler)

    # Record arguments
    logger.info(' '.join(sys.argv[0:]))

    if args.target:
        logger.info(f"Scanning {args.target}")
        if valid_ip(args.target):
            scan_range(args.target, user, options)
        else:
            scan_single(args.target, user, options)
    else:
        with args.file as file:
            target = file.readline().strip()
            while target:
                logger.info(f"Scanning {target}")
                if valid_ip(target):
                    scan_range(target, user, options)
                else:
                    scan_single(target, user, options)
                target = file.readline().strip()

    logger.info("Scan completed")


if __name__ == "__main__":
    main()
