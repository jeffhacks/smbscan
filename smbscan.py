#!/usr/bin/python
__author__ = "jeffhacks"

import getpass
import ipaddress
import logging
import os
import re
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

    # Refactor Options - config file?
    options = Options()
    options.jitter            = args.jitter
    options.jitterTarget      = args.jitter if args.jitter_target is None else args.jitter_target
    options.jitterOperation   = args.jitter if args.jitter_operation is None else args.jitter_operation
    options.timeout           = args.timeout
    options.logDirectory      = os.path.abspath(args.log_directory)
    os.makedirs(args.log_directory, exist_ok=True)
    options.csvFile = os.path.join(
        options.logDirectory, "smbscan-" + time.strftime("%Y%m%d-%H%M%S") + ".log"
    )
    options.crawlShares       = not args.shares_only
    options.maxDepth          = args.max_depth
    options.patternsFile      = args.patterns_file
    options.downloadFiles     = args.download_files
    options.logLevel          = logging.DEBUG if args.debug else logging.INFO
    
    if str(args.include_shares) != "None":
        options.includeShares = str(args.include_shares).split(",")
    if str(args.exclude_shares) != "None":
        options.excludeShares = str(args.exclude_shares).split(",")
    if str(args.exclude_hosts) != "None":
        options.excludeHosts = str(args.exclude_hosts).split(",")

    with open(options.patternsFile, "r") as k_file:
        for line in k_file:
            options.patterns.append(re.compile(line.strip(), re.IGNORECASE))

    user = User()
    if args.user:
        user.username = args.user
        user.password = args.password if args.password else getpass.getpass()
        user.domain   = args.domain if args.domain else ""

    logger = logging.getLogger('smbscan')
    logger.setLevel(options.logLevel)
    formatter = logging.Formatter("[%(asctime)s %(levelname)s] %(message)s",
                                "%Y-%m-%d %H:%M:%S")

    logFileHandler = handlers.RotatingFileHandler(options.csvFile,
                                            maxBytes=1024 * 1024 * 5,
                                            backupCount=2)
    logFileHandler.setLevel(options.logLevel)
    logFileHandler.setFormatter(formatter)
    logger.addHandler(logFileHandler)

    stdoutHandler = logging.StreamHandler(sys.stdout)
    stdoutHandler.setLevel(options.logLevel)
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
