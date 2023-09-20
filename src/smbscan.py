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
from scan import scan_single, User

from multiprocessing.pool import Pool
from multiprocessing.pool import ThreadPool
from multiprocessing import set_start_method
from threading import Thread

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
    options.threads           = args.threads
    options.logDirectory      = os.path.abspath(args.log_directory)
    os.makedirs(args.log_directory, exist_ok=True)
    options.csvFile = os.path.join(
        options.logDirectory, "smbscan-" + time.strftime("%Y%m%d-%H%M%S") + ".log"
    )
    if args.state_file == None:
        options.stateFile = os.path.join(
            options.logDirectory, "smbscan-" + time.strftime("%Y%m%d-%H%M%S") + ".state"
        )
    else:
        state_filename = args.state_file
        filename, file_extension = os.path.splitext(state_filename)
        if not file_extension == '.state':
            state_filename = f'{state_filename}.state'
        options.stateFile = os.path.join(
            options.logDirectory, state_filename
        )
    options.crawlShares       = not args.shares_only
    options.maxDepth          = args.max_depth
    options.patternsFile      = args.patterns_file
    options.downloadFiles     = args.download_files
    options.logLevel          = logging.DEBUG if args.debug else logging.INFO
    
    if str(args.include_paths) != "None":
        options.includePaths = str(args.include_paths).split(",")
    if str(args.exclude_paths) != "None":
        options.excludePaths = str(args.exclude_paths).split(",")
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
        ntlmHash = args.hash
        if ntlmHash:
            user.lmhash = ntlmHash.split(':')[0]
            user.nthash = ntlmHash.split(':')[1]
        elif args.no_pass:
            pass
        else:
            user.password = args.password if args.password else getpass.getpass()
        user.domain = args.domain if args.domain else ""

    options.kerberos = args.kerberos
    if args.kerberos:
        user.domain = args.domain if args.domain else ""
        options.dc_ip = args.dc_ip if args.dc_ip else ""
        options.aesKey = args.aesKey if args.aesKey else ""

    logger = logging.getLogger('smbscan')
    logger.setLevel(options.logLevel)
    formatter = logging.Formatter("[%(asctime)s %(threadName)s %(levelname)s] %(message)s",
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

    # Load targets into list
    target_list = []
    if args.target:
        logger.info(f"Scanning {args.target}")
        if valid_ip(args.target):
            for targetIP in ipaddress.IPv4Network(str(args.target)):
                target_list.append((targetIP, user, options))
        else:
            target_list.append((str(args.target), user, options))
    else:
        with args.file as file:
            target = file.readline().strip()
            while target:
                if len(target.split(',')) == 3:
                    hash_target = target.split(',')[0]
                    hash_username = target.split(',')[1]
                    hash_hash = target.split(',')[2]
                    logger.debug(f'Hash Target: {hash_target}, User: {hash_username}, Hash: {hash_hash}')

                    hash_user = User()
                    hash_user.username = hash_username
                    ntlmHash = hash_hash
                    if ntlmHash:
                        hash_user.lmhash = ntlmHash.split(':')[0]
                        hash_user.nthash = ntlmHash.split(':')[1]

                    if valid_ip(hash_target):
                        for targetIP in ipaddress.IPv4Network(str(hash_target)):
                            target_list.append((targetIP, hash_user, options))
                    else:
                        target_list.append((str(hash_target), hash_user, options))
                else:
                    logger.debug(f'Standard Target: {target}, User: {user.username}')
                    if valid_ip(target):
                        for targetIP in ipaddress.IPv4Network(str(target)):
                            target_list.append((targetIP, user, options))
                    else:
                        target_list.append((str(target), user, options))
                target = file.readline().strip()

    logger.info(f'Scanning with {options.threads} threads')
    set_start_method("spawn")
    with ThreadPool(processes=options.threads) as pool:
        result = pool.starmap_async(scan_single, target_list, chunksize=1)
        result.wait()
        
    logger.info("Scan completed")


if __name__ == "__main__":
    main()
