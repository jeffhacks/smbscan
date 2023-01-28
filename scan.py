import csv
import ipaddress
import logging
import socket
import traceback
import random
import time

from slugify import slugify

import scan_internals

logger = logging.getLogger('smbscan')

class Target:
    def __init__(self, target):
        self.ip          = None
        self.name        = None
        self.alias       = ""
        self.addressList = ""
        self.shares      = []

        try:
            # Assume target is an IP
            self.ip = str(ipaddress.ip_address(target))
            hostname, self.alias, self.addressList = socket.gethostbyaddr(str(self.ip))
            if is_valid_hostname(hostname):
                self.name = hostname
            else:
                self.name = self.ip
        except socket.herror:
            # No DNS resolution
            self.name = self.ip
        except ValueError:
            # Target is not an IP
            try:
                self.ip = socket.gethostbyname(target)
                self.name = target
            except socket.gaierror as e:
                logger.error(f"Target failure ({target}): {str(e)}")
        except Exception as e:
            logger.error(f"Target failure ({target}): {str(e)}")

class User:
    def __init__(self, username = "Guest", password = "", domain = "", lmhash = "", nthash = ""):
        self.username = username
        self.password = password
        self.domain   = domain
        self.lmhash   = lmhash
        self.nthash   = nthash
        self.results  = []

def scan_single(targetHost, user, options):
    if str(targetHost) in options.excludeHosts:
        logger.warning(
            "Skipping %1s (on exclusion list)" % (targetHost)
        )
    if is_host_in_statefile(options.stateFile, str(targetHost)):
        logger.warning(
            "Skipping %1s (already scanned)" % (targetHost)
        )
    else:
        logger.info(f'Scanning {targetHost}')
        target = Target(str(targetHost))
        smbClient = None
        targetScanResult = ''

        if not target.ip:
            targetScanResult = 'Unable to resolve'
        else:
            smbClient = scan_internals.get_client(target, user, options, 445)
            # TODO This could potentially be noisier than needed. Consider only using port 445
        # if (smbClient is None):
            # 	smbClient = get_client(target, user, options, 139)

            if smbClient is None:
                targetScanResult = 'Unable to connect'
            else:
                fileTimeStamp = time.strftime("%Y%m%d-%H%M%S")
                logfileName = (
                    options.logDirectory
                    + "/smbscan-"
                    + slugify(target.name)
                    + "-"
                    + fileTimeStamp
                    + ".csv"
                )
                if scan_internals.is_safe_filepath(options.logDirectory, logfileName):
                    try:
                        logfile = open(logfileName, "a")

                        logger.info(f"{target.ip} ({target.name}) Connected as {user.username}, Target OS: {smbClient.getServerOS()}")
                    
                        target.shares = scan_internals.get_shares(smbClient)
                    
                        if options.crawlShares:
                            scan_internals.get_files(smbClient, target, options, logfile)
                        user.results.append(target)
                    except Exception as e:
                        targetScanResult = 'Error'
                        logger.exception(f'General failure ({targetHost}): {str(e)}')
                        #print(traceback.format_exc())
                    finally:
                        targetScanResult = 'Scan completed'
                        smbClient.close()
                        logfile.close()

        add_target_to_statefile(options.stateFile, str(targetHost), targetScanResult)

        if options.jitterTarget > 0:
            time.sleep(random.randint(0, options.jitterTarget))

def is_valid_hostname(hostname):
    """"Returns True if host name does not contain illegal characters, as described in Microsoft Docs."""
    # https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/naming-conventions-for-computer-domain-site-ou
    illegalCharacters = ['\\','/',':','*','?','"','<','>','|']
    if any(char in hostname for char in illegalCharacters):
        logger.warning(f'Invalid hostname: {hostname}, contains illegal characters')
        return False
    else:
        return True

def add_target_to_statefile(statefileName, targetHost, targetScanResult):
    row = [
        targetHost,
        time.strftime("%Y%m%d %H%M%S"),
        targetScanResult
    ]
    with open(statefileName, 'a+', encoding='utf-8') as statefile:
        writer = csv.writer(statefile)
        writer.writerow(row)

def is_host_in_statefile(statefileName, targetHost):
    found = False
    try:
        with open(statefileName, 'r', encoding='utf-8') as statefile:
            reader = csv.reader(statefile, delimiter=',')
            found = any(targetHost == row[0].strip() for row in reader)

    except Exception as e:
        pass
    finally:
        return found