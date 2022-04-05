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
    def __init__(self, ip):
        self.ip          = ip
        self.name        = ""
        self.alias       = ""
        self.addressList = ""
        self.shares      = []
        # TODO this is probably where the DNS lookup occurs
        try:
            self.name, self.alias, self.addressList = socket.gethostbyaddr(ip)
        except socket.herror:
            self.name = ip
        except Exception as e:
            # print_status(ip, Colors.FAIL, "TARGET FAILURE: " + str(e), options)
            print(traceback.format_exc())

class User:
    def __init__(self, username = "Guest", password = "", domain = "", lmhash = "", nthash = ""):
        self.username = username
        self.password = password
        self.domain   = domain
        self.lmhash   = lmhash
        self.nthash   = nthash
        self.results  = []

def scan_range(targetIPRange, user, options):
    for targetIP in ipaddress.IPv4Network(str(targetIPRange)):
        scan_single(targetIP, user, options)

def scan_single(targetHost, user, options):
    target = Target(str(targetHost))
    # TODO This could potentially be noisier than needed. Consider only using port 445
    smbClient = scan_internals.get_client(target, user, options, 445)
    # if (smbClient is None):
    # 	smbClient = get_client(target, user, options, 139)
    if smbClient != None:
        try:
            fileTimeStamp = time.strftime("%Y%m%d-%H%M%S")
            logFileName = (
                options.logFileName
                if options.logFileName
                else "logs/smbscan-"
                + slugify(target.name)
                + "-"
                + fileTimeStamp
                + ".csv"
            )
            logFile = open(logFileName, "a")

            logger.info("CONNECTED AS %1s - %2s" % (user.username, smbClient.getServerOS()))
            
            scan_internals.get_shares(smbClient, target)
            if options.crawlShares:
                scan_internals.get_files(smbClient, target, options, logFile)
            user.results.append(target)
        except Exception as e:
            logger.exception("GENERAL FAILURE: " + str(e))
            print(traceback.format_exc())
        finally:
            smbClient.close()
            logFile.close()
    if options.jitter > 0:
        time.sleep(random.randint(0, options.jitter))
