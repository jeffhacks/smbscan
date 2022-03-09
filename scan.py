import ipaddress
import socket
import traceback
import random
import time

from slugify import slugify

import scan_internals
from print import printStatus, Colors

class Target:
    def __init__(self, ip):
        self.ip = ip
        self.name = ""
        self.alias = ""
        self.addressList = ""
        self.shares = []
        # TODO this is probably where the DNS lookup occurs
        try:
            self.name, self.alias, self.addressList = socket.gethostbyaddr(ip)
        except socket.herror:
            self.name = ip
        except Exception as e:
            # printStatus(ip, Colors.FAIL, "TARGET FAILURE: " + str(e), options)
            print(traceback.format_exc())

class User:
    def __init__(self, username="Guest", password="", domain="", lmhash="", nthash=""):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.results = []
        

def scanRange(targetIPRange, user, options):
    for targetIP in ipaddress.IPv4Network(str(targetIPRange)):
        scanSingle(targetIP, user, options)


def scanSingle(targetHost, user, options):
    target = Target(str(targetHost))
    # TODO This could potentially be noisier than needed. Consider only using port 445
    smbClient = scan_internals.getClient(target, user, options, 445)
    # if (smbClient is None):
    # 	smbClient = getClient(target, user, options, 139)
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

            printStatus(
                target,
                Colors.OKGREEN,
                "CONNECTED AS %1s - %2s" % (user.username, smbClient.getServerOS()),
                options,
            )
            scan_internals.getShares(smbClient, target)
            if options.crawlShares:
                scan_internals.getFiles(smbClient, target, options, logFile)
            user.results.append(target)
        except Exception as e:
            printStatus(target, Colors.FAIL, "GENERAL FAILURE: " + str(e), options)
            print(traceback.format_exc())
        finally:
            smbClient.close()
            logFile.close()
    if options.jitter > 0:
        time.sleep(random.randint(0, options.jitter))
