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
            logger.error(f"Target failure: {str(e)}")
            #print(traceback.format_exc())

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
    if str(targetHost) in options.excludeHosts:
        logger.warning(
            "Skipping %1s (on exclusion list)" % (targetHost)
        )
    else:
        target = Target(str(targetHost))
        # TODO This could potentially be noisier than needed. Consider only using port 445
        smbClient = scan_internals.get_client(target, user, options, 445)
        # if (smbClient is None):
        # 	smbClient = get_client(target, user, options, 139)
        if smbClient != None:
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
                    logger.exception("General failure: " + str(e))
                    #print(traceback.format_exc())
                finally:
                    smbClient.close()
                    logfile.close()

        if options.jitterTarget > 0:
            time.sleep(random.randint(0, options.jitterTarget))
