import ipaddress
import socket
import traceback

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

def scanRange(targetIPRange, user, options):
    for targetIP in ipaddress.IPv4Network(str(targetIPRange)):
        scanSingle(targetIP, user, options)


def scanSingle(targetHost, user, options):
    target = Target(str(targetHost))
    # TODO This could potentially be noisier than needed. Consider only using port 445
    smbClient = getClient(target, user, options, 445)
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
            getShares(smbClient, target)
            if options.crawlShares:
                getFiles(smbClient, target, options, logFile)
            user.results.append(target)
        except Exception as e:
            printStatus(target, Colors.FAIL, "GENERAL FAILURE: " + str(e), options)
            print(traceback.format_exc())
        finally:
            smbClient.close()
            logFile.close()
    if options.jitter > 0:
        time.sleep(random.randint(0, options.jitter))
