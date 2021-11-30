#!/usr/bin/python

import argparse
import csv
import datetime
import getpass
import ipaddress
import random
import socket
import sys
import time
import traceback

from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SMBConnection, SessionError
from slugify import slugify


class Options:
    def __init__(
        self,
        hostname="SMBScan",
        logFileName="log",
        kerberos=False,
        port=139,
        timeout=2,
        jitter=3,
        aesKey="",
        dc_ip="",
        outputLogFileName=[],
        inclusionList=[],
        exclusionList=[],
        maximumDepth=0,
    ):
        self.hostname = hostname
        self.logFileName = logFileName
        self.kerberos = kerberos
        self.port = port
        self.timeout = timeout
        self.jitter = jitter
        self.aesKey = aesKey
        self.dc_ip = dc_ip
        self.outputLogFileName = outputLogFileName
        self.inclusionList = inclusionList
        self.exclusionList = exclusionList
        self.maximumDepth = maximumDepth


class User:
    def __init__(self, username="Guest", password="", domain="", lmhash="", nthash=""):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.results = []


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


class Share:
    def __init__(self, shareName):
        self.shareName = shareName
        self.sharedFiles = []


class SharedFile:
    def __init__(self, fileName, fullPath, isDirectory, cTime, mTime, aTime, fileSize):
        self.fileName = fileName
        self.fullPath = fullPath
        self.isDirectory = isDirectory
        self.cTime = cTime
        self.mTime = mTime
        self.aTime = aTime
        self.fileSize = fileSize


class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def printStatus(target, color, message, options):
    statusSymbol = "[-]" if color == Colors.WARNING or color == Colors.FAIL else "[+]"
    if target is None:
        status = "%1s%2s %3s" % (color, statusSymbol, message)
    else:
        status = "%1s%2s %3s (%4s): %5s" % (
            color,
            statusSymbol,
            target.ip,
            target.name,
            message,
        )

    print(status)
    logFile = open(options.outputLogFileName, "a")
    logFile.write(status + "\r\n")
    logFile.close()


def createLogEntry(options, username, servername, target, share, sharedFile, logFile):
    row = [
        username,
        servername,
        target.name,
        target.ip,
        share.shareName,
        sharedFile.fileName,
        sharedFile.fullPath,
        ("D" if sharedFile.isDirectory > 0 else ""),
        sharedFile.cTime,
        sharedFile.mTime,
        sharedFile.aTime,
        sharedFile.fileSize,
    ]
    writer = csv.writer(logFile)
    writer.writerow(row)


def listFiles(target, smbClient, share, sharePath, options, logFile, currentDepth):
    try:
        for f in smbClient.listPath(share.shareName, sharePath + "\\*"):
            if f.get_longname() == "." or f.get_longname() == "..":
                continue

            sharedFile = SharedFile(
                fileName=f.get_longname(),
                fullPath=(sharePath + "\\" + f.get_longname()).strip(),
                isDirectory=f.is_directory(),
                cTime=time.ctime(float(f.get_ctime_epoch())),
                mTime=time.ctime(float(f.get_mtime_epoch())),
                aTime=time.ctime(float(f.get_atime_epoch())),
                fileSize=f.get_filesize(),
            )
            share.sharedFiles.append(sharedFile)

            keywords = [
                "password",
                "web.config",
                "wp-config.php",
                "passport",
                "handover",
            ]
            if any(keyword in sharedFile.fileName for keyword in keywords):
                printStatus(
                    target,
                    Colors.OKBLUE,
                    "%crw-rw-rw- %10d  %s %s"
                    % (
                        "d" if f.is_directory() > 0 else "-",
                        f.get_filesize(),
                        time.ctime(float(f.get_atime_epoch())),
                        f.get_longname(),
                    ),
                    options,
                )

            createLogEntry(
                options,
                smbClient.getCredentials()[0],
                smbClient.getServerName(),
                target,
                share,
                sharedFile,
                logFile,
            )

            if f.is_directory() > 0 and (
                options.maximumDepth == 0 or currentDepth < options.maximumDepth
            ):
                listFiles(
                    target,
                    smbClient,
                    share,
                    sharedFile.fullPath,
                    options,
                    logFile,
                    currentDepth + 1,
                )
    except Exception as e:
        printStatus(
            target,
            Colors.FAIL,
            "ERROR ACCESSING %1s: %3s" % (share.shareName, e),
            options,
        )
        return
    finally:
        if options.jitter > 0:
            time.sleep(random.randint(0, options.jitter))


def getShares(smbClient, target):
    resp = smbClient.listShares()
    for i in range(len(resp)):
        shareName = resp[i]["shi1_netname"][:-1]
        if shareName not in ["NETLOGON", "SYSVOL", "IPC$", "print$"]:
            target.shares.append(Share(shareName))


def getFiles(smbClient, target, options, logFile):
    for share in target.shares:
        if share.shareName in options.exclusionList:
            printStatus(
                target,
                Colors.WARNING,
                "Skipping %1s (on exclusion list)" % (share.shareName),
                options,
            )
        elif len(options.inclusionList) > 0:
            if share.shareName in options.inclusionList:
                printStatus(
                    target,
                    Colors.OKBLUE,
                    "Scanning %1s (on inclusion list)" % (share.shareName),
                    options,
                )
                listFiles(target, smbClient, share, "", options, logFile, 1)
            else:
                printStatus(
                    target,
                    Colors.WARNING,
                    "Skipping item %1s (not on inclusion list)" % (share.shareName),
                    options,
                )
        else:
            printStatus(
                target, Colors.OKBLUE, "Scanning %1s" % (share.shareName), options
            )
            listFiles(target, smbClient, share, "", options, logFile, 1)


def getClient(target, user, options, port):
    try:
        smbClient = SMBConnection(
            "*\\*SMBSERVER*", target.ip, timeout=options.timeout, sess_port=int(port)
        )
        if options.kerberos is True:
            smbClient.kerberosLogin(
                user.username,
                user.password,
                user.domain,
                user.lmhash,
                user.nthash,
                options.aesKey,
                options.dc_ip,
            )
        else:
            # smbClient.login(user.username, user.password, user.domain, user.lmhash, user.nthash, ntlmFallback=False)
            # TODO I'm not sure of any downsides to allowing ntlmFallback here...
            smbClient.login(
                user.username,
                user.password,
                user.domain,
                user.lmhash,
                user.nthash,
                ntlmFallback=True,
            )
        # Host is live
        return smbClient
    except SessionError as e:
        printStatus(
            target,
            Colors.WARNING,
            "SESSION FAILURE: (%1s, %2s) %3s" % (user.username, str(port), str(e)),
            options,
        )
        # Host is live
        return None
    except Exception as e:
        if "timed out" in str(e):
            None  # printStatus(target, Colors.WARNING, "CONNECTION FAILURE: " + str(e), options)
            # Host is not live
        elif "Connection refused" in str(e):
            printStatus(
                target,
                Colors.WARNING,
                "CONNECTION FAILURE: (%1s, %2s) %3s"
                % (user.username, str(port), str(e)),
                options,
            )
            # Host is live
        else:
            printStatus(
                target,
                Colors.FAIL,
                "CONNECTION FAILURE: (%1s, %2s) %3s"
                % (user.username, str(port), str(e)),
                options,
            )
            # Host is live
        return None


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


def validIP(addr):
    try:
        ipaddress.IPv4Network(str(addr))
        return True
    except ipaddress.AddressValueError:
        return False


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "target",
        nargs="?",
        help="Target for scanning. e.g. 192.168.1.1 or 192.168.1.0/24",
    )
    group.add_argument(
        "-f",
        "--file",
        help="List of targets for scanning.",
        type=argparse.FileType("r"),
    )
    parser.add_argument("-u", "--user", help="User to connect as")
    parser.add_argument(
        "-p", "--password", help="Password for user (will prompt if missing and needed)"
    )
    parser.add_argument("-d", "--domain", help="Domain for user")
    parser.add_argument("-k", "--kerberos", help="Not implemented", action="store_true")
    parser.add_argument(
        "-j",
        "--jitter",
        help="Random delay between some requests. Default 3 seconds.",
        type=int,
        default=3,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Set timeout for connections. Default 2 seconds.",
        type=int,
        default=2,
    )
    parser.add_argument(
        "-s",
        "--shares",
        help="Display shares only - dont crawl files",
        action="store_true",
    )
    parser.add_argument(
        "-l", "--logFileName", help="Override log file name (without extension)"
    )
    parser.add_argument(
        "-i",
        "--inclusionList",
        help="List of comma separated shares to include in scan. All others will be excluded.",
    )
    parser.add_argument(
        "-e",
        "--exclusionList",
        help="List of comma separated shares to exclude from scan. All others will be included.",
    )
    parser.add_argument(
        "-m",
        "--maximumDepth",
        help="Maximum depth to crawl. 0 (default) = unlimited.",
        type=int,
        default=0,
    )

    args = parser.parse_args()

    options = Options()
    options.jitter = args.jitter
    options.timeout = args.timeout
    options.logFileName = args.logFileName
    options.outputLogFileName = (
        "logs/smbscan-" + time.strftime("%Y%m%d-%H%M%S") + ".txt"
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
