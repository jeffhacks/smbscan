import os
import random
import re
import time

from impacket.smbconnection import SMBConnection, SessionError

from local_logging import create_log_entry
from print import print_status, Colors


class Share:
    def __init__(self, shareName):
        self.shareName   = shareName
        self.sharedFiles = []

class SharedFile:
    def __init__(self, fileName, fullPath, isDirectory, cTime, mTime, aTime, fileSize):
        self.fileName    = fileName
        self.fullPath    = fullPath
        self.isDirectory = isDirectory
        self.cTime       = cTime
        self.mTime       = mTime
        self.aTime       = aTime
        self.fileSize    = fileSize

def get_shares(smbClient, target):
    resp = smbClient.listShares()
    for i in range(len(resp)):
        shareName = resp[i]["shi1_netname"][:-1]
        if shareName not in ["NETLOGON", "SYSVOL", "IPC$", "print$"]:
            target.shares.append(Share(shareName))

def get_client(target, user, options, port):
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
        print_status(
            target,
            Colors.WARNING,
            "SESSION FAILURE: (%1s, %2s) %3s" % (user.username, str(port), str(e)),
            options,
        )
        # Host is live
        return None
    except Exception as e:
        if "timed out" in str(e):
            None  # print_status(target, Colors.WARNING, "CONNECTION FAILURE: " + str(e), options)
            # Host is not live
        elif "Connection refused" in str(e):
            print_status(
                target,
                Colors.WARNING,
                "CONNECTION FAILURE: (%1s, %2s) %3s"
                % (user.username, str(port), str(e)),
                options,
            )
            # Host is live
        else:
            print_status(
                target,
                Colors.FAIL,
                "CONNECTION FAILURE: (%1s, %2s) %3s"
                % (user.username, str(port), str(e)),
                options,
            )
            # Host is live
        return None

def list_files(target, smbClient, share, sharePath, options, logFile, currentDepth):
    try:
        for f in smbClient.listPath(share.shareName, sharePath + "\\*"):
            if f.get_longname() == "." or f.get_longname() == "..":
                continue

            sharedFile = SharedFile(
                fileName    = f.get_longname(),
                fullPath    = (sharePath + "\\" + f.get_longname()).strip(),
                isDirectory = f.is_directory(),
                cTime       = time.ctime(float(f.get_ctime_epoch())),
                mTime       = time.ctime(float(f.get_mtime_epoch())),
                aTime       = time.ctime(float(f.get_atime_epoch())),
                fileSize    = f.get_filesize(),
            )
            share.sharedFiles.append(sharedFile)

            if any(keyword in sharedFile.fileName.casefold() for keyword in options.keywords):
                print_status(
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

                # Download file
                if options.downloadFiles and not f.is_directory():
                    downloadPath = os.path.join('logs', target.name, share.shareName, sharePath.lstrip('\\').replace('\\', os.path.sep))
                    os.makedirs(downloadPath, exist_ok=True)
                    print(downloadPath)

                    downloadFile = os.path.join(downloadPath, f.get_longname())
                    print(downloadFile)

                    fh = open(downloadFile,'wb')
                    smbClient.getFile(share.shareName, sharedFile.fullPath, fh.write)
                    fh.close()

            create_log_entry(
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
                list_files(
                    target,
                    smbClient,
                    share,
                    sharedFile.fullPath,
                    options,
                    logFile,
                    currentDepth + 1,
                )
    except Exception as e:
        print_status(
            target,
            Colors.FAIL,
            "ERROR ACCESSING %1s: %3s" % (share.shareName, e),
            options,
        )
        return
    finally:
        if options.jitter > 0:
            time.sleep(random.randint(0, options.jitter))

def get_files(smbClient, target, options, logFile):
    for share in target.shares:
        if share.shareName in options.exclusionList:
            print_status(
                target,
                Colors.WARNING,
                "Skipping %1s (on exclusion list)" % (share.shareName),
                options,
            )
        elif len(options.inclusionList) > 0:
            if share.shareName in options.inclusionList:
                print_status(
                    target,
                    Colors.OKBLUE,
                    "Scanning %1s (on inclusion list)" % (share.shareName),
                    options,
                )
                list_files(target, smbClient, share, "", options, logFile, 1)
            else:
                print_status(
                    target,
                    Colors.WARNING,
                    "Skipping item %1s (not on inclusion list)" % (share.shareName),
                    options,
                )
        else:
            print_status(
                target, Colors.OKBLUE, "Scanning %1s" % (share.shareName), options
            )
            list_files(target, smbClient, share, "", options, logFile, 1)
