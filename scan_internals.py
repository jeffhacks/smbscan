import logging
import os
import random
import re
import time

from impacket.smbconnection import SMBConnection, SessionError

from local_logging import create_log_entry

logger = logging.getLogger('smbscan')

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
        logger.info(f"{target.ip} ({target.name}) Session failure: ({user.username}, {str(port)}) {str(e)}")
        # Host is live
        return None
    except Exception as e:
        if "timed out" in str(e):
            None  
            # logger.info(f"Connection failure: {str(e)}")
            # Host is not live - do not log this
        elif "Connection refused" in str(e) or "Permission denied" in str(e):
            logger.info(f"{target.ip} ({target.name}) Connection failure: {str(e)}")
            # Host is live
        else:
            logger.info(f"{target.ip} ({target.name}) Connection failure: ({user.username}, {str(port)}) {str(e)}")
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

            if any(regex.match(sharedFile.fileName) for regex in options.patterns):
                logger.critical(
                    f"Suspicous file: \\\\{target.name}\\{share.shareName}{sharedFile.fullPath} ({time.ctime(float(f.get_atime_epoch()))}, {f.get_filesize()})"
                )
                
                # Download file
                if options.downloadFiles and not f.is_directory():
                    downloadPath = os.path.join('logs', target.name, share.shareName, sharePath.lstrip('\\').replace('\\', os.path.sep))
                    os.makedirs(downloadPath, exist_ok=True)

                    downloadFile = os.path.join(downloadPath, f.get_longname())

                    fh = open(downloadFile,'wb')
                    smbClient.getFile(share.shareName, sharedFile.fullPath, fh.write)
                    fh.close()

                    # logger.critical(f"\tSaved to:\t{downloadFile}")

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
        logger.info(f"{target.ip} ({target.name}) Error accessing {share.shareName}")
        logger.debug(f"{e}")
        return
    finally:
        if options.jitter > 0:
            time.sleep(random.randint(0, options.jitter))

def get_files(smbClient, target, options, logFile):
    for share in target.shares:
        if share.shareName in options.exclusionList:
            logger.warning(
                "Skipping %1s (on exclusion list)" % (share.shareName)
            )
        elif len(options.inclusionList) > 0:
            if share.shareName in options.inclusionList:
                logger.info(
                    "Scanning %1s (on inclusion list)" % (share.shareName)
                )
                list_files(target, smbClient, share, "", options, logFile, 1)
            else:
                logger.warning(
                    "Skipping item %1s (not on inclusion list)" % (share.shareName)
                )
        else:
            logger.info(f"{target.ip} ({target.name}) Scanning \\\\{target.name}\\%1s" % (share.shareName))
            list_files(target, smbClient, share, "", options, logFile, 1)
