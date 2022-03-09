import os
import random
import re
import time

from local_logging import createLogEntry
from print import printStatus, Colors

class SharedFile:
    def __init__(self, fileName, fullPath, isDirectory, cTime, mTime, aTime, fileSize):
        self.fileName = fileName
        self.fullPath = fullPath
        self.isDirectory = isDirectory
        self.cTime = cTime
        self.mTime = mTime
        self.aTime = aTime
        self.fileSize = fileSize

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

            if any(keyword in sharedFile.fileName.casefold() for keyword in options.keywords):
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
