import logging
import ntpath
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

def get_shares(smbClient):
    """Get SMB share names from client and return a list."""
    shares = []
    resp = smbClient.listShares()
    for i in range(len(resp)):
        shareName = resp[i]["shi1_netname"][:-1]
        if is_valid_share_name(shareName) and shareName not in ["IPC$", "print$"]:
            shares.append(Share(shareName))
    return shares

def get_client(target, user, options, port):
    try:
        smbClient = SMBConnection(
            target.name,
            target.ip,
            timeout=options.timeout,
            sess_port=int(port)
        )
        if options.kerberos is True:
            logger.debug('Kerberos mode')
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
            logger.debug(f"{target.ip} ({target.name}) Connection failure: {str(e)}")
            # Host is live
        else:
            logger.debug(f"{target.ip} ({target.name}) Connection failure: ({user.username}, {str(port)}) {str(e)}")
            # Host is live
        return None

def list_files(target, smbClient, share, sharePath, options, logFile, currentDepth):
    try:
        if sharePath == '':
            # Always allow listing the root of each share
            logger.debug(f'Allowed [{sharePath}]')
        elif any(sharePath.lower().startswith(x) for x in options.excludePaths):
            # If there are any exclusions, make sure we skip these
            logger.info(f'Skipping [{sharePath}] (Path is in exclude list)')
            return
        elif any(sharePath.lower().startswith(x) for x in options.includePaths):
            # Always allow paths that are on the include list
            logger.debug(f'Allowed [{sharePath}] (Path is in include list)')
        elif len(options.includePaths) > 0:
            # If there is an include list, and we have not had a match yet, exclude all others
            logger.info(f'Skipping [{sharePath}] (Include list exists but does not contain this path)')
            return
        else:
            # Path is not on the exclusion list and there is no inclusion list
            logger.debug(f'Allowed [{sharePath}]')
        
        for f in smbClient.listPath(share.shareName, sharePath + "\\*"):
            if f.get_longname() == "." or f.get_longname() == "..":
                continue

            file = (sharePath + "\\" + f.get_longname()).strip()
            if not is_safe_remotepath(file):
                continue

            sharedFile = SharedFile(
                fileName    = f.get_longname(),
                fullPath    = file,
                isDirectory = f.is_directory(),
                cTime       = time.ctime(float(f.get_ctime_epoch())),
                mTime       = time.ctime(float(f.get_mtime_epoch())),
                aTime       = time.ctime(float(f.get_atime_epoch())),
                fileSize    = f.get_filesize(),
            )
            share.sharedFiles.append(sharedFile)

            if any(regex.match(sharedFile.fullPath) for regex in options.patterns):
                logger.critical(
                    f"Suspicous file: \\\\{target.name}\\{share.shareName}{sharedFile.fullPath} ({time.ctime(float(f.get_atime_epoch()))}, {f.get_filesize()})"
                )
                
                # Download file
                if options.downloadFiles and not f.is_directory():
                    filepath = sharePath.lstrip('\\').replace('\\', os.path.sep)
                    downloadPath = os.path.join(options.logDirectory, 
                                                    target.name, 
                                                    share.shareName, 
                                                    filepath)
                    downloadFile = os.path.join(downloadPath, f.get_longname())
                    
                    if is_safe_filepath(options.logDirectory, downloadPath) and is_safe_filepath(options.logDirectory, downloadFile):
                        os.makedirs(downloadPath, exist_ok=True)
                        logger.debug(f'Downloading {os.path.realpath(downloadFile)}')
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
                options.maxDepth == 0 or currentDepth < options.maxDepth
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
        if options.jitterOperation > 0:
            time.sleep(random.randint(0, options.jitterOperation))

def get_files(smbClient, target, options, logFile):
    for share in target.shares:
        if share.shareName in options.excludeShares:
            logger.warning(
                "Skipping %1s (on exclusion list)" % (share.shareName)
            )
        elif len(options.includeShares) > 0:
            if share.shareName in options.includeShares:
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

def is_valid_share_name(shareName):
    """"Returns True if share name does not contain illegal characters, as described in Microsoft Docs."""
    # Illegal share name characters: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/dc9978d7-6299-4c5a-a22d-a039cdc716ea
    illegalCharacters = ['"','\\','/','[',']',':','|','<','>','+','=',';',',','*','?'] 
    if any(char in shareName for char in illegalCharacters):
        logger.warning(f'Invalid share name: {shareName}, contains illegal characters')
        return False
    else:
        return True

def is_safe_remotepath(path):
    """Returns true if remote path is in UNC naming convention."""
    normpath = ntpath.normpath(path) # Force UNC naming convention by using ntpath
    if ntpath.isabs(path) and path == normpath:
        return True
    else:
        logger.warning(f'Unsafe remotepath: {path}')
        return False

def is_safe_filepath(logDir, path):
    """Returns true if file path is pointing to a subdirectory of log directory."""
    realpath = os.path.realpath(path)
    commonPath = os.path.commonpath((realpath, logDir))
    if commonPath == logDir:
        return True
    else:
        logger.warning(f'Unsafe filepath: {path}. Received {realpath}, which has no common path with {logDir}')
        return False
