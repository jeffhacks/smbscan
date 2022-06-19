import csv

def create_log_entry(options, username, servername, target, share, sharedFile, logFile):
    row = [
        username,
        servername,
        target.name,
        target.ip,
        share.shareName,
        sharedFile.fullPath,
        sharedFile.fileName,
        ("D" if sharedFile.isDirectory > 0 else ""),
        sharedFile.cTime,
        sharedFile.mTime,
        sharedFile.aTime,
        sharedFile.fileSize,
    ]
    writer = csv.writer(logFile)
    writer.writerow(row)

