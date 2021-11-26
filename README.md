# SMBScan

SMB scanner for enumerating fileshares accross network ranges to aid in locating sensitive files that may have been inadvertently shared.
The tool can scan individual hosts, ranges or read targets from a file.

Unlike other tools, no write operations are performed. There is also a jitter option that can be used to slow the scan down to avoid detection.

## Getting Started

Clone from the git repo.

### Prerequisites

This requires Impacket.

### Installing

No installation is required.

## Running the scans

Scan a single target as guest
```
python smbscan.py 192.168.0.0/24
```

Scan a range of targets as a specific domain user with a random delay of 1-3 seconds between hosts and directories:
```
python smbscan.py -f targetranges.txt -u testuser -d internal -j 3
```

Scan a single share (InterestingFiles) on a single target (fileserver-01) as a domain user with a delay of 1 second between directories:
```
python smbscan.py fileserver-01.internal -u testuser -d internal -j 1 -i InterestingFiles
```

Useful smbclient snippet to mass download after you've found some nice target files:
```
SMBClient Recursive Get
mask ""
recurse ON
prompt OFF
mget *
```

## Contributing

BUGS
- Currently does not create the logs subfolder if this does not already exist
- Some issue with unicode maybe...'ascii' codec can't encode character u'\u2019' in position 10: ordinal not in range(128)

 TODO
 - Add parameter values used to scan output (useful to know what options were used to run when reviewing output later - max depth etc)
 - Prevent scanning of printers (permissions seems to fail this as guest but unknown result will occur if authenticated)
 - Add in-line documentation
- Align parameters with smbclient
- Try to suppress DNS lookups (see in-line todo)
- Allow for saving sate and resuming or specify share name to resume from
- Add stealth mode - monitor network for new arp/ip activity, add host to DB and scan
- Add analysis script (include timestamps of analysis and separate log files)

Useful docs and examples
- https://github.com/SecureAuthCorp/impacket/blob/master/impacket/smbconnection.py
- https://github.com/SecureAuthCorp/impacket/blob/429f97a894d35473d478cbacff5919739ae409b4/impacket/smbconnection.py
- https://docs.python.org/2/howto/argparse.html

## Versioning

TBC

## Authors

TBC

## License

TBC

## Acknowledgments

* Impacket
