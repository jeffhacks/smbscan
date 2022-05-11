# SMBScan
SMB scanner for enumerating fileshares accross network ranges to aid in locating sensitive files that may have been inadvertently shared.
The tool can scan individual hosts, ranges or read targets from a file.

Unlike other tools, no write operations are performed. There is also a jitter option that can be used to slow the scan down to avoid detection.

## Getting Started

Clone or download from the git repo.

### Installation
```python3
pip3 install -r requirements.txt
```

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

## Authors
* Jeff Thomas - https://github.com/jeffhacks
* Yianna Paris - https://github.com/nekosoft

## Acknowledgments
* Wireghoul - https://github.com/wireghoul
* Impacket - https://github.com/SecureAuthCorp/impacket
