# SMBScan
SMB scanner for enumerating fileshares accross network ranges to aid in locating sensitive files that may have been inadvertently shared.
The tool can scan individual hosts, ranges or read targets from a file.

Unlike other tools, no write operations are performed. There is also a jitter option that can be used to slow the scan down to avoid detection.

## Getting Started

Clone or download from the git repo.

SMBScan is written in Python 3.7+, and requires `pip3` to install dependencies.

It's recommended to use a Virtual Environment, to prevent dependency issues. See below, [Using virtualenv](#using-virtualenv)

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

## Using virtualenv

Read more [here](https://github.com/pypa/virtualenv)

#### Create
```python3
python3 -m venv env
source env/bin/activate
```

#### Activate
```python3
source env/bin/activate
```

#### Deactivate
```python3
deactivate
```

#### Check which Python version is being used
```python3
which python python2 python3
```

## Resources
Useful documentation and examples
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
