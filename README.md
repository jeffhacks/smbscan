# SMBScan

### Overview
SMBScan is a tool developed to enumerate file shares on an internal network.

It's primary goals are:

* Scan a single target or hundreds of targets
* Enumerate all accessible shares and files
* Identify files that potentially contain credentials or secrets
* Try to avoid detection by blue teams



### Table of Contents
1. [Getting Started](#getting-started)
2. [Running Scans](#running-scans)
3. [Scan Output](#analysing-output)
4. [Fourth Example](#fourth-examplehttpwwwfourthexamplecom)

---
## Getting Started
Clone or download from the git repo.

### Installation
```python3
pip3 install -r requirements.txt
```

---
## Running scans
Scan a single target as guest
```
python smbscan.py 192.168.0.0/24
```

Scan a range of targets as a specific domain user with a random delay of 1-3 seconds between targets and operations on targets:
```
python smbscan.py -f targetranges.txt -u testuser -d internal -j 3
```

---
## Analysing Output


---
## Authors
* Jeff Thomas - https://github.com/jeffhacks
* Yianna Paris - https://github.com/nekosoft

---
## Acknowledgments
* Wireghoul - https://github.com/wireghoul
* Impacket - https://github.com/SecureAuthCorp/impacket
