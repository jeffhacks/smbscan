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
```bash
pip3 install -r requirements.txt
```

---
## Running scans
Scan a single target as guest
```bash
python smbscan.py 192.168.0.0/24
```

```log
[2022-05-21 22:14:17 INFO] ./smbscan.py -f ../targets.txt
[2022-05-21 22:14:17 INFO] Scanning 192.168.2.26
[2022-05-21 22:14:17 INFO] 192.168.2.26 (TESTSERVER) Connected as tester, Target OS: eWeblrdS
[2022-05-21 22:14:17 INFO] 192.168.2.26 (TESTSERVER) Scanning \\TESTSERVER\TESTER
[2022-05-21 22:14:17 CRITICAL] Suspicous file: \\TESTSERVER\TESTER\.ssh\id_rsa.pub (Sat May 21 21:12:21 2022, 563)
```

Scan a range of targets as a specific domain user with a random delay of 1-3 seconds between targets and operations on targets:
```bash
python smbscan.py -f targetranges.txt -u testuser -d internal -j 3
```

---
## Analysing Output
SMBScan produces a number of files.

* Primary logfile
  * A primary logfile for each scan - records everything that's output to the terminal
* File listing CSV files
  * A listing of all accessible shares and files. One CSV file per target
* Downloaded files
  * A collection of downloaded suspicious files (if download is enabled). Structured by TARGET\SHARE\DIRECTORY\FILE

```
logs
│   smbscan-20220518-075257.log
|   smbscan-<TARGET>-<YYYYMMDD>-<HHMMSS>.csv
│   smbscan-desktop-9kolm4-20220518-075257.csv
│   smbscan-testserver-20220518-075257.csv
│
└───<TARGET>
│   └───<SHARE>
│       └───<DIRECTORY>
│           │   suspicious-file
|
└───DESKTOP-9KOLKM4
│   └───inetpub
│       └───wwwroot
│           │   web.config
│   
└───TESTSERVER
│   └───TESTER
│       └───.aws
│           |   credentials
│       └───.ssh
│           |   id_rsa.pub
```

---
## Authors
* Jeff Thomas - https://github.com/jeffhacks
* Yianna Paris - https://github.com/nekosoft

---
## Acknowledgments
* Wireghoul - https://github.com/wireghoul
* Impacket - https://github.com/SecureAuthCorp/impacket
