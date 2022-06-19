# SMBScan

### Overview
SMBScan is a tool developed to enumerate file shares on an internal network.

It's primary objectives are:

* Scan a single target or hundreds of targets
* Enumerate all accessible shares and files
* Identify files that potentially contain credentials or secrets
* Try to avoid detection by blue teams

### Table of Contents
1. [Getting Started](#getting-started)
2. [Running Scans](#running-scans)
3. [Scan Output](#scan-output)
4. [Analysing Output](#analysing-output)
5. [Authors](#authors)
6. [Acknowledgements](#acknowledgments)

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
python3 src/smbscan.py 192.168.0.0/24
```

```log
[2022-05-21 22:14:17 INFO] src/smbscan.py 192.168.0.26
[2022-05-22 20:45:36 INFO] Scanning 192.168.0.26
[2022-05-21 22:14:17 INFO] 192.168.0.26 (TESTSERVER) Connected as tester, Target OS: eWeblrdS
[2022-05-21 22:14:17 INFO] 192.168.0.26 (TESTSERVER) Scanning \\TESTSERVER\TESTER
[2022-05-21 22:14:17 CRITICAL] Suspicous file: \\TESTSERVER\TESTER\.ssh\id_rsa.pub (Sat May 21 21:12:21 2022, 563)
[2022-05-21 22:14:17 CRITICAL] Suspicous file: \\TESTSERVER\TESTER\.ssh\id_rsa (Sat May 21 21:12:21 2022, 2590)
[2022-05-21 22:14:18 CRITICAL] Suspicous file: \\TESTSERVER\TESTER\.aws\credentials (Sat May 21 21:12:23 2022, 119)
[2022-05-21 22:14:26 INFO] Scan completed
```

Scan a range of targets as a specific domain user with a random delay of 1-3 seconds between targets and operations on targets:
```bash
python3 src/smbscan.py 192.168.0.0/24 -u tester -p Monkey123 ---download-files --max-depth 3 --exclude-hosts 192.168.0.18
```

```log
[2022-05-21 22:14:17 INFO] src/smbscan.py 192.168.0.0/24 -u tester -p Monkey123 ---download-files --max-depth 3 --exclude-hosts 192.168.0.18
[2022-05-21 22:14:17 INFO] Scanning 192.168.0.0/24
[2022-05-21 22:14:17 WARNING] Skipping 192.168.0.18 (on exclusion list)
[2022-05-21 22:14:17 INFO] 192.168.0.26 (TESTSERVER) Connected as tester, Target OS: eWeblrdS
[2022-05-21 22:14:17 INFO] 192.168.0.26 (TESTSERVER) Scanning \\TESTSERVER\TESTER
[2022-05-21 22:14:17 CRITICAL] Suspicous file: \\TESTSERVER\TESTER\.ssh\id_rsa.pub (Sat May 21 21:12:21 2022, 563)
[2022-05-21 22:14:17 CRITICAL] Suspicous file: \\TESTSERVER\TESTER\.ssh\id_rsa (Sat May 21 21:12:21 2022, 2590)
[2022-05-21 22:14:18 CRITICAL] Suspicous file: \\TESTSERVER\TESTER\.aws\credentials (Sat May 21 21:12:23 2022, 119)
[2022-05-21 22:14:18 INFO] Scanning 192.168.0.35
[2022-05-21 22:14:19 INFO] 192.168.0.35 (desktop-9kolkm4) Connected as tester, Target OS: Windows 10.0 Build 19041
[2022-05-21 22:14:19 INFO] 192.168.0.35 (desktop-9kolkm4) Scanning \\desktop-9kolkm4\ADMIN$
[2022-05-21 22:14:19 INFO] 192.168.0.35 (desktop-9kolkm4) Error accessing ADMIN$
[2022-05-21 22:14:19 INFO] 192.168.0.35 (desktop-9kolkm4) Scanning \\desktop-9kolkm4\Backups
[2022-05-21 22:14:19 INFO] 192.168.0.35 (desktop-9kolkm4) Scanning \\desktop-9kolkm4\C$
[2022-05-21 22:14:19 INFO] 192.168.0.35 (desktop-9kolkm4) Error accessing C$
[2022-05-21 22:14:20 INFO] 192.168.0.35 (desktop-9kolkm4) Scanning \\desktop-9kolkm4\E$
[2022-05-21 22:14:20 INFO] 192.168.0.35 (desktop-9kolkm4) Error accessing E$
[2022-05-21 22:14:20 INFO] 192.168.0.35 (desktop-9kolkm4) Scanning \\desktop-9kolkm4\inetpub
[2022-05-21 22:14:24 CRITICAL] Suspicous file: \\desktop-9kolkm4\inetpub\wwwroot\web.config (Sat May 21 20:48:54 2022, 31506)
[2022-05-21 22:14:24 INFO] 192.168.0.35 (desktop-9kolkm4) Scanning \\desktop-9kolkm4\Users
[2022-05-21 22:14:26 CRITICAL] Suspicous file: \\desktop-9kolkm4\Users\tester\Documents\Passwords.kdbx (Fri May 20 21:57:30 2022, 1870)
[2022-05-21 22:14:26 INFO] Scan completed
```

---
## Scan Output
SMBScan produces a number of files.

* Primary logfile
  * A primary logfile for each scan - records everything that's output to the terminal
* CSV index files
  * A listing of all accessible shares and files. One CSV file per target
* Downloaded files
  * A collection of downloaded suspicious files (if download is enabled). Structured by TARGET\SHARE\DIRECTORY\FILE

```
logs
│   smbscan-20220518-075257.log
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
│   |   └───wwwroot
│   |       │   web.config
│   └───Users
│       └───tester
│           └───Documents
│               │   Passwords.kdbx
│   
└───TESTSERVER
│   └───TESTER
│       └───.aws
│           |   credentials
│       └───.ssh
│           |   id_rsa.pub
```

---
## Analysing Output

### Search Downloaded Files
Use grep, or speed up the process with graudit (https://github.com/wireghoul/graudit)
```bash
graudit -d secrets -x *.csv logs/
```

### View CSV Files
```bash
cat logs/smbscan-desktop-9kolm4-20220518-075257.csv | sed -e 's/,,/, ,/g' | column -s, -t | less -#5 -N -S
```

```
1 tester  DESKTOP-9KOLKM4  desktop-9kolkm4  192.168.0.35  Backups  \MSSQL
2 tester  DESKTOP-9KOLKM4  desktop-9kolkm4  192.168.0.35  Backups  \MSSQL\BookingSystem.bak
3 tester  DESKTOP-9KOLKM4  desktop-9kolkm4  192.168.0.35  inetpub  \wwwroot
4 tester  DESKTOP-9KOLKM4  desktop-9kolkm4  192.168.0.35  inetpub  \wwwroot\index.cs
5 tester  DESKTOP-9KOLKM4  desktop-9kolkm4  192.168.0.35  inetpub  \wwwroot\Robots.txt
6 tester  DESKTOP-9KOLKM4  desktop-9kolkm4  192.168.0.35  inetpub  \wwwroot\web.config
```

### Search CSV Files
```bash
grep -i -e \.bak *.csv

tester,DESKTOP-9KOLKM4,desktop-9kolkm4,192.168.0.35,Backups,\MSSQL\BookingSystem.bak.....
```

---
## Authors
* Jeff Thomas - https://github.com/jeffhacks
* Yianna Paris - https://github.com/nekosoft

---
## Acknowledgments
* Wireghoul - https://github.com/wireghoul
* Justin Steven - https://github.com/justinsteven
* Impacket - https://github.com/SecureAuthCorp/impacket
