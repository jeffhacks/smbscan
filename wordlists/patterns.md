# Patterns

| Example Filename or Extension | Regular Expression | Description |
| --- | --- | --- |
| `My Passwords.txt` | `^.*(password\|credential\|logon).*\.(txt\|rtf\|doc\|xls).?$` | Text, RTF, and Office files containing `password`, `credential`, or `logon` in the filename |
| `web.config`, `*.conf` | `^.*\.(cfg\|conf(ig)?)$` | Config files, e.g. `web.config` |
| `wp-config.php`, `wp-config.bak` | `^.*wp-config.*$` | Wordpress config files e.g. `wp-config.php` and `wp-config.bak` |
| `*.env` | `^.*\.env$` | Environment variables |
| `*.bat` | `^.*\.bat$` | Batch files |
| `*.vbs` | `^.*\.vbs$` | VBScripts |
| `*.ps1` | `^.*\.ps1$` | PowerShell scripts |
| `*.sh` | `^.*\.sh$` | Shell scripts |
| `*.htpass` | `^.*\.htpass$` | Usernames and passwords |
| `Freds Handover.pptx` | `^.*(handover).*\.(txt\|rtf\|pdf\|doc\|ppt\|xls).?$` | Text, RTF, PDF, and Office files containing `handover` in the filename |
| `credentials` | `^credentials$` | AWS Credentials file, e.g. `~/.aws/credentials` |
| `unattend.xml `| `^unattend\.xml$` | Windows setup file |
| `unattended.xml` | `^unattended\.xml$` | Windows setup file |
| `sysprep.inf` | `^sysprep\.inf$` | Windows setup file |
| `sysprep.xml` | `^sysprep\.xml$` | Windows setup file |
| `group.xml` | `^group\.xml$` | Group Policy Preferences (GPP) |
| `groups.xml` | `^groups\.xml$` | Group Policy Preferences (GPP) |
| `services.xml` | `^services\.xml$` | Group Policy Preferences (GPP) Create/Update Services |
| `scheduledtasks.xml` | `^scheduledtasks\.xml$` | Group Policy Preferences (GPP) Scheduled Tasks |
| `printers.xml` | `^printers\.xml$` | Group Policy Preferences (GPP) Printer configuration |
| `drives.xml` | `^drives\.xml$` | Group Policy Preferences (GPP) Map drives |
| `datasources.xml` | `^datasources\.xml$` | Group Policy Preferences (GPP) Data Sources |
| `vnc.ini` | `^vnc\.ini$` | May contain encrypted password |
| `WinSCP.ini` | `^WinSCP\.ini$` | May contain ssh credentials |
| `ws_ftp.ini` | `^ws_ftp\.ini$` | May contain ftp credentials |
| `*.kdb`, `*.kdbx` | `^.*\.kdb.?$` | Keepass containers |
| `config.xml` | `^.*config\.xml$` | Config files in XML |
| `id_rsa` | `^.*(id_dsa\|id_ecdsa\|id_ed25519\|id_rsa).*$` | Default private key filenames from `ssh_keygen` |
| `*.pem`, `*.ppk` | `^.*\.(pem\|ppk)$` | Private keys |