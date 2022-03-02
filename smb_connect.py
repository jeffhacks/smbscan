from impacket.smbconnection import SMBConnection, SessionError
from print import printStatus, Colors

class Share:
    def __init__(self, shareName):
        self.shareName = shareName
        self.sharedFiles = []

def getShares(smbClient, target):
    resp = smbClient.listShares()
    for i in range(len(resp)):
        shareName = resp[i]["shi1_netname"][:-1]
        if shareName not in ["NETLOGON", "SYSVOL", "IPC$", "print$"]:
            target.shares.append(Share(shareName))


def getClient(target, user, options, port):
    try:
        smbClient = SMBConnection(
            "*\\*SMBSERVER*", target.ip, timeout=options.timeout, sess_port=int(port)
        )
        if options.kerberos is True:
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
        printStatus(
            target,
            Colors.WARNING,
            "SESSION FAILURE: (%1s, %2s) %3s" % (user.username, str(port), str(e)),
            options,
        )
        # Host is live
        return None
    except Exception as e:
        if "timed out" in str(e):
            None  # printStatus(target, Colors.WARNING, "CONNECTION FAILURE: " + str(e), options)
            # Host is not live
        elif "Connection refused" in str(e):
            printStatus(
                target,
                Colors.WARNING,
                "CONNECTION FAILURE: (%1s, %2s) %3s"
                % (user.username, str(port), str(e)),
                options,
            )
            # Host is live
        else:
            printStatus(
                target,
                Colors.FAIL,
                "CONNECTION FAILURE: (%1s, %2s) %3s"
                % (user.username, str(port), str(e)),
                options,
            )
            # Host is live
        return None
