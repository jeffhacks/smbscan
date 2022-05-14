import argparse

import setup


class Options:
    def __init__(
        self,
        hostname          = "SMBScan",
        logfile           = "log",
        kerberos          = False,
        port              = 139,
        timeout           = 2,
        jitter            = 3,
        aesKey            = "",
        dc_ip             = "",
        csvFile           = [],
        includeShares     = [],
        excludeShares     = [],
        maxDepth          = 0,
        patternsFile      = setup.OS_PATH_DEFAULT_PATTERN_PATH,
        downloadFiles     = 0
    ):
        self.hostname          = hostname
        self.logfile           = logfile
        self.kerberos          = kerberos
        self.port              = port
        self.timeout           = timeout
        self.jitter            = jitter
        self.aesKey            = aesKey
        self.dc_ip             = dc_ip
        self.csvFile           = csvFile
        self.includeShares     = includeShares
        self.excludeShares     = excludeShares
        self.maxDepth          = maxDepth,
        self.patternsFile      = patternsFile
        self.patterns          = []
        self.downloadFiles     = downloadFiles

def setup_command_line_args(args = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "target",
        nargs="?",
        help="Target for scanning. e.g. 192.168.1.1 or 192.168.1.0/24",
    )
    group.add_argument(
        "-f",
        "--file",
        help="List of targets for scanning.",
        type=argparse.FileType("r"),
    )
    parser.add_argument("-u", "--user", help="User to connect as")
    parser.add_argument(
        "-p", "--password", help="Password for user (will prompt if missing and needed)"
    )
    parser.add_argument("-d", "--domain", help="Domain for user")
    parser.add_argument("-k", "--kerberos", help="Not implemented", action="store_true")
    parser.add_argument(
        "-j",
        "--jitter",
        help="Random delay between some requests. Default 3 seconds.",
        type=int,
        default=3,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Set timeout for connections. Default 2 seconds.",
        type=int,
        default=2,
    )
    parser.add_argument(
        "-s",
        "--shares-only",
        help="Display shares only. Do not crawl directories and files.",
        action="store_true"
    )
    parser.add_argument(
        "-l", "--logfile", help="Override log file name (without extension)"
    )
    parser.add_argument(
        "-i",
        "--include-shares",
        help="List of comma separated shares to include in scan. All others will be excluded.",
    )
    parser.add_argument(
        "-e",
        "--exclude-shares",
        help="List of comma separated shares to exclude from scan. All others will be included.",
    )
    parser.add_argument(
        "-m",
        "--max-depth",
        help="Maximum depth to crawl. 0 (default) = unlimited.",
        type=int,
        default=0,
    )
    parser.add_argument(
        "-pf", "--patterns-file",
        help="Specify patterns file. Default if unspecified is patterns.txt",
        default=setup.OS_PATH_DEFAULT_PATTERN_PATH
    )
    parser.add_argument(
        "-df", "--download-files",
        help="Download suspicious files. 0 (default) = no.",
        action="store_true"
    )

    return parser.parse_args()
