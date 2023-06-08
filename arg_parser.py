import argparse
import logging
import os

import setup


class Options:
    def __init__(
        self,
        hostname          = "SMBScan",
        logDirectory      = os.path.join(os.getcwd(), "logs"),
        kerberos          = False,
        port              = 139,
        timeout           = 2,
        jitter            = 3,
        jitterTarget      = 3,
        jitterOperation   = 3,
        threads           = 1,
        aesKey            = "",
        dc_ip             = "",
        csvFile           = [],
        stateFile         = "",
        includePaths      = [],
        excludePaths      = [],
        includeShares     = [],
        excludeShares     = [],
        excludeHosts      = [],
        maxDepth          = 0,
        patternsFile      = setup.OS_PATH_DEFAULT_PATTERN_PATH,
        downloadFiles     = 0,
        logLevel          = logging.INFO
    ):
        self.hostname          = hostname
        self.logDirectory      = logDirectory
        self.kerberos          = kerberos
        self.port              = port
        self.timeout           = timeout
        self.threads           = threads
        self.jitter            = jitter
        self.jitterTarget      = jitterTarget
        self.jitterOperation   = jitterOperation
        self.aesKey            = aesKey
        self.dc_ip             = dc_ip
        self.csvFile           = csvFile
        self.stateFile         = stateFile
        self.includePaths      = includePaths
        self.excludePaths      = excludePaths
        self.includeShares     = includeShares
        self.excludeShares     = excludeShares
        self.excludeHosts      = excludeHosts
        self.maxDepth          = maxDepth,
        self.patternsFile      = patternsFile
        self.patterns          = []
        self.downloadFiles     = downloadFiles
        self.logLevel          = logLevel

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
    parser.add_argument(
        "--no-pass", help="Don't use a password. (Useful for Kerberos)", action="store_true"
    )
    parser.add_argument(
        "-H", "--hash", help="NTLM Hash for user"
    )
    parser.add_argument("-d", "--domain", help="Domain for user")
    parser.add_argument("-k", "--kerberos", help="Enable kerberos", action="store_true")
    parser.add_argument(
        "--aesKey",
        help="",
    )
    parser.add_argument(
        "--dc-ip",
        help="",
    )
    parser.add_argument(
        "-j",
        "--jitter",
        help="Random delay between some requests. Default 3 seconds.",
        type=int,
        default=3,
    )
    parser.add_argument(
        "-jt",
        "--jitter-target",
        help="Random delay before moving to next target. Default 3 seconds.",
        type=int,
    )
    parser.add_argument(
        "-jo",
        "--jitter-operation",
        help="Random delay between some file operations on target. Default 3 seconds.",
        type=int,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Set timeout for connections. Default 2 seconds.",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--threads",
        help="Set number of threads. Default 1 thread.",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--shares-only",
        help="Display shares only. Do not crawl directories and files.",
        action="store_true"
    )
    parser.add_argument(
        "--log-directory",
        help="Override log file directory",
        default=os.path.join(os.getcwd(), "logs")
    )
    parser.add_argument(
        "--include-paths",
        help="List of comma separated paths to include in scan. All others will be excluded.",
    )
    parser.add_argument(
        "--exclude-paths",
        help="List of comma separated paths to exclude from scan. All others will be included.",
    )
    parser.add_argument(
        "--include-shares",
        help="List of comma separated shares to include in scan. All others will be excluded.",
    )
    parser.add_argument(
        "--exclude-shares",
        help="List of comma separated shares to exclude from scan. All others will be included.",
    )
    parser.add_argument(
        "--exclude-hosts",
        help="List of comma separated hosts to exclude from scan.",
    )
    parser.add_argument(
        "--max-depth",
        help="Maximum depth to crawl. 0 (default) = unlimited.",
        type=int,
        default=0,
    )
    parser.add_argument(
        "--patterns-file",
        help="Specify patterns file. Default if unspecified is patterns.txt",
        default=setup.OS_PATH_DEFAULT_PATTERN_PATH
    )
    parser.add_argument(
        "-df",
        "--download-files",
        help="Download suspicious files. 0 (default) = no.",
        action="store_true"
    )
    parser.add_argument(
        "--debug",
        help="Include debug messages in terminal output.",
        action="store_true"
    )
    parser.add_argument(
        "--state-file",
        help="State file for tracking complete targets and skipping these on subsequent scans.",
    )

    return parser.parse_args()
