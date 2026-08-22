import pytest
from unittest.mock import patch

import arg_parser
import scan
import scan_internals


class FakeClient:
    """Minimal SMBConnection stand-in exposing what scan_single touches."""

    def __init__(self):
        self.closed = 0
        self.shares = []

    def getServerOS(self):
        return "Windows"

    def close(self):
        self.closed += 1


class FakeTarget:
    def __init__(self, ip="192.0.2.1", name="testhost"):
        self.ip = ip
        self.name = name


def make_options(tmp_path, crawl=True):
    opts = arg_parser.Options()
    opts.timeout = 2
    opts.threads = 1
    opts.jitter = 0
    opts.jitterTarget = 0
    opts.jitterOperation = 0
    opts.logDirectory = str(tmp_path)
    opts.stateFile = str(tmp_path / "test.state")
    opts.crawlShares = crawl
    opts.includePaths = []
    opts.excludePaths = []
    opts.includeShares = []
    opts.excludeShares = []
    opts.excludeHosts = []
    opts.maxDepth = 0
    opts.patterns = []
    opts.downloadFiles = False
    return opts


def read_state(tmp_path):
    lines = (tmp_path / "test.state").read_text().strip().splitlines()
    return [line for line in lines if "192.0.2.1" in line]


def test_scan_single_records_error_when_shares_crawl_fails(tmp_path):
    """A failure while enumerating shares/files must be recorded as 'Error'
    in the state file, not silently marked as 'Scan completed'."""
    opts = make_options(tmp_path, crawl=True)

    class FailingClient(FakeClient):
        def listShares(self):
            raise RuntimeError("boom")

    with patch.object(scan, "Target", return_value=FakeTarget()), \
         patch.object(scan_internals, "get_client",
                      return_value=FailingClient()), \
         patch.object(scan, "is_host_in_statefile", return_value=False):
        scan.scan_single("192.0.2.1", scan.User(), opts)

    entries = read_state(tmp_path)
    assert entries, "target should have been written to the state file"
    assert any("Error" in entry for entry in entries)


def test_scan_single_does_not_crash_when_no_logfile_opened(tmp_path):
    """If open(logfileName, 'a') fails, scan_single must not raise
    UnboundLocalError from logfile.close() in the finally block."""
    opts = make_options(tmp_path)
    real_open = open  # reference the real builtin before it is patched

    def fail_logfile_open(path, mode="r", *a, **k):
        # Only fail opening the CSV log file, so the state file can still be
        # written and the outcome verified.
        if "smbscan-" in path and mode == "a":
            raise OSError("permission denied")
        return real_open(path, mode, *a, **k)

    with patch.object(scan, "Target",
                      return_value=FakeTarget(name="testhost")), \
         patch.object(scan_internals, "get_client",
                      return_value=FakeClient()), \
         patch.object(scan, "is_host_in_statefile", return_value=False), \
         patch("builtins.open", side_effect=fail_logfile_open):
        # must not raise; the exception is swallowed by the except handler
        scan.scan_single("192.0.2.1", scan.User(), opts)

    entries = read_state(tmp_path)
    assert entries, "target should have been written to the state file"
    assert any("Error" in entry for entry in entries)