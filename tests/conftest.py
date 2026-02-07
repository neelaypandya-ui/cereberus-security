"""Shared test fixtures."""

import asyncio
import os
import tempfile
from collections import namedtuple
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _make_family(name: str):
    """Create a mock socket address family with a proper .name attribute."""
    family = MagicMock()
    family.name = name
    return family


@pytest.fixture
def mock_psutil_interfaces():
    """Mock psutil network interface data."""
    af_inet = _make_family("AF_INET")
    mock_addrs = {
        "Ethernet": [
            MagicMock(family=af_inet, address="192.168.1.100"),
        ],
        "TAP-Windows Adapter V9": [
            MagicMock(family=af_inet, address="10.8.0.2"),
        ],
        "Loopback": [
            MagicMock(family=af_inet, address="127.0.0.1"),
        ],
    }
    mock_stats = {
        "Ethernet": MagicMock(isup=True, speed=1000, mtu=1500),
        "TAP-Windows Adapter V9": MagicMock(isup=True, speed=100, mtu=1400),
        "Loopback": MagicMock(isup=True, speed=0, mtu=1500),
    }
    return mock_addrs, mock_stats


@pytest.fixture
def mock_subprocess_ipconfig():
    """Mock ipconfig /all output."""
    return """
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 8.8.8.8
                                        8.8.4.4

Ethernet adapter TAP-Windows Adapter V9:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.8.0.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.8.0.1
   DNS Servers . . . . . . . . . . . : 10.8.0.1
"""


@pytest.fixture
def mock_route_print():
    """Mock route print -4 output."""
    return """
===========================================================================
Interface List
  5...00 ff 12 34 56 78 ......TAP-Windows Adapter V9
  3...aa bb cc dd ee ff ......Intel(R) Ethernet Connection
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.8.0.1       10.8.0.2       5
          0.0.0.0          0.0.0.0     192.168.1.1   192.168.1.100      25
       10.8.0.0    255.255.255.0         On-link        10.8.0.2    261
     192.168.1.0    255.255.255.0         On-link    192.168.1.100    281
===========================================================================
"""


# --- Network Sentinel fixtures ---

SConn = namedtuple("sconn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])
Addr = namedtuple("addr", ["ip", "port"])


@pytest.fixture
def mock_connections():
    """Mock psutil network connections for testing."""
    return [
        SConn(fd=-1, family=2, type=1,
              laddr=Addr("192.168.1.100", 55000),
              raddr=Addr("10.0.0.1", 443),
              status="ESTABLISHED", pid=100),
        SConn(fd=-1, family=2, type=1,
              laddr=Addr("0.0.0.0", 80),
              raddr=(),
              status="LISTEN", pid=200),
        SConn(fd=-1, family=2, type=1,
              laddr=Addr("192.168.1.100", 60000),
              raddr=Addr("10.0.0.2", 4444),
              status="ESTABLISHED", pid=300),
        SConn(fd=-1, family=2, type=2,
              laddr=Addr("0.0.0.0", 53),
              raddr=(),
              status="NONE", pid=400),
    ]


# --- File Integrity fixtures ---

@pytest.fixture
def temp_watched_dir():
    """Create a temporary directory with test files for integrity monitoring."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "file1.txt").write_text("content of file 1")
        (Path(tmpdir) / "file2.py").write_text("print('hello')")
        (Path(tmpdir) / "ignore.tmp").write_text("temporary")
        (Path(tmpdir) / "skip.log").write_text("log entry")

        subdir = Path(tmpdir) / "subdir"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("nested content")

        yield tmpdir


# --- Process Analyzer fixtures ---

@pytest.fixture
def mock_process_list():
    """Create a mock list of process_iter results."""
    def _make_proc(pid, name, exe="", cpu=0.0, mem=0.0, status="running", ppid=0):
        proc = MagicMock()
        proc.info = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "username": "test_user",
            "cpu_percent": cpu,
            "memory_percent": mem,
            "status": status,
            "create_time": 1700000000.0,
            "ppid": ppid,
        }
        return proc

    return [
        _make_proc(100, "chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe"),
        _make_proc(200, "explorer.exe", r"C:\Windows\explorer.exe"),
        _make_proc(300, "mimikatz.exe", r"C:\temp\mimikatz.exe"),
    ]
