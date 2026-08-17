# Created by Nozomi Networks Labs

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# One valid indicator for each of the supported types.
MD5 = "3d4eaa47159a333d365d5a9aea441244"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "a8affe8562b5b02b2ddcceb228ed2bf9d3088789f7d5e1d027d8324883aa91b5"
IPV4 = "111.111.111.111"
DOMAIN = "test.com"
URL = "http://asd.it/test.exe"

ALL_IOC = [MD5, SHA1, SHA256, IPV4, DOMAIN, URL]

# A line that cannot be classified as any of the supported types.
INVALID_IOC = "wrong indicator"


def run_script(script, *args):
    """Run one of the CLI scripts the way a user would, from the repository root."""
    cmd = [sys.executable, script] + [str(a) for a in args]
    return subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)


@pytest.fixture
def write_iocs(tmp_path):
    """Return a helper writing a newline-separated indicator file and giving back its path."""
    def _write(iocs, name="indicators.txt"):
        path = tmp_path / name
        path.write_text("\n".join(iocs) + "\n")
        return path
    return _write


@pytest.fixture
def all_types_file(write_iocs):
    """An input file holding one indicator per supported type."""
    return write_iocs(ALL_IOC)
