import re
import socket
import validators
from fqdn import FQDN
from enum import Enum
from urllib.parse import urlparse


class StixItemType(Enum):
    UNKNOWN         =   0,
    IPADDR          =   1,
    DOMAIN          =   2,
    URL             =   3,
    SHA256          =   4,
    MD5             =   5,
    SHA1            =   6,


def guess_type(value):
        if not value or len(value) == 0:
            return StixItemType.UNKNOWN, "unknown"

        if re.match("^[a-f0-9]{64}$", value, flags=re.IGNORECASE):
            return StixItemType.SHA256, "SHA256"

        if re.match("^[a-f0-9]{40}$", value, flags=re.IGNORECASE):
            return StixItemType.SHA1, "SHA1"

        if re.match("^[a-f0-9]{32}$", value, flags=re.IGNORECASE):
            return StixItemType.MD5, "MD5"

        try:
            socket.inet_aton(value)
            return StixItemType.IPADDR, "IPv4"
        except socket.error:
            pass

        if len(value) <= 255:
            fqdn = FQDN(value)
            if fqdn.is_valid:
                return StixItemType.DOMAIN, "domain"

        if validators.url(value):
            return StixItemType.URL, "URL"

        return StixItemType.UNKNOWN, "unknown"
