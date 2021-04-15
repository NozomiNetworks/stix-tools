# Created by Nozomi Networks Labs

import re, socket, warnings, logging
warnings.filterwarnings("ignore")

from .logger import *
from fqdn import FQDN
from enum import Enum
from datetime import datetime
from urllib.parse import urlparse

# python-stix
import stix.utils as utils
from stix.indicator import Indicator
from stix.common import InformationSource, References
from stix.core import STIXPackage, STIXHeader

# python-cybox
from cybox.common import Time
from cybox.objects.uri_object import URI
from cybox.objects.file_object import File
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.bindings import domain_name_object, file_object, uri_object, address_object


# The following code was added to resolve an issue with missing name spaces. If the namespace "http://us-cert.gov/ciscp" is in a stix file, the program crashes
# as for some reason those name spaces are not in the library. As of April 2019 the problem is known, and this is a work around.
from stix.utils import nsparser
import mixbox.namespaces
from mixbox.namespaces import Namespace
from mixbox import fields

ADDITIONAL_NAMESPACES = [
    Namespace('http://us-cert.gov/ciscp', 'CISCP',
              'http://www.us-cert.gov/sites/default/files/STIX_Namespace/ciscp_vocab_v1.1.1.xsd')
]

class StixItemType(Enum):
    UNKNOWN         =   0,
    IPADDR          =   1,
    DOMAIN          =   2,
    URL             =   3,
    SHA256          =   4,
    MD5             =   5,
    SHA1            =   6,

class StixIndicator:
    def __init__(self, ioctype, value, title, descr, produced_time):
        self.value = value
        self.title = title
        self.descr = str(descr)
        self.type = ioctype
        self.timestamp = produced_time

    def __str__(self):
        return "[%s] value: %s" % (self.type, self.value)

    @property
    def type(self):
        return self._type 
       
    @type.setter 
    def type(self, val): 
        assert isinstance(val, StixItemType)
        self._type = val

    def is_unknown(self):
        return self._type == StixItemType.UNKNOWN

class StixManager(object):
    def __init__(self, threat_name="Generic Threat", threat_descr="Generic Threat", company="Nozomi Networks Labs" , log=True):

        for i in ADDITIONAL_NAMESPACES:
            nsparser.STIX_NAMESPACES.add_namespace(i)
            mixbox.namespaces.register_namespace(i)

        self._pkg = STIXPackage()
        self.set_stix_header(threat_name, threat_descr)
        self.__regex_sha256 = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
        self.__regex_md5 = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
        self.__regex_sha1 = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
        self._src_file = None
        self.__company = company
        

        self._lookup = set()
        self.__log = log
        
    def guess_type(self, value):
        '''
        Returns (type, description)
        '''

        if not value or len(value) == 0:
            return StixItemType.UNKNOWN, "unknown"

        # SHA256 check
        if self.__regex_sha256.match(value):
            return StixItemType.SHA256, "SHA256"

        # SHA1 check
        if self.__regex_sha1.match(value):
            return StixItemType.SHA1, "SHA1"

        # MD5 check
        if self.__regex_md5.match(value):
            return StixItemType.MD5, "MD5"

        # IPv4 check
        try:
            socket.inet_aton(value)
            return StixItemType.IPADDR, "IPv4"
        except socket.error:
            pass

        # Domain name
        if len(value) <= 255:
            fqdn = FQDN(value)
            if fqdn.is_valid:
                return StixItemType.DOMAIN, "domain"

        url = urlparse(value)
        if 3 <= len(url.scheme) <= 5 and url.netloc:
            return StixItemType.URL, "URL"

        return StixItemType.UNKNOWN, "unknown"

    def _is_ascii(self, value):
        return value.isascii()

    def load_raw_file(self, fname):
        with open(fname, 'r') as f:
            rawdata = f.readlines()

        for line in rawdata:
            ioc = line.strip()
            if len(ioc) > 0:
                res = self.add_raw_indicator(ioc)
                if res is True:
                    if self.__log is True:
                        logging.info("Auto-detected indicator: %s", ioc)
                else:
                    if self.__log is True:
                        logging.warning("Unknown indicator format: %s", ioc)
                self._src_file = fname
        return True

    def save_stix_file(self , file_name):
        try:
            with open(file_name, 'wb') as f:
                f.write(self._pkg.to_xml())
            return True
        except Exception as e:
            if self.__log is True:
                logging.error(e)
            return False

    def set_stix_header(self, threat_name, threat_descr, threat_source=None, reference=None):
        # Create a STIX Package
        hdr = STIXHeader()
        hdr.title =  threat_name
        hdr.add_description(threat_descr)
        hdr.information_source = InformationSource()

        if threat_source != None:
            hdr.information_source.description = threat_source

        if reference != None:
            hdr.information_source.references = fields.TypedField(reference, References)

        # Set the produced time to now
        hdr.information_source.time = Time()
        hdr.information_source.time.produced_time = datetime.utcnow()

        self._pkg.stix_header = hdr

    def add_raw_indicator(self , orig_indicator, ts=None):
        indicator_value = orig_indicator
        if not self._is_ascii(indicator_value):
            #print("WARNING: the indicator %s is not ASCII-decodable" % indicator_value)
            return False

        indicator_type, _ = self.guess_type(indicator_value)
        # Create a CyboX File Object
        if indicator_type == StixItemType.IPADDR:
            title = "Malicious IPv4 - %s" % indicator_value
            descr = "Malicious IPv4 involved with %s" % self._pkg.stix_header.title
            cybox = Address(indicator_value , Address.CAT_IPV4)
        elif indicator_type == StixItemType.DOMAIN:
            title = "Malicious domain - %s" % indicator_value
            descr = "Malicious domain involved with %s" % self._pkg.stix_header.title
            cybox = DomainName()
            cybox.value = indicator_value
        elif indicator_type == StixItemType.MD5:
            title = "Malicious MD5 - %s" % indicator_value
            descr = "Malicious MD5 involved with %s" % self._pkg.stix_header.title
            cybox = File()
            cybox.add_hash(indicator_value )
        elif indicator_type == StixItemType.SHA256:
            title = "Malicious SHA256 - %s" % indicator_value
            descr = "Malicious SHA256 involved with %s" % self._pkg.stix_header.title
            cybox = File()
            cybox.add_hash(indicator_value )
        elif indicator_type == StixItemType.SHA1:
            title = "Malicious SHA1 - %s" % indicator_value
            descr = "Malicious SHA1 involved with %s" % self._pkg.stix_header.title
            cybox = File()
            cybox.add_hash(indicator_value )
        elif indicator_type == StixItemType.URL:
            title = "Malicious URL - %s" % indicator_value
            descr = "Malicious URL involved with %s" % self._pkg.stix_header.title
            cybox = URI()
            cybox.value = indicator_value
            cybox.type_ = URI.TYPE_URL

        if indicator_type == StixItemType.UNKNOWN:
            return False

        indicator = Indicator()
        indicator.title = title
        indicator.description = descr
        indicator.add_object(cybox)
        indicator.set_producer_identity(self.__company)
        if ts:
            indicator.set_produced_time(ts)
        else:
            indicator.set_produced_time(utils.dates.now())

        self._add(indicator)
        return True

    def _add(self, indicator):
        ioc = self._parse_indicator(indicator)
        assert len(ioc) == 1, "Multiple observables in a single indicator not supported yet"
        ioc = ioc[0]

        # Check for duplicates
        if self.is_duplicated(ioc.value):
            if self.__log is True:
                logging.warning("Skipping duplicated indicator: %s", ioc.value)
            return False

        # Update description
        _, type_descr = self.guess_type(ioc.value)
        indicator.title = "Malicious %s - %s" % (type_descr, ioc.value)
        indicator.description = "Malicious %s involved with the threat %s" % (type_descr, self._pkg.stix_header.title)

        # Update the lookup table
        self._lookup.add(ioc.value)

        self._pkg.add(indicator)
        return True

    def is_duplicated(self, ivalue):
        return ivalue in self._lookup

    def _parse_indicator(self, indicator):
        processed_indicators = []

        title = indicator.title
        description = indicator.description
        timestamp = indicator.get_produced_time()
        identifier = indicator.id_

        if timestamp:
            timestamp = timestamp.value
        else:
            logging.warning("Failed to get produced time")

        for obj in indicator.observables:
            # Object attributes
            obj_val = None
            obj_type = None

            # Extract the object properties
            obj_prop = obj.to_obj().Object.Properties
            if isinstance(obj_prop, domain_name_object.DomainNameObjectType):
                obj_val = obj_prop.Value.valueOf_
                obj_type = StixItemType.DOMAIN
            elif isinstance(obj_prop, file_object.FileObjectType):
                # TODO: support multiple hashes
                obj_hash = obj_prop.Hashes.get_Hash()[0]
                obj_hash_type = obj_hash.Type.valueOf_.upper()
                if obj_hash_type in ['SHA256', 'SHA1', 'MD5']:
                    obj_val = obj_hash.get_Simple_Hash_Value().valueOf_
                    if obj_hash_type == 'SHA256':
                        obj_type = StixItemType.SHA256
                    elif obj_hash_type == 'SHA1':
                        obj_type = StixItemType.SHA1
                    elif obj_hash_type == 'MD5':
                        obj_type = StixItemType.MD5
                    else:
                        obj_type = StixItemType.UNKNOWN
                else:
                    if self.__log is True:
                        logging.warning("Unsupported hash type: %s" % obj_hash_type)
            elif isinstance(obj_prop, uri_object.URIObjectType):
                obj_val = obj_prop.Value.valueOf_
                obj_type = StixItemType.URL
            elif isinstance(obj_prop, address_object.AddressObjectType):
                obj_val = obj_prop.Address_Value.valueOf_
                obj_type = StixItemType.IPADDR
            else:
                obj_val = indicator
                obj_type = StixItemType.UNKNOWN

            # Strip-out the value
            obj_val = obj_val.strip()

            ioc = StixIndicator(obj_type, obj_val, title, description, timestamp)
            processed_indicators.append(ioc)

        # Return indicators
        return processed_indicators