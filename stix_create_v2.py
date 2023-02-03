# Created by Nozomi Networks Labs

import argparse
import logging
import re
from datetime import datetime
from urllib.parse import urlparse

from stix2 import Indicator, Bundle, Identity, Malware, Relationship, AttackPattern
from stix2 import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
from lib.stix_item import StixItemType, guess_type
from lib.logger import init_logging


def ioc_to_title_and_pattern(ioc_value):
    ioc_type = guess_type(ioc_value)[0]

    if ioc_type == StixItemType.SHA256:
        return f"Malicious SHA256 - {ioc_value}", f"[file:hashes.'SHA-256' = '{ioc_value.lower()}']"
    elif ioc_type == StixItemType.SHA1:
        return f"Malicious SHA1 - {ioc_value}", f"[file:hashes.'SHA-1' = '{ioc_value.lower()}']"
    elif ioc_type == StixItemType.MD5:
        return f"Malicious MD5 - {ioc_value}", f"[file:hashes.MD5 = '{ioc_value.lower()}']"
    elif ioc_type == StixItemType.IPADDR:
        return f"Malicious IP - {ioc_value}", f"[ipv4-addr:value = '{ioc_value}']"
    elif ioc_type == StixItemType.DOMAIN:
        return f"Malicious domain - {ioc_value}", f"[domain-name:value = '{ioc_value.lower()}']"
    elif ioc_type == StixItemType.URL:
        pattern = f"[url:value = '{ioc_value}']"
        if '\\' in pattern:
            pattern = pattern.replace('\\', '\\\\')
        return f"Malicious URL - {ioc_value}", pattern
    else:
        raise Exception(f"Unknown IOC type for value '{ioc_value}'")


def ids_to_mitre_attack_patterns(ids):
    aps = []
    for mid in ids.split(","):
        if not re.match(r"T\d{4}(\.\d{3})?$", mid):
            logging.warning(f"Skipping invalid MITRE technique ID: {mid}")
            continue
        if mid.startswith('T0'):
            url = f"https://collaborate.mitre.org/attackics/index.php/Technique/{mid}"
        else:
            url = f"https://attack.mitre.org/techniques/{mid}/"
        attack_pattern = AttackPattern(name=mid, external_references=[{"url": url, "source_name": "mitre-attack", "external_id": mid}])
        aps.append(attack_pattern)
    return aps


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-t", metavar="THREAT_NAME", dest="threat_name", help="Name of the threat", required=True)
    parser.add_argument("-d", metavar="THREAT_DESCRIPTION", dest="description", help="Description of the threat",
                        required=True)
    parser.add_argument("-i", metavar="INFILE", dest="infile", help="Input file(s) containing indicators (supported "
                                                                    "formats: plain-text)", nargs='+',
                        required=True)
    parser.add_argument("-o", metavar="OUTPUT", dest="output",
                        help="Create a new STIX file from INFILE storing into OUTPUT")
    parser.add_argument("-a", metavar="AUTHOR", dest="author", help="Author of the STIX bundle",
                        default="Nozomi Networks Labs")
    parser.add_argument("-s", metavar="SOURCE", dest="source", help="The name of the source")
    parser.add_argument("-u", metavar="URL", dest="url", help="URL reference to the external source")
    parser.add_argument("-m", metavar="MITRE", dest="mitre", help="Comma-separated MITRE ATT&CK techniques")
    parser.add_argument("--tlp", metavar="TLP", dest="tlp",
                        help="TLP color. Strings like 'TLP:GREEN' or 'amber' are accepted.")
    args = parser.parse_args()
    init_logging()

    logging.info("Title: %s" % args.threat_name)
    logging.info("Description: %s" % args.description)

    if args.source:
        logging.info("Source Name: %s" % args.source)
    if args.url:
        logging.info("Reference: %s" % args.url)

    if args.output:
        logging.info(f"Creating new STIX file '{args.output}'")

    all_ioc = []
    for fname in args.infile:
        with open(fname, "r") as f:
            all_ioc.extend(f.read().splitlines())

    identity = Identity(name=args.author)
    objects = [identity]
    malware = Malware(name=args.threat_name, is_family=False, description=args.description)

    if args.url:
        if args.source:
            source = args.source
        else:
            source = urlparse(args.url).netloc
        malware_with_ref = malware.new_version(external_references=[{"source_name": args.source, "url": args.url}])
        objects.append(malware_with_ref)
    else:
        objects.append(malware)

    tlp_mark = None
    if args.tlp:
        supported_tlps = {
            'clear': TLP_WHITE,
            'white': TLP_WHITE,
            'green': TLP_GREEN,
            'amber': TLP_AMBER,
            'red': TLP_RED,
        }
        tlp_str = args.tlp.lower()
        if tlp_str.startswith('tlp:'):
            tlp_str = tlp_str[4:]
        if tlp_str not in supported_tlps:
            logging.critical(
                f'"{args.tlp}" TLP code is not supported. Terminating script.')
            exit(1)
        tlp_mark = supported_tlps[tlp_str]

        objects.append(tlp_mark)

    aps = []
    if args.mitre:
        aps = ids_to_mitre_attack_patterns(args.mitre)
        objects.extend(aps)
    for ioc in all_ioc:
        try:
            title, pattern = ioc_to_title_and_pattern(ioc)
        except Exception as e:
            logging.error(f"Skipping indicator: {e}")
            continue
        description = " ".join(title.split()[:2]) + f" involved with {args.threat_name}"
        indicator = Indicator(labels="malicious-activity", pattern_type='stix', pattern=pattern,
                              valid_from=datetime.now(), description=description, name=title,
                              created_by_ref=identity, object_marking_refs=tlp_mark)
        relationship = Relationship(relationship_type='indicates', source_ref=indicator.id, target_ref=malware.id)
        objects.append(indicator)
        objects.append(relationship)
        for ap in aps:
            relationship = Relationship(relationship_type='indicates', source_ref=indicator.id, target_ref=ap.id)
            objects.append(relationship)

    bundle = Bundle(objects=objects)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(str(bundle))
    else:
        print(str(bundle))
