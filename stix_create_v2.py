# Created by Nozomi Networks Labs

import pytz
import argparse
import logging
import re
import datetime
import dateutil.parser
from colorama import Fore
from decimal import Decimal
from urllib.parse import urlparse

from stix2 import Indicator, Bundle, Identity, Malware, Relationship, AttackPattern, parse
from stix2 import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
from lib.stix_item import StixItemType, guess_type
from lib.logger import init_logging

INDICATOR_LIMIT = 1000
DEFAULT_ID_NAME = 'Nozomi Networks'


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
        attack_pattern = AttackPattern(name=mid, external_references=[
            {"url": url, "source_name": "mitre-attack", "external_id": mid}])
        aps.append(attack_pattern)
    return aps


def split_indicators(ioc, n=INDICATOR_LIMIT):
    for i in range(0, len(ioc), n):
        yield ioc[i:i + n]


def merge_indicators(stix_file, new_ioc):

    # Load base file
    with open(stix_file, 'r') as sfd:
        bundle = parse(sfd)

    # Peek needed previous info
    aps = []
    prev_ioc = []
    for b_obj in bundle.objects:
        if b_obj.type == 'malware':
            malware = b_obj
        elif b_obj.type == 'identity':
            identity = b_obj
        elif b_obj.type == 'indicator':
            prev_ioc.append(b_obj)
        elif b_obj.type == 'marking-definition':
            tlp_mark = b_obj
        elif b_obj.type == 'attack-pattern':
            aps.append(b_obj)

    # Check if new indicators are already there to discard them
    actual_new_ioc = []
    for ioc in new_ioc:
        title, pattern = ioc_to_title_and_pattern(ioc)
        if pattern not in prev_ioc:
            actual_new_ioc.append((title, pattern))

    # Create new indicator objects while adding needed relationships
    if len(actual_new_ioc) == 0:
        logging.info("No new indicators to be added")
        exit(1)

    produced_time = datetime.datetime.now(pytz.utc)
    for title, pattern in actual_new_ioc:
        description = " ".join(title.split()[:2]) + f" involved with {malware.name}"
        indicator = Indicator(indicator_types="malicious-activity", pattern_type='stix', pattern=pattern,
                              valid_from=produced_time, description=description, name=title,
                              created_by_ref=identity, created=produced_time, modified=produced_time,
                              object_marking_refs=[tlp_mark])
        relationship = Relationship(relationship_type='indicates', source_ref=indicator.id, target_ref=malware.id,
                                    created=produced_time, modified=produced_time)
        bundle.objects.append(indicator)
        bundle.objects.append(relationship)
        for ap in aps:
            relationship = Relationship(relationship_type='indicates', source_ref=indicator.id, target_ref=ap.id)
            bundle.objects.append(relationship)

    with open(stix_file, 'w') as fd:
        fd.write(bundle.serialize(indent=4))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    raw_creation_group = parser.add_argument_group('Creating a STIX2 file from scratch')
    raw_creation_group.add_argument("-t", metavar="THREAT_NAME", dest="threat_name", help="Name of the threat")
    raw_creation_group.add_argument("-d", metavar="THREAT_DESCRIPTION", dest="description",
                                    help="Description of the threat")
    merge_creation_group = parser.add_argument_group('Update an already existing STIX2 file')
    merge_creation_group.add_argument("--merge", help="Existing STIX2 file where indicators from INFILE will be added")

    parser.add_argument("-i", metavar="INFILE", dest="infile", help="Input file(s) containing indicators (supported "
                        "formats: plain-text)", nargs='+', required=True)
    parser.add_argument("-o", metavar="OUTPUT", dest="output",
                        help="Create a new STIX file from INFILE storing into OUTPUT")
    parser.add_argument("-a", metavar="AUTHOR", dest="author", help="Author of the STIX bundle",
                        default=DEFAULT_ID_NAME)
    parser.add_argument("-s", metavar="SOURCE", dest="source", help="The name of the source")
    parser.add_argument("-u", metavar="URL", dest="url", help="URL reference to the external source")
    parser.add_argument("-m", metavar="MITRE", dest="mitre", help="Comma-separated MITRE ATT&CK techniques")
    parser.add_argument("-p", metavar="TIME", dest="produced_time", help="Used to set the indicators' produced time")
    parser.add_argument("--tlp", metavar="TLP", dest="tlp",
                        help="TLP color. Strings like 'TLP:GREEN' or 'amber' are accepted.")
    parser.add_argument("--priority", metavar="PRIORITY", dest="priority", type=float,
                        help="Priority shown in N2OS interface.")
    parser.add_argument("--pretty", dest="pretty", action='store_true', help="Flag to prettify the JSON output.")
    args = parser.parse_args()
    init_logging()

    if args.threat_name and args.description:
        logging.info("Title: %s" % args.threat_name)
        logging.info("Description: %s" % args.description)
        if args.output:
            logging.info(f"Creating new STIX file '{args.output}'")
    elif args.merge:
        logging.info(f"Merging indicators from {args.infile} into '{args.merge}'")
    else:
        logging.error("The following arguments are required: -t and -d or --merge")
        exit(1)

    if args.source and args.url:
        logging.info("Source Name: %s" % args.source)
        logging.info("Reference: %s" % args.url)

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
            logging.critical(f'{args.tlp} is not supported by STIX. Terminating script.')
            exit(1)
        tlp_mark = supported_tlps[tlp_str]

    else:
        logging.info('No TLP color given as parameter. Assuming TLP:AMBER')
        tlp_mark = TLP_AMBER

    produced_time = datetime.datetime.now(pytz.utc)
    if args.produced_time:
        try:
            produced_time = dateutil.parser.parse(args.produced_time).replace(tzinfo=pytz.utc)
        except dateutil.parser.ParserError:
            logging.error('Error parsing produced time. Using current time.')

    custom_properties = {}

    if args.priority:
        if not 1.0 <= args.priority <= 10.0:
            logging.error(f'{Fore.RED}Priority value out of range [1.0, 10.0]: {args.priority}{Fore.RESET}')
            exit(1)

        decimal_places = Decimal(str(args.priority)).as_tuple().exponent
        num_of_decimals = max(0, -decimal_places)
        if num_of_decimals > 1:
            logging.error(f'{Fore.RED}Please, use only one decimal value for the priority: {args.priority}{Fore.RESET}')
            exit(1)

        logging.info(f'Priority: {Fore.CYAN}{args.priority}{Fore.RESET}')
        custom_properties['x_nn_priority'] = args.priority

    all_ioc = []
    for fname in args.infile:
        with open(fname, "r") as f:
            all_ioc.extend(set(f.read().splitlines()))
    all_ioc = [ioc.strip() for ioc in all_ioc]

    if args.merge and args.infile:
        merge_indicators(args.merge, all_ioc)
        exit(0)

    for cur_chunk, chunk in enumerate(split_indicators(all_ioc)):
        identity = Identity(name=args.author)
        objects = [identity]
        malware = Malware(name=args.threat_name, is_family=False, description=args.description,
                          created=produced_time, modified=produced_time)

        if tlp_mark == TLP_WHITE:
            fore_color = Fore.WHITE
            tlp_name = "WHITE"
        elif tlp_mark == TLP_GREEN:
            fore_color = Fore.GREEN
            tlp_name = "GREEN"
        elif tlp_mark == TLP_AMBER:
            fore_color = Fore.YELLOW
            tlp_name = "AMBER"
        elif tlp_mark == TLP_RED:
            fore_color = Fore.RED
            tlp_name = "RED"

        logging.info(f'TLP: {fore_color}TLP:{tlp_name}{Fore.RESET}')
        objects.append(tlp_mark)

        if args.url:
            if args.source:
                source = args.source
            else:
                source = urlparse(args.url).netloc

            malware_with_ref = malware.new_version(external_references=[{"source_name": source, "url": args.url}])
            objects.append(malware_with_ref)
        else:
            objects.append(malware)

        aps = []
        if args.mitre:
            aps = ids_to_mitre_attack_patterns(args.mitre)
            objects.extend(aps)
        for ioc in chunk:
            try:
                title, pattern = ioc_to_title_and_pattern(ioc)
            except Exception as e:
                logging.warning(f"Skipping indicator: {e}")
                continue
            description = " ".join(title.split()[:2]) + f" involved with {args.threat_name}"
            indicator = Indicator(indicator_types="malicious-activity", pattern_type='stix', pattern=pattern,
                                  valid_from=produced_time, description=description, name=title,
                                  created_by_ref=identity, created=produced_time, modified=produced_time,
                                  object_marking_refs=[tlp_mark])
            relationship = Relationship(relationship_type='indicates', source_ref=indicator.id, target_ref=malware.id,
                                        created=produced_time, modified=produced_time)
            objects.append(indicator)
            objects.append(relationship)
            for ap in aps:
                relationship = Relationship(relationship_type='indicates', source_ref=indicator.id, target_ref=ap.id)
                objects.append(relationship)

        bundle = Bundle(objects=objects, custom_properties=custom_properties)

        indent = 4 if args.pretty else None
        if args.output:
            if len(all_ioc) > INDICATOR_LIMIT and cur_chunk > 0:
                output_filename = args.output.replace(".json", f"_{cur_chunk}.json")
            else:
                output_filename = args.output
            with open(output_filename, 'w') as f:
                f.write(bundle.serialize(indent=indent))
        else:
            print(bundle.serialize(indent=indent))
