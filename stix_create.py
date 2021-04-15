# Created by Nozomi Networks Labs

import sys
if not sys.version_info >= (3, 4):
    print("Please use python 3")
    exit(1)

import argparse
import logging

from lib.stixv1 import StixManager
from lib.logger import init_logging

if __name__ == "__main__":

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-i", metavar="INFILE", dest="infile", help="Input file containing raw indicators", required=True)
    parser.add_argument("-o", metavar="OUTFILE", dest="outfile", help="STIX file containing the indicators", required=True)
    parser.add_argument("-c", metavar="Author", dest="author", default="Nozomi Networks Labs", help="Author creating the STIX")
    parser.add_argument("-t", metavar="THREAT", dest="threat", help="Threat name")
    parser.add_argument("-d", metavar="DESCRIPTION", dest="description", help="Threat description")
    parser.add_argument("-s", metavar="SOURCE_INFO", dest="srcinfo", help="Source information")
    parser.add_argument("-r", metavar="REFERENCE", dest="reference", help="Indicator references")
    args = parser.parse_args()

    # Init logging
    init_logging("INFO")

    stix = StixManager(company=args.author)
    logging.info("Title: %s" % args.threat)
    logging.info("Description: %s" % args.description)
    logging.info("Company: %s" % args.author)
    logging.info("Source: %s" % args.srcinfo)
    logging.info("Reference: %s" % args.reference)

    # Set the header info
    stix.set_stix_header(args.threat, args.description, args.srcinfo, args.reference)
    logging.info("Creating new STIX file '%s'", args.outfile)

    # Load IoCs
    stix.load_raw_file(args.infile)

    # Store result
    stix.save_stix_file(args.outfile)
    
    exit(0)