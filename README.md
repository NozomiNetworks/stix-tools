# Overview
Utility tool to auto-magically process IoC from a raw format to STIX.\
The input file is a file containing a newline-separated list of indicators.

The following indicator types are currently supported:
* IP Address
* Domain
* URL
* SHA256
* MD5
* SHA1

There is still no official support for TLP 2.0 in the stix2 library this code is using. For that reason, if you use `TLP:CLEAR`, it will be automatically translated to TLP 1.0 `TLP:WHITE` and `TLP:AMBER+STRICT` is not supported yet.

# Requirements
The code has been tested with Python >= v3.4.

The required dependencies can be easily installed using `pip` tool:\
`pip install -r requirements.txt`

# Usage
The basic usage of the tool just requires an input file containing the raw indicators and the path where the STIX file will be created.

Create a STIX 1 file starting from the example file contained in this repository:\
`python3 stix_create.py -i example/indicators.txt -o /tmp/example.xml`

Create a STIX 2 file starting from the example file contained in this repository:\
`python3 stix_create_v2.py -i example/indicators.txt -t threat -d description -o /tmp/example.json --pretty`

Add new indictors to an existing STIX 2 file:\
`python3 stix_create_v2.py --merge /tmp/example.json -i example/new_indicators.txt`

More parameters can be set using the command-line, use the `-h` for more information.
