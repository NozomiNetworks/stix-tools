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

In the current version only STIXv1 is supported.

# Requirements
The code has been tested with Python >= v3.4.

The required dependencies can be easily installed using `pip` tool:\
`pip install -r requirements.txt`

# Usage
The basic usage of the tool just requires an input file containing the raw indicators and the path where the STIX file will be created.

Create a STIX file starting from the example file contained in this repository:\
`python stix_create.py -i example/indicators.txt -o /tmp/example.xml`

More parameters can be set using the command-line, use the `-h` for more information.