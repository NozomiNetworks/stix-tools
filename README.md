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
The code has been tested with Python >= v3.10.

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

# Tests
The `tests` directory contains the end-to-end tests of the two scripts. Each test runs the script as a subprocess,
feeding it an input file with indicators, and then parses the generated file back to check that its content and its
format are correct:
* `tests/test_stix_create_e2e.py`: runs `stix_create.py` and validates the generated STIX 1 XML package (header,
  indicator titles and descriptions, CybOX observables for every supported indicator type, producer, handling of
  unknown and duplicated indicators).
* `tests/test_stix_create_v2_e2e.py`: runs `stix_create_v2.py` and validates the generated STIX 2.1 JSON bundle with
  the `stix2` library (indicator patterns for every supported indicator type, identity, malware, TLP marking,
  relationships, MITRE ATT&CK patterns, external references, priority, produced time, output splitting over 1000
  indicators and the `--merge` mode).

The test dependencies are installed with:\
`pip install -r requirements.txt -r requirements-test.txt`

The whole test suite is run from the root of the repository with:\
`python3 -m pytest tests`

The same suite is executed by the `Test` GitHub workflow (`.github/workflows/test.yml`) on every supported Python
version whenever a pull request targets `main`.
