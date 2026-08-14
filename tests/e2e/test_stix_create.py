# Created by Nozomi Networks Labs
#
# End-to-end tests for stix_create.py: the script is executed as a subprocess and the
# STIX 1 XML file it produces is parsed back and checked.

import xml.etree.ElementTree as ET

from conftest import (ALL_IOC, DOMAIN, INVALID_IOC, IPV4, MD5, SHA1, SHA256, URL, run_script)

SCRIPT = "stix_create.py"

NS = {
    "stix": "http://stix.mitre.org/stix-1",
    "stixCommon": "http://stix.mitre.org/common-1",
    "indicator": "http://stix.mitre.org/Indicator-2",
    "cybox": "http://cybox.mitre.org/cybox-2",
    "cyboxCommon": "http://cybox.mitre.org/common-2",
    "FileObj": "http://cybox.mitre.org/objects#FileObject-2",
    "AddressObj": "http://cybox.mitre.org/objects#AddressObject-2",
    "URIObj": "http://cybox.mitre.org/objects#URIObject-2",
    "DomainNameObj": "http://cybox.mitre.org/objects#DomainNameObject-1",
}


def create(outfile, infile, *extra):
    """Run the script and return the CompletedProcess."""
    return run_script(SCRIPT, "-i", infile, "-o", outfile, *extra)


def indicators(outfile):
    """Parse the generated file and return its indicator elements."""
    root = ET.parse(outfile).getroot()
    return root, root.findall("./stix:Indicators/stix:Indicator", NS)


def title(ind):
    return ind.findtext("indicator:Title", namespaces=NS)


def hashes(ind):
    """Map hash type -> value for a file observable."""
    path = ("indicator:Observable/cybox:Object/cybox:Properties/FileObj:Hashes/cyboxCommon:Hash")
    return {h.findtext("cyboxCommon:Type", namespaces=NS): h.findtext("cyboxCommon:Simple_Hash_Value", namespaces=NS)
            for h in ind.findall(path, NS)}


def test_creates_stix1_file_with_all_indicator_types(tmp_path, all_types_file):
    outfile = tmp_path / "out.xml"

    result = create(outfile, all_types_file, "-t", "threat", "-d", "description")

    assert result.returncode == 0, result.stderr
    assert outfile.exists()

    root, inds = indicators(outfile)
    assert root.tag == "{http://stix.mitre.org/stix-1}STIX_Package"
    assert root.get("version") == "1.2"
    assert len(inds) == len(ALL_IOC)

    assert {title(i) for i in inds} == {
        f"Malicious MD5 - {MD5}",
        f"Malicious SHA1 - {SHA1}",
        f"Malicious SHA256 - {SHA256}",
        f"Malicious IPv4 - {IPV4}",
        f"Malicious domain - {DOMAIN}",
        f"Malicious URL - {URL}",
    }


def test_indicator_observables_carry_the_expected_values(tmp_path, all_types_file):
    outfile = tmp_path / "out.xml"

    assert create(outfile, all_types_file, "-t", "threat", "-d", "description").returncode == 0

    _, inds = indicators(outfile)
    by_title = {title(i): i for i in inds}

    assert hashes(by_title[f"Malicious MD5 - {MD5}"]) == {"MD5": MD5}
    assert hashes(by_title[f"Malicious SHA1 - {SHA1}"]) == {"SHA1": SHA1}
    assert hashes(by_title[f"Malicious SHA256 - {SHA256}"]) == {"SHA256": SHA256}

    address = by_title[f"Malicious IPv4 - {IPV4}"].find(
        "indicator:Observable/cybox:Object/cybox:Properties", NS)
    assert address.get("category") == "ipv4-addr"
    assert address.findtext("AddressObj:Address_Value", namespaces=NS) == IPV4

    domain = by_title[f"Malicious domain - {DOMAIN}"].find(
        "indicator:Observable/cybox:Object/cybox:Properties", NS)
    assert domain.findtext("DomainNameObj:Value", namespaces=NS) == DOMAIN

    url = by_title[f"Malicious URL - {URL}"].find(
        "indicator:Observable/cybox:Object/cybox:Properties", NS)
    assert url.get("type") == "URL"
    assert url.findtext("URIObj:Value", namespaces=NS) == URL


def test_header_and_descriptions_report_the_threat(tmp_path, write_iocs):
    outfile = tmp_path / "out.xml"

    assert create(outfile, write_iocs([IPV4]), "-t", "MyThreat", "-d", "My description",
                  "-s", "Nozomi Networks Labs report", "-r", "https://example.com/report").returncode == 0

    root, inds = indicators(outfile)
    header = root.find("stix:STIX_Header", NS)
    assert header.findtext("stix:Title", namespaces=NS) == "MyThreat"
    assert header.findtext("stix:Description", namespaces=NS) == "My description"

    source = header.find("stix:Information_Source", NS)
    assert source.findtext("stixCommon:Description", namespaces=NS) == "Nozomi Networks Labs report"
    assert source.findtext("stixCommon:References/stixCommon:Reference", namespaces=NS) == "https://example.com/report"
    assert source.find("stixCommon:Time/cyboxCommon:Produced_Time", NS) is not None

    description = inds[0].findtext("indicator:Description", namespaces=NS)
    assert description == "Malicious IPv4 involved with the threat MyThreat"


def test_producer_defaults_to_nozomi_and_can_be_overridden(tmp_path, write_iocs):
    infile = write_iocs([IPV4])
    default_out = tmp_path / "default.xml"
    custom_out = tmp_path / "custom.xml"

    assert create(default_out, infile, "-t", "threat", "-d", "description").returncode == 0
    assert create(custom_out, infile, "-t", "threat", "-d", "description", "-a", "Custom Author").returncode == 0

    producer = "indicator:Producer/stixCommon:Identity/stixCommon:Name"
    assert indicators(default_out)[1][0].findtext(producer, namespaces=NS) == "Nozomi Networks Labs"
    assert indicators(custom_out)[1][0].findtext(producer, namespaces=NS) == "Custom Author"


def test_unknown_indicators_are_skipped(tmp_path, write_iocs):
    outfile = tmp_path / "out.xml"

    result = create(outfile, write_iocs([IPV4, INVALID_IOC, DOMAIN]), "-t", "threat", "-d", "description")

    assert result.returncode == 0, result.stderr
    assert f"Unknown indicator format: {INVALID_IOC}" in result.stderr
    _, inds = indicators(outfile)
    assert len(inds) == 2
    assert INVALID_IOC not in outfile.read_text()


def test_duplicated_indicators_are_stored_only_once(tmp_path, write_iocs):
    outfile = tmp_path / "out.xml"

    result = create(outfile, write_iocs([IPV4, IPV4, DOMAIN]), "-t", "threat", "-d", "description")

    assert result.returncode == 0, result.stderr
    assert f"Skipping duplicated indicator: {IPV4}" in result.stderr
    _, inds = indicators(outfile)
    assert len(inds) == 2


def test_empty_lines_are_ignored(tmp_path, write_iocs):
    outfile = tmp_path / "out.xml"

    assert create(outfile, write_iocs([IPV4, "", "   ", DOMAIN]), "-t", "threat", "-d", "description").returncode == 0

    _, inds = indicators(outfile)
    assert len(inds) == 2


def test_missing_required_arguments_fails(tmp_path, all_types_file):
    assert run_script(SCRIPT, "-i", all_types_file).returncode != 0
    assert run_script(SCRIPT, "-o", tmp_path / "out.xml").returncode != 0


def test_missing_input_file_fails(tmp_path):
    result = create(tmp_path / "out.xml", tmp_path / "does-not-exist.txt", "-t", "threat", "-d", "description")

    assert result.returncode != 0
    assert not (tmp_path / "out.xml").exists()
