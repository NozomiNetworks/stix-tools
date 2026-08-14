# Created by Nozomi Networks Labs
#
# End-to-end tests for stix_create_v2.py: the script is executed as a subprocess and the
# STIX 2.1 bundle it produces is loaded back, validated with the stix2 library and checked.

import json
from pathlib import Path

import pytest
from stix2 import parse

from tests.e2e.conftest import (ALL_IOC, DOMAIN, INVALID_IOC, IPV4, MD5, SHA1, SHA256, URL, run_script)

SCRIPT = Path(__file__).parent.parent.parent / "stix_create_v2.py"

EXPECTED_INDICATORS = {
    f"Malicious MD5 - {MD5}": f"[file:hashes.MD5 = '{MD5}']",
    f"Malicious SHA1 - {SHA1}": f"[file:hashes.'SHA-1' = '{SHA1}']",
    f"Malicious SHA256 - {SHA256}": f"[file:hashes.'SHA-256' = '{SHA256}']",
    f"Malicious IP - {IPV4}": f"[ipv4-addr:value = '{IPV4}']",
    f"Malicious domain - {DOMAIN}": f"[domain-name:value = '{DOMAIN}']",
    f"Malicious URL - {URL}": f"[url:value = '{URL}']",
}


def create(outfile, infile, *extra):
    """Run the script in 'create a new bundle' mode and return the CompletedProcess."""
    return run_script(SCRIPT, "-i", infile, "-t", "threat", "-d", "description", "-o", outfile, *extra)


def load(outfile, allow_custom=False):
    """Load the generated file, checking it is a valid STIX 2.1 bundle, and return it as a dict."""
    bundle = parse(outfile.read_text(), allow_custom=allow_custom)
    assert bundle.type == "bundle"
    assert bundle.id.startswith("bundle--")
    return json.loads(outfile.read_text())


def objects_of(bundle, obj_type):
    return [o for o in bundle["objects"] if o["type"] == obj_type]


def test_creates_stix2_bundle_with_all_indicator_types(tmp_path, all_types_file):
    outfile = tmp_path / "out.json"

    result = create(outfile, all_types_file)

    assert result.returncode == 0, result.stderr
    assert outfile.exists()

    bundle = load(outfile)
    indicators = objects_of(bundle, "indicator")
    assert len(indicators) == len(ALL_IOC)
    assert {i["name"]: i["pattern"] for i in indicators} == EXPECTED_INDICATORS

    for indicator in indicators:
        assert indicator["spec_version"] == "2.1"
        assert indicator["pattern_type"] == "stix"
        assert indicator["indicator_types"] == ["malicious-activity"]
        assert indicator["description"].endswith("involved with threat")
        assert indicator["valid_from"]


def test_bundle_links_indicators_identity_and_malware(tmp_path, all_types_file):
    outfile = tmp_path / "out.json"

    assert create(outfile, all_types_file, "-a", "Custom Author").returncode == 0

    bundle = load(outfile)
    identity = objects_of(bundle, "identity")[0]
    malware = objects_of(bundle, "malware")[0]
    indicators = objects_of(bundle, "indicator")
    relationships = objects_of(bundle, "relationship")

    assert identity["name"] == "Custom Author"
    assert malware["name"] == "threat"
    assert malware["description"] == "description"
    assert malware["is_family"] is False

    assert {i["created_by_ref"] for i in indicators} == {identity["id"]}

    # Every indicator is linked to the malware by an 'indicates' relationship.
    assert len(relationships) == len(indicators)
    assert {r["relationship_type"] for r in relationships} == {"indicates"}
    assert {r["target_ref"] for r in relationships} == {malware["id"]}
    assert {r["source_ref"] for r in relationships} == {i["id"] for i in indicators}


def test_author_defaults_to_nozomi_networks(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"

    assert create(outfile, write_iocs([IPV4])).returncode == 0

    assert objects_of(load(outfile), "identity")[0]["name"] == "Nozomi Networks"


def test_hashes_and_domains_are_lowercased_in_patterns(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"

    assert create(outfile, write_iocs([MD5.upper(), SHA256.upper(), DOMAIN.upper()])).returncode == 0

    patterns = {i["pattern"] for i in objects_of(load(outfile), "indicator")}
    assert patterns == {
        f"[file:hashes.MD5 = '{MD5}']",
        f"[file:hashes.'SHA-256' = '{SHA256}']",
        f"[domain-name:value = '{DOMAIN}']",
    }


def test_unknown_indicators_are_skipped(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"

    result = create(outfile, write_iocs([IPV4, INVALID_IOC, DOMAIN]))

    assert result.returncode == 0, result.stderr
    assert f"Unknown IOC type for value '{INVALID_IOC}'" in result.stderr
    assert len(objects_of(load(outfile), "indicator")) == 2


def test_indicators_are_read_from_multiple_input_files(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"
    first = write_iocs([IPV4], name="first.txt")
    second = write_iocs([DOMAIN, URL], name="second.txt")

    result = run_script(SCRIPT, "-i", first, second, "-t", "threat", "-d", "description", "-o", outfile)

    assert result.returncode == 0, result.stderr
    assert len(objects_of(load(outfile), "indicator")) == 3


def test_bundle_is_printed_on_stdout_when_no_output_file(tmp_path, write_iocs):
    result = run_script(SCRIPT, "-i", write_iocs([IPV4]), "-t", "threat", "-d", "description")

    assert result.returncode == 0, result.stderr
    bundle = json.loads(result.stdout)
    assert bundle["type"] == "bundle"
    assert [i["pattern"] for i in objects_of(bundle, "indicator")] == [f"[ipv4-addr:value = '{IPV4}']"]


def test_pretty_flag_indents_the_json_output(tmp_path, write_iocs):
    infile = write_iocs([IPV4])
    compact = tmp_path / "compact.json"
    pretty = tmp_path / "pretty.json"

    assert create(compact, infile).returncode == 0
    assert create(pretty, infile, "--pretty").returncode == 0

    assert "\n" not in compact.read_text()
    assert '\n    "type": "bundle"' in pretty.read_text()
    # Both hold the same data, only the formatting differs.
    assert objects_of(load(compact), "indicator")[0]["pattern"] == objects_of(load(pretty), "indicator")[0]["pattern"]


@pytest.mark.parametrize("tlp_arg, expected_name", [
    ("clear", "TLP:WHITE"),
    ("white", "TLP:WHITE"),
    ("TLP:GREEN", "TLP:GREEN"),
    ("amber", "TLP:AMBER"),
    ("TLP:red", "TLP:RED"),
])
def test_tlp_marking_is_applied(tmp_path, write_iocs, tlp_arg, expected_name):
    outfile = tmp_path / "out.json"

    assert create(outfile, write_iocs([IPV4]), "--tlp", tlp_arg).returncode == 0

    bundle = load(outfile)
    marking = objects_of(bundle, "marking-definition")[0]
    assert marking["name"] == expected_name
    assert objects_of(bundle, "indicator")[0]["object_marking_refs"] == [marking["id"]]


def test_tlp_defaults_to_amber(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"

    result = create(outfile, write_iocs([IPV4]))

    assert "Assuming TLP:AMBER" in result.stderr
    assert objects_of(load(outfile), "marking-definition")[0]["name"] == "TLP:AMBER"


def test_unsupported_tlp_aborts_without_creating_the_file(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"

    result = create(outfile, write_iocs([IPV4]), "--tlp", "TLP:AMBER+STRICT")

    assert result.returncode == 1
    assert "not supported by STIX" in result.stderr
    assert not outfile.exists()


def test_mitre_techniques_become_attack_patterns(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"

    assert create(outfile, write_iocs([IPV4, DOMAIN]), "-m", "T1059,T0801.001").returncode == 0

    bundle = load(outfile)
    attack_patterns = objects_of(bundle, "attack-pattern")
    assert {a["name"] for a in attack_patterns} == {"T1059", "T0801.001"}

    urls = {a["name"]: a["external_references"][0]["url"] for a in attack_patterns}
    assert urls["T1059"] == "https://attack.mitre.org/techniques/T1059/"
    assert urls["T0801.001"] == "https://collaborate.mitre.org/attackics/index.php/Technique/T0801.001"
    assert {a["external_references"][0]["source_name"] for a in attack_patterns} == {"mitre-attack"}

    # Each indicator is linked to the malware plus to every attack pattern.
    indicators = objects_of(bundle, "indicator")
    relationships = objects_of(bundle, "relationship")
    assert len(relationships) == len(indicators) * (1 + len(attack_patterns))
    for attack_pattern in attack_patterns:
        targeting_ap = [r for r in relationships if r["target_ref"] == attack_pattern["id"]]
        assert {r["source_ref"] for r in targeting_ap} == {i["id"] for i in indicators}


def test_invalid_mitre_techniques_are_skipped(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"

    result = create(outfile, write_iocs([IPV4]), "-m", "T1059,not-a-technique")

    assert result.returncode == 0, result.stderr
    assert "Skipping invalid MITRE technique ID: not-a-technique" in result.stderr
    assert [a["name"] for a in objects_of(load(outfile), "attack-pattern")] == ["T1059"]


def test_external_reference_is_added_from_url(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"

    assert create(outfile, write_iocs([IPV4]), "-u", "https://example.com/report",
                  "-s", "Example Source").returncode == 0

    malware = objects_of(load(outfile), "malware")[0]
    assert malware["external_references"] == [{"source_name": "Example Source", "url": "https://example.com/report"}]


def test_external_reference_source_defaults_to_the_url_domain(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"

    assert create(outfile, write_iocs([IPV4]), "-u", "https://example.com/report").returncode == 0

    assert objects_of(load(outfile), "malware")[0]["external_references"][0]["source_name"] == "example.com"


def test_priority_is_stored_as_a_custom_property(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"

    assert create(outfile, write_iocs([IPV4]), "--priority", "5.5").returncode == 0

    assert load(outfile, allow_custom=True)["x_nn_priority"] == 5.5


@pytest.mark.parametrize("priority, message", [
    ("0.5", "Priority value out of range"),
    ("10.5", "Priority value out of range"),
    ("5.55", "use only one decimal value"),
])
def test_invalid_priority_aborts_without_creating_the_file(tmp_path, write_iocs, priority, message):
    outfile = tmp_path / "out.json"

    result = create(outfile, write_iocs([IPV4]), "--priority", priority)

    assert result.returncode == 1
    assert message in result.stderr
    assert not outfile.exists()


def test_produced_time_is_used_for_the_indicators(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"

    assert create(outfile, write_iocs([IPV4]), "-p", "2024-05-06 10:11:12").returncode == 0

    bundle = load(outfile)
    indicator = objects_of(bundle, "indicator")[0]
    # The sub-second part is formatted differently depending on the property, only the instant matters here.
    for prop in ("created", "modified", "valid_from"):
        assert indicator[prop].startswith("2024-05-06T10:11:12"), indicator[prop]
    assert objects_of(bundle, "malware")[0]["created"].startswith("2024-05-06T10:11:12")


def test_indicators_are_split_in_chunks_over_the_limit(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"
    iocs = [f"10.{i // 256}.{i % 256}.1" for i in range(1200)]

    assert create(outfile, write_iocs(iocs)).returncode == 0

    extra_chunk = tmp_path / "out_1.json"
    assert extra_chunk.exists()
    assert len(objects_of(load(outfile), "indicator")) == 1000
    assert len(objects_of(load(extra_chunk), "indicator")) == 200


def test_merge_adds_new_indicators_to_an_existing_bundle(tmp_path, write_iocs):
    outfile = tmp_path / "out.json"
    assert create(outfile, write_iocs([IPV4, DOMAIN]), "--tlp", "green", "-m", "T1059").returncode == 0
    before = load(outfile)

    result = run_script(SCRIPT, "--merge", outfile, "-i", write_iocs([MD5, URL], name="new.txt"))

    assert result.returncode == 0, result.stderr
    after = load(outfile)

    # The original content is preserved and the new indicators are appended.
    assert objects_of(after, "identity") == objects_of(before, "identity")
    assert objects_of(after, "malware") == objects_of(before, "malware")
    assert objects_of(after, "attack-pattern") == objects_of(before, "attack-pattern")
    assert objects_of(after, "marking-definition") == objects_of(before, "marking-definition")

    new_indicators = [i for i in objects_of(after, "indicator") if i not in objects_of(before, "indicator")]
    assert {i["name"]: i["pattern"] for i in new_indicators} == {
        f"Malicious MD5 - {MD5}": f"[file:hashes.MD5 = '{MD5}']",
        f"Malicious URL - {URL}": f"[url:value = '{URL}']",
    }

    # The new indicators reuse the identity, the TLP marking and the attack pattern of the bundle.
    identity = objects_of(after, "identity")[0]
    marking = objects_of(after, "marking-definition")[0]
    malware = objects_of(after, "malware")[0]
    attack_pattern = objects_of(after, "attack-pattern")[0]
    for indicator in new_indicators:
        assert indicator["created_by_ref"] == identity["id"]
        assert indicator["object_marking_refs"] == [marking["id"]]
        targets = {r["target_ref"] for r in objects_of(after, "relationship") if r["source_ref"] == indicator["id"]}
        assert targets == {malware["id"], attack_pattern["id"]}


def test_merge_requires_an_existing_file(tmp_path, write_iocs):
    result = run_script(SCRIPT, "--merge", tmp_path / "missing.json", "-i", write_iocs([IPV4]))

    assert result.returncode != 0


def test_missing_threat_arguments_fails(tmp_path, all_types_file):
    outfile = tmp_path / "out.json"

    result = run_script(SCRIPT, "-i", all_types_file, "-o", outfile)

    assert result.returncode == 1
    assert "arguments are required" in result.stderr
    assert not outfile.exists()


def test_missing_input_file_argument_fails(tmp_path):
    result = run_script(SCRIPT, "-t", "threat", "-d", "description", "-o", tmp_path / "out.json")

    assert result.returncode != 0
