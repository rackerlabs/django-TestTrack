import contextlib
import hashlib
import json
import re

from cvss import CVSS3
from cvss.exceptions import CVSS3RHMalformedError, CVSS3RHScoreDoesNotMatch

from dojo.models import Finding


class JFrogXrayApiSummaryArtifactParser:
    # This function return a list of all the scan_type supported by your parser
    def get_scan_types(self):
        return ["JFrog Xray API Summary Artifact Scan"]

    # This function return a string used to provide some text in the UI (short
    # label)
    def get_label_for_scan_types(self, scan_type):
        return scan_type

    # This function return a string used to provide some text in the UI (long
    # description)
    def get_description_for_scan_types(self, scan_type):
        return "Import Xray findings in JSON format from the JFrog Xray API Summary/Artifact JSON response"

    # This function return a list of findings
    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = []
        if "artifacts" in tree:
            artifact_tree = tree["artifacts"]
            for artifactNode in artifact_tree:
                artifact_general = artifactNode["general"]
                artifact_issues = artifactNode["issues"]
                artifact = decode_artifact(artifact_general)
                for node in artifact_issues:
                    service = decode_service(artifact_general["name"])
                    item = get_item(
                        node,
                        str(service),
                        test,
                        artifact.name,
                        artifact.version,
                        artifact.sha256,
                    )
                    items.append(item)
        return items


# Retrieve the findings of the affected 1st level component (Artifact)
def get_item(
    vulnerability,
    service,
    test,
    artifact_name,
    artifact_version,
    artifact_sha256,
):
    cve = None
    cwe = None
    cvssv3 = None
    impact_path = ImpactPath("", "", "")

    if "severity" in vulnerability:
        severity = "Informational" if vulnerability["severity"] == "Unknown" else vulnerability["severity"].title()
    else:
        severity = "Informational"

    # Some entries have no CVE entries, despite they exist. Example
    # CVE-2017-1000502.
    cves = vulnerability.get("cves", [])
    vulnerability_ids = []
    if cves:
        if len(cves[0].get("cwe", [])) > 0:
            cwe = decode_cwe_number(cves[0].get("cwe", [])[0])
        if "cvss_v3" in cves[0]:
            cvss_v3 = cves[0]["cvss_v3"]
            # Note: Xray sometimes takes over malformed cvss scores like `5.9` that can not be parsed.
            #       Without the try-except block here the whole import of all findings would fail.
            with contextlib.suppress(CVSS3RHScoreDoesNotMatch, CVSS3RHMalformedError):
                cvssv3 = CVSS3.from_rh_vector(cvss_v3).clean_vector()

    impact_paths = vulnerability.get("impact_path", [])
    if len(impact_paths) > 0:
        impact_path = decode_impact_path(impact_paths[0])

    result = hashlib.sha256()
    if "issue_id" in vulnerability:
        unique_id = str(
            artifact_sha256
            + impact_path.name
            + impact_path.version
            + vulnerability["issue_id"],
        )
        vuln_id_from_tool = vulnerability["issue_id"]
    elif cve:
        unique_id = str(artifact_sha256 + impact_path.name + impact_path.version + cve)
    else:
        unique_id = str(
            artifact_sha256
            + impact_path.name
            + impact_path.version
            + vulnerability["summary"],
        )
        vuln_id_from_tool = ""
    result.update(unique_id.encode())
    unique_id_from_tool = result.hexdigest()

    finding = Finding(
        vuln_id_from_tool=vuln_id_from_tool,
        service=service,
        title=vulnerability["summary"],
        cwe=cwe,
        cvssv3=cvssv3,
        severity=severity,
        description=impact_path.name
        + ":"
        + impact_path.version
        + " -> "
        + vulnerability["description"],
        test=test,
        file_path=impact_paths[0],
        component_name=artifact_name,
        component_version=artifact_version,
        static_finding=True,
        dynamic_finding=False,
        unique_id_from_tool=unique_id_from_tool,
    )
    if vulnerability_ids:
        finding.unsaved_vulnerability_ids = vulnerability_ids

    # Add vulnerability ids
    vulnerability_ids = []
    if cves and "cve" in cves[0]:
        vulnerability_ids.append(cves[0]["cve"])
    if "issue_id" in vulnerability:
        vulnerability_ids.append(vulnerability["issue_id"])
    if vulnerability_ids:
        finding.unsaved_vulnerability_ids = vulnerability_ids

    return finding


# Regex helpers


def decode_service(name):
    match = re.match(r".*/(.*):", name, re.IGNORECASE)
    if match is None:
        return ""
    return match[1]


def decode_cwe_number(value):
    match = re.match(r"CWE-\d+", value, re.IGNORECASE)
    if match is None:
        return 0
    return int(match[0].rsplit("-")[1])


def decode_artifact(artifact_general):
    artifact = Artifact("", "", "")
    artifact.sha256 = artifact_general["sha256"]
    match = re.match(r"(.*):(.*)", artifact_general["name"], re.IGNORECASE)
    if match:
        artifact.name = match[1]
        artifact.version = match[2]
    return artifact


def decode_impact_path(path):
    impact_path = ImpactPath("", "", "")

    match = re.match(r".*\/(.*)$", str(path), re.IGNORECASE)
    if match is None:
        return impact_path
    fullname = match[1]

    match = re.match(r".*sha256__(.*).tar", path, re.IGNORECASE)
    if match:
        impact_path.sha = (match[1][:64]) if len(match[1]) > 64 else match[1]

    if ".jar" in fullname:
        match = re.match(r"(.*)-", fullname, re.IGNORECASE)
        if match:
            impact_path.name = match[1]
        match = re.match(r".*-(.*).jar", fullname, re.IGNORECASE)
        if match:
            impact_path.version = match[1]
    elif ":" in fullname:
        match = re.match(r"(.*):", fullname, re.IGNORECASE)
        if match:
            impact_path.name = match[1]
        match = re.match(r".*:(.*)", fullname, re.IGNORECASE)
        if match:
            impact_path.version = match[1]
    elif ".js" in fullname:
        match = re.match(r"(.*)-", fullname, re.IGNORECASE)
        if match:
            impact_path.name = match[1]
        match = re.match(r".*-(.*).js", fullname, re.IGNORECASE)
        if match:
            impact_path.version = match[1]
    else:
        impact_path.name = fullname

    return impact_path


class Artifact:
    def __init__(self, sha256, name, version):
        self.sha256 = sha256
        self.name = name
        self.version = version


class ImpactPath:
    def __init__(self, sha, name, version):
        self.sha = sha
        self.name = name
        self.version = version
