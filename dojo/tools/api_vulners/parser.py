import json
import logging

from cvss.cvss3 import CVSS3

from dojo.models import Endpoint, Finding

from .importer import VulnersImporter

logger = logging.getLogger(__name__)


vulners_severity_mapping = {
    1: "Info",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
}


class ApiVulnersParser:

    """Parser that can load data from Vulners Scanner API"""

    def get_scan_types(self):
        return ["Vulners"]

    def get_label_for_scan_types(self, scan_type):
        return "Vulners"

    def get_description_for_scan_types(self, scan_type):
        return "Import Vulners Audit reports in JSON."

    def requires_tool_type(self, scan_type):
        return "Vulners"

    def api_scan_configuration_hint(self):
        return "the field <b>Service key 1</b> has to be set with the Vulners API key."

    def requires_file(self, scan_type):
        return False

    def get_findings(self, file, test):
        findings = []

        if file:
            data = json.load(file).get("data", {})
            report = data.get("report", [])
            vulns = data.get("vulns", {})
        else:
            report = VulnersImporter().get_findings(test)
            vulns_id = [vuln.get("vulnID") for vuln in report]
            vulns = VulnersImporter().get_vulns_description(test, vulns_id)

        # for each issue found
        for component in report:
            vuln_id = component.get("vulnID")
            vuln = vulns.get(vuln_id, {})
            title = component.get("title", vuln_id)
            family = component.get("family")
            agentip = component.get("agentip")
            agentfqdn = component.get("agentfqdn")
            severity = vulners_severity_mapping[component.get("severity", 0)]

            finding = Finding(
                title=title,
                severity=severity,
                impact=severity,
                description=vuln.get("description", title),
                mitigation=component.get("cumulativeFix"),
                static_finding=False,  # by definition
                dynamic_finding=True,  # by definition
                vuln_id_from_tool="VNS/" + vuln_id,
                component_name=agentfqdn
                if agentfqdn != "unknown"
                else agentip,
            )

            endpoint = Endpoint(host=agentip)
            finding.unsaved_endpoints = [endpoint]
            finding.unsaved_vulnerability_ids = ["VNS/" + vuln_id]

            # CVE List
            cve_ids = vuln.get("cvelist", [])
            if len(cve_ids):
                for cve in cve_ids:
                    finding.unsaved_vulnerability_ids.append("VNS/" + cve)

            # CVSSv3 vector
            if vuln.get("cvss3"):
                finding.cvssv3 = CVSS3(
                    vuln.get("cvss3", {})
                    .get("cvssV3", {})
                    .get("vectorString", ""),
                ).clean_vector()

            # References
            references = (
                f"**Vulners ID** \nhttps://vulners.com/{family}/{vuln_id} \n"
            )
            if len(cve_ids):
                references += "**Related CVE** \n"
                for cveid in cve_ids:
                    references += f"https://vulners.com/cve/{cveid}  \n"

            external_references = vuln.get("references", [])
            if len(external_references):
                references += "**External References** \n"
                for ref in external_references:
                    references += f"{ref} \n"

            if references != "":
                finding.references = references

            findings.append(finding)
        return findings
