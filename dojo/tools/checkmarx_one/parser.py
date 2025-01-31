import datetime
import json
import re

from dateutil import parser
from django.conf import settings

from dojo.models import Finding, Test


class CheckmarxOneParser:
    def get_scan_types(self):
        return ["Checkmarx One Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Checkmarx One Scan"

    def _parse_date(self, value):
        if isinstance(value, str):
            return parser.parse(value)
        if isinstance(value, dict) and isinstance(value.get("seconds"), int):
            return datetime.datetime.fromtimestamp(value.get("seconds"), datetime.UTC)
        return None

    def _parse_cwe(self, cwe):
        if isinstance(cwe, str):
            cwe_num = re.findall(r"\d+", cwe)
            if cwe_num:
                return cwe_num[0]
            return None
        if isinstance(cwe, int):
            return cwe
        return None

    def parse_vulnerabilities_from_scan_list(
        self,
        test: Test,
        data: dict,
    ) -> list[Finding]:
        findings = []
        cwe_store = data.get("vulnerabilityDetails", [])
        # SAST
        if (results := data.get("scanResults", {}).get("resultsList")) is not None:
            findings += self.parse_sast_vulnerabilities(test, results, cwe_store)
        # IaC
        if (results := data.get("iacScanResults", {}).get("technology")) is not None:
            findings += self.parse_iac_vulnerabilities(test, results, cwe_store)
        # SCA
        if (results := data.get("scaScanResults", {}).get("packages")) is not None:
            findings += self.parse_sca_vulnerabilities(test, results, cwe_store)
        return findings

    def parse_iac_vulnerabilities(
        self,
        test: Test,
        results: list,
        cwe_store: list,
    ) -> list[Finding]:
        findings = []
        for technology in results:
            # Set the name aside for use in the title
            name = technology.get("name", "IaC Finding")
            for query in technology.get("queries", []):
                # Set up some base findings to be used by each
                # instance of the vulnerability
                base_finding_details = {
                    "title": f"{name}: {query.get('queryName')}",
                    "description": (
                        f"{query.get('description')}\n\n"
                        f"**Category**: {query.get('category')}\n"),
                    "verified": query.get("state") != "TO_VERIFY",
                    "test": test,
                }
                # Iterate over the individual issues
                for instance in query.get("resultsList"):
                    # Set the date depending on the first seen flag
                    if settings.USE_FIRST_SEEN:
                        date = self._parse_date(instance.get("firstDetectionDate"))
                    else:
                        date = self._parse_date(instance.get("lastDetectionDate"))
                    # Create the finding object
                    finding = Finding(
                        severity=instance.get("severity").title(),
                        date=date,
                        file_path=instance.get("fileName"),
                        mitigation=(
                            f"**Actual Value**: {instance.get('actualValue')}\n"
                            f"**Expected Value**: {instance.get('expectedValue')}\n"
                        ),
                        **base_finding_details,
                    )
                    # Add some details to the description
                    finding.description += (
                        f"**Issue Type**: {instance.get('issueType')}\n"
                        f"[View in Checkmarx One]({instance.get('resultViewerLink')})"
                    )
                    # Add at tag indicating what kind of finding this is
                    finding.unsaved_tags = ["iac"]
                    # Add the finding to the running list
                    findings.append(finding)
        return findings

    def parse_sca_vulnerabilities(
        self,
        test: Test,
        results: list,
        cwe_store: list,
    ) -> list[Finding]:
        # Not implemented yet
        return []

    def parse_sast_vulnerabilities(
        self,
        test: Test,
        results: list,
        cwe_store: list,
    ) -> list[Finding]:
        def get_cwe_store_entry(cwe_store: list, cwe: int) -> dict:
            # Quick base case
            if cwe is None:
                return {}
            # Iterate through the store to find a match
            for entry in cwe_store:
                if entry.get("cweId", 0) == cwe:
                    return entry
            return {}

        def get_markdown_categories(categories: list) -> str:
            value = ""
            for category in categories:
                value += f"- {category.get('name')}\n"
                for sub_category in category.get("subCategories", []):
                    value += f"\t- {sub_category}\n"
            return value

        def get_node_snippet(nodes: list) -> str:
            formatted_nodes = []
            for node in nodes:
                formatted_nodes.append(
                    f"**File Name**: {node.get('fileName')}\n"
                    f"**Method**: {node.get('method')}\n"
                    f"**Line**: {node.get('line')}\n"
                    f"**Code Snippet**: {node.get('code')}\n",
                )
            return "\n---\n".join(formatted_nodes)

        findings = []
        for result in results:
            # Get some info from the CWE
            cwe = result.get("cweId")
            cwe_info = get_cwe_store_entry(cwe_store, cwe)
            # Set up some base findings to be used by each
            # instance of the vulnerability
            base_finding_details = {
                "title": result.get(
                    "queryPath", result.get("queryName", "SAST Finding"),
                ).replace("_", " "),
                "description": (
                    f"{result.get('description')}\n\n"
                    f"{cwe_info.get('cause', '')}"),
                "references": get_markdown_categories(result.get("categories", [])),
                "impact": cwe_info.get("risk", ""),
                "mitigation": cwe_info.get("generalRecommendations", ""),
                "cwe": cwe,
                "test": test,
            }
            # Iterate over the individual issues
            for instance in result.get("vulnerabilities"):
                # Set the date depending on the first seen flag
                if settings.USE_FIRST_SEEN:
                    date = self._parse_date(instance.get("firstFoundDate"))
                else:
                    date = self._parse_date(instance.get("foundDate"))
                # Create the finding object
                finding = Finding(
                    severity=instance.get("severity").title(),
                    date=date,
                    file_path=instance.get("destinationFileName"),
                    line=instance.get("destinationLine"),
                    verified=instance.get("state") != "TO_VERIFY",
                    **base_finding_details,
                )
                # Add some details to the description
                if node_snippet := get_node_snippet(instance.get("nodes", [])):
                    finding.description += f"\n---\n{node_snippet}"
                # Add at tag indicating what kind of finding this is
                finding.unsaved_tags = ["sast"]
                # Add the finding to the running list
                findings.append(finding)
        return findings

    def parse_vulnerabilities(
        self,
        test: Test,
        results: list,
    ) -> list[Finding]:
        findings = []
        for result in results:
            result_id = result.get("identifiers")[0].get("value")
            cwe = None
            if "vulnerabilityDetails" in result:
                cwe = result.get("vulnerabilites").get("cweId")
            severity = result.get("severity")
            locations_uri = result.get("location").get("file")
            locations_startLine = result.get("location").get("start_line")
            locations_endLine = result.get("location").get("end_line")
            finding = Finding(
                unique_id_from_tool=result_id,
                file_path=locations_uri,
                line=locations_startLine,
                title=result_id + "_" + locations_uri,
                test=test,
                cwe=cwe,
                severity=severity,
                description="**id**: " + str(result_id) + "\n"
                + "**uri**: " + locations_uri + "\n"
                + "**startLine**: " + str(locations_startLine) + "\n"
                + "**endLine**: " + str(locations_endLine) + "\n",
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                static_finding=True,
                dynamic_finding=False,
            )
            findings.append(finding)
        return findings

    def parse_results(
        self,
        test: Test,
        results: list,
    ) -> list[Finding]:
        findings = []
        for vulnerability in results:
            result_type = vulnerability.get("type")
            date = self._parse_date(vulnerability.get("firstFoundAt"))
            cwe = self._parse_cwe(vulnerability.get("vulnerabilityDetails", {}).get("cweId", None))
            finding = None
            if result_type == "sast":
                finding = self.get_results_sast(test, vulnerability)
            elif result_type == "kics":
                finding = self.get_results_kics(test, vulnerability)
            elif result_type in ["sca", "sca-container"]:
                finding = self.get_results_sca(test, vulnerability)
            # Make sure we have a finding before continuing
            if finding is not None:
                # Add the type of vulnerability as a tag
                finding.date = date
                finding.cwe = cwe
                finding.unsaved_tags = [result_type]
                findings.append(finding)
        return findings

    def get_results_sast(
        self,
        test: Test,
        vulnerability: dict,
    ) -> Finding:
        description = vulnerability.get("description")
        file_path = vulnerability.get("data").get("nodes")[0].get("fileName")
        unique_id_from_tool = vulnerability.get("id", vulnerability.get("similarityId"))
        if description is None:
            description = vulnerability.get("severity").title() + " " + vulnerability.get("data").get("queryName").replace("_", " ")

        return Finding(
            description=description,
            title=description,
            file_path=file_path,
            severity=vulnerability.get("severity").title(),
            test=test,
            static_finding=True,
            unique_id_from_tool=unique_id_from_tool,
        )

    def get_results_kics(
        self,
        test: Test,
        vulnerability: dict,
    ) -> Finding:
        description = vulnerability.get("description")
        file_path = vulnerability.get("data").get("filename", vulnerability.get("data").get("fileName"))
        unique_id_from_tool = vulnerability.get("id", vulnerability.get("similarityId"))
        if description is None:
            description = vulnerability.get("severity").title() + " " + vulnerability.get("data").get("queryName").replace("_", " ")

        return Finding(
            title=description,
            description=description,
            severity=vulnerability.get("severity").title(),
            verified=vulnerability.get("state") != "TO_VERIFY",
            file_path=file_path,
            test=test,
            static_finding=True,
            unique_id_from_tool=unique_id_from_tool,
        )

    def get_results_sca(
        self,
        test: Test,
        vulnerability: dict,
    ) -> Finding:
        description = vulnerability.get("description")
        unique_id_from_tool = vulnerability.get("id", vulnerability.get("similarityId"))
        if description is None:
            description = vulnerability.get("severity").title() + " " + vulnerability.get("data").get("queryName").replace("_", " ")

        finding = Finding(
            title=description,
            description=description,
            severity=vulnerability.get("severity").title(),
            verified=vulnerability.get("state") != "TO_VERIFY",
            test=test,
            static_finding=True,
            unique_id_from_tool=unique_id_from_tool,
        )
        if (cveId := vulnerability.get("cveId")) is not None:
            finding.unsaved_vulnerability_ids = [cveId]

        return finding

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        if any(vuln_type in data for vuln_type in ["scaScanResults", "iacScanResults", "scanResults"]):
            findings = self.parse_vulnerabilities_from_scan_list(test, data)
        if (results := data.get("vulnerabilities", None)) is not None:
            findings = self.parse_vulnerabilities(test, results)
        elif (results := data.get("results", None)) is not None:
            findings = self.parse_results(test, results)

        return findings
