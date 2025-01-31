import json

from dojo.models import Finding


class OSVScannerParser:

    def get_scan_types(self):
        return ["OSV Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "OSV Scan"

    def get_description_for_scan_types(self, scan_type):
        return "OSV scan output can be imported in JSON format (option --format json)."

    def classify_severity(self, severity_input):
        return ("Medium" if severity_input == "MODERATE" else severity_input.lower().capitalize()) if severity_input != "" else "Low"

    def get_findings(self, file, test):
        try:
            data = json.load(file)
        except json.decoder.JSONDecodeError:
            return []
        findings = []
        for result in data.get("results", []):
            # Extract source locations if present
            source_path = result.get("source", {}).get("path", "")
            source_type = result.get("source", {}).get("type", "")
            for package in result.get("packages", []):
                package_name = package.get("package", {}).get("name")
                package_version = package.get("package", {}).get("version")
                package_ecosystem = package.get("package", {}).get("ecosystem", "")
                for vulnerability in package.get("vulnerabilities", []):
                    vulnerabilityid = vulnerability.get("id", "")
                    vulnerabilitysummary = vulnerability.get("summary", "")
                    vulnerabilitydetails = vulnerability.get("details", "")
                    vulnerabilitypackagepurl = ""
                    cwe = None
                    # Make sure we have an affected section to work with
                    if (affected := vulnerability.get("affected")) is not None:
                        if len(affected) > 0:
                            # Pull the package purl if present
                            if (vulnerabilitypackage := affected[0].get("package", "")) != "":
                                vulnerabilitypackagepurl = vulnerabilitypackage.get("purl", "")
                            # Extract the CWE
                            if (cwe := affected[0].get("database_specific", {}).get("cwes", None)) is not None:
                                cwe = cwe[0]["cweId"]
                    # Create some references
                    reference = ""
                    for ref in vulnerability.get("references"):
                        reference += ref.get("url") + "\n"
                    # Define the description
                    description = vulnerabilitysummary + "\n"
                    description += "**source_type**: " + source_type + "\n"
                    description += "**package_ecosystem**: " + package_ecosystem + "\n"
                    description += "**vulnerabilitydetails**: " + vulnerabilitydetails + "\n"
                    description += "**vulnerabilitypackagepurl**: " + vulnerabilitypackagepurl + "\n"
                    sev = vulnerability.get("database_specific", {}).get("severity", "")
                    finding = Finding(
                        title=vulnerabilityid + "_" + package_name,
                        test=test,
                        description=description,
                        severity=self.classify_severity(sev),
                        static_finding=True,
                        dynamic_finding=False,
                        component_name=package_name,
                        component_version=package_version,
                        cwe=cwe,
                        file_path=source_path,
                        references=reference,
                    )
                    if vulnerabilityid != "":
                        finding.unsaved_vulnerability_ids = []
                        finding.unsaved_vulnerability_ids.append(vulnerabilityid)
                    findings.append(finding)
        return findings
