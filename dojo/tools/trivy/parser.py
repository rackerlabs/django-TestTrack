"""Parser for Aquasecurity trivy (https://github.com/aquasecurity/trivy) Docker images scaner"""

import json
import logging

from dojo.models import Finding

logger = logging.getLogger(__name__)


TRIVY_SEVERITIES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Info",
}

DESCRIPTION_TEMPLATE = """{title}
**Target:** {target}
**Type:** {type}
**Fixed version:** {fixed_version}

{description_text}
"""

MISC_DESCRIPTION_TEMPLATE = """**Target:** {target}
**Type:** {type}

{description}
{message}
"""

SECRET_DESCRIPTION_TEMPLATE = """{title}
**Category:** {category}
**Match:** {match}
"""  # noqa: S105

LICENSE_DESCRIPTION_TEMPLATE = """{title}
**Category:** {category}
**Package:** {package}
"""


class TrivyParser:
    def get_scan_types(self):
        return ["Trivy Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Trivy Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import trivy JSON scan report."

    def convert_cvss_score(self, raw_value):
        if raw_value is None:
            return "Info"
        val = float(raw_value)
        if val == 0.0:
            return "Info"
        if val < 4.0:
            return "Low"
        if val < 7.0:
            return "Medium"
        if val < 9.0:
            return "High"
        return "Critical"

    def get_findings(self, scan_file, test):
        scan_data = scan_file.read()

        try:
            data = json.loads(str(scan_data, "utf-8"))
        except Exception:
            data = json.loads(scan_data)

        # Legacy format is empty
        if data is None:
            return []
        # Legacy format with results
        if isinstance(data, list):
            return self.get_result_items(test, data)
        schema_version = data.get("SchemaVersion", None)
        artifact_name = data.get("ArtifactName", "")
        cluster_name = data.get("ClusterName")
        if schema_version == 2:
            results = data.get("Results", [])
            return self.get_result_items(test, results, artifact_name=artifact_name)
        if cluster_name is not None:
            findings = []
            vulnerabilities = data.get("Vulnerabilities", [])
            for service in vulnerabilities:
                namespace = service.get("Namespace")
                kind = service.get("Kind")
                name = service.get("Name")
                service_name = ""
                if namespace:
                    service_name = f"{namespace} / "
                if kind:
                    service_name += f"{kind} / "
                if name:
                    service_name += f"{name} / "
                if len(service_name) >= 3:
                    service_name = service_name[:-3]
                findings += self.get_result_items(
                    test, service.get("Results", []), service_name,
                )
            misconfigurations = data.get("Misconfigurations", [])
            for service in misconfigurations:
                namespace = service.get("Namespace")
                kind = service.get("Kind")
                name = service.get("Name")
                service_name = ""
                if namespace:
                    service_name = f"{namespace} / "
                if kind:
                    service_name += f"{kind} / "
                if name:
                    service_name += f"{name} / "
                if len(service_name) >= 3:
                    service_name = service_name[:-3]
                findings += self.get_result_items(
                    test, service.get("Results", []), service_name,
                )
            resources = data.get("Resources", [])
            for resource in resources:
                namespace = resource.get("Namespace")
                kind = resource.get("Kind")
                name = resource.get("Name")
                if namespace:
                    resource_name = f"{namespace} / "
                if kind:
                    resource_name += f"{kind} / "
                if name:
                    resource_name += f"{name} / "
                if len(resource_name) >= 3:
                    resource_name = resource_name[:-3]
                findings += self.get_result_items(
                    test, resource.get("Results", []), resource_name,
                )
            return findings
        msg = "Schema of Trivy json report is not supported"
        raise ValueError(msg)

    def get_result_items(self, test, results, service_name=None, artifact_name=""):
        items = []
        for target_data in results:
            if (
                not isinstance(target_data, dict)
                or "Target" not in target_data
            ):
                continue
            target = target_data["Target"]

            target_target = target_data.get("Target")
            target_class = target_data.get("Class")
            target_type = target_data.get("Type")

            vulnerabilities = target_data.get("Vulnerabilities", []) or []
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                try:
                    vuln_id = vuln.get("VulnerabilityID", "0")
                    package_name = vuln["PkgName"]
                    severity_source = vuln.get("SeveritySource", None)
                    cvss = vuln.get("CVSS", None)
                    cvssv3 = None
                    if severity_source is not None and cvss is not None:
                        cvssclass = cvss.get(severity_source, None)
                        if cvssclass is not None:
                            if cvssclass.get("V3Score") is not None:
                                severity = self.convert_cvss_score(cvssclass.get("V3Score"))
                                cvssv3 = dict(cvssclass).get("V3Vector")
                            elif cvssclass.get("V2Score") is not None:
                                severity = self.convert_cvss_score(cvssclass.get("V2Score"))
                            else:
                                severity = self.convert_cvss_score(None)
                        else:
                            severity = TRIVY_SEVERITIES[vuln["Severity"]]
                    else:
                        severity = TRIVY_SEVERITIES[vuln["Severity"]]
                    if target_class == "os-pkgs" or target_class == "lang-pkgs":
                        file_path = vuln.get("PkgPath")
                        if file_path is None:
                            file_path = target_target
                    elif target_class == "config":
                        file_path = target_target
                    else:
                        file_path = None
                except KeyError as exc:
                    logger.warning("skip vulnerability due %r", exc)
                    continue
                package_version = vuln.get("InstalledVersion", "")
                references = "\n".join(vuln.get("References", []))
                mitigation = vuln.get("FixedVersion", "")
                cwe = int(vuln["CweIDs"][0].split("-")[1]) if len(vuln.get("CweIDs", [])) > 0 else 0
                vul_type = target_data.get("Type", "")
                title = f"{vuln_id} {package_name} {package_version}"
                description = DESCRIPTION_TEMPLATE.format(
                    title=vuln.get("Title", ""),
                    target=target,
                    type=vul_type,
                    fixed_version=mitigation,
                    description_text=vuln.get("Description", ""),
                )
                finding = Finding(
                    test=test,
                    title=title,
                    cwe=cwe,
                    severity=severity,
                    file_path=file_path,
                    references=references,
                    description=description,
                    mitigation=mitigation,
                    component_name=package_name,
                    component_version=package_version,
                    cvssv3=cvssv3,
                    static_finding=True,
                    dynamic_finding=False,
                    tags=[vul_type, target_class],
                    service=service_name,
                )

                if vuln_id:
                    finding.unsaved_vulnerability_ids = [vuln_id]

                items.append(finding)

            misconfigurations = target_data.get("Misconfigurations", [])
            for misconfiguration in misconfigurations:
                misc_type = misconfiguration.get("Type")
                misc_id = misconfiguration.get("ID")
                misc_title = misconfiguration.get("Title")
                misc_description = misconfiguration.get("Description")
                misc_message = misconfiguration.get("Message")
                misc_resolution = misconfiguration.get("Resolution")
                misc_severity = misconfiguration.get("Severity")
                misc_primary_url = misconfiguration.get("PrimaryURL")
                misc_references = misconfiguration.get("References", [])
                misc_causemetadata = misconfiguration.get("CauseMetadata", {})
                misc_cause_code = misc_causemetadata.get("Code", {})
                misc_cause_lines = misc_cause_code.get("Lines", [])
                string_lines_table = self.get_lines_as_string_table(misc_cause_lines)
                if string_lines_table != "":
                    misc_message += ("\n" + string_lines_table)

                title = f"{misc_id} - {misc_title}"
                description = MISC_DESCRIPTION_TEMPLATE.format(
                    target=target_target,
                    type=misc_type,
                    description=misc_description,
                    message=misc_message,
                )
                severity = TRIVY_SEVERITIES[misc_severity]
                references = None
                if misc_primary_url:
                    references = f"{misc_primary_url}\n"
                if misc_primary_url in misc_references:
                    misc_references.remove(misc_primary_url)
                if references:
                    references += "\n".join(misc_references)
                else:
                    references = "\n".join(misc_references)

                finding = Finding(
                    test=test,
                    title=title,
                    severity=severity,
                    references=references,
                    description=description,
                    mitigation=misc_resolution,
                    static_finding=True,
                    dynamic_finding=False,
                    tags=[target_type, target_class],
                    service=service_name,
                )
                items.append(finding)

            secrets = target_data.get("Secrets", [])
            for secret in secrets:
                secret_category = secret.get("Category")
                secret_title = secret.get("Title")
                secret_severity = secret.get("Severity")
                secret_match = secret.get("Match")
                secret_start_line = secret.get("StartLine")

                title = f"Secret detected in {target_target} - {secret_title}"
                description = SECRET_DESCRIPTION_TEMPLATE.format(
                    title=secret_title,
                    category=secret_category,
                    match=secret_match,
                )
                severity = TRIVY_SEVERITIES[secret_severity]

                finding = Finding(
                    test=test,
                    title=title,
                    severity=severity,
                    description=description,
                    file_path=target_target,
                    line=secret_start_line,
                    static_finding=True,
                    dynamic_finding=False,
                    tags=[target_class],
                    service=service_name,
                )
                items.append(finding)

            licenses = target_data.get("Licenses", [])
            for lic in licenses:
                license_severity = lic.get("Severity")
                license_category = lic.get("Category")
                license_pkgname = lic.get("PkgName")
                license_filepath = lic.get("FilePath")
                license_name = lic.get("Name")
                license_confidence = lic.get("Confidence")
                license_link = lic.get("Link")

                title = f"License detected in {target_target} - {license_name}"
                description = LICENSE_DESCRIPTION_TEMPLATE.format(
                    title=license_name,
                    category=license_category,
                    package=license_pkgname,
                )
                severity = TRIVY_SEVERITIES[license_severity]

                finding = Finding(
                    test=test,
                    title=title,
                    severity=severity,
                    description=description,
                    file_path=license_filepath,
                    scanner_confidence=license_confidence,
                    url=license_link,
                    static_finding=True,
                    dynamic_finding=False,
                    tags=[target_class],
                    service=service_name,
                )
                items.append(finding)

        return items

    def get_lines_as_string_table(self, lines):
        if lines is None:
            return ""
        # Define column headers
        headers = ["Number", "Content"]

        # Create the header row
        header_row = "\t".join(headers)

        # Create the table string
        table_string = f"{header_row}\n"
        for item in lines:
            row = "\t".join(str(item.get(header, "")) for header in headers)
            table_string += f"{row}\n"

        return table_string
