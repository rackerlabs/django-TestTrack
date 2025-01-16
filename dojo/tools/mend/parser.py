import hashlib
import json
import logging

from dojo.models import Finding

__author__ = "dr3dd589 + testaccount90009 aka SH"

logger = logging.getLogger(__name__)


class MendParser:
    def get_scan_types(self):
        return ["Mend Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Mend Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON report"

    def get_findings(self, file, test):
        if file is None:
            return []

        data = file.read()
        try:
            content = json.loads(str(data, "utf-8"))
        except Exception:
            content = json.loads(data)

        def _build_common_output(node, lib_name=None):
            # project only available in manual export
            # name --> CVE in manual, library name in pipeline
            cve = None
            component_name = None
            component_version = None
            impact = None
            description = "No Description Available"
            cvss3_score = None
            mitigation = "N/A"
            locations = []
            if "component" in node:
                description = (
                    "**Vulnerability Description**: "
                    + node["vulnerability"].get("description", "No Description Available")
                    + "\n\n"
                    + "**Component Name**: "
                    + node["component"].get("name", "")
                    + "\n"
                    + "**Component Type**: "
                    + node["component"].get("componentType", "")
                    + "\n"
                    + "**Root Library**: "
                    + str(node["component"].get("rootLibrary", ""))
                    + "\n"
                    + "**Library Type**: "
                    + node["component"].get("libraryType", "")
                    + "\n"
                )
                lib_name = node["component"].get("name")
                component_name = node["component"].get("artifactId")
                component_version = node["component"].get("version")
                impact = (
                    "**Direct or Transitive Vulnerability**: "
                    + node["component"].get("dependencyType", "")
                    + "\n"
                )
                cvss3_score = node["vulnerability"].get("score", None)
                component_path = node["component"].get("path", None)
                if component_path:
                    locations.append(component_path)
                if "topFix" in node:
                    try:
                        topfix_node = node.get("topFix")
                        mitigation = (
                            "**Resolution**: "
                            + topfix_node.get("date", "")
                            + "\n"
                            + topfix_node.get("message", "")
                            + "\n"
                            + topfix_node.get("fixResolution", "")
                            + "\n"
                        )
                    except Exception:
                        logger.exception("Error handling topFix node.")
            elif "library" in node:
                node.get("project")
                description = (
                    "**Description** : "
                    + node.get("description", "")
                    + "\n\n"
                    + "**Library Name** : "
                    + node["library"].get("name", "")
                    + "\n\n"
                    + "**Library Filename** : "
                    + node["library"].get("filename", "")
                    + "\n\n"
                    + "**Library Description** : "
                    + node["library"].get("description", "")
                    + "\n\n"
                    + "**Library Type** : "
                    + node["library"].get("type", "")
                    + "\n"
                )
                lib_name = node["library"].get("filename")
                component_name = node["library"].get("artifactId")
                component_version = node["library"].get("version")
                cvss3_score = node.get("cvss3_score", None)
                if "topFix" in node:
                    try:
                        topfix_node = node.get("topFix")
                        mitigation = "**Resolution** ({}): {}\n".format(
                            topfix_node.get("date"),
                            topfix_node.get("fixResolution"),
                        )
                    except Exception:
                        logger.exception("Error handling topFix node.")
            else:
                description = node.get("description", "Unknown")

            cve = node.get("name")
            title = "CVE-None | " + lib_name if cve is None else cve + " | " + lib_name
            # cvss2 by default in CLI, but cvss3 in UI. Adapting to have
            # homogeneous behavior.
            if "cvss3_severity" in node:
                cvss_sev = node.get("cvss3_severity")
            elif "vulnerability" in node:
                cvss_sev = node["vulnerability"].get("severity")
            else:
                cvss_sev = node.get("severity")
            severity = cvss_sev.lower().capitalize()

            cvss3_vector = node.get("scoreMetadataVector", None)
            severity_justification = "CVSS v3 score: {} ({})".format(
                cvss3_score if cvss3_score is not None else "N/A", cvss3_vector if cvss3_vector is not None else "N/A",
            )
            cwe = 1035  # default OWASP a9 until the report actually has them

            filepaths = []
            if "sourceFiles" in node:
                try:
                    sourceFiles_node = node.get("sourceFiles")
                    for sfile in sourceFiles_node:
                        filepaths.append(sfile.get("localPath"))
                except Exception:
                    logger.exception(
                        "Error handling local paths for vulnerability.",
                    )

            if "locations" in node:
                try:
                    locations_node = node.get("locations", [])
                    for location in locations_node:
                        path = location.get("path")
                        if path is not None:
                            locations.append(path)
                except Exception:
                    logger.exception(
                        "Error handling local paths for vulnerability.",
                    )
            if locations:
                # Join the locations into a single string
                joined_locations = ", ".join(locations)

                # If the length exceeds 3999 characters, trim it
                if len(joined_locations) > 3999:
                    # Iterate over the locations and trim until the total length is <= 3999
                    total_length = 0
                    truncated_locations = []

                    for loc in locations:
                        loc_length = len(loc)
                        # Check if adding this location will exceed the limit
                        if total_length + loc_length + len(truncated_locations) <= 3996:  # 3999 - len("...") = 3996
                            truncated_locations.append(loc)
                            total_length += loc_length
                        else:
                            # Stop if adding the next location will exceed the limit
                            break

                    # Add ellipsis at the end to indicate truncation
                    locations = truncated_locations
                    locations.append("...")  # Add the ellipsis to the end of the locations list

            filepaths = filepaths

            new_finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                cwe=cwe,
                mitigation=mitigation,
                file_path=", ".join(filepaths),
                component_name=component_name,
                component_version=component_version,
                severity_justification=severity_justification,
                dynamic_finding=True,
                cvssv3=cvss3_vector,
                cvssv3_score=float(cvss3_score) if cvss3_score is not None else None,
                impact=impact if impact is not None else None,
                steps_to_reproduce="**Locations Found**: " + ", ".join(locations) if locations is not None else None,
            )
            if cve:
                new_finding.unsaved_vulnerability_ids = [cve]

            return new_finding

        findings = []
        if "libraries" in content:
            # we are likely dealing with a report generated from CLI with -generateScanReport,
            # which will output vulnerabilities as an array of a library
            # In this scenario, build up an array
            tree_libs = content.get("libraries")
            for lib_node in tree_libs:
                # get the overall lib info here, before going into vulns
                if (
                    "vulnerabilities" in lib_node
                    and len(lib_node.get("vulnerabilities")) > 0
                ):
                    for vuln in lib_node.get("vulnerabilities"):
                        findings.append(
                            _build_common_output(vuln, lib_node.get("name")),
                        )

        elif "vulnerabilities" in content:
            # likely a manual json export for vulnerabilities only for a project.
            # Vulns are standalone, and library is a property.
            tree_node = content["vulnerabilities"]
            for node in tree_node:
                findings.append(_build_common_output(node))

        elif "components" in content:
            # likely a Mend Platform or 3.0 API SCA output - "library" is replaced as "component"
            tree_components = content.get("components")
            for comp_node in tree_components:
                # get component info here, before going into vulns
                if (
                    "response" in comp_node
                    and len(comp_node.get("response")) > 0
                ):
                    for vuln in comp_node.get("response"):
                        findings.append(
                            _build_common_output(vuln, comp_node.get("name")),
                        )

        elif "response" in content:
            # New schema: handle response array
            tree_node = content["response"]
            if tree_node:
                for node in tree_node:
                    if node.get("findingInfo", {}).get("status") == "ACTIVE":
                        findings.append(_build_common_output(node))

        def create_finding_key(f: Finding) -> str:
            # """Hashes the finding's description and title to retrieve a key for deduplication."""
            return hashlib.md5(
                f.description.encode("utf-8")
                + f.title.encode("utf-8"),
            ).hexdigest()

        dupes = {}
        for finding in findings:
            dupe_key = create_finding_key(finding)
            if dupe_key not in dupes:
                dupes[dupe_key] = finding

        return list(dupes.values())
