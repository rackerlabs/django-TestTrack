import json
import re

from cvss import CVSS3
from dateutil import parser
from django.conf import settings

from dojo.models import Endpoint, Finding


class VeracodeJSONParser:

    """
    This parser is written for Veracode REST Findings.

    API endpoints to use: https://docs.veracode.com/r/c_findings_v2_examples

    Example: curl <endpoint> | jq "{findings}"

    This should convert the format into something like this:
    {
        "findings": [
            {
                ...
            },
            ...
        ]
    }
    """

    severity_mapping = {
        0: "Info",
        1: "Info",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
    }

    exploitability_mapping = {
        -2: "Very Unlikely",
        -1: "Unlikely",
        0: "Neutral",
        1: "Likely",
        2: "Very Likely",
    }

    # This mapping was found here: https://docs.veracode.com/r/c_integrated_license_agent
    license_mapping = {
        0: ("Non OSS", "Non-OSS indicates that this file could be subject to commercial license terms. If so, you should refer to your applicable license agreement with such vendor for additional information."),
        1: ("Unrecognized", "Unrecognized indicates that no license was found for the component. However, this does not indicate that there is no risk associated with the license."),
        2: ("Low", "Low-risk licenses are typically permissive licenses that require you to preserve the copyright and license notices, but allow distribution under different terms without disclosing source code."),
        3: ("Medium", "Medium-risk licenses are typically weak copyleft licenses that require you to preserve the copyright and license notices, and require distributors to make the source code of the component and any modifications under the same terms."),
        4: ("High", "High-risk licenses are typically strong copyleft licenses that require you to preserve the copyright and license notices, and require distributors to make the source code of the component and any modifications under the same terms."),
    }

    def get_findings(self, json_output, test):
        findings = []
        if json_output:
            json_data = json.load(json_output)
            findings += self.get_items(json_data, test)
        return findings

    def get_items(self, tree, test):
        parsed_findings = []
        # Attempt to get the findings where they are expected to be
        # If they are not there, make an educated guess that the uploaded report
        # is in the format of the direct response from the API
        items = tree.get("findings", []) or tree.get("_embedded", {}).get("findings", [])
        for vuln in items:
            # Check the status of the finding to determine if an object should even be created
            # If the finding is closed, skip it
            if vuln.get("finding_status", {}).get("status", "") == "CLOSED":
                continue
            # Determine the scan type to dictate how that finding details will be handled
            scan_type = vuln.get("scan_type")
            # Get the finding details object
            finding_details = vuln.get("finding_details")
            # Get the info to determine if this finding violates a policy
            policy_violated = vuln.get("violates_policy")
            # Set up the finding with as many contextual details as possible
            finding = self.create_finding_from_details(finding_details, scan_type, policy_violated)
            # If the finding returned is empty, return nothing as the scan type must
            # not be supported yet
            if not finding:
                continue
            # Set the date of the finding from the report if it is present
            if finding_status := vuln.get("finding_status"):
                if settings.USE_FIRST_SEEN:
                    if first_found_date := finding_status.get("first_found_date"):
                        finding.date = parser.parse(first_found_date)
                else:
                    if last_found_date := finding_status.get("last_found_date"):
                        finding.date = parser.parse(last_found_date)
            # Generate the description
            finding = self.parse_description(finding, vuln.get("description"), scan_type)
            finding.nb_occurences = vuln.get("count", 1)
            finding.test = test

            parsed_findings.append(finding)

        return parsed_findings

    def create_finding_from_details(self, finding_details, scan_type, policy_violated) -> Finding:
        # Fetch the common attributes that should be in every scan type
        severity = self.severity_mapping.get(finding_details.get("severity", 1), 1)
        # Set up the finding with just severity for now
        finding = Finding(
            title=f"{scan_type} Finding",
            severity=severity,
            description="### Meta Information\n",
        )
        # Set some unsaved fields
        finding.unsaved_tags = []
        finding.unsaved_endpoints = []
        finding.unsaved_vulnerability_ids = []
        # Determine if this finding violates a policy
        if policy_violated:
            finding.unsaved_tags.append("policy-violation")
        # Store the title in a var in case it may be needed later
        cwe_title = None
        # Try to get the common fields that may not be present
        if cwe_dict := finding_details.get("cwe"):
            cwe_title = cwe_dict.get("name")
            finding.cwe = cwe_dict.get("id")
        # Attempt to get the CVSS score
        if uncleaned_cvss := finding_details.get("cvss"):
            if isinstance(uncleaned_cvss, str):
                if uncleaned_cvss.startswith(("CVSS:3.1/", "CVSS:3.0/")):
                    finding.cvssv3 = CVSS3(str(uncleaned_cvss)).clean_vector(output_prefix=True)
                elif not uncleaned_cvss.startswith("CVSS"):
                    finding.cvssv3 = CVSS3(f"CVSS:3.1/{uncleaned_cvss}").clean_vector(output_prefix=True)
            elif isinstance(uncleaned_cvss, float | int):
                finding.cvssv3_score = float(uncleaned_cvss)
        # Fill in extra info based on the scan type
        if scan_type == "STATIC":
            return self.add_static_details(finding, finding_details, backup_title=cwe_title)
        if scan_type == "DYNAMIC":
            return self.add_dynamic_details(finding, finding_details, backup_title=cwe_title)
        if scan_type == "SCA":
            return self.add_sca_details(finding, finding_details, backup_title=cwe_title)

        return None

    def add_static_details(self, finding, finding_details, backup_title=None) -> Finding:
        finding.dynamic_finding = False
        finding.static_finding = True
        # Get the finding category to get the high level info about the vuln
        category_title = category.get("name") if (category := finding_details.get("finding_category")) else None
        # Set the title of the finding to the name of the finding category.
        # If not present, fall back on CWE title. If that is not present, do nothing
        if category_title:
            finding.title = category_title
        elif backup_title:
            finding.title = backup_title
        # Fill in the file path and line number
        if file_path := finding_details.get("file_path"):
            finding.sast_source_file_path = file_path
            finding.sast_sink_file_path = file_path
            finding.file_path = file_path
        if file_line_number := finding_details.get("file_line_number"):
            finding.sast_source_line = file_line_number
            finding.sast_sink_line = file_line_number
            finding.line = file_line_number
        if function_object := finding_details.get("procedure"):
            if isinstance(function_object, str):
                finding.sast_source_object = function_object
                finding.sast_sink_object = function_object
        # Set the exploitability if present
        if exploitability_score := finding_details.get("exploitability"):
            finding.description += f"**Exploitability Predication**: {self.exploitability_mapping.get(exploitability_score)}\n"
        # Add the predicted attack vector if available
        if attack_vector := finding_details.get("attack_vector"):
            finding.description += f"**Attack Vector**: {attack_vector}\n"
        # Add the module this vuln is located into the description
        if module := finding_details.get("module"):
            finding.description += f"**Module**: {module}\n"

        return finding

    def add_dynamic_details(self, finding, finding_details, backup_title=None) -> Finding:
        finding.dynamic_finding = True
        finding.static_finding = False
        # Get the finding category to get the high level info about the vuln
        category_title = category.get("name") if (category := finding_details.get("finding_category")) else None
        # Set the title of the finding to the name of the finding category.
        # If not present, fall back on CWE title. If that is not present, do nothing
        if category_title:
            finding.title = category_title
        elif backup_title:
            finding.title = backup_title
        # Add the url to the finding
        if url := finding_details.get("url"):
            # Create the Endpoint object from the url
            finding.unsaved_endpoints.append(
                Endpoint.from_uri(url),
            )
        else:
            # build it from the other attributes
            host = finding_details.get("hostname")
            port = finding_details.get("port")
            path = finding_details.get("path")
            # Create the Endpoint object from all of the pieces
            finding.unsaved_endpoints.append(
                Endpoint(
                    host=host,
                    port=port,
                    path=path,
                ),
            )
        # Add the plugin if available
        if plugin := finding_details.get("plugin"):
            finding.description += f"**Plugin**: {plugin}\n"
        # Add the predicted attack vector if available
        if attack_vector := finding_details.get("attack_vector"):
            finding.description += f"**Attack Vector**: {attack_vector}\n"
        # Add the vulnerable parameter into the description
        if vulnerable_parameter := finding_details.get("vulnerable_parameter"):
            finding.description += f"**Vulnerable Parameter**: {vulnerable_parameter}\n"
        # Add a note that this finding was discovered by the VSA
        if discovered_by_vsa := finding_details.get("discovered_by_vsa"):
            if bool(discovered_by_vsa):
                finding.description += "**Note**: This finding was discovered by Virtual Scan Appliance\n"

        return finding

    def add_sca_details(self, finding, finding_details, backup_title=None) -> Finding:
        finding.dynamic_finding = False
        finding.static_finding = False
        # Set the initial standard as the CWE title
        finding.title = backup_title
        # Set some placeholders for title vars if needed
        vuln_id = None
        # Check for a CVE object
        if cve_dict := finding_details.get("cve"):
            vuln_id = cve_dict.get("name")
            finding.unsaved_vulnerability_ids.append(vuln_id)
            # See if the CVSS has already been set. If not, use the one here
            if not finding.cvssv3:
                if cvss_vector := cve_dict.get("cvss3", {}).get("vector"):
                    finding.cvssv3 = CVSS3(f"CVSS:3.1/{cvss_vector}").clean_vector(output_prefix=True)
        # Put the product ID in the metadata
        if product_id := finding_details.get("product_id"):
            finding.description += f"**Product ID**: {product_id}\n"
        # Put the component ID in the metadata
        if component_id := finding_details.get("component_id"):
            finding.description += f"**Component ID**: {component_id}\n"
        # Put the language in the metadata
        if language := finding_details.get("language"):
            finding.description += f"**Language**: {language}\n"
        # List the paths this component is found
        if component_paths := finding_details.get("component_path", []):
            # Build the license string
            component_paths_markdown = "#### Component Locations\n"
            for path in component_paths:
                component_paths_markdown += f"- {path.get('path')}\n"
            # Do not add any extra text if the there are no paths here
            if component_paths_markdown != "#### Component Locations\n":
                finding.description += component_paths_markdown
        # List the licenses at the bottom of the metadata
        if licenses := finding_details.get("licenses", []):
            # Build the license string
            license_markdown = "#### Licenses\n"
            for lic in licenses:
                license_name = lic.get("license_id")
                license_details = self.license_mapping.get(int(lic.get("risk_rating", 5)))
                license_markdown += f"- {license_name}: {license_details[0]}\n    - {license_details[1]}\n"
            # Do not add any extra text if the there are no licenses here
            if license_markdown != "#### Licenses\n":
                finding.description += license_markdown
        # Add the component name and version
        if component_name := finding_details.get("component_filename"):
            if component_version := finding_details.get("version"):
                finding.component_version = component_version
            # Replace the version in the component name
            finding.component_name = component_name.replace(finding.component_version, "")
            # Check for any wonky formats post version replacement that had extensions
            finding.component_name = finding.component_name.replace("-.", ".").replace("_.", ".")
            # Check for the event that the component name did not have an extension, but name has a dangling hyphen/underscore
            if finding.component_name.endswith("-") or finding.component_name.endswith("_"):
                finding.component_name = finding.component_name[:-1]
        # check if the CWE title was used. A cwe may not be present when a veracode SRCCLR is present
        if not finding.title:
            finding.title = f"{finding.component_name} - {vuln_id}"

        return finding

    def parse_description(self, finding, description_body, scan_type) -> Finding:
        if scan_type == "STATIC":
            # The description of the veracode finding is defined in three parts separated
            # by <span> tags:
            #  - Description: A detailed explanation of the vulnerability and why it is bad
            #  - Mitigation: What to do about the vulnerability
            #  - References: Any external links to further knowledge related to the vulnerability

            # Split the description body into sections based on a "<span>" delimiter
            sections = description_body.split("<span>")
            # Trim out the closing span tags and any trailing spaces in each section
            sections = [section.replace("</span>", "").strip() for section in sections if len(section) > 0]
            # Make sure there is something to grab from the expected places
            if len(sections) > 0:
                finding.description += f"### Details\n{sections[0]}"

            # Determine there is a mitigation section in the first index
            if len(sections) > 1 and "References:" not in sections[1]:
                finding.mitigation = sections[1]
            # Determine if the references section is actually in the first index
            elif len(sections) > 1 and "References:" in sections[1]:
                finding.references = self.parse_references(sections[1])

            # Determine if the references are in the second index
            if len(sections) > 2 and "References:" in sections[2]:
                finding.references = self.parse_references(sections[2])
        elif scan_type == "DYNAMIC":
            # The description of the veracode finding is defined in three parts separated
            # by <span> tags:
            #  - Description: A detailed explanation of the vulnerability and why it is bad
            #  - Mitigation: What to do about the vulnerability
            #  - References: (No "References:" string ) Any external links to further knowledge related to the vulnerability

            # Split the description body into sections based on a "<span>" delimiter
            sections = description_body.split("<span>")
            # Trim out the closing span tags and any trailing spaces in each section
            sections = [section.replace("</span>", "").strip() for section in sections if len(section) > 0]
            # Make sure there is something to grab from the expected places
            if len(sections) > 0:
                finding.description += f"### Details\n{sections[0]}"

            # Determine there is a mitigation section in the first index
            if len(sections) > 1 and "<a href" not in sections[1]:
                finding.mitigation = sections[1]
            # Determine if the references section is actually in the first index
            elif len(sections) > 1 and "<a href" in sections[1]:
                finding.references = self.parse_references(sections[1])

            # Determine if the references are in the second index
            if len(sections) > 2 and "<a href" in sections[2]:
                finding.references = self.parse_references(sections[2])
        elif scan_type == "SCA":
            finding.description += f"### Details\n{description_body}"

        return finding

    def parse_references(self, text) -> str:
        # Remove the "References: " tag from the text
        text = text.replace("References: ", "")
        # Split on the href tags
        sections = text.split("<a ")
        # Trim out the trailing spaces in each section
        sections = [section.strip() for section in sections if len(section) > 0]
        # Iterate over the references to find the link and label for each entry
        regex_search = 'href=\\"(.*)\\">(.*)</a>'
        references = []
        for reference in sections:
            if matches := re.search(regex_search, reference):
                references.append(matches.groups())
        # Build a markdown string for the references text
        reference_string = ""
        for reference in references:
            link = None
            label = None
            # Try to get the link
            if len(reference) > 0:
                link = reference[0]
            if len(reference) > 1:
                label = reference[1]
            # Build a full link if both the label and link are present
            if link and label:
                reference_string += f"- [{label}]({link})\n"
            elif link and not label:
                reference_string += f"- {link}\n"

        return reference_string
