import hashlib
import json
import logging
import re
from datetime import datetime

from dojo.models import Endpoint, Finding


class WhiteHatSentinelParser:

    """
    A class to parse WhiteHat Sentinel vulns from the WhiteHat Sentinel API vuln?query_site=[
    SITE_ID]&format=json&display_attack_vectors=all&display_custom_risk=1&display_risk=1&display_description=custom
    """

    _LOGGER = logging.getLogger(__name__)

    def get_scan_types(self):
        return ["WhiteHat Sentinel"]

    def get_label_for_scan_types(self, scan_type):
        return "WhiteHat Sentinel"

    def get_description_for_scan_types(self, scan_type):
        return "WhiteHat Sentinel output from api/vuln/query_site can be imported in JSON format."

    def get_findings(self, file, test):
        findings_collection = json.load(file)

        if not findings_collection.keys():
            return []

        # Make sure the findings key exists in the dictionary and that it is
        # not null or an empty list
        if (
            "collection" not in findings_collection
            or not findings_collection["collection"]
        ):
            msg = "collection key not present or there were not findings present."
            raise ValueError(msg)

        # Convert a WhiteHat Vuln with Attack Vectors to a list of DefectDojo
        # findings
        return self._convert_whitehat_sentinel_vulns_to_dojo_finding(
            findings_collection["collection"], test,
        )

        # # Loop through each vuln from WhiteHat
        # for whitehat_vuln in findings_collection['collection']:
        #
        #     # Append DefectDojo findings to list
        #     dojo_findings.append(dojo_finding)

    def _convert_whitehat_severity_id_to_dojo_severity(
        self, whitehat_severity_id: int,
    ) -> str | None:
        """
        Converts a WhiteHat Sentinel numerical severity to a DefectDojo severity.

        Args:
            whitehat_severity_id: The WhiteHat Severity ID (called risk_id in the API)
        Returns: A DefectDojo severity if a mapping can be found; otherwise a null value is returned

        """
        severities = [
            "Informational",
            "Informational",
            "Low",
            "Medium",
            "High",
            "Critical",
            "Critical",
        ]

        try:
            return severities[int(whitehat_severity_id)]
        except IndexError:
            return None

    def _parse_cwe_from_tags(self, whitehat_sentinel_tags) -> str:
        """
        Some Vulns include the CWE ID as a tag. This is used to pull it out of that list and return only the ID.

        Args:
            whitehat_sentinel_tags: The Tags list from the WhiteHat vuln
        Returns: The first CWE ID in the list, if it exists

        """
        for tag in whitehat_sentinel_tags:
            if tag.startswith("CWE-"):
                return tag.split("-")[1]
        return None

    def _parse_description(self, whitehat_sentinel_description: dict):
        """
        Manually converts the HTML description to a DefectDojo-friendly format.

        Args:
            whitehat_sentinel_description: The description section of the WhiteHat Sentinel vulnerability dict
        Returns: A dict with description and reference link

        """
        description_ref = {"description": "", "reference_link": ""}

        # The references section is always between <h2> or <strong> tags
        reference_heading_regex = "<.+>References<.+>"

        description_chunks = re.split(
            reference_heading_regex,
            whitehat_sentinel_description["description"],
        )

        description = description_chunks[0]

        description_ref["description"] = self.__remove_paragraph_tags(
            description,
        )

        if len(description_chunks) > 1:
            description_ref["reference_link"] = self.__get_href_url(
                description_chunks[1],
            )

        return description_ref

    def _parse_solution(self, whitehat_sentinel_vuln_solution):
        """
        Manually converts the solution HTML to Markdown to avoid importing yet-another-library like Markdownify
        Args:
            whitehat_sentinel_vuln_solution:

        """
        solution_html = whitehat_sentinel_vuln_solution["solution"]

        solution_text = re.sub(r"<.+>", "", solution_html)

        solution_text = solution_text.split("References")[0]

        if whitehat_sentinel_vuln_solution.get("solution_prepend"):
            solution_text = (
                f"{solution_text}"
                f"\n {whitehat_sentinel_vuln_solution.get('solution_prepend')}"
            )

        return solution_text

    def __get_href_url(self, text_to_search):
        """
        Searches for the anchor targets within a string that includes an anchor tag.

        Args:
            text_to_search: The text string to search for an anchor tag
        Returns:

        """
        links = ""

        for match in re.findall(r'(<a href=")(https://\S+)">', text_to_search):
            links = f"{match[1]}\n{links}"
        return links

    def __remove_paragraph_tags(self, html_string):
        """
        Manually remove <p> tags from HTML strings to avoid importing yet-another-library.

        Args:
            html_string: The HMTL string to remove <p> </p> tags from
        Returns: The original string stipped of paragraph tags

        """
        return re.sub(r"<p>|</p>", "", html_string)

    def _convert_attack_vectors_to_endpoints(
        self, attack_vectors: list[dict],
    ) -> list["Endpoint"]:
        """
        Takes a list of Attack Vectors dictionaries from the WhiteHat vuln API and converts them to Defect Dojo
        Endpoints
        Args:
            attack_vectors: The list of Attack Vector dictionaries
        Returns: A list of Defect Dojo Endpoints
        """
        endpoints_list = []

        # This should be in the Endpoint class should it not?
        for attack_vector in attack_vectors:
            endpoints_list.append(
                Endpoint.from_uri(attack_vector["request"]["url"]),
            )

        return endpoints_list

    def _convert_whitehat_sentinel_vulns_to_dojo_finding(
        self, whitehat_sentinel_vulns: [dict], test: str,
    ):
        """
        Converts a WhiteHat Sentinel vuln to a DefectDojo finding

        Args:
            whitehat_sentinel_vulns: The vuln dictionary from WhiteHat Sentinel vuln API
            test: The test ID that the DefectDojo finding should be associated with
        Returns: A DefectDojo Finding object

        """
        dupes = {}

        for whitehat_vuln in whitehat_sentinel_vulns:
            date_created = whitehat_vuln["found"].split("T")[0]
            mitigated_ts = whitehat_vuln.get("closed", None)
            if mitigated_ts is not None:
                mitigated_ts = datetime.strptime(mitigated_ts, "%Y-%m-%dT%H:%M:%SZ")
            cwe = self._parse_cwe_from_tags(
                whitehat_vuln["attack_vectors"][0].get("scanner_tags", []),
            )
            description_ref = self._parse_description(
                whitehat_vuln["description"],
            )
            description = description_ref["description"]
            references = (
                f"https://source.whitehatsec.com/asset-management/site"
                f"-summary/{whitehat_vuln['site']}/findings/{whitehat_vuln['id']}"
                f"\n{description_ref['reference_link']}"
            )
            steps = whitehat_vuln["description"].get("description_prepend", "")
            solution = self._parse_solution(whitehat_vuln["solution"])
            risk_id = whitehat_vuln.get("custom_risk") or whitehat_vuln.get("risk")
            severity = self._convert_whitehat_severity_id_to_dojo_severity(
                risk_id,
            )
            false_positive = whitehat_vuln.get("status") == "invalid"

            active = whitehat_vuln.get("status") in ("open")
            is_mitigated = not active

            dupe_key = hashlib.md5(
                whitehat_vuln["id"].encode("utf-8"),
            ).hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                dupes[dupe_key] = finding

            else:
                dupes[dupe_key] = True

                finding = Finding(
                    title=whitehat_vuln["class"],
                    test=test,
                    cwe=cwe,
                    active=active,
                    verified=True,
                    description=description,
                    steps_to_reproduce=steps,
                    mitigation=solution,
                    references=references,
                    severity=severity,
                    false_p=false_positive,
                    date=date_created,
                    is_mitigated=is_mitigated,
                    mitigated=mitigated_ts,
                    last_reviewed=whitehat_vuln.get("lastRetested", None),
                    dynamic_finding=True,
                    created=date_created,
                    unique_id_from_tool=whitehat_vuln["id"],
                )

                # Get Endpoints from Attack Vectors
                endpoints = self._convert_attack_vectors_to_endpoints(
                    whitehat_vuln["attack_vectors"],
                )

                finding.unsaved_endpoints = endpoints
                dupes[dupe_key] = finding

        return list(dupes.values())
