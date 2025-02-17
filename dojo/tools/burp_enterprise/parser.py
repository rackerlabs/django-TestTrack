import logging
import re

from lxml import etree, html

from dojo.models import Endpoint, Finding
from dojo.utils import first_elem

logger = logging.getLogger(__name__)


class BurpEnterpriseParser:
    vulnerability_list_xpath = (
        "/html/body/div/div[contains(@class, 'section details')]/div[contains(@class, 'issue-container')]"
    )
    table_contents_xpath = "/html/body/div/div[contains(@class, 'section') and .//table[contains(@class, 'issue-table')]]"
    description_headers = ["issue detail", "issue description"]
    request_response_headers = ["request", "response"]
    impact_headers = ["issue background", "issue remediation"]
    mitigation_headers = ["remediation detail", "remediation background"]
    references_headers = ["vulnerability classifications", "references"]

    def get_scan_types(self):
        return ["Burp Enterprise Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Burp Enterprise Edition findings in HTML format"

    def get_findings(self, filename, test):
        tree = html.parse(filename)
        if tree:
            return self.get_items(tree, test)
        return ()

    def _get_endpoints_title_severity_mapping(self, tree: etree.ElementTree) -> dict[str, str]:
        """
        Construct a dict that contains mappings of endpoints and severities by a a title key.

        Example: {
            "finding-title": {
                "title": "finding-title",
                "severity: "Medium",
                "cwe": None,
                "endpoints: [
                    "http://127.0.0.1/path/A",
                    "http://127.0.0.1/path/B",
                ],
            }
        }
        """
        finding_mapping = {}
        table_contents = tree.xpath(self.table_contents_xpath)
        for table in table_contents:
            # There is only one header in this div, so we will get a string back here
            base_endpoint = table.xpath("h1")[0].text.replace("Issues found on ", "").removesuffix("/")
            # Iterate over the table of endpoint paths and severities
            title = None
            for entry in table.xpath("table[contains(@class, 'issue-table')]/tbody/tr"):
                # The etree.element with a class of "issue-type-row" is the title of the finding
                if "issue-type-row" in entry.classes:
                    # The structure of this section is consistent
                    # <tr class="issue-type-row"><td colspan="4">... [number-of-instances]</td></tr>
                    title = " ".join(entry.xpath("td")[0].text.strip().split(" ")[:-1])
                    # Add the finding title as a new entry if needed
                    if title not in finding_mapping:
                        finding_mapping[title] = {
                            "title": title,
                            "severity": None,
                            "cwe": None,
                            "endpoints": [],
                        }
                else:
                    # The structure of this section is consistent
                    # <td class="issue-path issue-link">...</td>
                    # <td>...</td>
                    # Quick check to determine if we need to move to the
                    path = entry.xpath("td")[0].text.strip()
                    severity = entry.xpath("td")[1].text.strip()
                    # Update the finding_mapping
                    finding_mapping[title]["endpoints"].append(f"{base_endpoint}/{path.removeprefix('/')}")
                    finding_mapping[title]["severity"] = severity

        return finding_mapping

    def _get_content(self, container: etree.Element):
        # quick exit in case container is not found
        s = ""
        if container is None or (isinstance(container, list) and len(list) == 0):
            return s
        # Do some extra processing as needed
        if (
            container.tag == "div"
            and container.text is not None
            and not container.text.isspace()
            and len(container.text) > 0
        ):
            s += re.sub(r"[ \t]+", " ", (
                "".join(container.itertext())
                .strip()
                .replace("Snip", "\n<-------------- Snip -------------->")
                .replace("\t", "")
            ))
        else:
            for elem in container.iterchildren():
                if elem.text is not None and elem.text.strip() != "":
                    stripped_text = elem.text.strip()
                    if elem.tag == "a":
                        value = "[" + stripped_text + "](" + elem.attrib["href"] + ")" + "\n"
                    elif elem.tag == "p":
                        value = elem.text_content().strip().replace("\n", "")
                    elif elem.tag == "b":
                        value = f"**{stripped_text}**"
                    elif elem.tag == "li":
                        value = "- "
                        if stripped_text is not None:
                            value += stripped_text + "\n"
                    elif stripped_text.isspace():
                        value = first_elem(elem.itertext())
                    elif elem.tag == "div" or elem.tag == "span":
                        value = elem.text_content().strip().replace("\n", "") + "\n"
                    else:
                        continue
                    s += re.sub(r"\s+", " ", value)
                else:
                    s += self._get_content(elem)
        return s

    def _format_bulleted_lists(self, finding_details: dict, div_element: etree.ElementTree) -> tuple[str, list[str]]:
        """Create a mapping of bulleted lists with links into a formatted list, as well as the raw values."""
        formatted_string = ""
        content_list = []
        for a_tag in div_element.xpath("ul/li/a"):
            content = re.sub(r"\s+", " ", a_tag.text.strip())
            link = a_tag.attrib["href"]
            formatted_string += f"- [{content}]({link})\n"
            content_list.append(content)

        return formatted_string, content_list

    def _set_or_append_content(self, finding_details: dict, header: str, div_element: etree.ElementTree) -> None:
        """Determine whether we should set or append content in a given place."""
        header = header.replace(":", "")
        field = None
        # description
        if header.lower() in self.description_headers:
            field = "description"
            content = self._get_content(div_element)
        elif header.lower() in self.impact_headers:
            field = "impact"
            content = self._get_content(div_element)
        elif header.lower() in self.mitigation_headers:
            field = "mitigation"
            content = self._get_content(div_element)
        elif header.lower() in self.references_headers:
            field = "references"
            content, data_list = self._format_bulleted_lists(finding_details, div_element)
            # process the vulnerability_ids if we have them
            if header.lower() == "vulnerability classifications":
                for item in data_list:
                    cleaned_item = item.split(":")[0]
                    if (
                        finding_details["cwe"] is None
                        and (cwe_search := re.search(r"CWE-([0-9]*)", cleaned_item, re.IGNORECASE))
                    ):
                        finding_details["cwe"] = int(cwe_search.group(1))
                    if "vulnerability_ids" not in finding_details:
                        finding_details["vulnerability_ids"] = [cleaned_item]
                    else:
                        finding_details["vulnerability_ids"].append(cleaned_item)
        elif header.lower() in self.request_response_headers:
            field = "request_response"
            content = self._get_content(div_element)
            if header.lower() == "request":
                if "requests" not in finding_details:
                    finding_details["requests"] = [content]
                else:
                    finding_details["requests"].append(content)
            if header.lower() == "response":
                if "responses" not in finding_details:
                    finding_details["responses"] = [content]
                else:
                    finding_details["responses"].append(content)
            return

        else:
            return

        formatted_content = f"**{header}**:\n{content}\n"
        if (existing_field := finding_details.get(field)) is not None:
            if header not in existing_field:
                finding_details[field] += f"{formatted_content}\n---\n"
        else:
            finding_details[field] = f"{formatted_content}\n---\n"

    def _parse_elements_by_h3_element(self, issue: etree.Element, finding_details: dict) -> None:
        for header_element in issue.xpath("h3"):
            if (div_element := header_element.getnext()) is not None and div_element.tag == "div":
                # Determine where to put the content
                self._set_or_append_content(finding_details, header_element.text.strip(), div_element)

    def get_items(self, tree: etree.ElementTree, test):
        finding_details = self._get_endpoints_title_severity_mapping(tree)
        for issue in tree.xpath(self.vulnerability_list_xpath):
            # Get the title of the current finding
            title = issue.xpath("h2")[0].text.strip()
            # Fetch the bodies of the issues and process them
            self._parse_elements_by_h3_element(issue, finding_details[title])
            # Accommodate a newer format where request/response pairs in a separate div
            for request_response_div in issue.xpath("div[contains(@class, 'evidence-container')]"):
                # Fetch the bodies of the issues and process them
                self._parse_elements_by_h3_element(request_response_div, finding_details[title])
            # Merge the requests and response into a single dict
            requests = finding_details[title].pop("requests", [])
            responses = finding_details[title].pop("responses", [])
            finding_details[title]["request_response_pairs"] = [
                {
                    "request": requests[i] if i < len(requests) else None,
                    "response": responses[i] if i < len(responses) else None,
                }
                for i in range(max(len(requests), len(responses)))
            ]

        return list(self.create_findings(finding_details, test))

    def create_findings(self, findings_dict: dict[str, dict], test):
        # Pop off a few items to be processes after the finding is saved
        findings = []
        for finding_dict in findings_dict.values():
            endpoints = finding_dict.pop("endpoints", [])
            request_response_pairs = finding_dict.pop("request_response_pairs", [])
            vulnerability_ids = finding_dict.pop("vulnerability_ids", [])
            # Crete the finding from the rest of the dict
            finding = Finding(
                test=test,
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                mitigated=None,
                static_finding=False,
                dynamic_finding=True,
                **finding_dict,
            )
            # Add the unsaved versions of the other things
            # Endpoints
            finding.unsaved_endpoints = [Endpoint.from_uri(endpoint) for endpoint in endpoints]
            # Request Response Pairs

            finding.unsaved_req_resp = [
                {"req": request_response.get("request"), "resp": request_response.get("response")}
                for request_response in request_response_pairs
            ]
            # Vulnerability IDs
            finding.unsaved_vulnerability_ids = vulnerability_ids
            # Add the finding to the final list
            findings.append(finding)

        return findings
