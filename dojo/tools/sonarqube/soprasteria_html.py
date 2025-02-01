import logging

from dojo.tools.sonarqube.soprasteria_helper import SonarQubeSoprasteriaHelper
from dojo.utils import first_elem

logger = logging.getLogger(__name__)


class SonarQubeSoprasteriaHTML:
    def get_items(self, tree, test, mode):
        # Check that there is at least one vulnerability (the vulnerabilities
        # table is absent when no vuln are found)
        detailTbody = tree.xpath(
            "/html/body/div[contains(@class,'detail')]/table/tbody",
        )
        dupes = {}
        if len(detailTbody) == 2:
            # First is "Detail of the Detected Vulnerabilities" (not present if no vuln)
            # Second is "Known Security Rules"
            vulnerabilities_table = list(detailTbody[0].iter("tr"))
            rules_table = list(detailTbody[1].xpath("tr"))

            # iterate over the rules once to get the information we need
            rulesDic = {}
            for rule in rules_table:
                rule_properties = list(rule.iter("td"))
                rule_name = first_elem(rule_properties[0].iter("a")).text.strip()
                rule_details = first_elem(rule_properties[1].iter("details"))
                rulesDic[rule_name] = rule_details

            for vuln in vulnerabilities_table:
                vuln_properties = list(vuln.iter("td"))
                rule_key = first_elem(vuln_properties[0].iter("a")).text
                vuln_rule_name = rule_key and rule_key.strip()
                vuln_severity = SonarQubeSoprasteriaHelper().convert_sonar_severity(
                    vuln_properties[1].text and vuln_properties[1].text.strip(),
                )
                vuln_file_path = vuln_properties[2].text and vuln_properties[2].text.strip()
                vuln_line = vuln_properties[3].text and vuln_properties[3].text.strip()
                vuln_title = vuln_properties[4].text and vuln_properties[4].text.strip()
                vuln_mitigation = vuln_properties[5].text and vuln_properties[5].text.strip()
                vuln_key = vuln_properties[6].text and vuln_properties[6].text.strip()
                if vuln_title is None or vuln_mitigation is None:
                    raise ValueError(
                        "Parser ValueError: can't find a title or a mitigation for vulnerability of name "
                        + vuln_rule_name,
                    )
                try:
                    vuln_details = rulesDic[vuln_rule_name]
                    vuln_description = SonarQubeSoprasteriaHelper().get_description(vuln_details)
                    vuln_references = SonarQubeSoprasteriaHelper().get_references(
                        vuln_rule_name, vuln_details,
                    )
                    vuln_cwe = SonarQubeSoprasteriaHelper().get_cwe(vuln_references)
                except KeyError:
                    vuln_description = "No description provided"
                    vuln_references = ""
                    vuln_cwe = 0
                if mode is None:
                    SonarQubeSoprasteriaHelper().process_result_file_name_aggregated(
                        test,
                        dupes,
                        vuln_title,
                        vuln_cwe,
                        vuln_description,
                        vuln_file_path,
                        vuln_line,
                        vuln_severity,
                        vuln_mitigation,
                        vuln_references,
                    )
                else:
                    SonarQubeSoprasteriaHelper().process_result_detailed(
                        test,
                        dupes,
                        vuln_title,
                        vuln_cwe,
                        vuln_description,
                        vuln_file_path,
                        vuln_line,
                        vuln_severity,
                        vuln_mitigation,
                        vuln_references,
                        vuln_key,
                    )
        return list(dupes.values())
