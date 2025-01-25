import json
import textwrap
from datetime import datetime

from dojo.models import Finding
from dojo.tools.parser_test import ParserTest


class ScoutSuiteParser:

    """"ScoutSuite Wiki: https://github.com/nccgroup/ScoutSuite/wiki"""

    ID = "Scout Suite"

    item_data = ""
    pdepth = 0

    def get_scan_types(self):
        return [f"{self.ID} Scan"]

    def get_label_for_scan_types(self, scan_type):
        return f"{self.ID} Scan"  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "JS file in scoutsuite-results/scoutsuite_results_*.js."

    def get_tests(self, scan_type, handle):
        content = handle.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        raw_data = content.replace("scoutsuite_results =", "")
        data = json.loads(raw_data)

        account_id = data["account_id"]
        last_run = data["last_run"]

        test_description = ""
        test_description = f"{test_description}**Account:** `{account_id}`\n"
        test_description = "{}**Provider:** {}\n".format(
            test_description,
            data["provider_name"],
        )
        test_description = "{}**Ruleset:** `{}`\n".format(
            test_description,
            last_run["ruleset_name"],
        )
        test_description = "{}**Ruleset Description:** {}\n".format(
            test_description,
            last_run["ruleset_about"],
        )

        # Summary of Services
        test_description = (
            f"{test_description}\n\n Services | Checked Items | Flagged Items | Max Level | Resource Count | Rules Count"
        )
        test_description = f"{test_description}\n:---|---:|---:|---:|---:|---:"
        for service, items in list(last_run["summary"].items()):
            test_description += "\n"
            test_description += "|".join(
                [
                    service,
                    str(items["checked_items"]),
                    str(items["flagged_items"]),
                    str(items["max_level"]),
                    str(items["resources_count"]),
                    str(items["rules_count"]),
                ],
            )

        tests = []
        test = ParserTest(
            name=self.ID,
            parser_type=data["provider_name"],
            version=last_run.get("version"),
        )
        test.description = test_description

        test.findings = self.__get_items(data)
        tests.append(test)
        return tests

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        raw_data = content.replace("scoutsuite_results =", "")
        data = json.loads(raw_data)
        return self.__get_items(data)

    def __get_items(self, data):
        findings = []
        # get the date of the run
        last_run_date = None
        if "time" in data.get("last_run", {}):
            last_run_date = datetime.strptime(
                data["last_run"]["time"][0:10], "%Y-%m-%d",
            ).date()

        # Configured Services
        for service_name in data["services"]:
            service_item = data["services"][service_name]
            for finding_name in service_item.get("findings", []):
                finding = service_item["findings"][finding_name]
                for name in finding.get("items", []):
                    description_text = (
                        finding.get("rationale", "")
                        + "\n**Location:** "
                        + name
                        + "\n\n---\n"
                    )
                    key = name.split(".")
                    i = 1
                    lookup = service_item
                    while i < len(key):
                        if key[i] in lookup:
                            if isinstance(lookup[key[i]], dict):
                                lookup = lookup[key[i]]
                                if (
                                    key[i - 1] == "security_groups"
                                    or key[i - 1] == "PolicyDocument"
                                ):
                                    break
                        i = i + 1

                    self.recursive_print(lookup)
                    description_text = description_text + self.item_data
                    self.item_data = ""

                    find = Finding(
                        title=textwrap.shorten(finding["description"], 150),
                        date=last_run_date,
                        cwe=1032,  # Security Configuration Weaknesses, would like to fine tune
                        description=description_text,
                        severity=self.getCriticalityRating(finding["level"]),
                        mitigation=finding.get("remediation"),
                        file_path=name,
                        # we use file_path as a hack as there is no notion of
                        # "service" in finding today
                        dynamic_finding=False,
                        static_finding=True,
                        vuln_id_from_tool=":".join(
                            [data["provider_code"], finding_name],
                        ),
                    )
                    if finding.get("references"):
                        find.references = "\n".join(finding["references"])
                    findings.append(find)

        return findings

    def formatview(self, depth):
        if depth > 1:
            return "* "
        return ""

    def recursive_print(self, src, depth=0, key=""):
        def tabs(n):
            return " " * n * 2
        if isinstance(src, dict):
            for key, value in src.items():
                if isinstance(src, str):
                    self.item_data = self.item_data + key + "\n"
                self.recursive_print(value, depth + 1, key)
        elif isinstance(src, list):
            for litem in src:
                self.recursive_print(litem, depth + 2)
        else:
            if self.pdepth != depth:
                self.item_data = self.item_data + "\n"
            if key:
                self.item_data = (
                    self.item_data
                    + self.formatview(depth)
                    + f"**{key.title()}:** {src}\n\n"
                )
            else:
                self.item_data = (
                    self.item_data + self.formatview(depth) + f"{src}\n"
                )
            self.pdepth = depth

    # Criticality rating
    def getCriticalityRating(self, rating):
        criticality = "Info"
        if rating == "warning":
            criticality = "Medium"
        elif rating == "danger":
            criticality = "Critical"

        return criticality
