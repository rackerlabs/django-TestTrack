import json

from dojo.tools.awssecurityhub.compliance import Compliance
from dojo.tools.awssecurityhub.guardduty import GuardDuty
from dojo.tools.awssecurityhub.inspector import Inspector
from dojo.tools.parser_test import ParserTest


class AwsSecurityHubParser:
    ID = "AWS Security Hub"

    def get_scan_types(self):
        return ["AWS Security Hub Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Security Hub Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AWS Security Hub exports in JSON format."

    def get_tests(self, scan_type, scan):
        data = json.load(scan)
        findings = data.get("Findings", data.get("findings", None))
        if not isinstance(findings, list):
            msg = "Incorrect Security Hub report format"
            raise TypeError(msg)
        prod = []
        aws_acc = []
        for finding in findings:
            prod.append(finding.get("ProductName", "AWS Security Hub Ruleset"))
            aws_acc.append(finding.get("AwsAccountId", "No Account Found"))
        report_date = data.get("createdAt")
        test = ParserTest(
            name=self.ID, parser_type=self.ID, version="",
        )
        test.description = "**AWS Accounts:** " + ", ".join(set(aws_acc)) + "\n"
        test.description += "**Finding Origins:** " + ", ".join(set(prod)) + "\n"
        test.findings = self.get_items(data, report_date)
        return [test]

    def get_findings(self, filehandle, test):
        tree = json.load(filehandle)
        if not isinstance(tree, dict):
            msg = "Incorrect Security Hub report format"
            raise TypeError(msg)
        return self.get_items(tree, test)

    def get_items(self, tree: dict, test):
        items = {}
        findings = tree.get("Findings", tree.get("findings"))
        if not isinstance(findings, list):
            msg = "Incorrect Security Hub report format"
            raise TypeError(msg)
        for node in findings:
            aws_scanner_type = node.get("ProductFields", {}).get("aws/securityhub/ProductName", "")
            if aws_scanner_type == "Inspector":
                item = Inspector().get_item(node, test)
            elif aws_scanner_type == "GuardDuty":
                item = GuardDuty().get_item(node, test)
            else:
                item = Compliance().get_item(node, test)
            key = node["Id"]
            if not isinstance(key, str):
                msg = "Incorrect Security Hub report format"
                raise TypeError(msg)
            items[key] = item
        return list(items.values())
