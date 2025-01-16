import json
from datetime import datetime

from dojo.models import Endpoint, Test
from dojo.tools.asff.parser import AsffParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def sample_path(file_name):
    return get_unit_tests_scans_path("asff") / file_name


class TestAsffParser(DojoTestCase):
    def load_sample_json(self, file_name):
        with open(sample_path(file_name), encoding="utf-8") as file:
            return json.load(file)

    def common_check_finding(self, finding, data, index, guarddutydate=False):
        parser = AsffParser()
        resource_arns = parser.get_item_resource_arns(data[index])
        resource_arn_strings = ", ".join(resource_arns)
        control_description = data[index].get("Description", "")
        full_description = f"**AWS resource ARN:** {resource_arn_strings}\n\n{control_description}"
        self.assertEqual(finding.title, data[index]["Title"])
        self.assertEqual(finding.description, full_description)
        if guarddutydate:
            self.assertEqual(finding.date.date(),
                datetime.strptime(data[0]["CreatedAt"], "%Y-%m-%dT%H:%M:%S.%fZ").date())
        else:
            self.assertEqual(finding.date.date(),
                datetime.strptime(data[0]["CreatedAt"], "%Y-%m-%dT%H:%M:%SZ").date())
        self.assertEqual(finding.severity.lower(), data[index]["Severity"]["Label"].lower())
        self.assertTrue(finding.active)
        expected_ipv4s = data[0]["Resources"][0]["Details"]["AwsEc2Instance"][
            "IpV4Addresses"
        ]
        for endpoint in finding.unsaved_endpoints:
            self.assertIn(str(endpoint), expected_ipv4s)
            endpoint.clean()

    def test_asff_one_vuln(self):
        data = self.load_sample_json("one_vuln.json")
        with open(sample_path("one_vuln.json"), encoding="utf-8") as file:
            parser = AsffParser()
            findings = parser.get_findings(file, Test())
            self.assertEqual(1, len(findings))
            self.common_check_finding(findings[0], data, 0)

    def test_asff_many_vulns(self):
        data = self.load_sample_json("many_vulns.json")
        with open(sample_path("many_vulns.json"), encoding="utf-8") as file:
            parser = AsffParser()
            findings = parser.get_findings(file, Test())
            self.assertEqual(len(findings), 5)
            for index, finding in enumerate(findings):
                self.common_check_finding(finding, data, index)

    def test_asff_guardduty(self):
        data = self.load_sample_json("guardduty/Unusual Behaviors-User-Persistence IAMUser-NetworkPermissions.json")
        with open(sample_path("guardduty/Unusual Behaviors-User-Persistence IAMUser-NetworkPermissions.json"), encoding="utf-8") as file:
            parser = AsffParser()
            findings = parser.get_findings(file, Test())
            self.assertEqual(len(findings), 1)
            for index, finding in enumerate(findings):
                self.common_check_finding(finding, data, index, guarddutydate=True)
            self.assertEqual(finding.unsaved_endpoints[0], Endpoint(host="10.0.0.1"))
            self.assertTrue(finding.active)
