import datetime

from dojo.models import Test
from dojo.tools.aws_prowler.parser import AWSProwlerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAwsProwlerParser(DojoTestCase):
    def setup(self, testfile):
        parser = AWSProwlerParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        return findings

    def test_aws_prowler_parser_with_no_vuln_has_no_findings(self):
        findings = self.setup(
            open(get_unit_tests_scans_path("aws_prowler") / "no_vuln.csv", encoding="utf-8"))
        self.assertEqual(0, len(findings))

    def test_aws_prowler_parser_with_critical_vuln_has_one_findings(self):
        findings = self.setup(
            open(get_unit_tests_scans_path("aws_prowler") / "one_vuln.csv", encoding="utf-8"))
        self.assertEqual(1, len(findings))
        self.assertEqual(
            "Root user in the account wasn't accessed in the last 1 days", findings[0].title,
        )

    def test_aws_prowler_parser_with_many_vuln_has_many_findings(self):
        findings = self.setup(
            open(get_unit_tests_scans_path("aws_prowler") / "many_vuln.csv", encoding="utf-8"))
        self.assertEqual(4, len(findings))
        self.assertEqual(
            "Root user in the account wasn't accessed in the last 1 days", findings[0].title)
        self.assertEqual("High", findings[0].severity)
        self.assertEqual(
            "User example_user has never used access key 1 since creation and not rotated it in the past 90 days", findings[1].title)
        self.assertEqual("Medium", findings[1].severity)
        self.assertEqual("Password Policy has weak reuse requirement (lower than 24)", findings[2].title)
        self.assertEqual("Medium", findings[2].severity)
        self.assertEqual("eu-west-2: sg-01234567890qwerty is not being used!", findings[3].title)
        self.assertEqual("Low", findings[3].severity)

    def test_aws_prowler_parser_with_many_vuln_has_many_findings2(self):
        findings = self.setup(
            open(get_unit_tests_scans_path("aws_prowler") / "many_vuln2.csv", encoding="utf-8"))
        self.assertEqual(174, len(findings))
        self.assertEqual("Root user in the account wasn't accessed in the last 1 days", findings[0].title)
        self.assertEqual("Info", findings[0].severity)
        self.assertEqual(
            "User example has never used access key 1 since creation and not rotated it in the past 90 days", findings[4].title)
        self.assertEqual("Medium", findings[6].severity)

    def test_aws_prowler_parser_issue4450(self):
        findings = self.setup(
            open(get_unit_tests_scans_path("aws_prowler") / "issue4450.csv", encoding="utf-8"))
        self.assertEqual(4, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertFalse(finding.active)
            self.assertEqual(
                "Root user in the account wasn't accessed in the last 1 days", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(1032, finding.cwe)
        with self.subTest(i=1):
            finding = findings[1]
            self.assertTrue(finding.active)
            self.assertEqual(
                "User ansible-test-user has Password enabled but MFA disabled", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1032, finding.cwe)
            self.assertEqual(1, finding.nb_occurences)

    def test_aws_prowler_parser_with_no_vuln_has_no_findings_json(self):
        findings = self.setup(
            open(get_unit_tests_scans_path("aws_prowler") / "no_vuln.json", encoding="utf-8"))
        self.assertEqual(0, len(findings))

    def test_aws_prowler_parser_with_critical_vuln_has_one_findings_json(self):
        findings = self.setup(
            open(get_unit_tests_scans_path("aws_prowler") / "one_vuln.json", encoding="utf-8"))
        self.assertEqual(1, len(findings))
        self.assertEqual("eu-central-1: Only Virtual MFA is enabled for root", findings[0].title)
        self.assertIn("012345678912", findings[0].description)
        self.assertIn("Ensure hardware MFA is enabled for the root account", findings[0].description)
        self.assertIn("check114", findings[0].description)
        self.assertIn("1.14", findings[0].description)
        self.assertIn("eu-central-1", findings[0].description)
        self.assertIn("Software and Configuration Checks", findings[0].description)
        self.assertIn("iam", findings[0].description)
        self.assertIn("IAM", findings[0].description)
        self.assertIn("MFA", findings[0].description)
        self.assertEqual("Critical", findings[0].severity)
        self.assertIn("The root account is the most privileged user in an AWS account. MFA adds an extra layer", findings[0].impact)
        self.assertEqual("Using IAM console navigate to Dashboard and expand Activate MFA on your root account.", findings[0].mitigation)
        self.assertEqual("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa", findings[0].references)
        self.assertEqual(datetime.date(2021, 8, 23), findings[0].date)

    def test_aws_prowler_parser_with_many_vuln_has_many_findings_json(self):
        findings = self.setup(
            open(get_unit_tests_scans_path("aws_prowler") / "many_vuln.json", encoding="utf-8"))
        self.assertEqual(4, len(findings))
        with self.subTest(i=0):
            self.assertEqual("eu-central-1: Only Virtual MFA is enabled for root", findings[0].title)
            self.assertEqual("Critical", findings[0].severity)
        with self.subTest(i=1):
            self.assertEqual("eu-central-1: Cluster control plane access is not restricted for EKS cluster prod", findings[1].title)
            self.assertEqual("High", findings[1].severity)
        with self.subTest(i=2):
            self.assertEqual("eu-central-1: Control plane logging is not enabled for EKS cluster prod", findings[2].title)
            self.assertEqual("Medium", findings[2].severity)
        with self.subTest(i=3):
            self.assertEqual("eu-central-1: prod.config_read.iam has inline policy directly attached", findings[3].title)
            self.assertEqual("Low", findings[3].severity)
