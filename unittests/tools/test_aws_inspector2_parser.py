from django.test import TestCase

from dojo.models import Test
from dojo.tools.aws_inspector2.parser import AWSInspector2Parser
from unittests.dojo_test_case import get_unit_tests_scans_path


class TestAWSInspector2Parser(TestCase):

    def test_aws_inspector2_parser_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("aws_inspector2") / "aws_inspector2_zero_vul.json", encoding="utf-8") as testfile:
            parser = AWSInspector2Parser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(0, len(findings))

    def test_aws_inspector2_parser_with_one_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("aws_inspector2") / "aws_inspector2_one_vul.json", encoding="utf-8") as testfile:
            parser = AWSInspector2Parser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            self.assertEqual("CVE-2021-3744 - linux", findings[0].title)
            self.assertEqual("Medium", findings[0].severity)

    def test_aws_inspector2_parser_with_many_vuln_has_many_findings(self):
        with open(get_unit_tests_scans_path("aws_inspector2") / "aws_inspector2_many_vul.json", encoding="utf-8") as testfile:
            parser = AWSInspector2Parser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(8, len(findings))

    def test_aws_inspector2_parser_empty_with_error(self):
        with self.assertRaises(TypeError) as context, \
          open(get_unit_tests_scans_path("aws_inspector2") / "empty_with_error.json", encoding="utf-8") as testfile:
            parser = AWSInspector2Parser()
            parser.get_findings(testfile, Test())
            testfile.close()
            self.assertTrue(
                "Incorrect Inspector2 report format" in str(context.exception),
            )
