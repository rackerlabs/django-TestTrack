from datetime import UTC, datetime

from dojo.models import Test
from dojo.tools.bugcrowd.parser import BugCrowdParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBugCrowdParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("bugcrowd") / "BugCrowd-zero.csv", encoding="utf-8") as testfile:
            parser = BugCrowdParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("bugcrowd") / "BugCrowd-one.csv", encoding="utf-8") as testfile:
            parser = BugCrowdParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            self.assertEqual(findings[0].date, datetime(2020, 3, 1, 6, 15, 6, tzinfo=UTC))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open(get_unit_tests_scans_path("bugcrowd") / "BugCrowd-many.csv", encoding="utf-8") as testfile:
            parser = BugCrowdParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(5, len(findings))
