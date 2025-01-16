from datetime import datetime

from dojo.models import Test
from dojo.tools.gitlab_secret_detection_report.parser import (
    GitlabSecretDetectionReportParser,
)
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGitlabSecretDetectionReportParser(DojoTestCase):
    def test_gitlab_secret_detection_report_parser_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path() / "/gitlab_secret_detection_report/gitlab_secret_detection_report_0_vuln.json", encoding="utf-8") as testfile:
            parser = GitlabSecretDetectionReportParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_gitlab_secret_detection_report_parser_with_one_vuln_has_one_findings_v14(
        self,
    ):
        with open(get_unit_tests_scans_path() / "/gitlab_secret_detection_report/gitlab_secret_detection_report_1_vuln_v14.json", encoding="utf-8") as testfile:
            parser = GitlabSecretDetectionReportParser()
            findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        first_finding = findings[0]
        self.assertEqual(1, len(findings))
        self.assertEqual(datetime(2021, 6, 2, 9, 13, 9), first_finding.date)
        self.assertEqual(5, first_finding.line)
        self.assertEqual("Critical", first_finding.severity)
        self.assertEqual("README.md", first_finding.file_path)
        self.assertEqual("AWS\nAKIAIOSFODNN7EXAMPLE", first_finding.description)
        self.assertEqual(
            "714ed3e4e289ad35a089e0a888e8d0120b6a6083b1090a189cbc6a3227396240",
            first_finding.unique_id_from_tool,
        )

    def test_gitlab_secret_detection_report_parser_with_one_vuln_has_one_findings_v15(
        self,
    ):
        with open(get_unit_tests_scans_path() / "/gitlab_secret_detection_report/gitlab_secret_detection_report_1_vuln_v15.json", encoding="utf-8") as testfile:
            parser = GitlabSecretDetectionReportParser()
            findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        first_finding = findings[0]
        self.assertEqual(1, len(findings))
        self.assertEqual(datetime(2021, 6, 2, 9, 13, 9), first_finding.date)
        self.assertEqual(5, first_finding.line)
        self.assertEqual("Critical", first_finding.severity)
        self.assertEqual("README.md", first_finding.file_path)
        self.assertEqual("AWS\nAKIAIOSFODNN7EXAMPLE", first_finding.description)
        self.assertEqual(
            "714ed3e4e289ad35a089e0a888e8d0120b6a6083b1090a189cbc6a3227396240",
            first_finding.unique_id_from_tool,
        )

    def test_gitlab_secret_detection_report_parser_with_many_vuln_has_many_findings_v14(
        self,
    ):
        with open(get_unit_tests_scans_path() / "/gitlab_secret_detection_report/gitlab_secret_detection_report_3_vuln_v14.json", encoding="utf-8") as testfile:
            parser = GitlabSecretDetectionReportParser()
            findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(3, len(findings))

    def test_gitlab_secret_detection_report_parser_with_many_vuln_has_many_findings_v15(
        self,
    ):
        with open(get_unit_tests_scans_path() / "/gitlab_secret_detection_report/gitlab_secret_detection_report_3_vuln_v15.json", encoding="utf-8") as testfile:
            parser = GitlabSecretDetectionReportParser()
            findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(3, len(findings))
