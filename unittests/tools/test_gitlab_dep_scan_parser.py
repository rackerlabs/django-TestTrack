from dojo.models import Test
from dojo.tools.gitlab_dep_scan.parser import GitlabDepScanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGitlabDepScanParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path() / "/gitlab_dep_scan/gl-dependency-scanning-report-0-vuln.json", encoding="utf-8") as testfile:
            parser = GitlabDepScanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding_v14(self):
        with open(get_unit_tests_scans_path() / "/gitlab_dep_scan/gl-dependency-scanning-report-1-vuln_v14.json", encoding="utf-8") as testfile:
            parser = GitlabDepScanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding_v15(self):
        with open(get_unit_tests_scans_path() / "/gitlab_dep_scan/gl-dependency-scanning-report-1-vuln_v15.json", encoding="utf-8") as testfile:
            parser = GitlabDepScanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_two_vuln_has_one_missing_component__v14(self):
        with open(get_unit_tests_scans_path() / "/gitlab_dep_scan/gl-dependency-scanning-report-2-vuln-missing-component_v14.json", encoding="utf-8") as testfile:
            parser = GitlabDepScanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            finding = findings[0]
            self.assertEqual(None, finding.component_name)
            self.assertEqual(None, finding.component_version)
            finding = findings[1]
            self.assertEqual("golang.org/x/crypto", finding.component_name)
            self.assertEqual("v0.0.0-20190308221718-c2843e01d9a2", finding.component_version)

    def test_parse_file_with_two_vuln_has_one_missing_component__v15(self):
        with open(get_unit_tests_scans_path() / "/gitlab_dep_scan/gl-dependency-scanning-report-2-vuln-missing-component_v15.json", encoding="utf-8") as testfile:
            parser = GitlabDepScanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            finding = findings[0]
            self.assertEqual(None, finding.component_name)
            self.assertEqual(None, finding.component_version)
            finding = findings[1]
            self.assertEqual("golang.org/x/crypto", finding.component_name)
            self.assertEqual("v0.0.0-20190308221718-c2843e01d9a2", finding.component_version)

    def test_parse_file_with_multiple_vuln_has_multiple_findings_v14(self):
        with open(get_unit_tests_scans_path() / "/gitlab_dep_scan/gl-dependency-scanning-report-many-vuln_v14.json", encoding="utf-8") as testfile:
            parser = GitlabDepScanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertGreater(len(findings), 2)

            self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2020-29652", findings[0].unsaved_vulnerability_ids[0])

    def test_parse_file_with_multiple_vuln_has_multiple_findings_v15(self):
        with open(get_unit_tests_scans_path() / "/gitlab_dep_scan/gl-dependency-scanning-report-many-vuln_v15.json", encoding="utf-8") as testfile:
            parser = GitlabDepScanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertGreater(len(findings), 2)

            self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2020-29652", findings[0].unsaved_vulnerability_ids[0])
