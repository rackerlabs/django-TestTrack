from dojo.models import Test
from dojo.tools.mend.parser import MendParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestMendParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("mend") / "okhttp_no_vuln.json", encoding="utf-8") as testfile:
            parser = MendParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("mend") / "okhttp_one_vuln.json", encoding="utf-8") as testfile:
            parser = MendParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = list(findings)[0]
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2019-9658", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", finding.cvssv3)
            self.assertEqual(5.3, finding.cvssv3_score)

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open(get_unit_tests_scans_path("mend") / "okhttp_many_vuln.json", encoding="utf-8") as testfile:
            parser = MendParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(6, len(findings))

    def test_parse_file_with_multiple_vuln_cli_output(self):
        with open(
            get_unit_tests_scans_path("mend") / "cli_generated_many_vulns.json", encoding="utf-8",
        ) as testfile:
            parser = MendParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(20, len(findings))

    def test_parse_file_with_one_sca_vuln_finding(self):
        with open(get_unit_tests_scans_path("mend") / "mend_sca_vuln.json", encoding="utf-8") as testfile:
            parser = MendParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = list(findings)[0]
            self.assertEqual("D:\\MendRepo\\test-product\\test-project\\test-project-subcomponent\\path\\to\\the\\Java\\commons-codec-1.6_donotuse.jar", finding.file_path)

    def test_parse_file_with_no_vuln_has_no_findings_platform(self):
        with open(get_unit_tests_scans_path("mend") / "mend-sca-platform-api3-no-findings.json", encoding="utf-8") as testfile:
            parser = MendParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings_platform(self):
        with open(get_unit_tests_scans_path("mend") / "mend-sca-platform-api3-one-finding.json", encoding="utf-8") as testfile:
            parser = MendParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = list(findings)[0]
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2024-51744", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", finding.cvssv3)
            self.assertEqual(3.1, finding.cvssv3_score)

    def test_parse_file_with_multiple_vuln_has_multiple_finding_platform(self):
        with open(get_unit_tests_scans_path("mend") / "mend-sca-platform-api3-eleven-findings.json", encoding="utf-8") as testfile:
            parser = MendParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(11, len(findings))
