from dojo.models import Test
from dojo.tools.twistlock.parser import TwistlockParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTwistlockParser(DojoTestCase):
    def test_parse_file_with_no_vuln(self):
        testfile = open(get_unit_tests_scans_path() / "twistlock/no_vuln.json", encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln(self):
        testfile = open(get_unit_tests_scans_path() / "twistlock/one_vuln.json", encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
        self.assertEqual("CVE-2013-7459", findings[0].unsaved_vulnerability_ids[0])

    def test_parse_file_with_no_link(self):
        testfile = open(get_unit_tests_scans_path() / "twistlock/one_vuln_no_link.json", encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
        self.assertEqual("PRISMA-2021-0013", findings[0].unsaved_vulnerability_ids[0])

    def test_parse_file_with_many_vulns(self):
        testfile = open(get_unit_tests_scans_path() / "twistlock/many_vulns.json", encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(5, len(findings))

    def test_parse_file_which_contain_packages_info(self):
        testfile = open(get_unit_tests_scans_path() / "twistlock/findings_include_packages.json", encoding="utf-8")
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))

    def test_parse_file_prisma_twistlock_images_no_vuln(self):
        testfile = open(
            get_unit_tests_scans_path() / "twistlock/scan_report_prisma_twistlock_images_no_vuln.csv", encoding="utf-8",
        )
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_prisma_twistlock_images_four_vulns(self):
        testfile = open(
            get_unit_tests_scans_path() / "twistlock/scan_report_prisma_twistlock_images_four_vulns.csv", encoding="utf-8",
        )
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))
        self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-24977", findings[0].unsaved_vulnerability_ids[0])

    def test_parse_file_prisma_twistlock_images_long_package_name(self):
        testfile = open(
            get_unit_tests_scans_path() / "twistlock/scan_report_prisma_twistlock_images_long_package_name.csv",
            encoding="utf-8",
        )
        parser = TwistlockParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
