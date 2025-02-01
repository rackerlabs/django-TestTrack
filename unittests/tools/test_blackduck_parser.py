
from dojo.models import Test
from dojo.tools.blackduck.parser import BlackduckParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBlackduckHubParser(DojoTestCase):
    def test_blackduck_csv_parser_has_no_finding(self):
        testfile = get_unit_tests_scans_path("blackduck") / "no_vuln.csv"
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_blackduck_csv_parser_has_one_finding(self):
        testfile = get_unit_tests_scans_path("blackduck") / "one_vuln.csv"
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_blackduck_csv_parser_has_many_findings(self):
        testfile = get_unit_tests_scans_path("blackduck") / "many_vulns.csv"
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(24, len(findings))
        self.assertEqual(1, len(findings[10].unsaved_vulnerability_ids))
        self.assertEqual("CVE-2007-3386", findings[10].unsaved_vulnerability_ids[0])
        self.assertEqual(findings[4].component_name, "Apache Tomcat")
        self.assertEqual(findings[2].component_name, "Apache HttpComponents Client")
        self.assertEqual(findings[4].component_version, "5.5.23")
        self.assertEqual(findings[2].component_version, "4.5.2")

    def test_blackduck_csv_parser_new_format_has_many_findings(self):
        testfile = get_unit_tests_scans_path("blackduck") / "many_vulns_new_format.csv"
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(9, len(findings))
        self.assertEqual(findings[0].component_name, "kryo")
        self.assertEqual(findings[2].component_name, "jackson-databind")
        self.assertEqual(findings[0].component_version, "3.0.3")
        self.assertEqual(findings[2].component_version, "2.9.9.3")

    def test_blackduck_enhanced_has_many_findings(self):
        testfile = get_unit_tests_scans_path("blackduck") / "blackduck_enhanced_py3_unittest.zip"
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(11, len(findings))

    def test_blackduck_enhanced_zip_upload(self):
        testfile = get_unit_tests_scans_path("blackduck") / "blackduck_enhanced_py3_unittest_v2.zip"
        parser = BlackduckParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(11, len(findings))
