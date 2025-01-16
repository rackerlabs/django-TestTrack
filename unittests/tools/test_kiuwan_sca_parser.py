from dojo.models import Test
from dojo.tools.kiuwan_sca.parser import KiuwanSCAParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


# ./dc-unittest.sh --profile postgres-redis --test-case unittests.tools.test_kiuwan_sca_parser.TestKiuwanSCAParser
class TestKiuwanSCAParser(DojoTestCase):
    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("kiuwan_sca") / "kiuwan_sca_no_vuln.json", encoding="utf-8") as testfile:
            parser = KiuwanSCAParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_two_vuln_has_two_findings(self):
        with open(get_unit_tests_scans_path("kiuwan_sca") / "kiuwan_sca_two_vuln.json", encoding="utf-8") as testfile:
            parser = KiuwanSCAParser()
            findings = parser.get_findings(testfile, Test())
            # file contains 3, but we only get 2 as "muted" ones are ignored:
            self.assertEqual(2, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open(get_unit_tests_scans_path("kiuwan_sca") / "kiuwan_sca_many_vuln.json", encoding="utf-8") as testfile:
            parser = KiuwanSCAParser()
            findings = parser.get_findings(testfile, Test())
            # also tests deduplication as there are 28 findings in the file:
            self.assertEqual(27, len(findings))

    def test_correct_mapping(self):
        with open(get_unit_tests_scans_path("kiuwan_sca") / "kiuwan_sca_two_vuln.json", encoding="utf-8") as testfile:
            parser = KiuwanSCAParser()
            findings = parser.get_findings(testfile, Test())

            finding1 = findings[0]
            self.assertEqual(finding1.title, "org.apache.cxf:cxf-rt-ws-policy v3.3.5")
            self.assertEqual(finding1.cve, "CVE-2021-30468")
            self.assertEqual(finding1.severity, "High")
            self.assertEqual(finding1.component_name, "org.apache.cxf:cxf-rt-ws-policy")
            self.assertEqual(finding1.component_version, "3.3.5")
            self.assertEqual(finding1.cwe, 835)
            self.assertEqual(finding1.unique_id_from_tool, 158713)
            self.assertEqual(finding1.cvssv3_score, 7.5)
            self.assertEqual(finding1.epss_score, 0.1)
            self.assertEqual(finding1.epss_percentile, 0.2)
