from dojo.models import Test
from dojo.tools.sonatype.parser import SonatypeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSonatypeParser(DojoTestCase):
    def test_parse_file_with_two_vulns(self):
        testfile = open(get_unit_tests_scans_path("sonatype") / "two_vulns.json", encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))
        self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
        self.assertEqual("CVE-2016-2402", findings[0].unsaved_vulnerability_ids[0])

    def test_parse_file_with_many_vulns(self):
        testfile = open(get_unit_tests_scans_path("sonatype") / "many_vulns.json", encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))

    def test_parse_file_with_long_file_path(self):
        testfile = open(get_unit_tests_scans_path("sonatype") / "long_file_path.json", encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(findings))

    def test_find_no_vuln(self):
        testfile = open(get_unit_tests_scans_path("sonatype") / "no_vuln.json", encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_component_parsed_correctly(self):
        testfile = open(get_unit_tests_scans_path("sonatype") / "many_vulns.json", encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual("sonatype-2023-4856 - okhttp com.squareup.okhttp 2.6.0", findings[5].title)
        self.assertEqual("okhttp", findings[5].component_name)
        self.assertEqual("2.6.0", findings[5].component_version)

    def test_severity_parsed_correctly(self):
        testfile = open(get_unit_tests_scans_path("sonatype") / "many_vulns.json", encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual("Medium", findings[0].severity)
        self.assertEqual("High", findings[1].severity)
        self.assertEqual("High", findings[2].severity)
        self.assertEqual("Medium", findings[3].severity)
        self.assertEqual("Medium", findings[4].severity)
        self.assertEqual("Medium", findings[5].severity)

    def test_cwe_parsed_correctly(self):
        testfile = open(get_unit_tests_scans_path("sonatype") / "many_vulns.json", encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual("693", findings[5].cwe)

    def test_cvssv3_parsed_correctly(self):
        testfile = open(get_unit_tests_scans_path("sonatype") / "many_vulns.json", encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N", findings[5].cvssv3)

    def test_filepath_parsed_correctly(self):
        testfile = open(get_unit_tests_scans_path("sonatype") / "many_vulns.json", encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual("WEB-INF/lib/okhttp-2.6.0.jar", findings[5].file_path)
