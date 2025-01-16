from dojo.models import Test
from dojo.tools.solar_appscreener.parser import SolarAppscreenerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSolarAppscreenerParser(DojoTestCase):

    def test_solar_appscreener_parser_with_no_vuln_has_no_findings(self):
        testfile = open(
            get_unit_tests_scans_path("solar_appscreener") / "solar_appscreener_zero_vul.csv", encoding="utf-8")
        parser = SolarAppscreenerParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_solar_appscreener_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open(
            get_unit_tests_scans_path("solar_appscreener") / "solar_appscreener_one_vul.csv", encoding="utf-8")
        parser = SolarAppscreenerParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        finding = findings[0]
        self.assertEqual(1, len(findings))
        self.assertEqual("Hardcoded password", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("misc/shared.php", finding.file_path)
        self.assertEqual(151, finding.line)
        self.assertEqual("misc/shared.php", finding.sast_source_file_path)
        self.assertEqual(151, finding.sast_source_line)

    def test_solar_appscreener_parser_with_many_vuln_has_many_findings(self):
        testfile = open(
            get_unit_tests_scans_path("solar_appscreener") / "solar_appscreener_many_vul.csv", encoding="utf-8")
        parser = SolarAppscreenerParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        finding = findings[0]
        self.assertEqual(3, len(findings))
        self.assertEqual("Hardcoded password", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("misc/shared.php", finding.file_path)
        self.assertEqual(151, finding.line)
        self.assertEqual("misc/shared.php", finding.sast_source_file_path)
        self.assertEqual(151, finding.sast_source_line)
        finding = findings[1]
        self.assertEqual("Internal information leak", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("index.php", finding.file_path)
        self.assertEqual(5, finding.line)
        self.assertEqual("index.php", finding.sast_source_file_path)
        self.assertEqual(5, finding.sast_source_line)
        finding = findings[2]
        self.assertEqual("Trust boundary violation", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("index.php", finding.sast_source_file_path)
        self.assertEqual(51, finding.sast_source_line)
        self.assertEqual("index.php", finding.file_path)
        self.assertEqual(51, finding.line)
