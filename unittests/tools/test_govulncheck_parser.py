from dojo.models import Test
from dojo.tools.govulncheck.parser import GovulncheckParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGovulncheckParser(DojoTestCase):

    def test_parse_empty(self):
        with self.assertRaises(ValueError) as exp, \
          open(get_unit_tests_scans_path("govulncheck") / "empty.json", encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            parser.get_findings(testfile, Test())
        self.assertIn(
            "Invalid JSON format", str(exp.exception),
        )

    def test_parse_no_findings(self):
        with open(get_unit_tests_scans_path("govulncheck") / "no_vulns.json", encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        with open(get_unit_tests_scans_path("govulncheck") / "many_vulns.json", encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(3, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("GO-2022-1144", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("CVE-2022-41717", finding.cve)
                self.assertEqual("stdlib", finding.component_name)
                self.assertEqual("v1.19.0", finding.component_version)
                self.assertEqual("GO-2022-1144", finding.unique_id_from_tool)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2022-1144", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertEqual("https://go.dev/issue/56350", finding.references)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("GO-2022-1143", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("CVE-2022-41720", finding.cve)
                self.assertEqual("stdlib", finding.component_name)
                self.assertEqual("v1.19.0", finding.component_version)
                self.assertEqual("GO-2022-1143", finding.unique_id_from_tool)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2022-1143", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertEqual("https://go.dev/issue/56694", finding.references)

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("GO-2022-0969", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("CVE-2022-27664", finding.cve)
                self.assertEqual("stdlib", finding.component_name)
                self.assertEqual("v1.19.0", finding.component_version)
                self.assertEqual("GO-2022-0969", finding.unique_id_from_tool)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2022-0969", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertEqual("https://groups.google.com/g/golang-announce/c/x49AQzIVX-s", finding.references)

    def test_parse_new_version_no_findings(self):
        with open(get_unit_tests_scans_path("govulncheck") / "no_vulns_new_version.json", encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_new_version_many_findings(self):
        with open(get_unit_tests_scans_path("govulncheck") / "many_vulns_new_version.json", encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(1, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("GO-2023-1840 - stdlib - runtime", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("CVE-2023-29403", finding.cve)
                self.assertEqual("stdlib", finding.component_name)
                self.assertEqual("v1.20.1", finding.component_version)
                self.assertEqual("GO-2023-1840", finding.unique_id_from_tool)
                self.assertEqual("runtime", finding.file_path)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2023-1840", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertIsNotNone(finding.references)

    def test_parse_new_version_many_findings_custom_severity(self):
        with open(get_unit_tests_scans_path("govulncheck") / "many_vulns_new_version_custom_severity.json", encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(2, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Low", finding.severity)
                self.assertEqual("GO-2021-0113 - golang.org/x/text - golang.org/x/text/language", finding.title)
                self.assertEqual("CVE-2021-38561", finding.cve)
                self.assertEqual("golang.org/x/text", finding.component_name)
                self.assertEqual("v0.3.5", finding.component_version)
                self.assertEqual("GO-2021-0113", finding.unique_id_from_tool)
                self.assertEqual("golang.org/x/text/language", finding.file_path)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2021-0113", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertIsNotNone(finding.references)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("High", finding.severity)
                self.assertEqual("GO-2022-1059 - golang.org/x/text - golang.org/x/text/language", finding.title)
                self.assertEqual("CVE-2022-32149", finding.cve)
                self.assertEqual("golang.org/x/text", finding.component_name)
                self.assertEqual("v0.3.5", finding.component_version)
                self.assertEqual("GO-2022-1059", finding.unique_id_from_tool)
                self.assertEqual("golang.org/x/text/language", finding.file_path)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2022-1059", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertIsNotNone(finding.references)
