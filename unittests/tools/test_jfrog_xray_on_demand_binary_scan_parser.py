from dojo.models import Finding, Test
from dojo.tools.jfrog_xray_on_demand_binary_scan.parser import (
    JFrogXrayOnDemandBinaryScanParser,
    clean_title,
    get_component_name_version,
)
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestJFrogXrayOnDemandBinaryScanParser(DojoTestCase):

    def test_parse_file_with_one_vuln(self):
        testfile = open(get_unit_tests_scans_path("jfrog_xray_on_demand_binary_scan") / "one_vuln.json", encoding="utf-8")
        parser = JFrogXrayOnDemandBinaryScanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        item: Finding = findings[0]
        self.assertEqual("gav://test", item.component_name)
        self.assertEqual("CVE-2014-0114", item.unsaved_vulnerability_ids[0])
        self.assertEqual("High", item.severity)

    def test_parse_file_with_many_vulns(self):
        testfile = open(get_unit_tests_scans_path("jfrog_xray_on_demand_binary_scan") / "many_vulns.json", encoding="utf-8")
        parser = JFrogXrayOnDemandBinaryScanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(findings))

    def test_component_name_version(self):
        with self.subTest(""):
            self.assertEqual(("", ""), get_component_name_version(""))
        with self.subTest("gav://org.yaml:snakeyaml:1.16"):
            self.assertEqual(("gav://org.yaml:snakeyaml", "1.16"), get_component_name_version("gav://org.yaml:snakeyaml:1.16"))
        with self.subTest("npm://desopmo:1.33.7"):
            self.assertEqual(("npm://desopmo", "1.33.7"), get_component_name_version("npm://desopmo:1.33.7"))
        with self.subTest("pypi://django:4.1.4"):
            self.assertEqual(("pypi://django", "4.1.4"), get_component_name_version("pypi://django:4.1.4"))
        with self.subTest("alpine://3.18:libcrypto3:3.1.1-r1"):
            self.assertEqual(("alpine://3.18:libcrypto3", "3.1.1-r1"), get_component_name_version("alpine://3.18:libcrypto3:3.1.1-r1"))
        with self.subTest("npm://desopmo"):
            self.assertEqual(("npm://desopmo", ""), get_component_name_version("npm://desopmo"))

    def test_clean_title(self):
        with self.subTest(""):
            self.assertEqual("", clean_title(""))
        with self.subTest("ABC"):
            self.assertEqual("ABC", clean_title("ABC"))
        with self.subTest("Garbage"):
            self.assertEqual("Processing some specially crafted ASN.1 object identifiers or", clean_title("Issue summary: Processing some specially crafted ASN.1 object identifiers or\ndata containing them may be very slow."))

    def test_parse_file_with_many_vulns_docker(self):
        testfile = open(get_unit_tests_scans_path("jfrog_xray_on_demand_binary_scan") / "many_vulns_docker.json", encoding="utf-8")
        parser = JFrogXrayOnDemandBinaryScanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))

    def test_parse_file_with_many_vulns_pypi(self):
        testfile = open(get_unit_tests_scans_path("jfrog_xray_on_demand_binary_scan") / "many_vulns_pypi.json", encoding="utf-8")
        parser = JFrogXrayOnDemandBinaryScanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(99, len(findings))

        with self.subTest(finding=0):
            self.assertIn("sqlparse is a non-validating SQL parser module for Python", findings[0].title)
            self.assertIsNone(findings[0].severity_justification)
            self.assertEqual("High", findings[0].severity)
            self.assertIn("sqlparse is a non-validating SQL parser module for Python", findings[0].description)
            self.assertIn("- [0.4.4]", findings[0].mitigation)
            self.assertEqual("pypi://sqlparse", findings[0].component_name)
            self.assertEqual("0.4.3", findings[0].component_version)
            self.assertIn("pypi://django:4.1.4", findings[0].impact)
            self.assertIn("https://github.com/andialbrecht/sqlparse/commit/", findings[0].references)
            self.assertTrue(findings[0].static_finding)
            self.assertFalse(findings[0].dynamic_finding)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", findings[0].cvssv3)
            self.assertEqual("XRAY-515353", findings[0].vuln_id_from_tool)
            self.assertEqual(["CVE-2023-30608"], findings[0].unsaved_vulnerability_ids)

        with self.subTest(finding=1):
            self.assertIn("**Short description**\nA design problem in Django may lead to denial of service when processing multipart forms.\n", findings[1].severity_justification)
            self.assertIn("**Full description**\n[Django](https://www.djangoproject.com/) is a popular Python web framework that provides functions, components, and tools for fast web development.\r\n\r\nA vulnerability has been discovered in the Multipart Request Parser in Django. By passing certain inputs (such as an excessive number of parts) to multipart forms, an attacker can trigger too many open files or memory exhaustion, which may lead to a denial-of-service attack. \r\n\r\nThe issue is only exploitable when the `MultiPartParser` class is used by the Django app/\n", findings[1].severity_justification)
            self.assertIn("**JFrog research severity**\nHigh\n", findings[1].severity_justification)
            self.assertIn("**JFrog research severity reasons**\nExploitation of the issue is only possible when the vulnerable component is used in a specific manner. The attacker has to perform per-target research to determine the vulnerable attack vector\n", findings[1].severity_justification)
            self.assertIn("An attacker must find a multipart form that receives files in order to trigger this issue, although this does not require intimate per-target research and can be automated.\n", findings[1].severity_justification)
            self.assertIn("_Is positive:_ true\n", findings[1].severity_justification)
