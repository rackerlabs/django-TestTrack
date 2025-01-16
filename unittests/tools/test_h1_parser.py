from dateutil import parser as date_parser

from dojo.models import Test
from dojo.tools.h1.parser import H1Parser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class HackerOneVulnerabilityDisclosureProgramTests(DojoTestCase):
    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open(get_unit_tests_scans_path("h1") / "vuln_disclosure_many.json", encoding="utf-8") as testfile:
            parser = H1Parser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        with open(get_unit_tests_scans_path("h1") / "vuln_disclosure_one.json", encoding="utf-8") as testfile:
            parser = H1Parser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_no_vuln_has_no_finding(self):
        with open(get_unit_tests_scans_path("h1") / "vuln_disclosure_zero.json", encoding="utf-8") as testfile:
            parser = H1Parser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))


class HackerOneBugBountyProgramTests(DojoTestCase):
    def test_bug_bounty_hacker_one_many_findings_json(self):
        with open(get_unit_tests_scans_path("h1") / "bug_bounty_many.json", encoding="utf-8") as testfile:
            parser = H1Parser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            with self.subTest():
                finding = findings[0]
                self.assertEqual(
                    "Sensitive Account Balance Information Exposure via example's DaviPlata Payment Link Integration",
                    finding.title,
                )
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(date_parser.parse("2024-05-12 04:05:27 UTC"), finding.date)
                self.assertTrue(finding.active)
                self.assertIn("**Assigned To**: Group example.co Team", finding.description)
                self.assertIn("**Weakness Category**: Information Disclosure", finding.description)
                self.assertIn("**Reporter**: reporter", finding.description)
            with self.subTest():
                finding = findings[1]
                self.assertEqual("Acceso no autorizado a soporte premium sin pagar", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual(date_parser.parse("2024-09-10 15:38:20 UTC"), finding.date)
                self.assertTrue(finding.active)
                self.assertIn("**Reporter**: reporter", finding.description)
            with self.subTest():
                finding = findings[2]
                self.assertEqual("XSS - stg.pse.mock.example.co", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual(date_parser.parse("2024-08-25 07:27:18 UTC"), finding.date)
                self.assertEqual(date_parser.parse("2024-08-27 18:19:23 UTC"), finding.mitigated)
                self.assertFalse(finding.active)
                self.assertTrue(finding.is_mitigated)
                self.assertIn("**Reporter**: reporter", finding.description)
            with self.subTest():
                finding = findings[3]
                self.assertEqual("example.co/File creation via HTTP method PUT", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual(date_parser.parse("2024-07-22 17:54:36 UTC"), finding.date)
                self.assertEqual(date_parser.parse("2024-07-22 20:57:56 UTC"), finding.mitigated)
                self.assertFalse(finding.active)
                self.assertTrue(finding.is_mitigated)
                self.assertIn("**Reporter**: reporter", finding.description)
                self.assertIn("CVE-2017-12615", finding.unsaved_vulnerability_ids)

    def test_bug_bounty_hacker_one_one_findings_json(self):
        with open(get_unit_tests_scans_path("h1") / "bug_bounty_one.json", encoding="utf-8") as testfile:
            parser = H1Parser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            with self.subTest():
                finding = findings[0]
                self.assertEqual(
                    "Sensitive Account Balance Information Exposure via example's DaviPlata Payment Link Integration",
                    finding.title,
                )
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(date_parser.parse("2024-05-12 04:05:27 UTC"), finding.date)
                self.assertTrue(finding.active)
                self.assertIn("**Assigned To**: Group example.co Team", finding.description)
                self.assertIn("**Weakness Category**: Information Disclosure", finding.description)
                self.assertIn("**Reporter**: reporter", finding.description)

    def test_bug_bounty_hacker_one_zero_findings_json(self):
        with open(get_unit_tests_scans_path("h1") / "bug_bounty_zero.json", encoding="utf-8") as testfile:
            parser = H1Parser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_bug_bounty_hacker_one_many_findings_csv(self):
        with open(get_unit_tests_scans_path("h1") / "bug_bounty_many.json", encoding="utf-8") as testfile:
            parser = H1Parser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            with self.subTest():
                finding = findings[0]
                self.assertEqual(
                    "Sensitive Account Balance Information Exposure via example's DaviPlata Payment Link Integration",
                    finding.title,
                )
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(date_parser.parse("2024-05-12 04:05:27 UTC"), finding.date)
                self.assertTrue(finding.active)
                self.assertIn("**Assigned To**: Group example.co Team", finding.description)
                self.assertIn("**Weakness Category**: Information Disclosure", finding.description)
                self.assertIn("**Reporter**: reporter", finding.description)
            with self.subTest():
                finding = findings[1]
                self.assertEqual("Acceso no autorizado a soporte premium sin pagar", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual(date_parser.parse("2024-09-10 15:38:20 UTC"), finding.date)
                self.assertTrue(finding.active)
                self.assertIn("**Reporter**: reporter", finding.description)
            with self.subTest():
                finding = findings[2]
                self.assertEqual("XSS - stg.pse.mock.example.co", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual(date_parser.parse("2024-08-25 07:27:18 UTC"), finding.date)
                self.assertEqual(date_parser.parse("2024-08-27 18:19:23 UTC"), finding.mitigated)
                self.assertFalse(finding.active)
                self.assertTrue(finding.is_mitigated)
                self.assertIn("**Reporter**: reporter", finding.description)
            with self.subTest():
                finding = findings[3]
                self.assertEqual("example.co/File creation via HTTP method PUT", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual(date_parser.parse("2024-07-22 17:54:36 UTC"), finding.date)
                self.assertEqual(date_parser.parse("2024-07-22 20:57:56 UTC"), finding.mitigated)
                self.assertFalse(finding.active)
                self.assertTrue(finding.is_mitigated)
                self.assertIn("**Reporter**: reporter", finding.description)
                self.assertIn("CVE-2017-12615", finding.unsaved_vulnerability_ids)

    def test_bug_bounty_hacker_one_one_findings_csv(self):
        with open(get_unit_tests_scans_path("h1") / "bug_bounty_one.json", encoding="utf-8") as testfile:
            parser = H1Parser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            with self.subTest():
                finding = findings[0]
                self.assertEqual(
                    "Sensitive Account Balance Information Exposure via example's DaviPlata Payment Link Integration",
                    finding.title,
                )
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(date_parser.parse("2024-05-12 04:05:27 UTC"), finding.date)
                self.assertTrue(finding.active)
                self.assertIn("**Assigned To**: Group example.co Team", finding.description)
                self.assertIn("**Weakness Category**: Information Disclosure", finding.description)
                self.assertIn("**Reporter**: reporter", finding.description)

    def test_bug_bounty_hacker_one_zero_findings_csv(self):
        with open(get_unit_tests_scans_path("h1") / "bug_bounty_zero.json", encoding="utf-8") as testfile:
            parser = H1Parser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))


class TestHackerOneParser(
    HackerOneVulnerabilityDisclosureProgramTests,
    HackerOneBugBountyProgramTests,
):

    """Combined unit test runner."""
