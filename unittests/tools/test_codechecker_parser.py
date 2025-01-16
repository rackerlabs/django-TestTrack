from dojo.models import Test
from dojo.tools.codechecker.parser import CodeCheckerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCodeCheckerParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(
            get_unit_tests_scans_path("codechecker") / "cc-report-0-vuln.json", encoding="utf-8",
        ) as testfile:
            parser = CodeCheckerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        with open(
            get_unit_tests_scans_path("codechecker") / "cc-report-1-vuln.json", encoding="utf-8",
        ) as testfile:
            parser = CodeCheckerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("clang-diagnostic-sign-compare", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("/opt/_ga/openvpn/src/openvpn/push.c", finding.file_path)
            self.assertEqual("/opt/_ga/openvpn/src/openvpn/push.c", finding.sast_source_file_path)
            self.assertEqual(576, finding.line)
            self.assertEqual(576, finding.sast_source_line)
            self.assertFalse(finding.verified)
            self.assertFalse(finding.false_p)
            self.assertFalse(finding.risk_accepted)

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open(
            get_unit_tests_scans_path("codechecker") / "cc-report-many-vuln.json", encoding="utf-8",
        ) as testfile:
            parser = CodeCheckerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(94, len(findings), str(len(findings)))

            self.assertEqual(sum(1 for f in findings if f.duplicate), 0)
            self.assertEqual(sum(1 for f in findings if f.severity.upper() == "HIGH"), 20)
            self.assertEqual(sum(1 for f in findings if f.severity.upper() == "INFO"), 6)
            self.assertEqual(sum(1 for f in findings if f.severity.upper() == "CRITICAL"), 0)
            self.assertEqual(sum(1 for f in findings if f.severity.upper() == "LOW"), 5)
            self.assertEqual(sum(1 for f in findings if f.severity.upper() == "MEDIUM"), 63)

            finding = findings[0]
            self.assertEqual("clang-diagnostic-sign-compare", finding.title)
            self.assertEqual("Medium", finding.severity)

            finding = findings[22]
            self.assertEqual("deadcode.DeadStores", finding.title)
            self.assertEqual("Low", finding.severity)

            finding = findings[93]
            self.assertEqual("core.NullDereference", finding.title)
            self.assertEqual("High", finding.severity)

    def test_parse_file_with_various_review_statuses(self):
        with open(
            get_unit_tests_scans_path("codechecker") / "cc-report-review-status.json", encoding="utf-8",
        ) as testfile:
            parser = CodeCheckerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 4)

            finding = findings[0]
            self.assertTrue(finding.active)
            self.assertFalse(finding.verified)
            self.assertFalse(finding.risk_accepted)
            self.assertFalse(finding.false_p)
            self.assertEqual(576, finding.line)
            self.assertEqual("/opt/_ga/openvpn/src/openvpn/push.c", finding.file_path)

            finding = findings[1]
            self.assertTrue(finding.active)
            self.assertTrue(finding.verified)
            self.assertFalse(finding.risk_accepted)
            self.assertFalse(finding.false_p)
            self.assertEqual(679, finding.line)
            self.assertEqual("/opt/_ga/openvpn/src/openvpn/push.c", finding.file_path)

            finding = findings[2]
            self.assertFalse(finding.active)
            self.assertFalse(finding.verified)
            self.assertFalse(finding.risk_accepted)
            self.assertTrue(finding.false_p)
            self.assertEqual(402, finding.line)
            self.assertEqual("/opt/_ga/openvpn/src/openvpn/multi.h", finding.file_path)

            finding = findings[3]
            self.assertFalse(finding.active)
            self.assertFalse(finding.verified)
            self.assertTrue(finding.risk_accepted)
            self.assertFalse(finding.false_p)
            self.assertEqual(91, finding.line)
            self.assertEqual("/opt/_ga/openvpn/src/openvpn/vlan.c", finding.file_path)
