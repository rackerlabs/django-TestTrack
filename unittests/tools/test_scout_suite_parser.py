import datetime

from dojo.models import Test
from dojo.tools.scout_suite.parser import ScoutSuiteParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestScoutSuiteParser(DojoTestCase):
    def test_scout_suite_parser_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("scout_suite") / "no_vuln.js", encoding="utf-8") as test_file:
            parser = ScoutSuiteParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(0, len(findings))

    def test_scout_suite_parser_with_two_findings(self):
        with open(get_unit_tests_scans_path("scout_suite") / "two_findings.js", encoding="utf-8") as test_file:
            parser = ScoutSuiteParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(4, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Bucket with Logging Disabled", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1032, finding.cwe)
                self.assertEqual("gcp:cloudstorage-bucket-no-logging", finding.vuln_id_from_tool)
            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Bucket with Versioning Disabled", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1032, finding.cwe)
                self.assertEqual(datetime.date(2021, 1, 8), finding.date)
                self.assertEqual("gcp:cloudstorage-bucket-no-versioning", finding.vuln_id_from_tool)

    def test_get_findings(self):
        with open(get_unit_tests_scans_path("scout_suite") / "new2.js", encoding="utf-8") as test_file:
            parser = ScoutSuiteParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(356, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("CloudTrail Service Not Configured", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual(1032, finding.cwe)
                self.assertEqual("aws:cloudtrail-not-configured", finding.vuln_id_from_tool)
            with self.subTest(i=15):
                finding = findings[15]
                self.assertEqual("CloudTrail Service Not Configured", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual(1032, finding.cwe)
                self.assertEqual("aws:cloudtrail-not-configured", finding.vuln_id_from_tool)
            with self.subTest(i=29):
                finding = findings[29]
                self.assertEqual("AWS Config Not Enabled", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1032, finding.cwe)
                self.assertEqual("aws:config-recorder-not-configured", finding.vuln_id_from_tool)

    def test_get_tests(self):
        with open(get_unit_tests_scans_path("scout_suite") / "new2.js", encoding="utf-8") as test_file:
            parser = ScoutSuiteParser()
            scan_type = parser.get_scan_types()[0]
            tests = parser.get_tests(scan_type, test_file)
            self.assertEqual(1, len(tests))
            test = tests[0]
            self.assertEqual("Scout Suite", test.name)
            self.assertIn("Amazon Web Services", test.description)  # check that the Cloud provider is in the description
            self.assertIn("430150006394", test.description)  # check that the account is in the description (very usefull)
            findings = test.findings
            self.assertEqual(356, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("CloudTrail Service Not Configured", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual(1032, finding.cwe)
                self.assertEqual(datetime.date(2021, 10, 1), finding.date)
                self.assertEqual("aws:cloudtrail-not-configured", finding.vuln_id_from_tool)
            with self.subTest(i=15):
                finding = findings[15]
                self.assertEqual("CloudTrail Service Not Configured", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual(1032, finding.cwe)
                self.assertEqual("aws:cloudtrail-not-configured", finding.vuln_id_from_tool)
            with self.subTest(i=29):
                finding = findings[29]
                self.assertEqual("AWS Config Not Enabled", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1032, finding.cwe)
                self.assertEqual("aws:config-recorder-not-configured", finding.vuln_id_from_tool)
