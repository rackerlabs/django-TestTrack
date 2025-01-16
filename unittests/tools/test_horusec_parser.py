import datetime

from dojo.models import Test
from dojo.tools.horusec.parser import HorusecParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestHorusecParser(DojoTestCase):
    def test_get_findings(self):
        """Version 2.6.3 with big project in Python"""
        with open(get_unit_tests_scans_path() / "horusec/version_2.6.3.json", encoding="utf-8") as testfile:
            parser = HorusecParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(267, len(findings))
            self.assertEqual("2021-10-19", findings[0].date.strftime("%Y-%m-%d"))

    def test_get_tests(self):
        """Version 2.6.3 with big project in Python"""
        with open(get_unit_tests_scans_path() / "horusec/version_2.6.3.json", encoding="utf-8") as testfile:
            parser = HorusecParser()
            tests = parser.get_tests("Horusec Scan", testfile)
            self.assertEqual(1, len(tests))
            test = tests[0]
            self.assertEqual("2.6.3", test.version)
            self.assertEqual(267, len(test.findings))
            findings = test.findings
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Hard-coded password", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual("docker/entrypoint.sh", finding.file_path)
                self.assertEqual(20, finding.line)
                self.assertEqual(datetime.date(2021, 10, 19), finding.date.date())
            with self.subTest(i=50):
                finding = findings[50]
                self.assertEqual("Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("dojo/tools/huskyci/parser.py", finding.file_path)
                self.assertEqual(55, finding.line)
                self.assertEqual(datetime.date(2021, 10, 19), finding.date.date())
            with self.subTest(i=266):
                finding = findings[266]
                self.assertEqual("Try, Except, Pass detected.", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual("tests/base_test_class.py", finding.file_path)
                self.assertEqual(191, finding.line)
                self.assertEqual(datetime.date(2021, 10, 19), finding.date.date())

    def test_get_tests_ok(self):
        """Version 2.6.3 with big project in Python"""
        with open(get_unit_tests_scans_path() / "horusec/horres3.json", encoding="utf-8") as testfile:
            parser = HorusecParser()
            tests = parser.get_tests("Horusec Scan", testfile)
            self.assertEqual(1, len(tests))
            test = tests[0]
            self.assertEqual(266, len(test.findings))
            findings = test.findings
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Hard-coded password", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual("Dockerfile.nginx", finding.file_path)
                self.assertEqual(83, finding.line)
                self.assertGreaterEqual(finding.scanner_confidence, 3)  # "Firm"
                self.assertLessEqual(finding.scanner_confidence, 5)  # "Firm"
            with self.subTest(i=50):
                finding = findings[50]
                self.assertEqual("Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("dojo/tools/trufflehog3/parser.py", finding.file_path)
                self.assertEqual(50, finding.line)
                self.assertGreaterEqual(finding.scanner_confidence, 6)  # "Tentative"
            with self.subTest(i=265):
                finding = findings[265]
                self.assertEqual("Try, Except, Pass detected.", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual("tests/base_test_class.py", finding.file_path)
                self.assertEqual(191, finding.line)
                self.assertLessEqual(finding.scanner_confidence, 2)  # "Certain"

    def test_get_tests_issue_6258(self):
        """"""
        with open(get_unit_tests_scans_path() / "horusec/issue_6258.json", encoding="utf-8") as testfile:
            parser = HorusecParser()
            tests = parser.get_tests("Horusec Scan", testfile)
            self.assertEqual(1, len(tests))
            test = tests[0]
            self.assertEqual(14, len(test.findings))
            findings = test.findings
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("No use eval", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual("GetGestaoVisaoWeb/src/main/webapp/js/jquery/jquery-ui-1.9.1.custom.min.js", finding.file_path)
                self.assertEqual(0, finding.line)
                self.assertGreaterEqual(finding.scanner_confidence, 3)  # "Firm"
                self.assertLessEqual(finding.scanner_confidence, 5)  # "Firm"
                self.assertEqual(datetime.date(2022, 5, 6), finding.date.date())
            with self.subTest(i=10):
                finding = findings[10]
                self.assertEqual("Remote code injection Apache Log4j", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual("resources-external/GetGestao/security/env.xml", finding.file_path)
                self.assertEqual(35, finding.line)
                self.assertGreaterEqual(finding.scanner_confidence, 3)  # "Firm"
                self.assertLessEqual(finding.scanner_confidence, 5)  # "Firm"
                self.assertEqual(datetime.date(2022, 5, 6), finding.date.date())
            with self.subTest(i=13):
                finding = findings[13]
                self.assertEqual("Base64 Encode", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("GetGestaoVisaoWeb/src/main/java/br/gov/dataprev/get/web/util/ErrorHandlingUtils.java", finding.file_path)
                self.assertEqual(146, finding.line)
                self.assertGreaterEqual(finding.scanner_confidence, 6)  # "Tentative"
                self.assertEqual(datetime.date(2022, 5, 6), finding.date.date())

    def test_get_tests_pr_6563(self):
        """"""
        with open(get_unit_tests_scans_path() / "horusec/pr_6563.json", encoding="utf-8") as testfile:
            parser = HorusecParser()
            tests = parser.get_tests("Horusec Scan", testfile)
            self.assertEqual(1, len(tests))
            test = tests[0]
            self.assertEqual(1, len(test.findings))
            findings = test.findings
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("No use eval", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual("GetGestaoVisaoWeb/src/main/webapp/js/jquery/jquery-ui-1.9.1.custom.min.js", finding.file_path)
                self.assertEqual(None, finding.line)
                self.assertGreaterEqual(finding.scanner_confidence, 3)  # "Firm"
                self.assertLessEqual(finding.scanner_confidence, 5)  # "Firm"
                self.assertEqual(datetime.date(2022, 5, 6), finding.date.date())

    def test_issue_9939(self):
        """"""
        with open(get_unit_tests_scans_path() / "horusec/issue_9939.json", encoding="utf-8") as testfile:
            parser = HorusecParser()
            tests = parser.get_tests("Horusec Scan", testfile)
            self.assertEqual(1, len(tests))
            test = tests[0]
            self.assertEqual(1, len(test.findings))
