from dojo.models import Test
from dojo.tools.invicti.parser import InvictiParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestInvictiParser(DojoTestCase):

    def test_parse_file_with_one_finding(self):
        with open(get_unit_tests_scans_path("invicti") / "invicti_one_finding.json", encoding="utf-8") as testfile:
            parser = InvictiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(16, finding.cwe)
                self.assertEqual("25/06/2021", finding.date.strftime("%d/%m/%Y"))
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "http://php.testsparker.com/auth/login.php")

    def test_parse_file_with_multiple_finding(self):
        with open(get_unit_tests_scans_path("invicti") / "invicti_many_findings.json", encoding="utf-8") as testfile:
            parser = InvictiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(16, len(findings))
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(16, finding.cwe)
                self.assertEqual("25/06/2021", finding.date.strftime("%d/%m/%Y"))
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "http://php.testsparker.com/auth/login.php")

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Critical", finding.severity)
                self.assertEqual(89, finding.cwe)
                self.assertEqual("25/06/2021", finding.date.strftime("%d/%m/%Y"))
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding.cvssv3)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "http://php.testsparker.com/artist.php?id=-1%20OR%2017-7=10")

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(205, finding.cwe)
                self.assertEqual("25/06/2021", finding.date.strftime("%d/%m/%Y"))
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N/E:H/RL:O/RC:C", finding.cvssv3)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "http://php.testsparker.com")

    def test_parse_file_issue_9816(self):
        with open(get_unit_tests_scans_path("invicti") / "issue_9816.json", encoding="utf-8") as testfile:
            parser = InvictiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("High", finding.severity)
                self.assertEqual(614, finding.cwe)
                self.assertEqual("03/02/2019", finding.date.strftime("%d/%m/%Y"))

    def test_parse_file_issue_10311(self):
        with open(get_unit_tests_scans_path("invicti") / "issue_10311.json", encoding="utf-8") as testfile:
            parser = InvictiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("High", finding.severity)
                self.assertEqual(614, finding.cwe)
                self.assertEqual("03/02/2019", finding.date.strftime("%d/%m/%Y"))
