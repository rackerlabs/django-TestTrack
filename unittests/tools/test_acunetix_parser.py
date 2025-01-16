import datetime
from datetime import datetime as date

from dojo.models import Test
from dojo.tools.acunetix.parser import AcunetixParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAcunetixParser(DojoTestCase):

    def test_parse_file_with_one_finding(self):
        with open(get_unit_tests_scans_path("acunetix") / "one_finding.xml", encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(352, finding.cwe)
                self.assertEqual(datetime.date(2018, 9, 24), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertFalse(finding.false_p)
                self.assertEqual("Vijay Test Imapact", finding.impact)
                self.assertIsNotNone(finding.references)
                self.assertGreater(len(finding.references), 0)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                # check endpoints
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual("https", endpoint.protocol)
                self.assertEqual(443, endpoint.port)
                self.assertEqual("vijaytest.com", endpoint.host)
                self.assertEqual("some/path", endpoint.path)

    def test_parse_file_with_multiple_finding(self):
        with open(get_unit_tests_scans_path("acunetix") / "many_findings.xml", encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(4, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(datetime.date(2020, 2, 27), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", finding.cvssv3)
                self.assertFalse(finding.false_p)
                self.assertEqual("A single machine can take down another machine's web server with minimal bandwidth and side effects on unrelated services and ports.", finding.impact)
                # check that this finding have references
                self.assertIsNotNone(finding.references)
                self.assertGreater(len(finding.references), 0)
                # check endpoints
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertIsNone(endpoint.protocol)
                self.assertIsNone(endpoint.port)
                self.assertEqual("www.itsecgames.com", endpoint.host)
                self.assertIsNone(endpoint.path)
                # check req/resp
                self.assertEqual(1, len(finding.unsaved_req_resp))
                req_resp = finding.unsaved_req_resp[0]
                self.assertIn("req", req_resp)
                self.assertIsNotNone(req_resp["req"])
                self.assertIsInstance(req_resp["req"], str)
                self.assertIn("resp", req_resp)
                self.assertIsNotNone(req_resp["resp"])
                self.assertIsInstance(req_resp["resp"], str)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Possible virtual host found", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual(200, finding.cwe)
                self.assertEqual(datetime.date(2020, 2, 27), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", finding.cvssv3)
                self.assertFalse(finding.false_p)
                self.assertEqual("Possible sensitive information disclosure.", finding.impact)
                # check that this finding have references
                self.assertIsNotNone(finding.references)
                self.assertGreater(len(finding.references), 0)
                # check endpoints
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertIsNone(endpoint.protocol)
                self.assertIsNone(endpoint.port)
                self.assertEqual("www.itsecgames.com", endpoint.host)
                self.assertIsNone(endpoint.path)
                # check req/resp
                self.assertEqual(1, len(finding.unsaved_req_resp))
                req_resp = finding.unsaved_req_resp[0]
                self.assertIn("req", req_resp)
                self.assertIsNotNone(req_resp["req"])
                self.assertIsInstance(req_resp["req"], str)
                self.assertIn("resp", req_resp)
                self.assertIsNotNone(req_resp["resp"])
                self.assertIsInstance(req_resp["resp"], str)

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Unencrypted connection (verified)", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual(310, finding.cwe)
                self.assertEqual(datetime.date(2020, 2, 27), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", finding.cvssv3)
                self.assertFalse(finding.false_p)
                self.assertEqual("Possible information disclosure.", finding.impact)
                # check that this finding have no references
                self.assertIsNone(finding.references)
                # check endpoints
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertIsNone(endpoint.protocol)
                self.assertIsNone(endpoint.port)
                self.assertEqual("www.itsecgames.com", endpoint.host)
                self.assertIsNone(endpoint.path)
                # check req/resp
                self.assertEqual(1, len(finding.unsaved_req_resp))
                req_resp = finding.unsaved_req_resp[0]
                self.assertIn("req", req_resp)
                self.assertIsNotNone(req_resp["req"])
                self.assertIsInstance(req_resp["req"], str)
                self.assertIn("resp", req_resp)
                self.assertIsNotNone(req_resp["resp"])
                self.assertIsInstance(req_resp["resp"], str)

    def test_parse_file_with_example_com(self):
        with open(get_unit_tests_scans_path("acunetix") / "XML_http_example_co_id_.xml", encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(7, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("HTML form without CSRF protection", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(datetime.date(2020, 4, 28), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", finding.cvssv3)
                self.assertFalse(finding.false_p)
                self.assertIn("An attacker could use CSRF to trick a victim into accessing a website hosted by the attacker,", finding.impact)
                # aggregated
                self.assertEqual(3, finding.nb_occurences)
                # check that this finding have references
                self.assertIsNotNone(finding.references)
                self.assertGreater(len(finding.references), 0)
                # check endpoints
                self.assertEqual(3, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertIsNone(endpoint.protocol)
                self.assertIsNone(endpoint.port)
                self.assertEqual("example.co.id", endpoint.host)
                self.assertEqual("h/search", endpoint.path)
                endpoint = finding.unsaved_endpoints[1]
                self.assertIsNone(endpoint.protocol)
                self.assertIsNone(endpoint.port)
                self.assertEqual("example.co.id", endpoint.host)
                self.assertEqual("m/zmain", endpoint.path)
                # check req/resp
                self.assertEqual(3, len(finding.unsaved_req_resp))
                for req_resp in finding.unsaved_req_resp:
                    self.assertIn("req", req_resp)
                    self.assertIsNotNone(req_resp["req"])
                    self.assertIsInstance(req_resp["req"], str)
                    self.assertIn("resp", req_resp)
                    self.assertIsNotNone(req_resp["resp"])
                    self.assertIsInstance(req_resp["resp"], str)

            with self.subTest(i=6):
                finding = findings[6]
                self.assertEqual("Content Security Policy (CSP) not implemented", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual(datetime.date(2020, 4, 28), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertFalse(finding.false_p)
                self.assertIn("CSP can be used to prevent and/or mitigate attacks that involve content/code injection,", finding.impact)
                # check that this finding have references
                self.assertIsNotNone(finding.references)
                self.assertGreater(len(finding.references), 0)
                # check endpoints
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertIsNone(endpoint.protocol)
                self.assertIsNone(endpoint.port)
                self.assertEqual("example.co.id", endpoint.host)
                self.assertIsNone(endpoint.path)
                # check req/resp
                self.assertEqual(1, len(finding.unsaved_req_resp))
                req_resp = finding.unsaved_req_resp[0]
                self.assertIn("req", req_resp)
                self.assertIsNotNone(req_resp["req"])
                self.assertIsInstance(req_resp["req"], str)
                self.assertIn("resp", req_resp)
                self.assertIsNotNone(req_resp["resp"])
                self.assertIsInstance(req_resp["resp"], str)

    def test_parse_file_with_one_finding_acunetix360(self):
        with open(get_unit_tests_scans_path("acunetix") / "acunetix360_one_finding.json", encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(16, finding.cwe)
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "http://php.testsparker.com/auth/login.php")
                self.assertEqual(finding.date, date(2021, 6, 16, 12, 30))
                self.assertIn("https://online.acunetix360.com/issues/detail/735f4503-e9eb-4b4c-4306-ad49020a4c4b", finding.references)

    def test_parse_file_with_one_finding_false_positive(self):
        with open(get_unit_tests_scans_path("acunetix") / "acunetix360_one_finding_false_positive.json", encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(16, finding.cwe)
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "http://php.testsparker.com/auth/login.php")
                self.assertTrue(finding.false_p)

    def test_parse_file_with_one_finding_risk_accepted(self):
        with open(get_unit_tests_scans_path("acunetix") / "acunetix360_one_finding_accepted_risk.json", encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(16, finding.cwe)
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "http://php.testsparker.com/auth/login.php")
                self.assertTrue(finding.risk_accepted)

    def test_parse_file_with_multiple_finding_acunetix360(self):
        with open(get_unit_tests_scans_path("acunetix") / "acunetix360_many_findings.json", encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(16, len(findings))
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(16, finding.cwe)
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
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N/E:H/RL:O/RC:C", finding.cvssv3)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "http://php.testsparker.com")

    def test_parse_file_with_mulitple_cwe(self):
        with open(get_unit_tests_scans_path("acunetix") / "acunetix360_multiple_cwe.json", encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(16, finding.cwe)
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "http://php.testsparker.com/auth/login.php")

    def test_parse_file_issue_10370(self):
        with open(get_unit_tests_scans_path("acunetix") / "issue_10370.json", encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_issue_10435(self):
        with open(get_unit_tests_scans_path("acunetix") / "issue_10435.json", encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_issue_11206(self):
        with open(get_unit_tests_scans_path("acunetix") / "issue_11206.json", encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual(finding.date, date(2021, 6, 12, 12, 30))
