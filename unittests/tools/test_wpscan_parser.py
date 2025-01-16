import datetime

from dojo.models import Test
from dojo.tools.wpscan.parser import WpscanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWpscanParser(DojoTestCase):

    def test_parse_file_empty(self):
        """Report from the tool wich have no data"""
        with open(get_unit_tests_scans_path("wpscan") / "empty.json", encoding="utf-8") as testfile:
            parser = WpscanParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_exemple(self):
        with open(get_unit_tests_scans_path("wpscan") / "sample.json", encoding="utf-8") as testfile:
            parser = WpscanParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(4, len(findings))
            finding = findings[0]
            self.assertIsNone(finding.unique_id_from_tool)  # interesting findings are not vlunerability
            self.assertEqual("Info", finding.severity)  # it is not a vulnerability so severity should be 'Info'
            self.assertEqual("Interesting finding: Headers", finding.title)
            self.assertEqual(datetime.datetime(2021, 3, 26, 11, 50, 50, tzinfo=datetime.UTC), finding.date)

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("wpscan") / "wordpress_no_vuln.json", encoding="utf-8") as testfile:
            parser = WpscanParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(7, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("wpscan") / "wordpress_one_vuln.json", encoding="utf-8") as testfile:
            parser = WpscanParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(8, len(findings))
            finding = findings[0]
            self.assertEqual("8873", finding.unique_id_from_tool)
            self.assertNotEqual("Info", finding.severity)  # it is a vulnerability so not 'Info'
            self.assertEqual("YouTube Embed <= 11.8.1 - Cross-Site Request Forgery (CSRF)", finding.title)
            self.assertEqual(datetime.datetime(2019, 7, 2, 19, 11, 16, tzinfo=datetime.UTC), finding.date)

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open(get_unit_tests_scans_path("wpscan") / "wordpress_many_vuln.json", encoding="utf-8") as testfile:
            parser = WpscanParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(8, len(findings))
            finding = findings[0]
            self.assertEqual("8873", finding.unique_id_from_tool)
            self.assertNotEqual("Info", finding.severity)  # it is a vulnerability so not 'Info'
            self.assertEqual("YouTube Embed <= 11.8.1 - Cross-Site Request Forgery (CSRF)", finding.title)
            self.assertEqual(datetime.datetime(2019, 7, 2, 19, 11, 16, tzinfo=datetime.UTC), finding.date)

    def test_parse_file_with_multiple_vuln(self):
        with open(get_unit_tests_scans_path("wpscan") / "wpscan.json", encoding="utf-8") as testfile:
            parser = WpscanParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(6, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("7391118e-eef5-4ff8-a8ea-f6b65f442c63", finding.unique_id_from_tool)
                self.assertNotEqual("Info", finding.severity)  # it is a vulnerability so not 'Info'
                self.assertEqual("Contact Form 7 < 5.3.2 - Unrestricted File Upload", finding.title)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2020-35489", finding.unsaved_vulnerability_ids[0])
                self.assertEqual(datetime.datetime(2021, 3, 17, 12, 21, 6, tzinfo=datetime.UTC), finding.date)
                self.assertEqual("", finding.get_scanner_confidence_text())  # data are => 100%

            with self.subTest(i=4):
                finding = findings[4]
                self.assertIsNone(finding.unique_id_from_tool)  # interesting findings are not vlunerability
                self.assertEqual("Info", finding.severity)  # it is not a vulnerability so severity should be 'Info'
                self.assertEqual("Interesting finding: WordPress readme found: http://example/readme.html", finding.title)
                self.assertEqual(datetime.datetime(2021, 3, 17, 12, 21, 6, tzinfo=datetime.UTC), finding.date)
                self.assertEqual("", finding.get_scanner_confidence_text())  # data are => "confidence": 100,

    def test_parse_file_with_multiple_vuln_in_version(self):
        with open(get_unit_tests_scans_path("wpscan") / "wordpress_vuln_version.json", encoding="utf-8") as testfile:
            parser = WpscanParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(11, len(findings))

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("d40374cf-ee95-40b7-9dd5-dbb160b877b1", finding.unique_id_from_tool)
                self.assertNotEqual("Info", finding.severity)  # it is a vulnerability so not 'Info'
                self.assertEqual("WordPress 2.8.1-4.7.2 - Control Characters in Redirect URL Validation", finding.title)
                self.assertEqual("fixed in : 4.6.4", finding.mitigation)
                self.assertEqual("", finding.get_scanner_confidence_text())  # data are => 100%

    def test_parse_file_issue5774(self):
        with open(get_unit_tests_scans_path("wpscan") / "issue5774.json", encoding="utf-8") as testfile:
            parser = WpscanParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(59, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("16353d45-75d1-4820-b93f-daad90c322a8", finding.unique_id_from_tool)
                self.assertNotEqual("Info", finding.severity)
                self.assertEqual("All in One SEO Pack <= 2.9.1.1 - Authenticated Stored Cross-Site Scripting (XSS)", finding.title)
                self.assertEqual("fixed in : 2.10", finding.mitigation)
                self.assertEqual(7, finding.scanner_confidence)
                self.assertEqual("Tentative", finding.get_scanner_confidence_text())  # data are at 30%
            with self.subTest(i=19):
                finding = findings[19]
                self.assertEqual("WordPress 3.7-4.9.1 - MediaElement Cross-Site Scripting (XSS)", finding.title)
                self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2018-5776", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("CVE-2016-9263", finding.unsaved_vulnerability_ids[1])
            with self.subTest(i=30):
                finding = findings[0]
                self.assertEqual("16353d45-75d1-4820-b93f-daad90c322a8", finding.unique_id_from_tool)
                self.assertNotEqual("Info", finding.severity)
                self.assertEqual("All in One SEO Pack <= 2.9.1.1 - Authenticated Stored Cross-Site Scripting (XSS)", finding.title)
                self.assertEqual("fixed in : 2.10", finding.mitigation)
                self.assertEqual("Tentative", finding.get_scanner_confidence_text())  # data are at 30%

            with self.subTest(i=50):
                finding = findings[50]
                self.assertEqual("6a3ec618-c79e-4b9c-9020-86b157458ac5", finding.unique_id_from_tool)
                self.assertNotEqual("Info", finding.severity)
                self.assertEqual("WordPress 4.7-5.7 - Authenticated Password Protected Pages Exposure", finding.title)
                self.assertEqual("fixed in : 4.7.20", finding.mitigation)
                self.assertEqual(0, finding.scanner_confidence)
                finding.scanner_confidence = 1
                self.assertEqual("Certain", finding.get_scanner_confidence_text())  # data are => 100%

    def test_confidence(self):
        parser = WpscanParser()
        self.assertEqual(0, parser._get_scanner_confidence(100))
        self.assertEqual(5, parser._get_scanner_confidence(50))
        self.assertEqual(7, parser._get_scanner_confidence(30))
        self.assertEqual(10, parser._get_scanner_confidence(0))
