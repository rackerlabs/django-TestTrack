import datetime

from dojo.models import Test
from dojo.tools.arachni.parser import ArachniParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestArachniParser(DojoTestCase):

    def test_parser_has_one_finding(self):
        with open(get_unit_tests_scans_path("arachni") / "arachni.afr.json", encoding="utf-8") as testfile:
            parser = ArachniParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            # finding 0
            finding = findings[0]
            self.assertEqual("Cross-Site Scripting (XSS)", finding.title)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("High", finding.severity)
            self.assertEqual(datetime.datetime(2017, 11, 14, 2, 57, 29, tzinfo=datetime.UTC), finding.date)

    def test_parser_has_many_finding(self):
        with open(get_unit_tests_scans_path("arachni") / "dd.com.afr.json", encoding="utf-8") as testfile:
            parser = ArachniParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(3, len(findings))
            # finding 0
            finding = findings[0]
            self.assertEqual("Missing 'Strict-Transport-Security' header", finding.title)
            self.assertEqual(200, finding.cwe)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(datetime.datetime(2021, 3, 17, 19, 41, 46,
                tzinfo=datetime.timezone(datetime.timedelta(seconds=3600))), finding.date)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("demo.defectdojo.org", endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertEqual("https", endpoint.protocol)
            # finding 2
            finding = findings[2]
            self.assertEqual("Interesting response", finding.title)
            self.assertIsNone(finding.cwe)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(datetime.datetime(2021, 3, 17, 19, 41, 46,
                tzinfo=datetime.timezone(datetime.timedelta(seconds=3600))), finding.date)
            self.assertIn("interesting", finding.unsaved_tags)
            self.assertIn("response", finding.unsaved_tags)
            self.assertIn("server", finding.unsaved_tags)

    def test_parser_has_many_finding2(self):
        with open(get_unit_tests_scans_path("arachni") / "js.com.afr.json", encoding="utf-8") as testfile:
            parser = ArachniParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(10, len(findings))
            # finding 0
            finding = findings[0]
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual(89, finding.cwe)
            self.assertEqual("High", finding.severity)
            self.assertEqual(datetime.datetime(2021, 3, 18, 10, 29, 55,
                tzinfo=datetime.timezone(datetime.timedelta(seconds=3600))), finding.date)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("juice-shop.herokuapp.com", endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertEqual("https", endpoint.protocol)
            # finding 9
            finding = findings[9]
            self.assertEqual("Interesting response", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(datetime.datetime(2021, 3, 18, 10, 29, 55,
                tzinfo=datetime.timezone(datetime.timedelta(seconds=3600))), finding.date)
            self.assertIsNone(finding.cwe)
            self.assertEqual(25, finding.nb_occurences)
            self.assertEqual(25, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("juice-shop.herokuapp.com", endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertEqual("https", endpoint.protocol)
