from dojo.models import Engagement, Product, Test
from dojo.tools.microfocus_webinspect.parser import MicrofocusWebinspectParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestMicrofocusWebinspectParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with open(
            get_unit_tests_scans_path("microfocus_webinspect") / "Webinspect_no_vuln.xml", encoding="utf-8",
        ) as testfile:
            parser = MicrofocusWebinspectParser()
            findings = parser.get_findings(testfile, test)
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with open(
            get_unit_tests_scans_path("microfocus_webinspect") / "Webinspect_one_vuln.xml", encoding="utf-8",
        ) as testfile:
            parser = MicrofocusWebinspectParser()
            findings = parser.get_findings(testfile, test)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            item = findings[0]
            self.assertEqual(200, item.cwe)
            self.assertEqual(1, len(item.unsaved_endpoints))
            endpoint = item.unsaved_endpoints[0]
            self.assertEqual("www.microfocus.com", endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertIsNone(endpoint.path)  # path begins with '/' but Endpoint store "root-less" path

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with open(
            get_unit_tests_scans_path("microfocus_webinspect") / "Webinspect_many_vuln.xml", encoding="utf-8",
        )as testfile:
            parser = MicrofocusWebinspectParser()
            findings = parser.get_findings(testfile, test)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(8, len(findings))
            item = findings[1]
            self.assertEqual(525, item.cwe)
            self.assertIsNotNone(item.references)
            self.assertEqual(
                "1cfe38ee-89f7-4110-ad7c-8fca476b2f04", item.unique_id_from_tool,
            )
            self.assertEqual(1, len(item.unsaved_endpoints))
            endpoint = item.unsaved_endpoints[0]
            self.assertEqual("php.vulnweb.com", endpoint.host)
            self.assertEqual(80, endpoint.port)
            self.assertIsNone(endpoint.path)  # path begins with '/' but Endpoint store "root-less" path

    def test_convert_severity(self):
        with self.subTest("convert info", val="0"):
            self.assertEqual(
                "Info", MicrofocusWebinspectParser.convert_severity("0"),
            )
        with self.subTest("convert medium", val="2"):
            self.assertEqual(
                "Medium", MicrofocusWebinspectParser.convert_severity("2"),
            )

    def test_parse_file_version_18_20(self):
        with open(get_unit_tests_scans_path("microfocus_webinspect") / "Webinspect_V18_20.xml", encoding="utf-8") as testfile:
            parser = MicrofocusWebinspectParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(4, len(findings))
            item = findings[0]
            self.assertEqual("Cache Management: Headers", item.title)
            self.assertEqual("Info", item.severity)
            self.assertEqual(200, item.cwe)
            self.assertEqual(2, item.nb_occurences)
            self.assertEqual(2, len(item.unsaved_endpoints))
            endpoint = item.unsaved_endpoints[0]
            self.assertEqual("www.microfocus.com", endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertIsNone(endpoint.path)  # path begins with '/' but Endpoint store "root-less" path
            endpoint = item.unsaved_endpoints[1]
            self.assertEqual("www.microfocus.com", endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertEqual("en-us/home", endpoint.path)  # path begins with '/' but Endpoint store "root-less" path
            item = findings[1]
            self.assertEqual(525, item.cwe)
            self.assertEqual(1, item.nb_occurences)
            self.assertEqual(1, len(item.unsaved_endpoints))
            endpoint = item.unsaved_endpoints[0]
            self.assertEqual("www.microfocus.com", endpoint.host)
            self.assertEqual(443, endpoint.port)
            item = findings[2]
            self.assertEqual(200, item.cwe)
            self.assertEqual(1, item.nb_occurences)
            self.assertEqual(1, len(item.unsaved_endpoints))
            endpoint = item.unsaved_endpoints[0]
            self.assertEqual("www.microfocus.com", endpoint.host)
            self.assertEqual(443, endpoint.port)
            item = findings[3]
            self.assertEqual(613, item.cwe)
            self.assertEqual(1, item.nb_occurences)
            self.assertEqual(1, len(item.unsaved_endpoints))
            endpoint = item.unsaved_endpoints[0]
            self.assertEqual("www.microfocus.com", endpoint.host)
            self.assertEqual(443, endpoint.port)

    def test_parse_file_issue7690(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with open(
            get_unit_tests_scans_path("microfocus_webinspect") / "issue_7690.xml", encoding="utf-8",
        ) as testfile:
            parser = MicrofocusWebinspectParser()
            findings = parser.get_findings(testfile, test)
            self.assertEqual(30, len(findings))
