from datetime import datetime

import pytz

from dojo.models import Test
from dojo.tools.qualys_infrascan_webgui.parser import QualysInfrascanWebguiParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestQualysInfrascanWebguiParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(
            get_unit_tests_scans_path("qualys_infrascan_webgui") / "qualys_infrascan_webgui_0.xml", encoding="utf-8",
        ) as testfile:
            parser = QualysInfrascanWebguiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    # Sample with One Test
    # + also verify data with one test
    def test_parse_file_with_one_vuln_has_one_findings(self):
        with open(
            get_unit_tests_scans_path("qualys_infrascan_webgui") / "qualys_infrascan_webgui_1.xml", encoding="utf-8",
        ) as testfile:
            parser = QualysInfrascanWebguiParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual("Oracle Java SE Critical Patch Update - January 2015", finding.title)
            self.assertEqual("Critical", finding.severity)  # Negligible is translated to Informational
            self.assertEqual(datetime(2019, 4, 2, 10, 14, 53, tzinfo=pytz.utc), finding.date)

    # Sample with Multiple Test
    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open(
            get_unit_tests_scans_path("qualys_infrascan_webgui") / "qualys_infrascan_webgui_multiple.xml", encoding="utf-8",
        ) as testfile:
            parser = QualysInfrascanWebguiParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(6, len(findings))
            # finding 0
            finding = findings[0]
            self.assertEqual("UDP Constant IP Identification Field Fingerprinting Vulnerability", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(datetime(2019, 4, 2, 10, 14, 53, tzinfo=pytz.utc), finding.date)
            # finding 4
            finding = findings[4]
            self.assertEqual("Hidden RPC Services", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(datetime(2019, 4, 2, 10, 14, 53, tzinfo=pytz.utc), finding.date)
            self.assertEqual("Some impact\n\n", finding.impact)

    # Sample with Multiple Test
    def test_parse_file_with_finding_no_dns(self):
        with open(
            get_unit_tests_scans_path("qualys_infrascan_webgui") / "qualys_infrascan_webgui_3.xml", encoding="utf-8",
        ) as testfile:
            parser = QualysInfrascanWebguiParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            # finding 0
            finding = findings[0]
            self.assertEqual("UDP Constant IP Identification Field Fingerprinting Vulnerability", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(datetime(2019, 4, 2, 10, 14, 53, tzinfo=pytz.utc), finding.date)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            unsaved_endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("10.1.10.1", unsaved_endpoint.host)
