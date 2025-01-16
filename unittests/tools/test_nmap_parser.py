import datetime

from dojo.models import Test
from dojo.tools.nmap.parser import NmapParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNmapParser(DojoTestCase):

    def test_parse_file_with_no_open_ports_has_no_findings(self):
        with open(get_unit_tests_scans_path("nmap") / "nmap_0port.xml", encoding="utf-8") as testfile:
            parser = NmapParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(0, len(findings))

    def test_parse_file_with_single_open_ports_has_single_finding(self):
        with open(get_unit_tests_scans_path("nmap") / "nmap_1port.xml", encoding="utf-8") as testfile:
            parser = NmapParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Info", finding.severity)
                self.assertEqual("Open port: 5432/tcp", finding.title)
                self.assertEqual(datetime.datetime(2014, 3, 29, 14, 46, 56), finding.date)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual("localhost.localdomain", endpoint.host)
                self.assertEqual(5432, endpoint.port)
                self.assertEqual("tcp", endpoint.protocol)

    def test_parse_file_with_multiple_open_ports_has_multiple_finding(self):
        with open(get_unit_tests_scans_path("nmap") / "nmap_multiple_port.xml", encoding="utf-8") as testfile:
            parser = NmapParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(13, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Info", finding.severity)
                self.assertEqual("Open port: 21/tcp", finding.title)
                self.assertEqual(datetime.datetime(2016, 5, 16, 17, 56, 59), finding.date)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual("mocha2005.mochahost.com", endpoint.host)
                self.assertEqual(21, endpoint.port)
                self.assertEqual("tcp", endpoint.protocol)

    def test_parse_file_with_script_vulner(self):
        with open(get_unit_tests_scans_path("nmap") / "nmap_script_vulners.xml", encoding="utf-8") as testfile:
            parser = NmapParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(3, len(findings))

            self.assertEqual("Medium", findings[0].severity)
            self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2018-15919", findings[0].unsaved_vulnerability_ids[0])
            self.assertEqual("openssh", findings[0].component_name)
            self.assertEqual("7.4", findings[0].component_version)
            self.assertEqual(datetime.datetime(2020, 2, 17, 9, 7, 25), findings[0].date)

            self.assertEqual("Medium", findings[1].severity)
            self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2017-15906", findings[1].unsaved_vulnerability_ids[0])
            self.assertEqual("openssh", findings[1].component_name)
            self.assertEqual("7.4", findings[1].component_version)
            self.assertEqual(datetime.datetime(2020, 2, 17, 9, 7, 25), findings[1].date)

            self.assertEqual("Info", findings[2].severity)
            self.assertEqual(datetime.datetime(2020, 2, 17, 9, 7, 25), findings[2].date)

    def test_parse_issue4406(self):
        with open(get_unit_tests_scans_path("nmap") / "issue4406.xml", encoding="utf-8") as testfile:
            parser = NmapParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(67, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("openssh", finding.component_name)
                self.assertEqual("7.4", finding.component_version)
                self.assertEqual(datetime.datetime(2021, 4, 29, 9, 26, 36), finding.date)
                self.assertEqual("MSF:ILITIES/UBUNTU-CVE-2019-6111/", finding.vuln_id_from_tool)
            with self.subTest(i=22):
                finding = findings[22]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2019-6111", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("openssh", finding.component_name)
                self.assertEqual("7.4", finding.component_version)
                self.assertEqual(datetime.datetime(2021, 4, 29, 9, 26, 36), finding.date)
            with self.subTest(i=27):
                finding = findings[27]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283", finding.title)
                self.assertEqual(datetime.datetime(2021, 4, 29, 9, 26, 36), finding.date)
                self.assertEqual("EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283", finding.vuln_id_from_tool)
            with self.subTest(i=48):
                finding = findings[48]
                self.assertEqual("Info", finding.severity)
                self.assertEqual("Open port: 9100/tcp", finding.title)
                self.assertEqual(datetime.datetime(2021, 4, 29, 9, 26, 36), finding.date)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual("ip-10-250-195-71.eu-west-1.compute.internal", endpoint.host)
                self.assertEqual(9100, endpoint.port)
                self.assertEqual("tcp", endpoint.protocol)
            with self.subTest(i=66):
                finding = findings[66]
                self.assertEqual("Info", finding.severity)
                self.assertEqual("Open port: 31641/tcp", finding.title)
                self.assertEqual(datetime.datetime(2021, 4, 29, 9, 26, 36), finding.date)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual("ip-10-250-195-71.eu-west-1.compute.internal", endpoint.host)
                self.assertEqual(31641, endpoint.port)
                self.assertEqual("tcp", endpoint.protocol)
            with self.subTest(i=55):
                finding = findings[55]
                self.assertEqual("### Host\n\n**IP Address:** 10.250.195.71\n**FQDN:** ip-10-250-195-71.eu-west-1.compute.internal\n\n\n**Port/Protocol:** 30150/tcp\n\n\n**Script ID:** fingerprint-strings\n**Script Output:** \n  GenericLines: \n    E_BAD_PROTOCOL\n\n\n", finding.description)
