from dojo.models import Engagement, Product, Test
from dojo.tools.openvas.parser import OpenVASParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOpenVASParser(DojoTestCase):
    def test_openvas_csv_one_vuln(self):
        with open(get_unit_tests_scans_path("openvas") / "one_vuln.csv", encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            # finding
            self.assertEqual("SSH Weak Encryption Algorithms Supported", findings[0].title)
            self.assertEqual("Medium", findings[0].severity)
            # endpoints
            self.assertEqual(1, len(findings[0].unsaved_endpoints))
            # endpoint
            self.assertEqual("10.0.0.8", findings[0].unsaved_endpoints[0].host)
            self.assertEqual("tcp", findings[0].unsaved_endpoints[0].protocol)
            self.assertEqual(22, findings[0].unsaved_endpoints[0].port)

    def test_openvas_csv_many_vuln(self):
        with open(get_unit_tests_scans_path("openvas") / "many_vuln.csv", encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(4, len(findings))
            # finding
            finding = findings[3]
            self.assertEqual("HTTP Brute Force Logins With Default Credentials Reporting", finding.title)
            self.assertEqual("High", finding.severity)
            # endpoints
            self.assertEqual(1, len(finding.unsaved_endpoints))
            # endpoint
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("LOGSRV", endpoint.host)
            self.assertEqual("tcp", endpoint.protocol)
            self.assertEqual(9200, endpoint.port)
            finding = findings[2]
            self.assertEqual(finding.unsaved_vulnerability_ids[0], "CVE-2011-3389")

    def test_openvas_csv_report_usingCVE(self):
        with open(get_unit_tests_scans_path("openvas") / "report_using_CVE.csv", encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(43, len(findings))
            finding = findings[4]
            self.assertEqual("CVE-2014-0117", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(finding.unsaved_vulnerability_ids[0], "CVE-2014-0117")

    def test_openvas_csv_report_usingOpenVAS(self):
        with open(get_unit_tests_scans_path("openvas") / "report_using_openVAS.csv", encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(13, len(findings))
            finding = findings[2]
            self.assertEqual("Apache HTTP Server Detection Consolidation", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(finding.unsaved_vulnerability_ids, [])

    def test_openvas_xml_no_vuln(self):
        with open(get_unit_tests_scans_path("openvas") / "no_vuln.xml", encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            self.assertEqual(0, len(findings))

    def test_openvas_xml_one_vuln(self):
        with open(get_unit_tests_scans_path("openvas") / "one_vuln.xml", encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Mozilla Firefox Security Update (mfsa_2023-32_2023-36) - Windows_10.0.101.2_general/tcp", finding.title)
                self.assertEqual("Critical", finding.severity)

    def test_openvas_xml_many_vuln(self):
        with open(get_unit_tests_scans_path("openvas") / "many_vuln.xml", encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(44, len(findings))
