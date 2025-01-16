from dojo.models import Engagement, Finding, Product, Test
from dojo.tools.tenable.parser import TenableParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTenableParser(DojoTestCase):
    def create_test(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        return test

    def test_parse_some_findings_nessus_legacy(self):
        with open(get_unit_tests_scans_path() / "tenable/nessus/nessus_many_vuln.xml", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(6, len(findings))
            finding = findings[5]
            self.assertEqual("Info", finding.severity)
            self.assertIsNone(finding.cwe)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("https", endpoint.protocol)
            endpoint = finding.unsaved_endpoints[1]
            self.assertEqual("tcp", endpoint.protocol)

    def test_parse_some_findings_csv_nessus_legacy(self):
        """Test one report provided by a user"""
        with open(get_unit_tests_scans_path() / "tenable/nessus/nessus_many_vuln.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(4, len(findings))
            for i in [0, 1, 2, 3]:
                finding = findings[i]
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(0, finding.cwe)
            # check some data
            finding = findings[0]
            self.assertEqual(1, len(finding.unsaved_endpoints))
            self.assertEqual("10.1.1.1", finding.unsaved_endpoints[0].host)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N/E:P/RL:O/RC:C", finding.cvssv3)
            # TODO: work on component attributes for Nessus CSV parser
            self.assertIsNotNone(finding.component_name)
            self.assertEqual("md5", finding.component_name)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2004-2761", finding.unsaved_vulnerability_ids[0])
            # this vuln have 'CVE-2013-2566,CVE-2015-2808' as CVE
            finding = findings[3]
            self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2013-2566", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("CVE-2015-2808", finding.unsaved_vulnerability_ids[1])

    def test_parse_some_findings_csv2_nessus_legacy(self):
        """Test that use default columns of Nessus Pro 8.13.1 (#257)"""
        with open(get_unit_tests_scans_path() / "tenable/nessus/nessus_many_vuln2-default.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(29, len(findings))
            finding = findings[0]
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(0, len(finding.unsaved_vulnerability_ids))
            self.assertEqual(0, finding.cwe)
            self.assertEqual("HTTP Server Type and Version", finding.title)
            finding = findings[25]
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("SSL Certificate Signed Using Weak Hashing Algorithm (Known CA)", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2004-2761", finding.unsaved_vulnerability_ids[0])

    def test_parse_some_findings_csv2_all_nessus_legacy(self):
        """Test that use a report with all columns of Nessus Pro 8.13.1 (#257)"""
        with open(get_unit_tests_scans_path() / "tenable/nessus/nessus_many_vuln2-all.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(29, len(findings))
            finding = findings[0]
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(0, len(finding.unsaved_vulnerability_ids))
            self.assertEqual(0, finding.cwe)
            self.assertEqual("HTTP Server Type and Version", finding.title)
            finding = findings[25]
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("SSL Certificate Signed Using Weak Hashing Algorithm (Known CA)", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2004-2761", finding.unsaved_vulnerability_ids[0])

    def test_parse_some_findings_csv_bytes_nessus_legacy(self):
        """This tests is designed to test the parser with different read modes"""
        with open(get_unit_tests_scans_path() / "tenable/nessus/nessus_many_vuln2-all.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
        with open(get_unit_tests_scans_path() / "tenable/nessus/nessus_many_vuln2-all.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
        with open(get_unit_tests_scans_path() / "tenable/nessus/nessus_many_vuln2-all.csv", "rb") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

    def test_parse_some_findings_samples_nessus_legacy(self):
        """Test that come from samples repo"""
        with open(get_unit_tests_scans_path() / "tenable/nessus/nessus_v_unknown.xml", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(32, len(findings))

            finding = findings[0]
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(0, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("Nessus Scan Information", finding.title)

            finding = findings[25]
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("Nessus SYN scanner", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(0, len(finding.unsaved_vulnerability_ids))
            endpoint = finding.unsaved_endpoints[26]
            self.assertEqual("http", endpoint.protocol)
            endpoint = finding.unsaved_endpoints[37]
            self.assertEqual("tcp", endpoint.protocol)

            finding = findings[9]
            self.assertEqual(7, len(finding.unsaved_vulnerability_ids))
            for vulnerability_id in finding.unsaved_vulnerability_ids:
                self.assertEqual("CVE-2005-1794", vulnerability_id)

    def test_parse_some_findings_with_cvssv3_nessus_legacy(self):
        """Test with cvssv3"""
        with open(get_unit_tests_scans_path() / "tenable/nessus/nessus_with_cvssv3.nessus", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(48, len(findings))
            finding = findings[3]
            self.assertEqual("Medium", finding.severity)
            self.assertIsNone(finding.cwe)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("http", endpoint.protocol)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", finding.cvssv3)

    def test_parse_many_findings_xml_nessus_was_legacy(self):
        with open(get_unit_tests_scans_path("tenable/nessus_was") / "nessus_was_many_vuln.xml", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(5, len(findings))
            for i in [0, 1, 2, 3, 4]:
                finding = findings[i]
                self.assertEqual("http", finding.unsaved_endpoints[0].protocol)
                self.assertIsNone(finding.cwe)
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("Cross-Site Scripting (XSS)", finding.title)

    def test_parse_one_findings_xml_nessus_was_legacy(self):
        with open(get_unit_tests_scans_path("tenable/nessus_was") / "nessus_was_one_vuln.xml", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("http", finding.unsaved_endpoints[0].protocol)
            self.assertIsNone(finding.cwe)
            self.assertEqual("High", finding.severity)
            self.assertEqual("Cross-Site Scripting (XSS)", finding.title)

    def test_parse_no_findings_xml_nessus_was_legacy(self):
        with open(get_unit_tests_scans_path("tenable/nessus_was") / "nessus_was_no_vuln.xml", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(0, len(findings))

    def test_parse_many_findings_csv_nessus_was_legacy(self):
        with open(get_unit_tests_scans_path("tenable/nessus_was") / "nessus_was_many_vuln.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(5, len(findings))
            for i in [0, 1, 2, 3, 4]:
                finding = findings[i]
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertEqual("google.com", finding.unsaved_endpoints[0].host)
                self.assertEqual(0, len(finding.unsaved_vulnerability_ids))
            finding = findings[0]
            self.assertEqual("7.1", finding.cvssv3_score)
            self.assertEqual("High", finding.severity)
            self.assertEqual("http", finding.unsaved_endpoints[0].protocol)

    def test_parse_one_findings_csv_nessus_was_legacy(self):
        with open(get_unit_tests_scans_path("tenable/nessus_was") / "nessus_was_one_vuln.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("google.com", finding.unsaved_endpoints[0].host)
            self.assertEqual(0, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("7.1", finding.cvssv3_score)
            self.assertEqual("High", finding.severity)
            self.assertEqual("http", finding.unsaved_endpoints[0].protocol)

    def test_parse_no_findings_csv_nessus_was_legacy(self):
        with open(get_unit_tests_scans_path("tenable/nessus_was") / "nessus_was_no_vuln.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            self.assertEqual(0, len(findings))

    def test_parse_many_tenable_vulns(self):
        with open(get_unit_tests_scans_path("tenable") / "tenable_many_vuln.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(9, len(findings))
            finding = findings[0]
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("High", finding.severity)
            self.assertEqual("ip-127-0-0-1.us-west-2.compute.internal", finding.unsaved_endpoints[0].host)
            self.assertEqual("Amazon Linux 2 : kernel (ALAS-2023-2050)", finding.title)
            self.assertEqual("tcp", finding.unsaved_endpoints[0].protocol)
            self.assertEqual(None, finding.unsaved_endpoints[0].port)
            self.assertIn("https://alas.aws.amazon.com/AL2/ALAS-2023-2050.html", finding.references)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            for vulnerability_id in finding.unsaved_vulnerability_ids:
                self.assertEqual("CVE-2023-32233", vulnerability_id)

    def test_parse_issue_6992(self):
        with open(get_unit_tests_scans_path("tenable/nessus") / "issue_6992.nessus", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            self.assertEqual("High", findings[0].severity)

    def test_parse_nessus_new(self):
        with open(get_unit_tests_scans_path("tenable/nessus") / "nessus_new.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            self.assertEqual(99, len(findings))
            finding = findings[0]
            self.assertEqual("Blah1", finding.unsaved_endpoints[0].host)
            self.assertEqual("Blah1", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("3.1", finding.cvssv3_score)

    def test_parse_issue_9612(self):
        with open(get_unit_tests_scans_path("tenable") / "issue_9612.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(2, len(findings))
            self.assertEqual("Critical", findings[0].severity)

    def test_parse_issue_11102(self):
        with open(get_unit_tests_scans_path("tenable") / "issue_11102.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(2, len(findings))
            self.assertEqual("Reconfigure the affected application if possible to avoid use of medium strength ciphers.", findings[0].mitigation)

    def test_parse_issue_11127(self):
        with open(get_unit_tests_scans_path("tenable") / "issue_11102.csv", encoding="utf-8") as testfile:
            parser = TenableParser()
            findings = parser.get_findings(testfile, self.create_test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            reference = """https://www.openssl.org/blog/blog/2016/08/24/sweet32/
https://sweet32.info
Tenable Plugin ID: 42873
Plugin Publication Date: Nov 23, 2009 12:00:00 UTC
Plugin Modification Date: Feb 3, 2021 12:00:00 UTC"""
            self.assertEqual(reference, findings[0].references)
