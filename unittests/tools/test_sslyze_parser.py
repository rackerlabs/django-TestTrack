from dojo.models import Test
from dojo.tools.sslyze.parser import SslyzeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSslyzeJSONParser(DojoTestCase):
    def test_parse_json_file_with_one_target_has_zero_vuln_old(self):
        with open(get_unit_tests_scans_path() / "sslyze/one_target_zero_vuln_old.json", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_json_file_issue_9848(self):
        with open(get_unit_tests_scans_path() / "sslyze/issue_9848.json", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_parse_json_file_with_one_target_has_one_vuln_old(self):
        with open(get_unit_tests_scans_path() / "sslyze/one_target_one_vuln_old.json", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Problems in certificate deployments (www.example.com:443)", finding.title)
            description = """www.example.com:443 has problems in certificate deployments:
 - certificate has expired for trust store Android, version 9.0.0_r9
 - certificate has expired for trust store Apple, version iOS 13, iPadOS 13, macOS 10.15, watchOS 6, and tvOS 13
 - certificate has expired for trust store Java, version jdk-13.0.2
 - certificate has expired for trust store Mozilla, version 2019-11-28
 - certificate has expired for trust store Windows, version 2020-05-04"""
            self.assertEqual(description, finding.description)
            self.assertEqual("Medium", finding.severity)

            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("www.example.com", endpoint.host)
            self.assertEqual(443, endpoint.port)

    def test_parse_json_file_with_one_target_has_four_vuln_old(self):
        with open(get_unit_tests_scans_path() / "sslyze/one_target_many_vuln_old.json", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(4, len(findings))

            self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2014-0160", findings[0].unsaved_vulnerability_ids[0])

            self.assertEqual(1, len(findings[1].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2014-0224", findings[1].unsaved_vulnerability_ids[0])

    def test_parse_json_file_with_two_target_has_many_vuln_old(self):
        with open(get_unit_tests_scans_path() / "sslyze/two_targets_two_vuln_old.json", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(2, len(findings))

    def test_parse_json_file_with_one_target_has_zero_vuln_new(self):
        with open(get_unit_tests_scans_path() / "sslyze/one_target_zero_vuln_new.json", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_json_file_with_one_target_has_one_vuln_new(self):
        with open(get_unit_tests_scans_path() / "sslyze/one_target_one_vuln_new.json", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Unrecommended cipher suites for TLS 1.2 (example.com:443)", finding.title)
            description = """example.com:443 accepts unrecommended cipher suites for TLS 1.2:
 - TLS_RSA_WITH_AES_256_GCM_SHA384
 - TLS_RSA_WITH_AES_256_CCM_8
 - TLS_RSA_WITH_AES_256_CCM
 - TLS_RSA_WITH_AES_256_CBC_SHA256
 - TLS_RSA_WITH_AES_256_CBC_SHA
 - TLS_RSA_WITH_AES_128_GCM_SHA256
 - TLS_RSA_WITH_AES_128_CCM_8
 - TLS_RSA_WITH_AES_128_CCM
 - TLS_RSA_WITH_AES_128_CBC_SHA256
 - TLS_RSA_WITH_AES_128_CBC_SHA
 - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
 - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
 - TLS_DHE_RSA_WITH_AES_256_CCM_8
 - TLS_DHE_RSA_WITH_AES_256_CBC_SHA
 - TLS_DHE_RSA_WITH_AES_128_CCM_8
 - TLS_DHE_RSA_WITH_AES_128_CBC_SHA"""
            self.assertEqual(description, finding.description)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(
                "TLS recommendations of German BSI: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf?__blob=publicationFile&v=10",
                finding.references,
            )

            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("example.com", endpoint.host)
            self.assertEqual(443, endpoint.port)

    def test_parse_json_file_with_one_target_has_three_vuln_new(self):
        with open(get_unit_tests_scans_path() / "sslyze/one_target_many_vuln_new.json", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_parse_json_file_with_two_target_has_many_vuln_new(self):
        with open(get_unit_tests_scans_path() / "sslyze/two_targets_many_vuln_new.json", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            # We look at 2 examplary findings, the others are similar and don't give more test coverage
            finding = findings[0]
            self.assertEqual("Unrecommended cipher suites for TLS 1.2 (example.com:443)", finding.title)
            description = """example.com:443 accepts unrecommended cipher suites for TLS 1.2:
 - TLS_RSA_WITH_AES_256_GCM_SHA384
 - TLS_RSA_WITH_AES_256_CBC_SHA256
 - TLS_RSA_WITH_AES_256_CBC_SHA
 - TLS_RSA_WITH_AES_128_GCM_SHA256
 - TLS_RSA_WITH_AES_128_CBC_SHA256
 - TLS_RSA_WITH_AES_128_CBC_SHA
 - TLS_RSA_WITH_3DES_EDE_CBC_SHA
 - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
 - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
 - TLS_DHE_RSA_WITH_AES_256_CBC_SHA
 - TLS_DHE_RSA_WITH_AES_128_CBC_SHA"""
            self.assertEqual(description, finding.description)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(
                "TLS recommendations of German BSI: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf?__blob=publicationFile&v=10",
                finding.references,
            )

            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("example.com", endpoint.host)
            self.assertEqual(443, endpoint.port)

            finding = findings[1]
            self.assertEqual("TLS 1.0 not recommended (example2.com:443)", finding.title)
            self.assertEqual("example2.com:443 accepts TLS 1.0 connections", finding.description)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(
                "TLS recommendations of German BSI: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf?__blob=publicationFile&v=10",
                finding.references,
            )

            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("example2.com", endpoint.host)
            self.assertEqual(443, endpoint.port)


class TestSSLyzeXMLParser(DojoTestCase):
    def test_parse_file_with_one_target_has_three_vuln(self):
        with open(get_unit_tests_scans_path() / "sslyze/report_one_target_three_vuln.xml", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(3, len(findings))

    def test_parse_xml_file_with_one_target_has_one_vuln(self):
        with open(get_unit_tests_scans_path() / "sslyze/report_one_target_one_vuln.xml", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))

    def test_parse_xml_file_with_one_target_has_three_vuln(self):
        with open(get_unit_tests_scans_path() / "sslyze/report_one_target_three_vuln.xml", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(3, len(findings))

    def test_parse_xml_file_with_two_target_has_many_vuln(self):
        with open(get_unit_tests_scans_path() / "sslyze/report_two_target_many_vuln.xml", encoding="utf-8") as testfile:
            parser = SslyzeParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(7, len(findings))
