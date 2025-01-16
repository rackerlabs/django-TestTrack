import datetime

from django.test import override_settings

from dojo.models import Engagement, Product, Test
from dojo.tools.nexpose.parser import NexposeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNexposeParser(DojoTestCase):

    def test_nexpose_parser_has_no_finding(self):
        with open(get_unit_tests_scans_path("nexpose") / "no_vuln.xml", encoding="utf-8") as testfile:
            parser = NexposeParser()
            findings = parser.get_findings(testfile, Test())

            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            self.assertEqual(1, len(findings))

            # vuln 1
            finding = findings[0]
            self.assertEqual("Info", finding.severity)
            self.assertEqual("Host Up", finding.title)

    def test_nexpose_parser_has_many_finding(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with open(get_unit_tests_scans_path("nexpose") / "many_vulns.xml", encoding="utf-8") as testfile:
            parser = NexposeParser()
            findings = parser.get_findings(testfile, test)

            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            self.assertEqual(38, len(findings))

            # vuln 1
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("TCP Sequence Number Approximation Vulnerability", finding.title)
            self.assertEqual(3, len(finding.unsaved_endpoints))
            self.assertIn("https://www.securityfocus.com/bid/10183", finding.references)  # BID: 10183
            self.assertIn("https://www.kb.cert.org/vuls/id/415294.html", finding.references)  # CERT-VN: 415294
            self.assertIn("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0230", finding.references)  # CVE: CVE-2004-0230
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2004-0230", finding.unsaved_vulnerability_ids[0])

            # vuln 2
            finding = findings[2]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("TCP timestamp response", finding.title)
            self.assertEqual(5, len(finding.unsaved_endpoints))
            self.assertIsNone(finding.unsaved_vulnerability_ids)

            # vuln 2 - endpoint
            endpoint = finding.unsaved_endpoints[0]
            self.assertIsNone(endpoint.port)
            self.assertIsNone(endpoint.protocol)

            # vuln 5
            finding = findings[5]
            self.assertEqual('Default SSH password: root password "root"', finding.title)
            self.assertEqual(1, len(finding.unsaved_endpoints))

            # vuln 5 - endpoint
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(22, endpoint.port)
            self.assertEqual("ssh", endpoint.protocol)

            # vuln 9
            finding = findings[9]
            self.assertEqual("Missing HttpOnly Flag From Cookie", finding.title)
            self.assertEqual(1, len(finding.unsaved_endpoints))

            # vuln 9 - endpoint
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(80, endpoint.port)
            self.assertEqual("http", endpoint.protocol)

            # vuln 26
            finding = findings[26]
            self.assertIn("radius (RADIUS authentication protocol (RFC\n2138))", finding.description)
            self.assertEqual("radius-radius-authentication-protocol-rfc-2138", finding.unsaved_tags[0])
            self.assertEqual("udp", finding.unsaved_endpoints[0].protocol)

            # vuln 27
            finding = findings[27]
            self.assertIn("nfs_acl", finding.description)
            self.assertEqual("nfs-acl", finding.unsaved_tags[0])
            self.assertEqual("tcp", finding.unsaved_endpoints[0].protocol)

            # vuln 29
            finding = findings[29]
            self.assertIn("Backup Exec Agent Browser", finding.description)
            self.assertEqual("backup-exec-agent-browser", finding.unsaved_tags[0])
            self.assertEqual("tcp", finding.unsaved_endpoints[0].protocol)

            # vuln 31
            finding = findings[31]
            self.assertIn("sun-answerbook (Sun Answerbook HTTP server)", finding.description)
            self.assertEqual("sun-answerbook-sun-answerbook-http-server", finding.unsaved_tags[0])
            self.assertEqual("tcp", finding.unsaved_endpoints[0].protocol)

            # vuln 32
            finding = findings[32]
            self.assertIn("HP JetDirect Data", finding.description)
            self.assertEqual("hp-jetdirect-data", finding.unsaved_tags[0])
            self.assertEqual("tcp", finding.unsaved_endpoints[0].protocol)

            # vuln 33
            finding = findings[33]
            self.assertEqual("TLS/SSL Server Supports DES and IDEA Cipher Suites", finding.title)
            self.assertEqual(1, len(finding.unsaved_endpoints))

            # vuln 33 - endpoint
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(443, endpoint.port)
            self.assertEqual("tcp", endpoint.protocol)

            # vuln 37
            finding = findings[37]
            self.assertEqual("Open port UDP/137", finding.title)
            self.assertIn('udp/137 port is open with "CIFS Name Service" service', finding.description)
            self.assertIn("cifs-name-service", finding.unsaved_tags)
            self.assertEqual(1, len(finding.unsaved_endpoints))

            # vuln 37 - endpoint
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(137, endpoint.port)
            self.assertEqual("udp", endpoint.protocol)

    def test_nexpose_parser_tests_outside_endpoint(self):
        with open(get_unit_tests_scans_path("nexpose") / "report_auth.xml", encoding="utf-8") as testfile:
            parser = NexposeParser()

            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            self.assertEqual(5, len(findings))

            # vuln 0
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("ICMP redirection enabled", finding.title)
            self.assertEqual(4, len(finding.unsaved_endpoints))
            self.assertIsNone(finding.unsaved_vulnerability_ids)

            # vuln 1
            finding = findings[1]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("No password for Grub", finding.title)
            self.assertEqual(4, len(finding.unsaved_endpoints))
            self.assertIsNone(finding.unsaved_vulnerability_ids)

            # vuln 2
            finding = findings[2]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("User home directory mode unsafe", finding.title)
            self.assertEqual(16, len(finding.unsaved_endpoints))
            self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_nexpose_parser_dns(self):
        with open(get_unit_tests_scans_path("nexpose") / "dns.xml", encoding="utf-8") as testfile:
            parser = NexposeParser()
            findings = parser.get_findings(testfile, Test())

            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            self.assertEqual(6, len(findings))
            # vuln 1
            finding = findings[1]
            self.assertEqual("DNS server allows cache snooping", finding.title)
            self.assertEqual(2, len(finding.unsaved_endpoints))
            self.assertEqual("dns", str(finding.unsaved_endpoints[0].protocol))
            self.assertEqual("tcp", str(finding.unsaved_endpoints[0].fragment))
            self.assertEqual("dns", str(finding.unsaved_endpoints[1].protocol))
            self.assertEqual("udp", str(finding.unsaved_endpoints[1].fragment))
            self.assertEqual("dns://192.168.1.1#tcp", str(finding.unsaved_endpoints[0]))
            self.assertEqual("dns://192.168.1.1#udp", str(finding.unsaved_endpoints[1]))

            # vuln 2
            finding = findings[2]
            self.assertEqual("Nameserver Processes Recursive Queries", finding.title)
            self.assertEqual(2, len(finding.unsaved_endpoints))
            self.assertEqual("dns", str(finding.unsaved_endpoints[0].protocol))
            self.assertEqual("tcp", str(finding.unsaved_endpoints[0].fragment))
            self.assertEqual("dns", str(finding.unsaved_endpoints[1].protocol))
            self.assertEqual("udp", str(finding.unsaved_endpoints[1].fragment))
            self.assertEqual("dns://192.168.1.1#tcp", str(finding.unsaved_endpoints[0]))
            self.assertEqual("dns://192.168.1.1#udp", str(finding.unsaved_endpoints[1]))

            # vuln 4
            finding = findings[4]
            self.assertEqual("DNS Traffic Amplification", finding.title)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            self.assertEqual("dns", str(finding.unsaved_endpoints[0].protocol))
            self.assertEqual("udp", str(finding.unsaved_endpoints[0].fragment))
            self.assertEqual("dns://192.168.1.1#udp", str(finding.unsaved_endpoints[0]))

    @override_settings(USE_FIRST_SEEN=True)
    def test_nexpose_parser_use_first_seen(self):
        with open(get_unit_tests_scans_path("nexpose") / "dns.xml", encoding="utf-8") as testfile:
            parser = NexposeParser()
            findings = parser.get_findings(testfile, Test())

            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            self.assertEqual(6, len(findings))
            finding = findings[2]
            self.assertEqual(datetime.datetime(2021, 2, 11, 16, 45, 6, 81000), finding.date, finding.title)
            finding = findings[4]
            self.assertEqual(datetime.datetime(2021, 2, 11, 16, 45, 6, 81000), finding.date, finding.title)
