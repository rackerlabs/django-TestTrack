from dojo.models import Finding, Test
from dojo.tools.zap.parser import ZapParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestZapParser(DojoTestCase):
    def test_parse_no_findings(self):
        with open(get_unit_tests_scans_path("zap") / "empty_2.9.0.xml", encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(0, len(findings))

    def test_parse_some_findings(self):
        with open(get_unit_tests_scans_path("zap") / "some_2.9.0.xml", encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(7, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

    def test_parse_some_findings_0(self):
        with open(get_unit_tests_scans_path("zap") / "0_zap_sample.xml", encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(4, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

    def test_parse_some_findings_1(self):
        with open(get_unit_tests_scans_path("zap") / "1_zap_sample_0_and_new_absent.xml", encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(4, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

    def test_parse_some_findings_2(self):
        with open(get_unit_tests_scans_path("zap") / "2_zap_sample_0_and_new_endpoint.xml", encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(4, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

    def test_parse_some_findings_3(self):
        with open(get_unit_tests_scans_path("zap") / "3_zap_sampl_0_and_different_severities.xml", encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(4, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

    def test_parse_some_findings_5(self):
        with open(get_unit_tests_scans_path("zap") / "5_zap_sample_one.xml", encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(2, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

    def test_parse_issue4360(self):
        """
        Report from GitHub issue 4360
        see: https://github.com/DefectDojo/django-DefectDojo/issues/4360
        """
        with open(get_unit_tests_scans_path("zap") / "dvwa_baseline_dojo.xml", encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(19, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("X-Frame-Options Header Not Set", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("10020", finding.vuln_id_from_tool)
                self.assertEqual(11, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual("172.17.0.2", endpoint.host)
                self.assertEqual(80, endpoint.port)
                endpoint = finding.unsaved_endpoints[1]
                self.assertEqual("http", endpoint.protocol)
                self.assertEqual("172.17.0.2", endpoint.host)
                self.assertEqual("vulnerabilities/sqli_blind/", endpoint.path)
            with self.subTest(i=18):
                finding = findings[18]
                self.assertEqual("Private IP Disclosure", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual("2", finding.vuln_id_from_tool)
                self.assertEqual(3, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]

    def test_parse_issue4697(self):
        """
        Report from GitHub issue 4697
        see: https://github.com/DefectDojo/django-DefectDojo/issues/4697
        """
        with open(get_unit_tests_scans_path("zap") / "zap-results-first-scan.xml", encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertIsInstance(findings, list)
            self.assertEqual(15, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("User Controllable HTML Element Attribute (Potential XSS)", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("10031", finding.vuln_id_from_tool)
                self.assertEqual(11, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual("http", endpoint.protocol)
                self.assertEqual("bodgeit.securecodebox-demo.svc", endpoint.host)
                self.assertEqual(8080, endpoint.port)
                endpoint = finding.unsaved_endpoints[1]
                self.assertEqual("http", endpoint.protocol)
                self.assertEqual("bodgeit.securecodebox-demo.svc", endpoint.host)
                self.assertEqual("bodgeit/product.jsp", endpoint.path)
            with self.subTest(i=14):
                finding = findings[14]
                self.assertEqual("PII Disclosure", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("10062", finding.vuln_id_from_tool)
                self.assertEqual(359, finding.cwe)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual("http", endpoint.protocol)
                self.assertEqual("bodgeit.securecodebox-demo.svc", endpoint.host)
                self.assertEqual("bodgeit/contact.jsp", endpoint.path)

    def test_parse_juicy(self):
        """Generated with OWASP Juicy shop"""
        with open(get_unit_tests_scans_path("zap") / "juicy2.xml", encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertIsInstance(findings, list)
            self.assertEqual(6, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Incomplete or No Cache-control Header Set", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual("10015", finding.vuln_id_from_tool)
                self.assertEqual(20, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual("https", endpoint.protocol)
                self.assertEqual("juice-shop.herokuapp.com", endpoint.host)
                self.assertEqual(443, endpoint.port)
                endpoint = finding.unsaved_endpoints[1]
                self.assertEqual("https", endpoint.protocol)
                self.assertEqual("juice-shop.herokuapp.com", endpoint.host)
                self.assertEqual("assets/public/polyfills-es2018.js", endpoint.path)
            with self.subTest(i=5):
                finding = findings[5]
                self.assertEqual("CSP: Wildcard Directive", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("10055", finding.vuln_id_from_tool)
                self.assertEqual(693, finding.cwe)
                self.assertEqual(2, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual("https", endpoint.protocol)
                self.assertEqual("juice-shop.herokuapp.com", endpoint.host)
                self.assertEqual("assets", endpoint.path)

    def test_parse_xml_plus_format(self):
        with open(get_unit_tests_scans_path("zap") / "zap-xml-plus-format.xml", encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertIsInstance(findings, list)
            self.assertEqual(1, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Insecure HTTP Method - PUT", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("90028", finding.vuln_id_from_tool)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual("http", endpoint.protocol)
                self.assertEqual("localhost", endpoint.host)
                self.assertEqual(8080, endpoint.port)
                # Check request and response pair
                request_pair = finding.unsaved_req_resp[0]
                request = request_pair["req"]
                response = request_pair["resp"]
                self.assertEqual('HTTP/1.1 403 Forbidden\nServer: Apache-Coyote/1.1\nContent-Type: text/html;charset=utf-8\nContent-Language: en\nContent-Length: 1004\nDate: Fri, 30 Sep 2022 06:40:15 GMT\n\n<!DOCTYPE html><html><head><title>Apache Tomcat/8.0.37 - Error report</title><style type="text/css">H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} P {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;}A {color : black;}A.name {color : black;}.line {height: 1px; background-color: #525D76; border: none;}</style> </head><body><h1>HTTP Status 403 - </h1><div class="line"></div><p><b>type</b> Status report</p><p><b>message</b> <u></u></p><p><b>description</b> <u>Access to the specified resource has been forbidden.</u></p><hr class="line"><h3>Apache Tomcat/8.0.37</h3></body></html>', response)
                self.assertEqual('PUT http://localhost:8080/bodgeit/js/qndto7n63d HTTP/1.1\nHost: localhost:8080\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0\nAccept: */*\nAccept-Language: de,en-US;q=0.7,en;q=0.3\nConnection: keep-alive\nReferer: https://localhost:8080/bodgeit/\nCookie: JSESSIONID=9E75E26E50F681208096FFAA0B566901\nSec-Fetch-Dest: script\nSec-Fetch-Mode: no-cors\nSec-Fetch-Site: same-origin\nContent-Length: 35\n\n"J0O0glajHdR0Mgp":"UToh9IpCY5zh3CB"', request)
