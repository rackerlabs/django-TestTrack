import datetime

from dojo.models import Engagement, Finding, Product, Test
from dojo.tools.generic.parser import GenericParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFile:

    def read(self):
        return self.content

    def __init__(self, name, content):
        self.name = name
        self.content = content


class TestGenericParser(DojoTestCase):

    def setUp(self):
        self.product = Product(name="sample product",
                               description="what a description")
        self.engagement = Engagement(name="sample engagement",
                                     product=self.product)
        self.test = Test(engagement=self.engagement)

    def test_parse_report1(self):
        with open(get_unit_tests_scans_path("generic") / "generic_report1.csv", encoding="utf-8") as file:
            parser = GenericParser()
            findings = parser.get_findings(file, self.test)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(5, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("vulnerable.endpoint.com", endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertEqual("resource1/asdf", endpoint.path)
            endpoint = finding.unsaved_endpoints[1]
            self.assertEqual("vulnerable.endpoint.com", endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertEqual("resource2/qwerty", endpoint.path)
            self.assertEqual("https", endpoint.protocol)

    def test_parse_no_csv_content_no_findings(self):
        findings = ""
        file = TestFile("findings.csv", findings)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        self.assertEqual(0, len(findings))

    def test_parse_csv_with_only_headers_results_in_no_findings(self):
        content = "Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified"
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        self.assertEqual(0, len(findings))

    def test_parse_csv_with_single_vulnerability_results_in_single_finding(
            self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/16,Potential XSS Vulnerability,79,,High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        self.assertEqual(1, len(findings))

    def test_parse_csv_with_multiple_vulnerabilities_results_in_multiple_findings(
            self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/16,Potential XSS Vulnerability,79,,High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE
11/7/16,Potential SQL Injection,112,,High,"FileName: UserData.cs
Description: Potential SQL Injection Vulnerability
Line:42
Code Line: strSQL=""SELECT * FROM users WHERE user_id="" + request_user_id",None,,,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        self.assertEqual(2, len(findings))

    def test_parse_csv_with_duplicates_results_in_single_findings(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/16,Potential XSS Vulnerability,79,,High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE
11/7/16,Potential XSS Vulnerability,79,,High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        self.assertEqual(1, len(findings))

    def test_parsed_finding_has_date(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,,High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        self.assertEqual(datetime.date(2015, 11, 7), findings[0].date)

    def test_parsed_finding_has_title(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,,High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        self.assertEqual("Potential XSS Vulnerability",
                         findings[0].title)

    def test_parsed_finding_has_cve(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified,CVE
11/7/2015,Potential XSS Vulnerability,79,,High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE,CVE-2021-26919
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
        self.assertEqual("CVE-2021-26919", findings[0].unsaved_vulnerability_ids[0])

    def test_parsed_finding_has_cwe(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,,High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        self.assertEqual(79, findings[0].cwe)

    def test_parsed_finding_has_url(self):
        """Test url management as an EndPoint"""
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            finding.clean()
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual(1, len(finding.unsaved_endpoints))
        endpoint = finding.unsaved_endpoints[0]
        self.assertEqual("localhost", endpoint.host)
        self.assertEqual(80, endpoint.port)
        self.assertEqual("http", endpoint.protocol)
        self.assertEqual("default.aspx", endpoint.path)
        self.assertIsNone(endpoint.query)
        self.assertIsNone(endpoint.fragment)
        self.assertEqual(True, finding.active)
        self.assertEqual(False, finding.verified)

    def test_parsed_finding_has_severity(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual("High", findings[0].severity)

    def test_parsed_finding_with_invalid_severity_has_info_severity(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",Unknown,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual("Info", findings[0].severity)

    def test_parsed_finding_has_description(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);",None,,,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(
            "FileName: default.aspx.cs\nDescription: Potential XSS Vulnerability\nLine:18\nCode Line: Response.Write(output);",
            findings[0].description)

    def test_parsed_finding_has_mitigation(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);","None Currently Available",,,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual("None Currently Available",
                         findings[0].mitigation)

    def test_parsed_finding_has_impact(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);","None Currently Available","Impact is currently unknown",,TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual("Impact is currently unknown",
                         findings[0].impact)

    def test_parsed_finding_has_references(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);","None Currently Available","Impact is currently unknown","Finding has references.",TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual("Finding has references.", findings[0].references)

    def test_parsed_finding_has_positive_active_status(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);","None Currently Available","Impact is currently unknown","Finding has references.",TRUE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(True, findings[0].active)

    def test_parsed_finding_has_negative_active_status(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);","None Currently Available","Impact is currently unknown","Finding has references.",FALSE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(False, findings[0].active)

    def test_parsed_finding_has_positive_verified_status(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);","None Currently Available","Impact is currently unknown","Finding has references.",FALSE,TRUE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(True, findings[0].verified)

    def test_parsed_finding_has_negative_verified_status(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);","None Currently Available","Impact is currently unknown","Finding has references.",FALSE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(False, findings[0].verified)

    def test_parsed_finding_has_positive_false_positive_status(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified,FalsePositive
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);","None Currently Available","Impact is currently unknown","Finding has references.",FALSE,FALSE,TRUE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(True, findings[0].false_p)

    def test_parsed_finding_has_negative_false_positive_status(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified,FalsePositive
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);","None Currently Available","Impact is currently unknown","Finding has references.",FALSE,FALSE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(False, findings[0].false_p)

    def test_parsed_finding_is_duplicate_has_positive_value(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified,FalsePositive,Duplicate
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);","None Currently Available","Impact is currently unknown","Finding has references.",FALSE,FALSE,FALSE,TRUE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(True, findings[0].duplicate)

    def test_parsed_finding_is_duplicate_has_negative_value(self):
        content = """Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified,FalsePositive,Duplicate
11/7/2015,Potential XSS Vulnerability,79,"http://localhost/default.aspx",High,"FileName: default.aspx.cs
Description: Potential XSS Vulnerability
Line:18
Code Line: Response.Write(output);","None Currently Available","Impact is currently unknown","Finding has references.",FALSE,FALSE,FALSE,FALSE
"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        findings = parser.get_findings(file, self.test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(False, findings[0].duplicate)

    def test_missing_columns_is_fine(self):
        content = """Date,Title,Url,Severity,Description,References,Active,Verified"""
        file = TestFile("findings.csv", content)
        parser = GenericParser()
        parser.get_findings(file, self.test)

    def test_column_order_is_flexible(self):
        content1 = """\
Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active,Verified
11/7/2015,Title,0,http://localhost,Severity,Description,Mitigation,Impact,References,True,True
"""
        content2 = """\
Verified,Date,Title,CweId,Url,Severity,Description,Mitigation,Impact,References,Active
True,11/7/2015,Title,0,http://localhost,Severity,Description,Mitigation,Impact,References,True
"""
        file1 = TestFile("findings.csv", content1)
        file2 = TestFile("findings.csv", content2)

        parser1 = GenericParser()
        findings1 = parser1.get_findings(file1, self.test)
        for finding in findings1:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        parser2 = GenericParser()
        findings2 = parser2.get_findings(file2, self.test)
        for finding in findings2:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

        finding1 = findings1[0]
        finding2 = findings2[0]

        fields1 = {k: v for k, v in finding1.__dict__.items() if k != "_state"}
        fields2 = {k: v for k, v in finding2.__dict__.items() if k != "_state"}

        self.assertEqual(fields1, fields2)

    def test_parse_json(self):
        with open(get_unit_tests_scans_path("generic") / "generic_report1.json", encoding="utf-8") as file:
            parser = GenericParser()
            findings = parser.get_findings(file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("test title", finding.title)
                self.assertEqual(True, finding.active)
                self.assertEqual(True, finding.verified)
                self.assertEqual(False, finding.duplicate)
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2020-36234", finding.unsaved_vulnerability_ids[0])
                self.assertEqual(261, finding.cwe)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)
                self.assertIn("security", finding.tags)
                self.assertIn("network", finding.tags)
                self.assertEqual("3287f2d0-554f-491b-8516-3c349ead8ee5", finding.unique_id_from_tool)
                self.assertEqual("TEST1", finding.vuln_id_from_tool)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("test title2", finding.title)
                self.assertEqual(True, finding.active)
                self.assertEqual(False, finding.verified)
                self.assertEqual(False, finding.duplicate)
                self.assertIn(finding.severity, Finding.SEVERITIES)

    def test_parse_json2(self):
        with open(get_unit_tests_scans_path("generic") / "generic_report2.json", encoding="utf-8") as file:
            parser = GenericParser()
            findings = parser.get_findings(file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("test title3", finding.title)
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2020-36234", finding.unsaved_vulnerability_ids[0])
                self.assertEqual(261, finding.cwe)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)
                self.assertEqual("Some mitigation", finding.mitigation)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("test title4", finding.title)
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertEqual("Some mitigation", finding.mitigation)

    def test_parse_json3(self):
        with open(get_unit_tests_scans_path("generic") / "generic_report3.json", encoding="utf-8") as file:
            parser = GenericParser()
            findings = parser.get_findings(file, Test())
            self.assertEqual(3, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                finding.clean()
                self.assertEqual("test title with endpoints as dict", finding.title)
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2020-36234", finding.unsaved_vulnerability_ids[0])
                self.assertEqual(261, finding.cwe)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)
                self.assertEqual("Some mitigation", finding.mitigation)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                endpoint.clean()
                self.assertEqual("exemple.com", endpoint.host)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("test title with endpoints as strings", finding.title)
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertEqual("Some mitigation", finding.mitigation)
                self.assertEqual(2, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                endpoint.clean()
                self.assertEqual("http", endpoint.protocol)
                self.assertEqual("urlfiltering.paloaltonetworks.com", endpoint.host)
                self.assertEqual(80, endpoint.port)
                self.assertEqual("test-command-and-control", endpoint.path)
                endpoint = finding.unsaved_endpoints[1]
                endpoint.clean()
                self.assertEqual("https", endpoint.protocol)
                self.assertEqual("urlfiltering.paloaltonetworks.com", endpoint.host)
                self.assertEqual(2345, endpoint.port)
                self.assertEqual("test-pest", endpoint.path)

    def test_parse_endpoints_and_vulnerability_ids_json(self):
        with open(get_unit_tests_scans_path("generic") / "generic_report4.json", encoding="utf-8") as file:
            parser = GenericParser()
            findings = parser.get_findings(file, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            finding.clean()
            self.assertEqual(4, len(finding.unsaved_endpoints))

            endpoint = finding.unsaved_endpoints[0]
            endpoint.clean()
            self.assertEqual("www.example.com", endpoint.host)

            endpoint = finding.unsaved_endpoints[1]
            endpoint.clean()
            self.assertEqual("localhost", endpoint.host)

            endpoint = finding.unsaved_endpoints[2]
            endpoint.clean()
            self.assertEqual("127.0.0.1", endpoint.host)
            self.assertEqual(80, endpoint.port)

            endpoint = finding.unsaved_endpoints[3]
            endpoint.clean()
            self.assertEqual("foo.bar", endpoint.host)
            self.assertEqual("path", endpoint.path)

            self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("GHSA-5mrr-rgp6-x4gr", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("CVE-2015-9235", finding.unsaved_vulnerability_ids[1])

    def test_parse_host_and_vulnerability_id_csv(self):
        with open(get_unit_tests_scans_path("generic") / "generic_report4.csv", encoding="utf-8") as file:
            parser = GenericParser()
            findings = parser.get_findings(file, Test())
            self.assertEqual(4, len(findings))

            finding = findings[0]
            finding.clean()
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            endpoint.clean()
            self.assertEqual("www.example.com", endpoint.host)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2015-9235", finding.unsaved_vulnerability_ids[0])

            finding = findings[1]
            finding.clean()
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            endpoint.clean()
            self.assertEqual("localhost", endpoint.host)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("GHSA-5mrr-rgp6-x4gr", finding.unsaved_vulnerability_ids[0])

            finding = findings[2]
            finding.clean()
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            endpoint.clean()
            self.assertEqual("127.0.0.1", endpoint.host)
            self.assertEqual(80, endpoint.port)
            self.assertIsNone(finding.unsaved_vulnerability_ids)

            finding = findings[3]
            finding.clean()
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            endpoint.clean()
            self.assertEqual("foo.bar", endpoint.host)
            self.assertEqual("path", endpoint.path)
            self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_parse_json_with_image(self):
        with open(get_unit_tests_scans_path("generic") / "test_with_image.json", encoding="utf-8") as file:
            parser = GenericParser()
            findings = parser.get_findings(file, Test())
            self.assertEqual(1, len(findings))

            finding = findings[0]
            finding.clean()
            self.assertEqual(1, len(finding.unsaved_files))
            image = finding.unsaved_files[0]
            self.assertEqual("Screenshot from 2017-04-10 16-54-19.png", image.get("title"))
            self.assertIn("data", image)

    def test_parse_json_custom_test(self):
        with open(get_unit_tests_scans_path("generic") / "generic_custom_test.json", encoding="utf-8") as file:
            parser = GenericParser()
            tests = parser.get_tests(parser.get_scan_types()[0], file)
            self.assertEqual(1, len(tests))
            findings = tests[0].findings
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("test title", finding.title)
                self.assertEqual(True, finding.active)
                self.assertEqual(True, finding.verified)
                self.assertEqual(False, finding.duplicate)
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertEqual("CVE-2020-36234", finding.cve)
                self.assertEqual(261, finding.cwe)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)
                self.assertIn("security", finding.tags)
                self.assertIn("network", finding.tags)
                self.assertEqual("3287f2d0-554f-491b-8516-3c349ead8ee5", finding.unique_id_from_tool)
                self.assertEqual("TEST1", finding.vuln_id_from_tool)

    def test_parse_json_empty_finding(self):
        with open(get_unit_tests_scans_path("generic") / "generic_empty.json", encoding="utf-8") as file:
            parser = GenericParser()
            with self.assertRaisesMessage(ValueError,
                    "Required fields are missing: ['description', 'severity', 'title']"):
                parser.get_findings(file, Test())

    def test_parse_json_invalid_finding(self):
        with open(get_unit_tests_scans_path("generic") / "generic_invalid.json", encoding="utf-8") as file:
            parser = GenericParser()
            with self.assertRaisesMessage(ValueError,
                    "Not allowed fields are present: ['invalid_field', 'last_status_update']"):
                parser.get_findings(file, Test())

    def test_parse_csv_with_epss(self):
        with open(get_unit_tests_scans_path("generic") / "generic_csv_with_epss.csv", encoding="utf-8") as file:
            parser = GenericParser()
            findings = parser.get_findings(file, self.test)
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(.00042, finding.epss_score)
            self.assertEqual(.23474, finding.epss_percentile)
