import datetime

from django.test import override_settings

from dojo.models import Endpoint, Engagement, Product, Product_Type, Test
from dojo.tools.veracode.parser import VeracodeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestVeracodeScannerParser(DojoTestCase):

    def setUp(self):
        product_type, _ = Product_Type.objects.get_or_create(name="Fake unit tests")
        product, _ = Product.objects.get_or_create(name="product", prod_type=product_type)
        engagement = Engagement(product=product)

        self.test = Test(engagement=engagement)

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_one_finding_first_seen(self):
        self.parse_file_with_one_finding()

    def test_parse_file_with_one_finding(self):
        self.parse_file_with_one_finding()

    def parse_file_with_one_finding(self):
        with open(get_unit_tests_scans_path("veracode") / "one_finding.xml", encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_many_findings_different_hash_code_different_unique_id_first_seen(self):
        self.parse_file_many_findings_different_hash_code_different_unique_id()

    def test_parse_file_many_findings_different_hash_code_different_unique_id(self):
        self.parse_file_many_findings_different_hash_code_different_unique_id()

    def parse_file_many_findings_different_hash_code_different_unique_id(self):
        with open(get_unit_tests_scans_path("veracode") / "many_findings_different_hash_code_different_unique_id.xml", encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(123, finding.cwe)
            self.assertEqual("catname", finding.title)
            self.assertFalse(finding.is_mitigated)
            self.assertEqual("sourcefilepathMyApp2.java", finding.file_path)
            self.assertEqual(2, finding.line)
            self.assertEqual("app-12345_issue-1", finding.unique_id_from_tool)
            finding = findings[1]
            self.assertEqual("Medium", finding.severity)
            self.assertTrue(finding.dynamic_finding)
            finding = findings[2]
            self.assertEqual("High", finding.severity)
            self.assertIsNone(finding.cwe)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-1234-1234", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("Vulnerable component: library:1234", finding.title)
            self.assertFalse(finding.is_mitigated)

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_multiple_finding_first_seen(self):
        self.parse_file_with_multiple_finding()

    def test_parse_file_with_multiple_finding(self):
        self.parse_file_with_multiple_finding()

    def parse_file_with_multiple_finding(self):
        with open(get_unit_tests_scans_path("veracode") / "many_findings.xml", encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(123, finding.cwe)
            self.assertEqual("catname", finding.title)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.is_mitigated)
            self.assertEqual("sourcefilepathMyApp.java", finding.file_path)
            self.assertEqual(2, finding.line)
            self.assertEqual("app-1234_issue-1", finding.unique_id_from_tool)
            self.assertIn("sast", finding.unsaved_tags)
            finding = findings[1]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(456, finding.cwe)
            self.assertTrue(finding.dynamic_finding)
            self.assertIn("dast", finding.unsaved_tags)
            finding = findings[2]
            self.assertEqual("High", finding.severity)
            self.assertIsNone(finding.cwe)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-1234-1234", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("Vulnerable component: library:1234", finding.title)
            self.assertFalse(finding.is_mitigated)
            self.assertIn("sca", finding.unsaved_tags)
            finding = findings[3]
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-5678-5678", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("Vulnerable component: library1:1234", finding.title)
            self.assertFalse(finding.is_mitigated)
            self.assertIn("sca", finding.unsaved_tags)

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_multiple_finding2_first_seen(self):
        finding = self.parse_file_with_multiple_finding2()
        self.assertEqual(datetime.datetime(2018, 2, 17, 0, 35, 18), finding.date)  # date_first_occurrence="2018-02-17 00:35:18 UTC"

    def test_parse_file_with_multiple_finding2(self):
        finding = self.parse_file_with_multiple_finding2()
        self.assertEqual(datetime.datetime.today().date(), finding.date)

    def parse_file_with_multiple_finding2(self):
        with open(get_unit_tests_scans_path("veracode") / "veracode_scan.xml", encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(7, len(findings))
            finding = findings[0]
            self.assertEqual("Information Exposure Through Sent Data", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(201, finding.cwe)
            finding = findings[1]
            self.assertEqual("Low", finding.severity)
            self.assertEqual(201, finding.cwe)
            self.assertEqual("/devTools/utility.jsp", finding.file_path)
            self.assertEqual(361, finding.line)
            self.assertIsNone(finding.component_name)
            self.assertIsNone(finding.component_version)
            # finding 6
            finding = findings[6]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2012-6153", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(20, finding.cwe)
            self.assertEqual("commons-httpclient", finding.component_name)
            self.assertEqual("3.1", finding.component_version)
            self.assertEqual(4.3, finding.cvssv3_score)
            return findings[0]

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_mitigated_finding_first_seen(self):
        self.parse_file_with_mitigated_finding()

    def test_parse_file_with_mitigated_finding(self):
        self.parse_file_with_mitigated_finding()

    def parse_file_with_mitigated_finding(self):
        with open(get_unit_tests_scans_path("veracode") / "mitigated_finding.xml", encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, self.test)
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertTrue(finding.is_mitigated)
            self.assertEqual(datetime.datetime(2020, 6, 1, 10, 2, 1), finding.mitigated)
            self.assertEqual("app-1234_issue-1", finding.unique_id_from_tool)
            self.assertEqual(0, finding.sla_age)

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_mitigated_fixed_finding_first_seen(self):
        self.parse_file_with_mitigated_fixed_finding()

    def test_parse_file_with_mitigated_fixed_finding(self):
        self.parse_file_with_mitigated_fixed_finding()

    def parse_file_with_mitigated_fixed_finding(self):
        with open(get_unit_tests_scans_path("veracode") / "mitigated_fixed_finding.xml", encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertTrue(finding.is_mitigated)
            self.assertEqual("app-1234_issue-1", finding.unique_id_from_tool)

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_mitigated_sca_finding_first_seen(self):
        self.parse_file_with_mitigated_sca_finding()

    def test_parse_file_with_mitigated_sca_finding(self):
        self.parse_file_with_mitigated_sca_finding()

    def parse_file_with_mitigated_sca_finding(self):
        with open(get_unit_tests_scans_path("veracode") / "veracode_scan_sca_mitigated.xml", encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertTrue(finding.is_mitigated)
            self.assertEqual(datetime.datetime(2022, 9, 12, 14, 29, 18), finding.mitigated)

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_dynamic_finding_first_seen(self):
        finding = self.parse_file_with_dynamic_finding()
        self.assertEqual(datetime.datetime(2021, 9, 3, 10, 0, 0), finding.date)

    def test_parse_file_with_dynamic_finding(self):
        finding = self.parse_file_with_dynamic_finding()
        self.assertEqual(datetime.datetime.today().date(), finding.date)

    def parse_file_with_dynamic_finding(self):
        with open(get_unit_tests_scans_path("veracode") / "dynamic_finding.xml", encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(456, finding.cwe)
            self.assertTrue(finding.dynamic_finding)
            self.assertEqual("catname", finding.title)
            self.assertEqual("Description", finding.description)
            self.assertFalse(finding.is_mitigated)
            self.assertIn("dast", finding.unsaved_tags)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("https", endpoint.protocol)
            self.assertEqual("www.example.com", endpoint.host)
            self.assertEqual("index.html", endpoint.path)

            return finding

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_changed_severity_first_seen(self):
        self.parse_file_with_changed_severity()

    def test_parse_file_with_changed_severity(self):
        self.parse_file_with_changed_severity()

    def parse_file_with_changed_severity(self):
        with open(get_unit_tests_scans_path("veracode") / "veracode_scan_changed_severity.xml", encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(7, len(findings))
            # finding 6
            finding = findings[6]
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2012-6153", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(20, finding.cwe)
            self.assertEqual("commons-httpclient", finding.component_name)
            self.assertEqual("3.1", finding.component_version)
            self.assertEqual(4.3, finding.cvssv3_score)

    @override_settings(USE_FIRST_SEEN=True)
    def test_maven_component_name_first_seen(self):
        self.maven_component_name()

    def test_maven_component_name(self):
        self.maven_component_name()

    def maven_component_name(self):
        with open(get_unit_tests_scans_path("veracode") / "veracode_maven.xml", encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2022-41852", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("commons-jxpath", finding.component_name)
            self.assertEqual("1.3", finding.component_version)
            self.assertEqual(9.8, finding.cvssv3_score)

    def json_static_findings_test(self, file_name):
        with open(file_name, encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            finding = findings[0]
            self.assertEqual(finding.title, "Cross-Site Scripting (XSS)")
            self.assertEqual(finding.severity, "Medium")
            self.assertEqual(finding.cwe, 80)
            self.assertEqual(finding.description, (
                "### Meta Information\n"
                "**Exploitability Predication**: Likely\n"
                "**Attack Vector**: page.html\n"
                "**Module**: CoolProduct.jsa\n"
                "### Details\n"
                "This call to page.html() contains a cross-site scripting "
                "(XSS) flaw.  The application populates the HTTP response with "
                "untrusted input, allowing an attacker to embed malicious "
                "content, such as Javascript code, which will be executed in "
                "the context of the victim's browser.  XSS vulnerabilities are "
                "commonly exploited to steal or manipulate cookies, modify "
                "presentation of content, and compromise confidential "
                "information, with new attack vectors being discovered on a "
                "regular basis."
            ))
            self.assertEqual(finding.mitigation, (
                "Use contextual escaping on all untrusted data before using it "
                "to construct any portion of an HTTP response.  The escaping "
                "method should be chosen based on the specific use case of the "
                "untrusted data, otherwise it may not protect fully against the "
                "attack. For example, if the data is being written to the body "
                "of an HTML page, use HTML entity escaping; if the data is "
                "being written to an attribute, use attribute escaping; etc.  "
                "Both the OWASP Java Encoder library and the Microsoft AntiXSS "
                "library provide contextual escaping methods. For more details "
                "on contextual escaping, see "
                "https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md. "
                "In addition, as a best practice, always validate untrusted "
                "input to ensure that it conforms to the expected format, using "
                "centralized data validation routines when possible."
            ))
            self.assertEqual(finding.references, (
                "- [CWE](https://cwe.mitre.org/data/definitions/79.html)\n"
                "- [OWASP](https://owasp.org/www-community/attacks/xss/)\n"
                "- [Supported Cleansers](https://docs.veracode.com/r/review_cleansers)\n"
            ))
            self.assertEqual(finding.line, 50)
            self.assertEqual(finding.sast_source_line, 50)
            self.assertEqual(finding.sast_sink_line, 50)
            self.assertEqual(finding.file_path, "/WEB-INF/views/contact.jsp")
            self.assertEqual(finding.sast_source_file_path, "/WEB-INF/views/contact.jsp")
            self.assertEqual(finding.sast_sink_file_path, "/WEB-INF/views/contact.jsp")
            self.assertEqual(finding.sast_source_object, "lambda_3")
            self.assertEqual(finding.sast_sink_object, "lambda_3")
            self.assertEqual(finding.unsaved_tags, ["policy-violation"])

    @override_settings(USE_FIRST_SEEN=True)
    def test_json_static_findings_list_format_first_seen(self):
        self.json_static_findings_list_format()

    def test_json_static_findings_list_format(self):
        self.json_static_findings_list_format()

    def json_static_findings_list_format(self):
        self.json_static_findings_test(get_unit_tests_scans_path("veracode") / "static_findings_list_format.json")

    @override_settings(USE_FIRST_SEEN=True)
    def test_json_static_embedded_format_first_seen(self):
        self.json_static_embedded_format()

    def test_json_static_embedded_format(self):
        self.json_static_embedded_format()

    def json_static_embedded_format(self):
        self.json_static_findings_test(get_unit_tests_scans_path("veracode") / "static_embedded_format.json")

    def json_dynamic_findings_test(self, file_name):
        with open(file_name, encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            finding = findings[0]
            self.assertEqual(finding.title, "Code Injection")
            self.assertEqual(finding.severity, "High")
            self.assertEqual(finding.cwe, 74)
            self.assertEqual(finding.description, (
                "### Meta Information\n"
                "**Plugin**: Code Injection\n"
                "**Attack Vector**: Improper Neutralization of Special "
                "Elements in Output Used by a Downstream Component "
                "('Injection')\n"
                "**Vulnerable Parameter**: api\n"
                "### Details\n"
                "Injections happen when untrusted data is inserted into an "
                "interpreted syntax and subsequently evaluated on the server "
                "side. This syntax may be a SQL query, a parsed JSON or XML "
                "document, an executed script or other syntax that may be in "
                "use within the application. Although the target syntax has "
                "not been identified, the application behavior demonstrates "
                "that the input HTTP parameter may be inserted without proper "
                "escaping. It was observed by sending valid and invalid "
                "payloads that should throw or should not throw errors. By "
                "inserting a proper and improper comments such as ``, `*/_/*`, "
                "`/*_*/` into the `api` parameter, the scanner was able to "
                "spot a difference in the responses, which is a good indicator "
                "of a potential vulnerability. Confidence: medium. Response "
                "codes: `404`, `404`, `404`. Similarities: `` vs `*/_/*`: 0.0; "
                "`*/_/*` vs `/*_*/`: 0.0; `` vs `/*_*/`: 1.0."
            ))
            self.assertEqual(finding.mitigation, (
                "It is recommended to identify how the current parameter is "
                "used in the application source code, and make sure it is "
                "escaped before inserting into any syntax or query. You can add "
                "valid values to an allowlist and invalid values to a "
                "blocklist."
            ))
            self.assertEqual(finding.references, (
                "- [CWE](http://cwe.mitre.org/cgi-bin/jumpmenu.cgi?id=74)\n"
            ))
            self.assertEqual(finding.unsaved_tags, ["policy-violation"])
            self.assertEqual(finding.unsaved_endpoints[0], Endpoint(
                protocol="https",
                host="application.insecure-company-alliance.com",
                port=443,
                path="api/*_*//new_user_sign_up",
                query="param=wild-things",
            ))

    @override_settings(USE_FIRST_SEEN=True)
    def test_json_dynamic_findings_list_format_first_seen(self):
        self.json_dynamic_findings_list_format()

    def test_json_dynamic_findings_list_format(self):
        self.json_dynamic_findings_list_format()

    def json_dynamic_findings_list_format(self):
        self.json_dynamic_findings_test(get_unit_tests_scans_path("veracode") / "dynamic_findings_list_format.json")

    @override_settings(USE_FIRST_SEEN=True)
    def test_json_dynamic_embedded_format_first_seen(self):
        self.json_dynamic_embedded_format()

    def test_json_dynamic_embedded_format(self):
        self.json_dynamic_embedded_format()

    def json_dynamic_embedded_format(self):
        self.json_dynamic_findings_test(get_unit_tests_scans_path("veracode") / "dynamic_embedded_format.json")

    def json_sca_findings_test(self, file_name):
        with open(file_name, encoding="utf-8") as testfile:
            parser = VeracodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(7, len(findings))
            finding = findings[0]
            self.assertEqual(finding.title, "Uncontrolled Resource Consumption")
            self.assertEqual(finding.severity, "High")
            self.assertEqual(finding.cwe, 400)
            self.assertEqual(finding.description, (
                "### Meta Information\n"
                "**Product ID**: abc123-bca321\n"
                "**Component ID**: efg456-gfe654\n"
                "**Language**: JAVA\n"
                "#### Component Locations\n"
                "- path/to/alpha/spring-boot-autoconfigure-2.5.14.jar\n"
                "- path/to/beta/spring-boot-autoconfigure-2.5.14.jar\n"
                "- path/to/charlie/spring-boot-autoconfigure-2.5.14.jar\n"
                "- path/to/delta/spring-boot-autoconfigure-2.5.14.jar\n"
                "#### Licenses\n"
                "- apache-2.0: Low\n"
                "    - Low-risk licenses are typically permissive licenses "
                "that require you to preserve the copyright and license "
                "notices, but allow distribution under different terms without "
                "disclosing source code.\n"
                "### Details\n"
                "spring-boot-autoconfigure is vulnerable to Denial Of Service "
                "(DoS). The vulnerability is applicable when the application "
                "has Spring MVC auto-configuration enabled and uses the Spring "
                "Boot welcome page, which can be either static or templated, "
                "and the application is deployed behind a proxy which caches "
                "the 404 responses. An attacker can cause the application to "
                "crash by submitting a request to the welcome page which the "
                "server is unable to properly respond to."
            ))
            self.assertEqual(finding.cvssv3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
            self.assertEqual(finding.component_name, "spring-boot-autoconfigure.jar")
            self.assertEqual(finding.component_version, "2.5.14")
            self.assertEqual(finding.unsaved_tags, ["policy-violation"])
            self.assertEqual(finding.unsaved_vulnerability_ids, ["CVE-2023-20883"])
            finding = findings[3]
            self.assertEqual(finding.title, "inflight - SRCCLR-SID-41137")
            self.assertEqual(finding.severity, "Medium")
            self.assertEqual(finding.cwe, 0)
            self.assertEqual(finding.description, (
                "### Meta Information\n"
                "**Product ID**: abc123-bca321\n"
                "**Component ID**: efg456-gfe654\n"
                "**Language**: JAVASCRIPT\n"
                "#### Component Locations\n"
                "- path/to/alpha/node_modules:inflight\n"
                "#### Licenses\n"
                "- isc: Low\n"
                "    - Low-risk licenses are typically permissive licenses "
                "that require you to preserve the copyright and license "
                "notices, but allow distribution under different terms without "
                "disclosing source code.\n"
                "### Details\n"
                "inflight is vulnerable to a Memory Leak. The vulnerability is "
                "caused by improper memory management due to a lack of "
                "resource freeing, which can result in Denial of Service "
                "conditions."
            ))
            self.assertEqual(finding.cvssv3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
            self.assertEqual(finding.component_name, "inflight")
            self.assertEqual(finding.component_version, "1.0.6")
            self.assertEqual(finding.unsaved_tags, ["policy-violation"])
            self.assertEqual(finding.unsaved_vulnerability_ids, ["SRCCLR-SID-41137"])

    @override_settings(USE_FIRST_SEEN=True)
    def test_json_sca_findings_list_format_first_seen(self):
        self.json_sca_findings_list_format()

    def test_json_sca_findings_list_format(self):
        self.json_sca_findings_list_format()

    def json_sca_findings_list_format(self):
        self.json_sca_findings_test(get_unit_tests_scans_path("veracode") / "sca_findings_list_format.json")

    @override_settings(USE_FIRST_SEEN=True)
    def test_json_sca_embedded_format_first_seen(self):
        self.json_sca_embedded_format()

    def test_json_sca_embedded_format(self):
        self.json_sca_embedded_format()

    def json_sca_embedded_format(self):
        self.json_sca_findings_test(get_unit_tests_scans_path("veracode") / "sca_embedded_format.json")
