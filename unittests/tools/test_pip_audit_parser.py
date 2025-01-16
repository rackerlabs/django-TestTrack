from dojo.models import Test
from dojo.tools.pip_audit.parser import PipAuditParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPipAuditParser(DojoTestCase):

    def test_parser_empty(self):
        testfiles = [get_unit_tests_scans_path("pip_audit") / "empty.json",
                     get_unit_tests_scans_path("pip_audit") / "empty_new.json"]
        for path in testfiles:
            testfile = open(path, encoding="utf-8")
            parser = PipAuditParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(0, len(findings))

    def test_parser_zero_findings(self):
        testfiles = [get_unit_tests_scans_path("pip_audit") / "zero_vulns.json",
                     get_unit_tests_scans_path("pip_audit") / "zero_vulns_new.json"]
        for path in testfiles:
            testfile = open(path, encoding="utf-8")
            parser = PipAuditParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(0, len(findings))

    def test_parser_many_vulns(self):
        testfiles = [get_unit_tests_scans_path("pip_audit") / "many_vulns.json",
                     get_unit_tests_scans_path("pip_audit") / "many_vulns_new.json"]
        for path in testfiles:
            testfile = open(path, encoding="utf-8")
            parser = PipAuditParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(7, len(findings))

            finding = findings[0]
            self.assertEqual("PYSEC-2021-76 in aiohttp:3.6.2", finding.title)
            description = 'aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. In aiohttp before version 3.7.4 there is an open redirect vulnerability. A maliciously crafted link to an aiohttp-based web-server could redirect the browser to a different website. It is caused by a bug in the `aiohttp.web_middlewares.normalize_path_middleware` middleware. This security problem has been fixed in 3.7.4. Upgrade your dependency using pip as follows "pip install aiohttp >= 3.7.4". If upgrading is not an option for you, a workaround can be to avoid using `aiohttp.web_middlewares.normalize_path_middleware` in your applications.'
            self.assertEqual(description, finding.description)
            self.assertEqual(1395, finding.cwe)
            vulnerability_ids = finding.unsaved_vulnerability_ids
            self.assertEqual(1, len(vulnerability_ids))
            self.assertEqual("PYSEC-2021-76", vulnerability_ids[0])
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("Upgrade to version: 3.7.4", finding.mitigation)
            self.assertEqual("aiohttp", finding.component_name)
            self.assertEqual("3.6.2", finding.component_version)
            self.assertEqual("PYSEC-2021-76", finding.vuln_id_from_tool)

            finding = findings[1]
            self.assertEqual("PYSEC-2021-439 in django:3.2.9", finding.title)
            description = "In Django 2.2 before 2.2.25, 3.1 before 3.1.14, and 3.2 before 3.2.10, HTTP requests for URLs with trailing newlines could bypass upstream access control based on URL paths."
            self.assertEqual(description, finding.description)
            vulnerability_ids = finding.unsaved_vulnerability_ids
            self.assertEqual(1, len(vulnerability_ids))
            self.assertEqual("PYSEC-2021-439", vulnerability_ids[0])
            self.assertEqual(1395, finding.cwe)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("django", finding.component_name)
            self.assertEqual("3.2.9", finding.component_version)
            self.assertEqual("PYSEC-2021-439", finding.vuln_id_from_tool)

            finding = findings[2]
            self.assertEqual("PYSEC-2021-852 in lxml:4.6.4", finding.title)
            description = "lxml is a library for processing XML and HTML in the Python language. Prior to version 4.6.5, the HTML Cleaner in lxml.html lets certain crafted script content pass through, as well as script content in SVG files embedded using data URIs. Users that employ the HTML cleaner in a security relevant context should upgrade to lxml 4.6.5 to receive a patch. There are no known workarounds available."
            self.assertEqual(description, finding.description)
            vulnerability_ids = finding.unsaved_vulnerability_ids
            self.assertEqual(1, len(vulnerability_ids))
            self.assertEqual("PYSEC-2021-852", vulnerability_ids[0])
            self.assertEqual(1395, finding.cwe)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("lxml", finding.component_name)
            self.assertEqual("4.6.4", finding.component_version)
            self.assertEqual("PYSEC-2021-852", finding.vuln_id_from_tool)

            finding = findings[3]
            self.assertEqual("PYSEC-2019-128 in twisted:18.9.0", finding.title)

            finding = findings[4]
            self.assertEqual("PYSEC-2020-260 in twisted:18.9.0", finding.title)

            finding = findings[5]
            self.assertEqual("PYSEC-2019-129 in twisted:18.9.0", finding.title)

            finding = findings[6]
            self.assertEqual("PYSEC-2020-259 in twisted:18.9.0", finding.title)
