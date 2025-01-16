from dojo.models import Test
from dojo.tools.auditjs.parser import AuditJSParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAuditJSParser(DojoTestCase):

    def test_auditjs_parser_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("auditjs") / "auditjs_zero_vul.json", encoding="utf-8") as testfile:
            parser = AuditJSParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_auditjs_parser_with_one_criticle_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("auditjs") / "auditjs_one_vul.json", encoding="utf-8") as testfile:
            parser = AuditJSParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            self.assertEqual("mysql", findings[0].component_name)
            self.assertEqual("2.0.0", findings[0].component_version)
            self.assertEqual(9.6, findings[0].cvssv3_score)
            self.assertEqual("Critical", findings[0].severity)
            self.assertEqual("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", findings[0].cvssv3)
            self.assertEqual("da5a3b11-c75b-48e7-9c28-1123f0a492bf", findings[0].unique_id_from_tool)
            self.assertEqual("Unverified Certificate", findings[0].title)
            self.assertEqual("> When using SSL to connect to a MySQL server, the SSL procedure implemented does not actually check if the remote server has a trusted certificate or not.\n> \n> -- [github.com](https://github.com/mysqljs/mysql/issues/816)",
                findings[0].description)
            self.assertEqual("https://ossindex.sonatype.org/vulnerability/da5a3b11-c75b-48e7-9c28-1123f0a492bf?component-type=npm&component-name=mysql&utm_source=auditjs&utm_medium=integration&utm_content=4.0.25",
                findings[0].references)

    def test_auditjs_parser_with_many_vuln_has_many_findings(self):
        with open(get_unit_tests_scans_path("auditjs") / "auditjs_many_vul.json", encoding="utf-8") as testfile:
            parser = AuditJSParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            # Notice that there are 13 vulnerabilities but 1 duplicate in this report
            self.assertEqual(12, len(findings))
            self.assertEqual("connect", findings[0].component_name)
            self.assertEqual("2.6.0", findings[0].component_version)
            self.assertEqual(5.4, findings[0].cvssv3_score)
            self.assertEqual("Medium", findings[0].severity)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", findings[0].cvssv3)
            self.assertEqual("7df31426-09a2-4b5f-a0ab-acc699023c57", findings[0].unique_id_from_tool)
            self.assertEqual("connect node module before 2.14.0 suffers from a Cross-Site Scripting (XSS) vulnerability due to a lack of validation of file in directory.js middleware.",
                findings[0].description)
            self.assertEqual("[CVE-2018-3717] connect node module before 2.14.0 suffers from a Cross-Site Scripting (XSS) vuln...",
                findings[0].title)
            self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2018-3717", findings[0].unsaved_vulnerability_ids[0])
            self.assertEqual("https://ossindex.sonatype.org/vulnerability/7df31426-09a2-4b5f-a0ab-acc699023c57?component-type=npm&component-name=connect&utm_source=auditjs&utm_medium=integration&utm_content=4.0.25",
                findings[0].references)
            self.assertEqual(400, findings[4].cwe)

    def test_auditjs_parser_empty_with_error(self):
        with self.assertRaises(ValueError) as context:
            with open(get_unit_tests_scans_path("auditjs") / "empty_with_error.json", encoding="utf-8") as testfile:
                parser = AuditJSParser()
                parser.get_findings(testfile, Test())

        self.assertIn(
            "Invalid JSON format. Are you sure you used --json option ?", str(context.exception),
        )

    def test_auditjs_parser_with_package_name_has_namespace(self):
        with open(get_unit_tests_scans_path("auditjs") / "auditjs_with_package_namespace.json", encoding="utf-8") as testfile:
            parser = AuditJSParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(1, len(findings))
            self.assertEqual("%40next/env", findings[0].component_name)
