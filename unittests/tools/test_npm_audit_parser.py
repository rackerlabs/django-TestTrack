
from dojo.models import Test
from dojo.tools.npm_audit.parser import NpmAuditParser, censor_path_hashes
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNpmAuditParser(DojoTestCase):
    def test_npm_audit_parser_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("npm_audit") / "no_vuln.json", encoding="utf-8") as testfile:
            parser = NpmAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_npm_audit_parser_with_one_criticle_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("npm_audit") / "one_vuln.json", encoding="utf-8") as testfile:
            parser = NpmAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.assertEqual(94, findings[0].cwe)
            self.assertEqual("growl", findings[0].component_name)
            self.assertEqual("1.9.2", findings[0].component_version)

    def test_npm_audit_parser_with_many_vuln_has_many_findings(self):
        with open(get_unit_tests_scans_path("npm_audit") / "many_vuln.json", encoding="utf-8") as testfile:
            parser = NpmAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            for find in findings:
                if find.file_path == "censored_by_npm_audit>send>mime":
                    self.assertEqual(1, len(find.unsaved_vulnerability_ids))
                    self.assertEqual("CVE-2017-16138", find.unsaved_vulnerability_ids[0])
                if find.file_path == "express>fresh":
                    self.assertEqual(1, len(find.unsaved_vulnerability_ids))
                    self.assertEqual("CVE-2017-16119", find.unsaved_vulnerability_ids[0])
            self.assertEqual("mime", findings[4].component_name)
            self.assertEqual("1.3.4", findings[4].component_version)

    def test_npm_audit_parser_multiple_cwes_per_finding(self):
        # cwes formatted as escaped list: "cwe": "[\"CWE-346\",\"CWE-453\"]",
        with open(get_unit_tests_scans_path("npm_audit") / "multiple_cwes.json", encoding="utf-8") as testfile:
            parser = NpmAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(41, len(findings))
            self.assertEqual(400, findings[0].cwe)
            self.assertEqual(359, findings[12].cwe)

    def test_npm_audit_parser_multiple_cwes_per_finding_list(self):
        # cwes formatted as proper list: "cwe": ["CWE-918","CWE-1333"],
        with open(get_unit_tests_scans_path("npm_audit") / "multiple_cwes2.json", encoding="utf-8") as testfile:
            parser = NpmAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(6, len(findings))
            self.assertEqual(918, findings[0].cwe)

    def test_npm_audit_parser_with_one_criticle_vuln_has_null_as_cwe(self):
        with open(get_unit_tests_scans_path("npm_audit") / "cwe_null.json", encoding="utf-8") as testfile:
            parser = NpmAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.assertEqual(1035, findings[0].cwe)
            self.assertEqual("growl", findings[0].component_name)
            self.assertEqual("1.9.2", findings[0].component_version)

    def test_npm_audit_parser_empty_with_error(self):
        with self.assertRaises(ValueError) as context, \
          open(get_unit_tests_scans_path("npm_audit") / "empty_with_error.json", encoding="utf-8") as testfile:
            parser = NpmAuditParser()
            parser.get_findings(testfile, Test())

        self.assertIn("npm audit report contains errors:", str(context.exception))
        self.assertIn("ENOAUDIT", str(context.exception))

    def test_npm_audit_parser_many_vuln_npm7(self):
        with self.assertRaises(ValueError) as context, \
          open(get_unit_tests_scans_path("npm_audit") / "many_vuln_npm7.json", encoding="utf-8") as testfile:
            parser = NpmAuditParser()
            parser.get_findings(testfile, Test())

        self.assertIn("npm7 with auditReportVersion 2 or higher not yet supported", str(context.exception))

    def test_npm_audit_censored_hash(self):
        path = "77d76e075ae87483063c4c74885422f98300f9fc0ecbd3b8dfb60152a36e5269>axios"
        censored_path = censor_path_hashes(path)
        self.assertEqual(censored_path, "censored_by_npm_audit>axios")

        path = "7f888b06cc55dd893be344958d300da5ca1d84eebd0928d8bcb138b4029eff9f>c748e76b6a1b63450590f72e14f9b53ad357bc64632ff0bda73d00799c4a0a91>lodash"
        censored_path = censor_path_hashes(path)
        self.assertEqual(censored_path, "censored_by_npm_audit>censored_by_npm_audit>lodash")

    def test_npm_audit_parser_issue_7897(self):
        with open(get_unit_tests_scans_path("npm_audit") / "issue_7897.json", encoding="utf-8") as testfile:
            parser = NpmAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))
