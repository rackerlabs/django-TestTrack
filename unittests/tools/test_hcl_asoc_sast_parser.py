from dojo.tools.hcl_asoc_sast.parser import HCLASoCSASTParser
from unittests.dojo_test_case import DojoTestCase


class TestHCLASoCSASTParser(DojoTestCase):

    def test_no_findings(self):
        my_file_handle = open("unittests/scans/hcl_asoc_sast/no_issues.xml", encoding="utf-8")
        parser = HCLASoCSASTParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(0, len(findings))

    def test_one_finding(self):
        my_file_handle = open("unittests/scans/hcl_asoc_sast/one_issue.xml", encoding="utf-8")
        parser = HCLASoCSASTParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "PrivilegeEscalation")
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[0].cwe, 266)

    def test_many_findings(self):
        my_file_handle = open("unittests/scans/hcl_asoc_sast/many_issues.xml", encoding="utf-8")
        parser = HCLASoCSASTParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(83, len(findings))
        self.assertEqual(findings[0].title, "Authentication Bypass")
        self.assertEqual(findings[2].title, "Configuration")
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[9].severity, "High")
        self.assertEqual(findings[9].file_path, "sample-php/src/adminEditCodeLanguageForm.php")
        self.assertEqual(findings[5].line, 48)
        self.assertEqual(findings[9].cwe, 79)
