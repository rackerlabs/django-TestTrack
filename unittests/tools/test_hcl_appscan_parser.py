from dojo.tools.hcl_appscan.parser import HCLAppScanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestHCLAppScanParser(DojoTestCase):

    def test_no_findings(self):
        my_file_handle = open(get_unit_tests_scans_path("hcl_appscan") / "no_findings.xml", encoding="utf-8")
        parser = HCLAppScanParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(0, len(findings))

    def test_many_findings(self):
        my_file_handle = open(get_unit_tests_scans_path("hcl_appscan") / "many_findings.xml", encoding="utf-8")
        parser = HCLAppScanParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(60, len(findings))
        self.assertEqual(findings[0].title, "Unencrypted Login Request_mani-virtual-machine_/dvja-1.0-SNAPSHOT/register.action")
        self.assertEqual(findings[1].title, "Unencrypted Login Request_mani-virtual-machine_/dvja-1.0-SNAPSHOT/login.action;jsessionid=AD12F9CF7835CC92885A381859462BAC")
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[9].severity, "Medium")
        self.assertEqual(findings[1].description, "Issue-Type:attLoginNotOverSSL\nThreat-Class: catInsufficientTransLayerProtection\nEntity: 7521140967381157376\nSecurity-Risks: loginNotOverSSL\nCause-Id: sensitiveDataNotSSL\nIssue-Type-Name:Unencrypted Login Request\nLocation: http://mani-virtual-machine:9000/dvja-1.0-SNAPSHOT/login.action;jsessionid=AD12F9CF7835CC92885A381859462BAC\nDomain: mani-virtual-machine\nElement: password\nElementType: Parameter\nPath: /dvja-1.0-SNAPSHOT/login.action;jsessionid=AD12F9CF7835CC92885A381859462BAC\nScheme: http\nHost: mani-virtual-machine\nPort: 9000\n")
        self.assertEqual(findings[5].mitigation, "Remediation: fix_61640\nAdvisory: GD_autocompleteInForm")
        self.assertEqual(findings[9].cwe, 522)

    def test_issue_9279(self):
        my_file_handle = open(get_unit_tests_scans_path("hcl_appscan") / "issue_9279.xml", encoding="utf-8")
        parser = HCLAppScanParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(18, len(findings))
        self.assertEqual(findings[0].title, "attUnnecessaryResponseHeaders_7089695691196187648_insecureWebAppConfiguration")
        self.assertEqual(findings[1].title, "attHttpsToHttp_7089695691196187648_sensitiveDataNotSSL")
        self.assertEqual(findings[0].severity, "Low")
        self.assertEqual(findings[5].mitigation, "Remediation: fix_61771\nAdvisory: attReferrerPolicyHeaderExist")
        self.assertEqual(findings[1].description, "Issue-Type:attHttpsToHttp\nThreat-Class: catInformationLeakage\nEntity: 7089695691196187648\nSecurity-Risks: sensitiveNotOverSSL\nCause-Id: sensitiveDataNotSSL\n")
        self.assertEqual(findings[10].cwe, 1275)

    def test_issue_10074(self):
        with open(get_unit_tests_scans_path("hcl_appscan") / "issue_10074.xml", encoding="utf-8") as my_file_handle:
            parser = HCLAppScanParser()
            findings = parser.get_findings(my_file_handle, None)
            my_file_handle.close()
            self.assertEqual(4, len(findings))
            self.assertEqual(findings[0].severity, "Info")
