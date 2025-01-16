from dojo.models import Test
from dojo.tools.snyk.parser import SnykParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSnykParser(DojoTestCase):

    def test_snykParser_single_has_no_finding(self):
        testfile = open(get_unit_tests_scans_path("snyk") / "single_project_no_vulns.json", encoding="utf-8")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))
        testfile.close()

    def test_snykParser_allprojects_has_no_finding(self):
        testfile = open(get_unit_tests_scans_path("snyk") / "all-projects_no_vulns.json", encoding="utf-8")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))
        testfile.close()

    def test_snykParser_single_has_one_finding(self):
        testfile = open(get_unit_tests_scans_path("snyk") / "single_project_one_vuln.json", encoding="utf-8")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        testfile.close()

    def test_snykParser_allprojects_has_one_finding(self):
        testfile = open(get_unit_tests_scans_path("snyk") / "all-projects_one_vuln.json", encoding="utf-8")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_snykParser_single_has_many_findings(self):
        testfile = open(get_unit_tests_scans_path("snyk") / "single_project_many_vulns.json", encoding="utf-8")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(41, len(findings))

    def test_snykParser_allprojects_has_many_findings(self):
        testfile = open(get_unit_tests_scans_path("snyk") / "all-projects_many_vulns.json", encoding="utf-8")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))

    def test_snykParser_finding_has_fields(self):
        testfile = open(get_unit_tests_scans_path("snyk") / "single_project_one_vuln.json", encoding="utf-8")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        finding = findings[0]
        self.assertEqual(
            "com.test:myframework@1.0.0-SNAPSHOT: XML External Entity (XXE) Injection",
            finding.title,
        )
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(
            "Issue severity of: **Medium** from a base CVSS score of: **6.5**",
            finding.severity_justification,
        )
        self.assertEqual(
            "SNYK-JAVA-ORGAPACHESANTUARIO-460281", finding.vuln_id_from_tool,
        )
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2019-12400", finding.unsaved_vulnerability_ids[0])
        self.assertEqual(611, finding.cwe)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L", finding.cvssv3)
        self.assertEqual(
            "## Remediation\nUpgrade `org.apache.santuario:xmlsec` to version 2.1.4 or higher.\n\n"
            + "Upgrade Location: pom.xml\n"
            + "Upgrade from org.apache.santuario:xmlsec@2.1.1 to org.apache.santuario:xmlsec@2.1.4 to fix this issue, as well as updating the following:\n - org.apache.santuario:xmlsec@2.1.1",
            finding.mitigation,
        )
        self.assertEqual(
            "**SNYK ID**: https://app.snyk.io/vuln/SNYK-JAVA-ORGAPACHESANTUARIO-460281\n\n**GitHub "
            + "Commit**: https://github.com/apache/santuario-java/commit/52ae824cf5f5c873a0e37bb33fedcc3b387"
            + "cdba6\n**GitHub Commit**: https://github.com/apache/santuario-java/commit/c5210f77a77105fba81"
            + "311d16c07ceacc21f39d5\n**Possible Jira Issue**: https://issues.apache.org/jira/browse/SANTUARIO-"
            + "504?jql=project%20%3D%20SANTUARIO\n**Security Release**: http://santuario.apache.org/secadv.data/"
            + "CVE-2019-12400.asc?version=1&modificationDate=1566573083000&api=v2\n",
            finding.references,
        )
        self.assertEqual(
            "com.test:myframework > org.apache.santuario:xmlsec", finding.file_path,
        )

    def test_snykParser_file_path_with_ampersand_is_preserved(self):
        testfile = open(get_unit_tests_scans_path("snyk") / "single_project_one_vuln_with_ampersands.json", encoding="utf-8")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual(
            "myproject > @angular/localize > @babel/core > lodash",
            finding.file_path,
        )

    def test_snykParser_allprojects_issue4277(self):
        """Report to linked to issue 4277"""
        testfile = open(get_unit_tests_scans_path("snyk") / "all_projects_issue4277.json", encoding="utf-8")
        parser = SnykParser()
        findings = list(parser.get_findings(testfile, Test()))
        testfile.close()
        self.assertEqual(82, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("Microsoft.AspNetCore", finding.component_name)
            self.assertEqual("2.2.0", finding.component_version)
            self.assertEqual("SNYK-DOTNET-MICROSOFTASPNETCORE-174184", finding.vuln_id_from_tool)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2019-0815", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(200, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", finding.cvssv3)
        with self.subTest(i=40):
            finding = findings[40]
            self.assertEqual("High", finding.severity)
            self.assertEqual("lodash", finding.component_name)
            self.assertEqual("4.17.11", finding.component_version)
            self.assertEqual("SNYK-JS-LODASH-1040724", finding.vuln_id_from_tool)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2021-23337", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(78, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:P/RL:U/RC:C", finding.cvssv3)
        with self.subTest(i=81):
            finding = findings[81]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("yargs-parser", finding.component_name)
            self.assertEqual("5.0.0", finding.component_version)
            self.assertEqual("SNYK-JS-YARGSPARSER-560381", finding.vuln_id_from_tool)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2020-7608", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(400, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C", finding.cvssv3)

    def test_snykParser_cvssscore_none(self):
        with open(get_unit_tests_scans_path("snyk") / "single_project_None_cvss.json", encoding="utf-8") as testfile:
            parser = SnykParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual(
                "SNYK-SLES153-PERMISSIONS-2648113", finding.vuln_id_from_tool,
            )

    def test_snykParser_target_file(self):
        with open(get_unit_tests_scans_path("snyk") / "all_containers_target_output.json", encoding="utf-8") as testfile:
            parser = SnykParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(40, len(findings))
            # Mobile-Security-Framework-MobSF@0.0.0: SQL Injection
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertIn("target_file:Mobile-Security-Framework-MobSF/requirements.txt", finding.unsaved_tags)

    def test_snykParser_update_libs_tag(self):
        with open(get_unit_tests_scans_path("snyk") / "single_project_upgrade_libs.json", encoding="utf-8") as testfile:
            parser = SnykParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(254, len(findings))
            # acme-review@1.0.0: Remote Code Execution (RCE)
            finding = findings[227]
            self.assertEqual("High", finding.severity)
            self.assertIn("target_file:package-lock.json", finding.unsaved_tags)
            self.assertIn("upgrade_to:react-scripts@5.0.0", finding.unsaved_tags)
            self.assertIn("shell-quote@1.7.2", finding.mitigation)

    def test_snykcontainer_issue_9270(self):
        with open(get_unit_tests_scans_path("snyk") / "snykcontainer_issue_9270.json", encoding="utf-8") as testfile:
            parser = SnykParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(25, len(findings))

    def test_snykcode_issue_9270(self):
        with open(get_unit_tests_scans_path("snyk") / "snykcode_issue_9270.json", encoding="utf-8") as testfile:
            parser = SnykParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(39, len(findings))

    def test_snykcode_issue_9270_epss(self):
        with open(get_unit_tests_scans_path("snyk") / "snykcontainer_issue_epss.json", encoding="utf-8") as testfile:
            parser = SnykParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.assertEqual(0.00046, float(findings[0].epss_score))
            self.assertEqual(0.14414, float(findings[0].epss_percentile))
            self.assertEqual(
                "docker-image|sarim04/juiceshop@latest: CVE-2023-4039",
                findings[0].title,
            )
