from dojo.models import Test
from dojo.tools.meterian.parser import MeterianParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestMeterianParser(DojoTestCase):

    def test_meterianParser_invalid_security_report_raise_ValueError_exception(self):
        with self.assertRaises(ValueError):
            with open(get_unit_tests_scans_path("meterian") / "report_invalid.json", encoding="utf-8") as testfile:
                parser = MeterianParser()
                parser.get_findings(testfile, Test())

    def test_meterianParser_report_has_no_finding(self):
        with open(get_unit_tests_scans_path("meterian") / "report_no_vulns.json", encoding="utf-8") as testfile:
            parser = MeterianParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(0, len(findings))

    def test_meterianParser_report_has_one_findings(self):
        with open(get_unit_tests_scans_path("meterian") / "report_one_vuln.json", encoding="utf-8") as testfile:
            parser = MeterianParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(1, len(findings))

    def test_meterianParser_report_has_many_findings(self):
        with open(get_unit_tests_scans_path("meterian") / "report_many_vulns.json", encoding="utf-8") as testfile:
            parser = MeterianParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(20, len(findings))

    def test_meterianParser_finding_has_fields(self):
        with open(get_unit_tests_scans_path("meterian") / "report_one_vuln.json", encoding="utf-8") as testfile:
            parser = MeterianParser()
            findings = parser.get_findings(testfile, Test())

            finding = findings[0]
            self.assertEqual(1, len(findings))
            self.assertEqual("date-and-time:0.6.3", finding.title)
            self.assertEqual("2021-06-02", finding.date)
            self.assertEqual("High", finding.severity)
            self.assertEqual("Issue severity of: **High** from a base "
                + "CVSS score of: **7.5**", finding.severity_justification)
            self.assertEqual("date-and-time is an npm package for manipulating "
                + "date and time. In date-and-time before version 0.14.2, there a regular "
                + "expression involved in parsing which can be exploited to to cause a denial "
                + "of service. This is fixed in version 0.14.2.", finding.description)
            self.assertEqual("7be36211-b569-30c0-8851-26b4bb8740ca", finding.unique_id_from_tool)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2020-26289", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(400, finding.cwe)
            self.assertTrue(finding.mitigation.startswith("## Remediation"), finding.mitigation)
            self.assertIn("Upgrade date-and-time to version 0.14.2 or higher.", finding.mitigation)
            self.assertIn("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26289", finding.references, "found " + finding.references)
            self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2020-26289", finding.references, "found " + finding.references)
            self.assertIn("https://www.npmjs.com/package/date-and-time", finding.references, "found " + finding.references)
            self.assertIn("https://github.com/knowledgecode/date-and-time/security/advisories/GHSA-r92x-f52r-x54g", finding.references, "found " + finding.references)
            self.assertIn("https://github.com/knowledgecode/date-and-time/commit/9e4b501eacddccc8b1f559fb414f48472ee17c2a", finding.references, "found " + finding.references)
            self.assertIn("Manifest file", finding.file_path)
            self.assertEqual(["nodejs"], finding.tags)

    def test_meterianParser_finding_has_no_remediation(self):
        with open(get_unit_tests_scans_path("meterian") / "report_one_vuln_no_remediation.json", encoding="utf-8") as testfile:
            parser = MeterianParser()
            findings = parser.get_findings(testfile, Test())

            finding = findings[0]
            self.assertTrue(finding.mitigation.startswith("We were not able to provide a safe version for this library."), finding.mitigation)
            self.assertIn("You should consider replacing this component as it could be an "
                + "issue for the safety of your application.", finding.mitigation)

    def test_meterianParser_dual_language_report_has_two_findins(self):
        with open(get_unit_tests_scans_path("meterian") / "report_multi_language.json", encoding="utf-8") as testfile:
            parser = MeterianParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(2, len(findings))
            self.assertIn("nodejs", findings[0].tags)
            self.assertIn("ruby", findings[1].tags)
