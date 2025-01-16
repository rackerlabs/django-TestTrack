import datetime

from dojo.models import Finding, Test
from dojo.tools.stackhawk.parser import StackHawkParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestStackHawkParser(DojoTestCase):
    __test_datetime = datetime.datetime(2022, 2, 16, 23, 7, 19, 575000, datetime.UTC)

    def test_invalid_json_format(self):
        with open(get_unit_tests_scans_path("stackhawk") / "invalid.json", encoding="utf-8") as testfile:
            parser = StackHawkParser()
            with self.assertRaises(ValueError):
                parser.get_findings(testfile, Test())

    def test_parser_ensures_data_is_for_stackhawk_before_parsing(self):
        with open(get_unit_tests_scans_path("stackhawk") / "oddly_familiar_json_that_isnt_us.json", encoding="utf-8") as testfile:
            parser = StackHawkParser()
            with self.assertRaises(ValueError):
                parser.get_findings(testfile, Test())

    def test_stackhawk_parser_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("stackhawk") / "stackhawk_zero_vul.json", encoding="utf-8") as testfile:
            parser = StackHawkParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_stackhawk_parser_with_one_high_vuln_has_one_findings(self):
        with open(get_unit_tests_scans_path("stackhawk") / "stackhawk_one_vul.json", encoding="utf-8") as testfile:
            parser = StackHawkParser()
            findings = parser.get_findings(testfile, Test())
            self.__assertAllEndpointsAreClean(findings)
            self.assertEqual(1, len(findings))

            finding = findings[0]

            self.__assertFindingEquals(
                finding,
                "Anti CSRF Tokens Scanner",
                self.__test_datetime,
                "Secured Application",
                "Development",
                "High",
                "https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27/finding/20012",
                "20012",
                "10",
                false_positive=False,
                risk_accepted=False,
            )

    def test_stackhawk_parser_with_many_vuln_has_many_findings_and_removes_duplicates(self):
        with open(get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul.json", encoding="utf-8") as testfile:
            parser = StackHawkParser()
            findings = parser.get_findings(testfile, Test())
            self.__assertAllEndpointsAreClean(findings)
            self.assertEqual(6, len(findings))

            self.__assertFindingEquals(
                findings[0],
                "Cookie Slack Detector",
                self.__test_datetime,
                "Secured Application",
                "Development",
                "Low",
                "https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27/finding/90027",
                "90027",
                "10",
                false_positive=False,
                risk_accepted=False,
            )

            self.__assertFindingEquals(
                findings[1],
                "Proxy Disclosure",
                self.__test_datetime,
                "Secured Application",
                "Development",
                "Medium",
                "https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27/finding/40025",
                "40025",
                "10",
                false_positive=False,
                risk_accepted=False,
            )

            self.__assertFindingEquals(
                findings[2],
                "Anti CSRF Tokens Scanner",
                self.__test_datetime,
                "Secured Application",
                "Development",
                "High",
                "https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27/finding/20012",
                "20012",
                "10",
                false_positive=False,
                risk_accepted=False,
            )

            self.__assertFindingEquals(
                findings[3],
                "Cross Site Scripting Weakness (Reflected in JSON Response)",
                self.__test_datetime,
                "Secured Application",
                "Development",
                "High",
                "https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27/finding/40012",
                "40012",
                "1",
                false_positive=False,
                risk_accepted=False,
            )

            self.__assertFindingEquals(
                findings[4],
                "Content Security Policy (CSP) Header Not Set",
                self.__test_datetime,
                "Secured Application",
                "Development",
                "Medium",
                "https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27/finding/10038",
                "10038",
                "12",
                false_positive=False,
                risk_accepted=False,
            )

            self.__assertFindingEquals(
                findings[5],
                "Permissions Policy Header Not Set",
                self.__test_datetime,
                "Secured Application",
                "Development",
                "Low",
                "https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27/finding/10063",
                "10063",
                "12",
                false_positive=False,
                risk_accepted=False,
            )

    def test_that_a_scan_import_updates_the_test_description(self):
        with open(get_unit_tests_scans_path("stackhawk") / "stackhawk_zero_vul.json", encoding="utf-8") as testfile:
            parser = StackHawkParser()
            test = Test()
            parser.get_findings(testfile, test)
            self.assertEqual(
                test.description,
                "View scan details here: "
                + "[https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27]"
                + "(https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27)",
            )

    def test_that_a_scan_with_all_false_positive_endpoints_on_a_finding_marks_as_false_positive(self):
        with open(get_unit_tests_scans_path("stackhawk") / "stackhawk_one_vuln_all_endpoints_false_positive.json", encoding="utf-8") as testfile:
            parser = StackHawkParser()
            findings = parser.get_findings(testfile, Test())
            self.__assertAllEndpointsAreClean(findings)
            self.assertEqual(1, len(findings))
            self.__assertFindingEquals(
                findings[0],
                "Cookie Slack Detector",
                self.__test_datetime,
                "Secured Application",
                "Development",
                "Low",
                "https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27/finding/90027",
                "90027",
                "3",
                false_positive=True,
                risk_accepted=False,
            )

    def test_that_a_scan_with_all_risk_accepted_endpoints_on_a_finding_marks_as_risk_accepted(self):
        with open(get_unit_tests_scans_path("stackhawk") / "stackhawk_one_vuln_all_endpoints_risk_accepted.json", encoding="utf-8") as testfile:
            parser = StackHawkParser()
            findings = parser.get_findings(testfile, Test())
            self.__assertAllEndpointsAreClean(findings)
            self.assertEqual(1, len(findings))
            self.__assertFindingEquals(
                findings[0],
                "Cookie Slack Detector",
                self.__test_datetime,
                "Secured Application",
                "Development",
                "Low",
                "https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27/finding/90027",
                "90027",
                "3",
                false_positive=False,
                risk_accepted=True,
            )

    def test_that_a_scan_with_endpoints_in_differing_statuses_does_not_mark_as_risk_accepted_or_false_positive(self):
        with open(get_unit_tests_scans_path("stackhawk") / "stackhawk_one_vuln_all_endpoints_have_different_status.json", encoding="utf-8") as testfile:
            parser = StackHawkParser()
            findings = parser.get_findings(testfile, Test())
            self.__assertAllEndpointsAreClean(findings)
            self.assertEqual(1, len(findings))
            self.__assertFindingEquals(
                findings[0],
                "Cookie Slack Detector",
                self.__test_datetime,
                "Secured Application",
                "Development",
                "Low",
                "https://app.stackhawk.com/scans/e2ff5651-7eef-47e9-b743-0c2f7d861e27/finding/90027",
                "90027",
                "3",
                false_positive=False,
                risk_accepted=False,
            )

    def __assertFindingEquals(
            self,
            actual_finding: Finding,
            title,
            date: datetime.datetime,
            application_name,
            environment,
            severity,
            finding_url,
            finding_id,
            count,
            false_positive,
            risk_accepted,
    ):
        self.assertEqual(title, actual_finding.title)
        self.assertEqual(date, actual_finding.date)
        self.assertEqual(application_name, actual_finding.component_name)
        self.assertEqual(environment, actual_finding.component_version)
        self.assertEqual(severity, actual_finding.severity)
        self.assertEqual("View this finding in the StackHawk platform at:\n[" + finding_url + "](" + finding_url + ")",
                         actual_finding.description)
        self.assertRegex(
            actual_finding.steps_to_reproduce,
            "Use a specific message link and click 'Validate' to see the cURL!.*",
        )
        self.assertFalse(actual_finding.static_finding)
        self.assertTrue(actual_finding.dynamic_finding)
        self.assertEqual(finding_id, actual_finding.vuln_id_from_tool)
        self.assertEqual(count, actual_finding.nb_occurences)
        self.assertEqual(application_name, actual_finding.service)
        self.assertEqual(false_positive, actual_finding.false_p)
        self.assertEqual(risk_accepted, actual_finding.risk_accepted)
        # The following fields should be not be set from this parser.
        self.assertIsNone(actual_finding.unique_id_from_tool)

    def __assertAllEndpointsAreClean(self, findings):
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
