from dojo.models import Test
from dojo.tools.kubebench.parser import KubeBenchParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestKubeBenchParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(
            get_unit_tests_scans_path("kubebench") / "kube-bench-report-zero-vuln.json", encoding="utf-8",
        ) as testfile:
            parser = KubeBenchParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        with open(
            get_unit_tests_scans_path("kubebench") / "kube-bench-report-one-vuln.json", encoding="utf-8",
        ) as testfile:
            parser = KubeBenchParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open(
            get_unit_tests_scans_path("kubebench") / "kube-bench-report-many-vuln.json", encoding="utf-8",
        ) as testfile:
            parser = KubeBenchParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 4)

    def test_parse_file_with_controls_tag(self):

        # The testfile has been derived from https://github.com/kubernetes-sigs/wg-policy-prototypes/blob/master/policy-report/kube-bench-adapter/samples/kube-bench-output.json
        with open(
            get_unit_tests_scans_path("kubebench") / "kube-bench-controls.json", encoding="utf-8",
        ) as testfile:
            parser = KubeBenchParser()
            findings = parser.get_findings(testfile, Test())

            medium_severities = 0
            info_severities = 0
            for finding in findings:
                if finding.severity == "Medium":
                    medium_severities += 1
                if finding.severity == "Info":
                    info_severities += 1

            self.assertEqual(36, medium_severities)
            self.assertEqual(20, info_severities)

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("1.1.1 - Ensure that the API server pod specification file permissions are set to 644 or more restrictive (Automated)", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertIsNotNone(finding.description)
                self.assertIsNotNone(finding.mitigation)
                self.assertTrue(finding.static_finding)
                self.assertFalse(finding.dynamic_finding)
                self.assertEqual("1.1.1", finding.vuln_id_from_tool)
