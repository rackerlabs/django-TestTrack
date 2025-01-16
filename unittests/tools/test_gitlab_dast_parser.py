from dojo.models import Test
from dojo.tools.gitlab_dast.parser import GitlabDastParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGitlabDastParser(DojoTestCase):
    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("gitlab_dast") / "gitlab_dast_zero_vul.json", encoding="utf-8") as testfile:
            parser = GitlabDastParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding_v14(self):
        with open(get_unit_tests_scans_path("gitlab_dast") / "gitlab_dast_one_vul_v14.json", encoding="utf-8") as testfile:
            parser = GitlabDastParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]

            # endpoint validation
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

            self.assertEqual(
                "5ec00bbc-2e53-44cb-83e9-3d35365277e3", finding.unique_id_from_tool,
            )
            self.assertEqual(3, finding.scanner_confidence)
            # vulnerability does not have a name: fallback to using id as a title
            self.assertEqual("5ec00bbc-2e53-44cb-83e9-3d35365277e3", finding.title)
            self.assertIsInstance(finding.description, str)

            date = finding.date.strftime("%Y-%m-%dT%H:%M:%S.%f")
            self.assertEqual("2021-04-23T15:46:40.615000", date)
            self.assertIsNone(finding.references)  # should be None as there are no links

            self.assertEqual("High", finding.severity)
            self.assertEqual("", finding.mitigation)  # no solution proposed

            self.assertEqual(359, finding.cwe)

    def test_parse_file_with_one_vuln_has_one_finding_v15(self):
        with open(get_unit_tests_scans_path("gitlab_dast") / "gitlab_dast_one_vul_v15.json", encoding="utf-8") as testfile:
            parser = GitlabDastParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]

            # endpoint validation
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

            self.assertEqual(
                "5ec00bbc-2e53-44cb-83e9-3d35365277e3", finding.unique_id_from_tool,
            )
            self.assertEqual(None, finding.scanner_confidence)
            # vulnerability does not have a name: fallback to using id as a title
            self.assertEqual("5ec00bbc-2e53-44cb-83e9-3d35365277e3", finding.title)
            self.assertIsInstance(finding.description, str)

            date = finding.date.strftime("%Y-%m-%dT%H:%M:%S.%f")
            self.assertEqual("2021-04-23T15:46:40.615000", date)
            self.assertIsNone(finding.references)  # should be None as there are no links

            self.assertEqual("High", finding.severity)
            self.assertEqual("", finding.mitigation)  # no solution proposed

            self.assertEqual(359, finding.cwe)

    def test_parse_file_with_multiple_vuln_has_multiple_findings_v14(self):
        with open(get_unit_tests_scans_path("gitlab_dast") / "gitlab_dast_many_vul_v14.json", encoding="utf-8") as testfile:
            parser = GitlabDastParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(10, len(findings))

            # endpoint validation
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            # the first one is done above
            finding = findings[1]
            # must-have fields
            self.assertEqual(3, finding.scanner_confidence)
            self.assertIn("Content Security Policy (CSP)", finding.description)
            self.assertEqual(False, finding.static_finding)
            self.assertEqual(True, finding.dynamic_finding)

            # conditional fields
            date = finding.date.strftime("%Y-%m-%dT%H:%M:%S.%f")
            self.assertEqual("2021-04-23T15:46:40.644000", date)
            self.assertEqual(
                "87e98ddf-7d75-444a-be6d-45400151a0fe", finding.unique_id_from_tool,
            )
            # vulnerability does not have a name: fallback to using id as a title
            self.assertEqual(finding.unique_id_from_tool, finding.title)
            self.assertEqual(16, finding.cwe)
            self.assertIn("http://www.w3.org/TR/CSP/", finding.references)
            self.assertEqual("Medium", finding.severity)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(str(endpoint), "http://api-server/v1/tree/10")
            self.assertEqual(endpoint.host, "api-server")  # host port path
            self.assertEqual(endpoint.port, 80)
            self.assertEqual(endpoint.path, "v1/tree/10")
            self.assertIn("Ensure that your web server,", finding.mitigation)

    def test_parse_file_with_multiple_vuln_has_multiple_findings_v15(self):
        with open(get_unit_tests_scans_path("gitlab_dast") / "gitlab_dast_many_vul_v15.json", encoding="utf-8") as testfile:
            parser = GitlabDastParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(10, len(findings))

            # endpoint validation
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            # the first one is done above
            finding = findings[1]
            # must-have fields
            self.assertEqual(None, finding.scanner_confidence)
            self.assertIn("Content Security Policy (CSP)", finding.description)
            self.assertEqual(False, finding.static_finding)
            self.assertEqual(True, finding.dynamic_finding)

            # conditional fields
            date = finding.date.strftime("%Y-%m-%dT%H:%M:%S.%f")
            self.assertEqual("2021-04-23T15:46:40.644000", date)
            self.assertEqual(
                "87e98ddf-7d75-444a-be6d-45400151a0fe", finding.unique_id_from_tool,
            )
            # vulnerability does not have a name: fallback to using id as a title
            self.assertEqual(finding.unique_id_from_tool, finding.title)
            self.assertEqual(16, finding.cwe)
            self.assertIn("http://www.w3.org/TR/CSP/", finding.references)
            self.assertEqual("Medium", finding.severity)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(str(endpoint), "http://api-server/v1/tree/10")
            self.assertEqual(endpoint.host, "api-server")  # host port path
            self.assertEqual(endpoint.port, 80)
            self.assertEqual(endpoint.path, "v1/tree/10")
            self.assertIn("Ensure that your web server,", finding.mitigation)
