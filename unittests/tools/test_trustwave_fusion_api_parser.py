from dojo.models import Test
from dojo.tools.trustwave_fusion_api.parser import TrustwaveFusionAPIParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTrustwaveFusionAPIParser(DojoTestCase):
    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(
            get_unit_tests_scans_path("trustwave_fusion_api") / "trustwave_fusion_api_zero_vul.json", encoding="utf-8",
        ) as testfile:
            parser = TrustwaveFusionAPIParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_vuln_with_valid_cve(self):
        with open(get_unit_tests_scans_path("trustwave_fusion_api") / "test_cve.json", encoding="utf-8") as testfile:
            parser = TrustwaveFusionAPIParser()
            findings = parser.get_findings(testfile, Test())

            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            # first example
            finding = findings[0]
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2017-7529", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(
                "Vulnerability/Missing Patch", finding.description,
            )

            # second example
            finding = findings[1]
            self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2013-2566", finding.unsaved_vulnerability_ids[0])
            self.assertEqual("CVE-2015-2808", finding.unsaved_vulnerability_ids[1])
            self.assertEqual(
                "Cryptography/Weak Cryptography",
                finding.description,
            )
            self.assertEqual(str(finding.unsaved_endpoints[0]), "https://google.com")

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open(
            get_unit_tests_scans_path("trustwave_fusion_api") / "trustwave_fusion_api_many_vul.json", encoding="utf-8",
        ) as testfile:
            parser = TrustwaveFusionAPIParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(3, len(findings))  # checking dupes

            # endpoint validation
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()

            finding = findings[0]
            self.assertEqual("0123456:id", finding.unique_id_from_tool)
            self.assertEqual("Website Detected", finding.title)
            self.assertEqual(
                "Information/Service Discovery", finding.description,
            )
            self.assertIsNone(finding.unsaved_vulnerability_ids)
            date = finding.date.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
            self.assertEqual("2021-06-15T07:48:08.727000+0000", date)
            self.assertEqual("Info", finding.severity)
            self.assertIsNone(finding.unsaved_vulnerability_ids)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(str(endpoint), "https://google.com")
            self.assertEqual(endpoint.host, "google.com")
            self.assertIsNone(endpoint.path)
            self.assertEqual(endpoint.port, 443)

            # testing component_name and component_version
            finding = findings[2]
            self.assertEqual("nginx:nginx", finding.component_name)
            self.assertEqual("1.20.0", finding.component_version)
