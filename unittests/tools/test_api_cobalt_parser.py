import json
from unittest.mock import patch

from dojo.models import Test, Test_Type
from dojo.tools.api_cobalt.parser import ApiCobaltParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestApiCobaltParser(DojoTestCase):

    def test_cobalt_api_parser_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_zero_vul.json", encoding="utf-8") as testfile:
            parser = ApiCobaltParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_cobalt_api_parser_with_many_vuln_has_many_findings(self):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_many_vul.json", encoding="utf-8") as testfile:
            parser = ApiCobaltParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(3, len(findings))

    def test_cobalt_api_parser_with_carried_over_finding(self):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_one_vul_carried_over.json", encoding="utf-8") as testfile:
            parser = ApiCobaltParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Missing firewall", finding.title)
            self.assertEqual("2021-06-03", finding.date)
            self.assertEqual("Low", finding.severity)
            self.assertIn("A firewall is...", finding.description)
            self.assertEqual("Be sure to...", finding.mitigation)
            self.assertEqual("Try this...", finding.steps_to_reproduce)
            self.assertEqual("2021-06-05", finding.last_status_update)
            self.assertEqual("vu_5wXY6bq", finding.unique_id_from_tool)
            self.assertTrue(finding.active)
            self.assertTrue(finding.verified)
            self.assertFalse(finding.false_p)
            self.assertFalse(finding.duplicate)
            self.assertFalse(finding.out_of_scope)
            self.assertFalse(finding.risk_accepted)
            self.assertFalse(finding.is_mitigated)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

    def test_cobalt_api_parser_with_check_fix_finding(self):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_one_vul_check_fix.json", encoding="utf-8") as testfile:
            parser = ApiCobaltParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Cross Site Scripting", finding.title)
            self.assertEqual("2021-05-11", finding.date)
            self.assertEqual("Medium", finding.severity)
            self.assertIn("A XSS injection attack...", finding.description)
            self.assertEqual("Ensure that...", finding.mitigation)
            self.assertEqual("Do this...", finding.steps_to_reproduce)
            self.assertEqual("2021-05-12", finding.last_status_update)
            self.assertEqual("vu_3wXY4bq", finding.unique_id_from_tool)
            self.assertTrue(finding.active)
            self.assertTrue(finding.verified)
            self.assertFalse(finding.false_p)
            self.assertFalse(finding.duplicate)
            self.assertFalse(finding.out_of_scope)
            self.assertFalse(finding.risk_accepted)
            self.assertFalse(finding.is_mitigated)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

    def test_cobalt_api_parser_with_invalid_finding(self):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_one_vul_invalid.json", encoding="utf-8") as testfile:
            parser = ApiCobaltParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual("2021-01-01", finding.date)
            self.assertEqual("Critical", finding.severity)
            self.assertIn("A SQL injection attack...", finding.description)
            self.assertEqual("Ensure this...", finding.mitigation)
            self.assertEqual("Do this than that...", finding.steps_to_reproduce)
            self.assertEqual("2021-01-02", finding.last_status_update)
            self.assertEqual("vu_5wXY6bq", finding.unique_id_from_tool)
            self.assertFalse(finding.active)
            self.assertTrue(finding.verified)
            self.assertTrue(finding.false_p)
            self.assertFalse(finding.duplicate)
            self.assertFalse(finding.out_of_scope)
            self.assertFalse(finding.risk_accepted)
            self.assertFalse(finding.is_mitigated)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

    def test_cobalt_api_parser_with_need_fix_finding(self):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_one_vul_need_fix.json", encoding="utf-8") as testfile:
            parser = ApiCobaltParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual("2021-04-01", finding.date)
            self.assertEqual("High", finding.severity)
            self.assertIn("A SQL injection attack...", finding.description)
            self.assertEqual("Ensure this...", finding.mitigation)
            self.assertEqual("Do this than that...", finding.steps_to_reproduce)
            self.assertEqual("2021-04-05", finding.last_status_update)
            self.assertEqual("vu_2wXY3bq", finding.unique_id_from_tool)
            self.assertTrue(finding.active)
            self.assertTrue(finding.verified)
            self.assertFalse(finding.false_p)
            self.assertFalse(finding.duplicate)
            self.assertFalse(finding.out_of_scope)
            self.assertFalse(finding.risk_accepted)
            self.assertFalse(finding.is_mitigated)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

    def test_cobalt_api_parser_with_new_finding(self):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_one_vul_new.json", encoding="utf-8") as testfile:
            parser = ApiCobaltParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual("2021-01-01", finding.date)
            self.assertEqual("Info", finding.severity)
            self.assertIn("A SQL injection attack...", finding.description)
            self.assertEqual("Ensure this...", finding.mitigation)
            self.assertEqual("Do this than that...", finding.steps_to_reproduce)
            self.assertEqual("2021-01-01", finding.last_status_update)
            self.assertEqual("vu_5wXY6bq", finding.unique_id_from_tool)
            self.assertTrue(finding.active)
            self.assertFalse(finding.verified)
            self.assertFalse(finding.false_p)
            self.assertFalse(finding.duplicate)
            self.assertFalse(finding.out_of_scope)
            self.assertFalse(finding.risk_accepted)
            self.assertFalse(finding.is_mitigated)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

    def test_cobalt_api_parser_with_out_of_scope_finding(self):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_one_vul_out_of_scope.json", encoding="utf-8") as testfile:
            parser = ApiCobaltParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual("2021-01-01", finding.date)
            self.assertEqual("Info", finding.severity)
            self.assertIn("A SQL injection attack...", finding.description)
            self.assertEqual("Ensure this...", finding.mitigation)
            self.assertEqual("Do this than that...", finding.steps_to_reproduce)
            self.assertEqual("2021-01-02", finding.last_status_update)
            self.assertEqual("vu_5wXY6bq", finding.unique_id_from_tool)
            self.assertFalse(finding.active)
            self.assertTrue(finding.verified)
            self.assertFalse(finding.false_p)
            self.assertFalse(finding.duplicate)
            self.assertTrue(finding.out_of_scope)
            self.assertFalse(finding.risk_accepted)
            self.assertFalse(finding.is_mitigated)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

    def test_cobalt_api_parser_with_triaging_finding(self):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_one_vul_triaging.json", encoding="utf-8") as testfile:
            parser = ApiCobaltParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual("2021-01-01", finding.date)
            self.assertEqual("Info", finding.severity)
            self.assertIn("A SQL injection attack...", finding.description)
            self.assertEqual("Ensure this...", finding.mitigation)
            self.assertEqual("Do this than that...", finding.steps_to_reproduce)
            self.assertEqual("2021-01-02", finding.last_status_update)
            self.assertEqual("vu_5wXY6bq", finding.unique_id_from_tool)
            self.assertTrue(finding.active)
            self.assertFalse(finding.verified)
            self.assertFalse(finding.false_p)
            self.assertFalse(finding.duplicate)
            self.assertFalse(finding.out_of_scope)
            self.assertFalse(finding.risk_accepted)
            self.assertFalse(finding.is_mitigated)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

    def test_cobalt_api_parser_with_valid_fix_finding(self):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_one_vul_valid_fix.json", encoding="utf-8") as testfile:
            parser = ApiCobaltParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual("2021-01-01", finding.date)
            self.assertEqual("Low", finding.severity)
            self.assertIn("A SQL injection attack...", finding.description)
            self.assertEqual("Ensure this...", finding.mitigation)
            self.assertEqual("Do this than that...", finding.steps_to_reproduce)
            self.assertEqual("2021-01-03", finding.last_status_update)
            self.assertEqual("vu_5wXY6bq", finding.unique_id_from_tool)
            self.assertFalse(finding.active)
            self.assertTrue(finding.verified)
            self.assertFalse(finding.false_p)
            self.assertFalse(finding.duplicate)
            self.assertFalse(finding.out_of_scope)
            self.assertFalse(finding.risk_accepted)
            self.assertTrue(finding.is_mitigated)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

    def test_cobalt_api_parser_with_wont_fix_finding(self):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_one_vul_wont_fix.json", encoding="utf-8") as testfile:
            parser = ApiCobaltParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual("2021-01-01", finding.date)
            self.assertEqual("Low", finding.severity)
            self.assertIn("A SQL injection attack...", finding.description)
            self.assertEqual("Ensure this...", finding.mitigation)
            self.assertEqual("Do this than that...", finding.steps_to_reproduce)
            self.assertEqual("2021-01-02", finding.last_status_update)
            self.assertEqual("vu_5wXY6bq", finding.unique_id_from_tool)
            self.assertTrue(finding.active)
            self.assertTrue(finding.verified)
            self.assertFalse(finding.false_p)
            self.assertFalse(finding.duplicate)
            self.assertFalse(finding.out_of_scope)
            self.assertTrue(finding.risk_accepted)
            self.assertFalse(finding.is_mitigated)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

    @patch("dojo.tools.api_cobalt.importer.CobaltApiImporter.get_findings")
    def test_cobalt_api_parser_with_api(self, mock):
        with open(get_unit_tests_scans_path("api_cobalt") / "cobalt_api_many_vul.json", encoding="utf-8") as api_findings_file:
            api_findings = json.load(api_findings_file)
        mock.return_value = api_findings

        test_type = Test_Type()
        test_type.name = "test_type"
        test = Test()
        test.test_type = test_type

        parser = ApiCobaltParser()
        findings = parser.get_findings(None, test)

        mock.assert_called_with(test)
        self.assertEqual(3, len(findings))
        self.assertEqual(findings[0].title, "SQL Injection")
        self.assertEqual(findings[1].title, "Cross Site Scripting")
        self.assertEqual(findings[2].title, "Missing firewall")
