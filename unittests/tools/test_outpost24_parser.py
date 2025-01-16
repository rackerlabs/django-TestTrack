from dojo.models import Test
from dojo.tools.outpost24.parser import Outpost24Parser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOutpost24Parser(DojoTestCase):
    def assert_file_has_n_items(self, filename, item_count):
        with open(filename, encoding="utf-8") as file:
            parser = Outpost24Parser()
            findings = parser.get_findings(file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(item_count, len(findings))
            if item_count > 0:
                for item in findings:
                    endpoint_count = len(item.unsaved_endpoints)
                    self.assertGreater(endpoint_count, 0)
            if item_count == 1:
                self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
                self.assertEqual("CVE-2019-9315", findings[0].unsaved_vulnerability_ids[0])

    def test_parser_no_items(self):
        self.assert_file_has_n_items(get_unit_tests_scans_path("outpost24") / "none.xml", 0)

    def test_parser_one_item(self):
        self.assert_file_has_n_items(get_unit_tests_scans_path("outpost24") / "one.xml", 1)

    def test_parser_sample_items(self):
        self.assert_file_has_n_items(get_unit_tests_scans_path("outpost24") / "sample.xml", 24)
