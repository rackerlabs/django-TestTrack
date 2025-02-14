from dojo.models import Test
from dojo.tools.anchore_engine.parser import AnchoreEngineParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAnchoreEngineParser(DojoTestCase):
    def test_anchore_engine_parser_has_many_findings(self):
        with open(get_unit_tests_scans_path("anchore_engine") / "many_vulns.json", encoding="utf-8") as testfile:
            parser = AnchoreEngineParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(84, len(findings))
