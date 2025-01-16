
from dojo.models import Test
from dojo.tools.blackduck_component_risk.parser import BlackduckComponentRiskParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBlackduckComponentRiskParser(DojoTestCase):
    def test_blackduck_enhanced_zip_upload(self):
        testfile = get_unit_tests_scans_path("blackduck_component_risk") / "blackduck_hub_component_risk.zip"
        parser = BlackduckComponentRiskParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(12, len(findings))
