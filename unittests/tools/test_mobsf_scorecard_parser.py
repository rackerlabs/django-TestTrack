from dojo.models import Test
from dojo.tools.mobsf_scorecard.parser import MobSFScorecardParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestMobSFScorecardParser(DojoTestCase):

    def test_parse_android_empty_file(self):

        parser = MobSFScorecardParser()

        with open(get_unit_tests_scans_path("mobsf_scorecard") / "dvba_4_0_7_android_empty.json", encoding="utf-8") as android_empty_file:

            android_empty_findings = parser.get_findings(android_empty_file, Test())
            self.assertEqual(0, len(android_empty_findings))

    def test_parse_android_one_file(self):

        parser = MobSFScorecardParser()

        with open(get_unit_tests_scans_path("mobsf_scorecard") / "dvba_4_0_7_android_one.json", encoding="utf-8") as android_one_file:

            android_one_findings = parser.get_findings(android_one_file, Test())
            self.assertEqual(1, len(android_one_findings))

            item = android_one_findings[0]
            self.assertEqual("Base config is insecurely configured to permit clear text traffic to all domains", item.title)
            self.assertEqual("High", item.severity)

    def test_parse_android_full_file(self):

        parser = MobSFScorecardParser()

        with open(get_unit_tests_scans_path("mobsf_scorecard") / "dvba_4_0_7_android_full.json", encoding="utf-8") as android_full_file:

            android_full_findings = parser.get_findings(android_full_file, Test())
            self.assertEqual(18, len(android_full_findings))

            item = android_full_findings[2]
            self.assertEqual("App can be installed on a vulnerable upatched Android version", item.title)
            self.assertEqual("High", item.severity)

            item = android_full_findings[17]
            self.assertEqual("This application has no privacy trackers", item.title)
            self.assertEqual("Info", item.severity)

    def test_parse_ios_empty_file(self):

        parser = MobSFScorecardParser()

        with open(get_unit_tests_scans_path("mobsf_scorecard") / "dvia2_4_0_7_ios_empty.json", encoding="utf-8") as ios_empty_file:
            ios_empty_findings = parser.get_findings(ios_empty_file, Test())

            self.assertEqual(0, len(ios_empty_findings))

    def test_parse_ios_one_file(self):

        parser = MobSFScorecardParser()

        with open(get_unit_tests_scans_path("mobsf_scorecard") / "dvia2_4_0_7_ios_one.json", encoding="utf-8") as ios_one_file:
            ios_one_findings = parser.get_findings(ios_one_file, Test())

            self.assertEqual(1, len(ios_one_findings))

            item = ios_one_findings[0]
            self.assertEqual("App Transport Security AllowsArbitraryLoads is allowed", item.title)
            self.assertEqual("High", item.severity)

    def test_parse_ios_full_file(self):

        parser = MobSFScorecardParser()

        with open(get_unit_tests_scans_path("mobsf_scorecard") / "dvia2_4_0_7_ios_full.json", encoding="utf-8") as ios_full_file:
            ios_full_findings = parser.get_findings(ios_full_file, Test())

            self.assertEqual(11, len(ios_full_findings))

            item = ios_full_findings[2]
            self.assertEqual("Binary makes use of the insecure Random function(s)", item.title)
            self.assertEqual("High", item.severity)

            item = ios_full_findings[10]
            self.assertEqual("Found 1 certificate/key file(s)", item.title)
            self.assertEqual("Low", item.severity)
