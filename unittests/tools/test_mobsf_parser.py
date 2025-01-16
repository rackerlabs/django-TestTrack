from dojo.models import Engagement, Product, Test
from dojo.tools.mobsf.parser import MobSFParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestMobSFParser(DojoTestCase):

    def test_parse_file(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open(get_unit_tests_scans_path("mobsf") / "report1.json", encoding="utf-8")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(68, len(findings))
        item = findings[0]
        self.assertEqual("android.permission.WRITE_EXTERNAL_STORAGE", item.title)
        self.assertEqual("High", item.severity)
        item = findings[2]
        self.assertEqual("android.permission.INTERNET", item.title)
        self.assertEqual("Info", item.severity)
        item = findings[10]
        self.assertEqual("This shared object does not have RELRO enabled", item.title)
        self.assertEqual("High", item.severity)
        self.assertEqual("lib/armeabi-v7a/libdivajni.so", item.file_path)
        self.assertEqual(1, item.nb_occurences)
        item = findings[17]
        self.assertEqual("This shared object does not have a stack canary value added to the stack", item.title)
        self.assertEqual("High", item.severity)
        self.assertEqual(1, item.nb_occurences)

    def test_parse_file2(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open(get_unit_tests_scans_path("mobsf") / "report2.json", encoding="utf-8")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(1022, len(findings))
        item = findings[1]
        self.assertEqual("Potential API Key found", item.title)
        self.assertEqual("Info", item.severity)

    def test_parse_file_3_1_9_android(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open(get_unit_tests_scans_path("mobsf") / "android.json", encoding="utf-8")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        item = findings[1]
        self.assertEqual("android.permission.ACCESS_GPS", item.title)
        self.assertEqual("High", item.severity)
        item = findings[4]
        self.assertEqual("android.permission.ACCESS_LOCATION", item.title)
        self.assertEqual("High", item.severity)
        item = findings[7]
        self.assertEqual("android.permission.READ_PHONE_STATE", item.title)
        self.assertEqual("High", item.severity)
        item = findings[70]
        self.assertEqual("HTTPS Connection", item.title)
        self.assertEqual("Info", item.severity)
        self.assertEqual(1, item.nb_occurences)

    def test_parse_file_3_1_9_ios(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open(get_unit_tests_scans_path("mobsf") / "ios.json", encoding="utf-8")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(11, len(findings))
        item = findings[2]
        self.assertEqual("NSLocationAlwaysUsageDescription", item.title)
        self.assertEqual("High", item.severity)
        item = findings[3]
        self.assertEqual("NSLocationWhenInUseUsageDescription", item.title)
        self.assertEqual("High", item.severity)
        item = findings[10]
        self.assertEqual("App is compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature that provides automatic memory management of Objective-C objects and is an exploit mitigation mechanism against memory corruption vulnerabilities.", item.title)
        self.assertEqual("Info", item.severity)
        self.assertEqual(1, item.nb_occurences)

    def test_parse_file_mobsf_3_7_9(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open(get_unit_tests_scans_path("mobsf") / "mobsf_3_7_9.json", encoding="utf-8")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(2, len(findings))
        self.assertEqual(findings[0].title, "The binary may contain the following insecure API(s) _memcpy\n, _strlen\n")
        self.assertEqual(findings[1].title, "The binary may use _malloc\n function instead of calloc")
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[1].severity, "High")

    def test_parse_issue_9132(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open(get_unit_tests_scans_path("mobsf") / "issue_9132.json", encoding="utf-8")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(37, len(findings))

    def test_parse_allsafe(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open(get_unit_tests_scans_path("mobsf") / "allsafe.json", encoding="utf-8")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(93, len(findings))

    def test_parse_damnvulnrablebank(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open(get_unit_tests_scans_path("mobsf") / "damnvulnrablebank.json", encoding="utf-8")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(80, len(findings))
