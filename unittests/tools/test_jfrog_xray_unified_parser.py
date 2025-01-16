import datetime

from dojo.models import Test
from dojo.tools.jfrog_xray_unified.parser import JFrogXrayUnifiedParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestJFrogXrayUnifiedParser(DojoTestCase):

    def test_parse_file_with_no_vuln(self):
        testfile = open(get_unit_tests_scans_path("jfrog_xray_unified") / "no_vuln.json", encoding="utf-8")
        parser = JFrogXrayUnifiedParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln(self):
        testfile = open(get_unit_tests_scans_path("jfrog_xray_unified") / "one_vuln.json", encoding="utf-8")
        parser = JFrogXrayUnifiedParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        item = findings[0]

        self.assertEqual("XRAY-139239 - This affects the package", item.title[:38])
        self.assertEqual(" memory.", item.title[-8:])
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-28493", item.unsaved_vulnerability_ids[0])
        self.assertEqual("Medium", item.severity)
        self.assertEqual("This affects the package", item.description[:24])
        self.assertEqual(" memory.", item.description[-8:])
        self.assertIsNotNone(item.mitigation)
        self.assertGreater(len(item.mitigation), 0)
        self.assertEqual("Jinja2", item.component_name)
        self.assertEqual('"packagetype_pypi"', item.tags)
        self.assertEqual("2.11.2", item.component_version)
        self.assertEqual("pypi-remote/30/9e/f663a2aa66a09d838042ae1a2c5659828bb9b41ea3a6efa20a20fd92b121/Jinja2-2.11.2-py2.py3-none-any.whl", item.file_path)
        self.assertIsNotNone(item.severity_justification)
        self.assertGreater(len(item.severity_justification), 0)
        self.assertIsNotNone(item.references)
        self.assertGreater(len(item.references), 0)
        self.assertEqual("Medium", item.impact)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", item.cvssv3)
        self.assertEqual(datetime.date(2021, 1, 15), item.date.date())
        self.assertEqual("XRAY-139239", item.unique_id_from_tool)

    def test_parse_file_with_many_vulns(self):
        testfile = open(get_unit_tests_scans_path("jfrog_xray_unified") / "many_vulns.json", encoding="utf-8")
        parser = JFrogXrayUnifiedParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(findings))

    def test_parse_file_with_very_many_vulns(self):
        testfile = open(get_unit_tests_scans_path("jfrog_xray_unified") / "very_many_vulns.json", encoding="utf-8")
        parser = JFrogXrayUnifiedParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertEqual(14219, len(findings))

        # blank cvss2
        item = [i for i in findings if i.title[:11] == "XRAY-106730"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2018-10754", item.unsaved_vulnerability_ids[0])
        self.assertIsNotNone(item.severity_justification)
        self.assertGreater(len(item.severity_justification), 0)

        # blank cvss3
        item = [i for i in findings if i.title[:11] == "XRAY-100538"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2015-2716", item.unsaved_vulnerability_ids[0])
        self.assertIsNotNone(item.severity_justification)
        self.assertGreater(len(item.severity_justification), 0)

        # 0 references
        item = [i for i in findings if i.title[:11] == "XRAY-100015"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-13790", item.unsaved_vulnerability_ids[0])
        self.assertIsNotNone(item.references)
        self.assertEqual(len(item.references), 0)

        # 1 reference
        item = [i for i in findings if i.title[:11] == "XRAY-101489"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-14040", item.unsaved_vulnerability_ids[0])
        self.assertIsNotNone(item.references)
        self.assertGreater(len(item.references), 0)

        # many references
        item = [i for i in findings if i.title[:11] == "XRAY-100092"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-12723", item.unsaved_vulnerability_ids[0])
        self.assertIsNotNone(item.references)
        self.assertGreater(len(item.references), 50)

        # multiple cvss scores - all have cvss3
        item = [i for i in findings if i.title[:10] == "XRAY-96518"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2016-10745", item.unsaved_vulnerability_ids[0])
        self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", item.cvssv3)

        # multiiple cvss scores, some cvss2 missing
        item = [i for i in findings if i.title[:11] == "XRAY-128854"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2019-17006", item.unsaved_vulnerability_ids[0])
        self.assertEqual("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", item.cvssv3)

        # multiiple cvss scores, some cvss3 missing
        item = [i for i in findings if i.title[:11] == "XRAY-135206"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2019-17006", item.unsaved_vulnerability_ids[0])
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", item.cvssv3)

        # 0 fixed verisons
        item = [i for i in findings if i.title[:11] == "XRAY-100015"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-13790", item.unsaved_vulnerability_ids[0])
        self.assertIsNone(item.mitigation)

        # 1 fixed version
        item = [i for i in findings if i.title[:11] == "XRAY-100646"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-14062", item.unsaved_vulnerability_ids[0])
        self.assertIsNotNone(item.mitigation)
        self.assertGreater(len(item.mitigation), 0)

        # multiple fixed versions
        item = [i for i in findings if i.title[:11] == "XRAY-127258"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-27216", item.unsaved_vulnerability_ids[0])
        self.assertIsNotNone(item.mitigation)
        self.assertGreater(len(item.mitigation), 50)

        # fixed versions with weird characters
        item = [i for i in findings if i.title[:11] == "XRAY-128876"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-8623", item.unsaved_vulnerability_ids[0])
        self.assertIsNotNone(item.mitigation)
        self.assertGreater(len(item.mitigation), 0)

        # severity unknown
        item = [i for i in findings if i.title[:11] == "XRAY-119297"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-12403", item.unsaved_vulnerability_ids[0])
        self.assertEqual("Info", item.severity)
        self.assertEqual("Info", item.impact)

        # severity low
        item = [i for i in findings if i.title[:11] == "XRAY-100046"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-13871", item.unsaved_vulnerability_ids[0])
        self.assertEqual("Low", item.severity)
        self.assertEqual("Low", item.impact)

        # severity medium
        item = [i for i in findings if i.title[:11] == "XRAY-100757"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-14155", item.unsaved_vulnerability_ids[0])
        self.assertEqual("Medium", item.severity)
        self.assertEqual("Medium", item.impact)

        # severity high
        item = [i for i in findings if i.title[:11] == "XRAY-109517"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2019-5827", item.unsaved_vulnerability_ids[0])
        self.assertEqual("High", item.severity)
        self.assertEqual("High", item.impact)

        # external severity in details
        item = [i for i in findings if i.title[:11] == "XRAY-111224"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2015-8385", item.unsaved_vulnerability_ids[0])
        self.assertEqual("Red Hat Severity: Important", item.description[-27:])

        # **various packages**
        # alpine
        item = [i for i in findings if i.title[:11] == "XRAY-100301"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-13871", item.unsaved_vulnerability_ids[0])
        self.assertEqual("XRAY-100301 - SQLite 3.32.2 has a use", item.title[:37])
        self.assertEqual(" is too late.", item.title[-13:])
        self.assertEqual("Medium", item.severity)
        self.assertEqual("SQLite 3.32.2 has a use", item.description[:23])
        self.assertEqual(" is too late.", item.description[-13:])
        self.assertIsNone(item.mitigation)
        self.assertEqual("3.12:sqlite-libs", item.component_name)
        self.assertEqual('"packagetype_alpine"', item.tags)
        self.assertEqual("3.32.1-r0", item.component_version)
        self.assertEqual("dockerhub-remote/kiwigrid/k8s-sidecar/sha256__7cba93c3dde21c78fe07ee3f8ed8d82d05bf00415392606401df8a7d72057b5b/", item.file_path)
        self.assertIsNotNone(item.severity_justification)
        self.assertGreater(len(item.severity_justification), 0)
        self.assertIsNotNone(item.references)
        self.assertGreater(len(item.references), 0)
        self.assertEqual("Medium", item.impact)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", item.cvssv3)
        self.assertEqual(datetime.date(2021, 5, 4), item.date.date())
        self.assertEqual("XRAY-100301", item.unique_id_from_tool)

        # debian
        item = [i for i in findings if i.title[:11] == "XRAY-137237"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-1971", item.unsaved_vulnerability_ids[0])
        self.assertEqual("XRAY-137237 - The X.509 GeneralName", item.title[:35])
        self.assertEqual("(Affected 1.0.2-1.0.2w).", item.title[-24:])
        self.assertEqual("High", item.severity)
        self.assertEqual("The X.509 GeneralName", item.description[:21])
        self.assertEqual("(Affected 1.0.2-1.0.2w).", item.description[-24:])
        self.assertIsNone(item.mitigation)
        self.assertEqual("ubuntu:bionic:libssl1.1", item.component_name)
        self.assertEqual('"packagetype_debian"', item.tags)
        self.assertEqual("1.1.1-1ubuntu2.1~18.04.6", item.component_version)
        self.assertEqual("dockerhub-remote/library/mongo/sha256__31f6433f7cfcd2180483e40728cbf97142df1e85de36d80d75c93e5e7fe10405/", item.file_path)
        self.assertIsNotNone(item.severity_justification)
        self.assertGreater(len(item.severity_justification), 0)
        self.assertIsNotNone(item.references)
        self.assertGreater(len(item.references), 0)
        self.assertEqual("High", item.impact)
        self.assertEqual("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", item.cvssv3)
        self.assertEqual(datetime.date(2021, 3, 9), item.date.date())
        self.assertEqual("XRAY-137237", item.unique_id_from_tool)

        # go
        item = [i for i in findings if i.title[:10] == "XRAY-86054"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2014-0047", item.unsaved_vulnerability_ids[0])
        self.assertEqual("XRAY-86054 - Docker before 1.5 allows", item.title[:37])
        self.assertEqual("/tmp usage.", item.title[-11:])
        self.assertEqual("Medium", item.severity)
        self.assertEqual("Docker before 1.5 allows", item.description[:24])
        self.assertEqual("/tmp usage.", item.description[-11:])
        self.assertIsNotNone(item.mitigation)
        self.assertGreater(len(item.mitigation), 0)
        self.assertEqual("github.com/docker/docker", item.component_name)
        self.assertEqual('"packagetype_go"', item.tags)
        self.assertEqual("1.4.2-0.20200203170920-46ec8731fbce", item.component_version)
        self.assertEqual("dockerhub-remote/fluxcd/helm-controller/sha256__27790f965d8965884e8dfc12cba0d1f609794a1abc69bc81a658bd76e463ffce/", item.file_path)
        self.assertIsNotNone(item.severity_justification)
        self.assertGreater(len(item.severity_justification), 0)
        self.assertIsNotNone(item.references)
        self.assertGreater(len(item.references), 0)
        self.assertEqual("Medium", item.impact)
        self.assertEqual("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", item.cvssv3)
        self.assertEqual(datetime.date(2021, 2, 2), item.date.date())
        self.assertEqual("XRAY-86054", item.unique_id_from_tool)

        # maven
        item = [i for i in findings if i.title[:11] == "XRAY-126663"][-1]
        self.assertIsNone(item.unsaved_vulnerability_ids)  # has cvss score but no cve??
        self.assertEqual("XRAY-126663 - FasterXML jackson", item.title[:31])
        self.assertEqual("Expansion Remote Issue", item.title[-22:])
        self.assertEqual("High", item.severity)
        self.assertEqual("FasterXML jackson", item.description[:17])
        self.assertEqual("sensitive information.", item.description[-22:])
        self.assertIsNone(item.mitigation)
        self.assertEqual("com.fasterxml.jackson.core:jackson-databind", item.component_name)
        self.assertEqual('"packagetype_maven"', item.tags)
        self.assertEqual("2.10.4", item.component_version)
        self.assertEqual("elastic-docker-remote/elasticsearch/elasticsearch/7.9.1-amd64/", item.file_path)
        self.assertIsNotNone(item.severity_justification)
        self.assertGreater(len(item.severity_justification), 0)
        self.assertIsNotNone(item.references)
        self.assertGreater(len(item.references), 0)
        self.assertEqual("High", item.impact)
        self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H", item.cvssv3)
        self.assertEqual(datetime.date(2021, 1, 14), item.date.date())
        self.assertEqual("XRAY-126663", item.unique_id_from_tool)

        # npm
        item = [i for i in findings if i.title[:10] == "XRAY-97245"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2020-11023", item.unsaved_vulnerability_ids[0])
        self.assertEqual("XRAY-97245 - In jQuery versions great", item.title[:37])
        self.assertEqual("patched in jQuery 3.5.0.", item.title[-24:])
        self.assertEqual("Medium", item.severity)
        self.assertEqual("In jQuery versions great", item.description[:24])
        self.assertEqual("patched in jQuery 3.5.0.", item.description[-24:])
        self.assertIsNotNone(item.mitigation)
        self.assertGreater(len(item.mitigation), 0)
        self.assertEqual("jquery", item.component_name)
        self.assertEqual('"packagetype_npm"', item.tags)
        self.assertEqual("3.4.1", item.component_version)
        self.assertEqual("pypi-remote/cc/94/5f7079a0e00bd6863ef8f1da638721e9da21e5bacee597595b318f71d62e/Werkzeug-1.0.1-py2.py3-none-any.whl", item.file_path)
        self.assertIsNotNone(item.severity_justification)
        self.assertGreater(len(item.severity_justification), 0)
        self.assertIsNotNone(item.references)
        self.assertGreater(len(item.references), 0)
        self.assertEqual("Medium", item.impact)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", item.cvssv3)
        self.assertEqual(datetime.date(2021, 1, 15), item.date.date())
        self.assertEqual("XRAY-97245", item.unique_id_from_tool)

        # pypi
        item = [i for i in findings if i.title[:10] == "XRAY-97724"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2018-20225", item.unsaved_vulnerability_ids[0])
        self.assertEqual("XRAY-97724 - An issue was discovered", item.title[:36])
        self.assertEqual("an arbitrary version number).", item.title[-29:])
        self.assertEqual("Medium", item.severity)
        self.assertEqual("An issue was discovered", item.description[:23])
        self.assertEqual("an arbitrary version number).", item.description[-29:])
        self.assertIsNotNone(item.mitigation)
        self.assertGreater(len(item.mitigation), 0)
        self.assertEqual("pip", item.component_name)
        self.assertEqual('"packagetype_pypi"', item.tags)
        self.assertEqual("20.2.3", item.component_version)
        self.assertEqual("dockerhub-remote/kiwigrid/k8s-sidecar/sha256__4b5a25c8dbac9637f8e680566959fdccd1a98d74ce2f2746f9b0f9ff6b57d03b/", item.file_path)
        self.assertIsNotNone(item.severity_justification)
        self.assertGreater(len(item.severity_justification), 0)
        self.assertIsNotNone(item.references)
        self.assertGreater(len(item.references), 0)
        self.assertEqual("Medium", item.impact)
        self.assertEqual("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", item.cvssv3)
        self.assertEqual(datetime.date(2021, 2, 12), item.date.date())
        self.assertEqual("XRAY-97724", item.unique_id_from_tool)

        # rpm
        item = [i for i in findings if i.title[:11] == "XRAY-106044"][-1]
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2019-19645", item.unsaved_vulnerability_ids[0])
        self.assertEqual("XRAY-106044 - CVE-2019-19645 sqlite: infinite", item.title[:45])
        self.assertEqual("TABLE statements", item.title[-16:])
        self.assertEqual("Medium", item.severity)
        self.assertEqual("alter.c in SQLite", item.description[:17])
        self.assertEqual("TABLE statements.\n\nRed Hat Severity: Moderate", item.description[-45:])
        self.assertIsNone(item.mitigation)
        self.assertEqual("7:sqlite:0", item.component_name)
        self.assertIn("packagetype_rpm", item.tags)
        self.assertEqual("3.7.17-8.el7_7.1", item.component_version)
        self.assertEqual("elastic-docker-remote/elasticsearch/elasticsearch/7.9.1-amd64/", item.file_path)
        self.assertIsNotNone(item.severity_justification)
        self.assertGreater(len(item.severity_justification), 0)
        self.assertIsNotNone(item.references)
        self.assertEqual(len(item.references), 0)
        self.assertEqual("Medium", item.impact)
        self.assertEqual("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", item.cvssv3)
        self.assertEqual(datetime.date(2021, 1, 14), item.date.date())
        self.assertEqual("XRAY-106044", item.unique_id_from_tool)
        # **finished various packages**

    def test_parse_file_with_another_report(self):
        testfile = open(get_unit_tests_scans_path("jfrog_xray_unified") / "Vulnerabilities-Report-XRAY_Unified.json", encoding="utf-8")
        parser = JFrogXrayUnifiedParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(7, len(findings))
