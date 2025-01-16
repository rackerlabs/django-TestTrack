import datetime

from dojo.models import Test
from dojo.tools.trufflehog3.parser import TruffleHog3Parser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def sample_path(file_name):
    return get_unit_tests_scans_path("trufflehog3") / file_name


class TestTruffleHog3Parser(DojoTestCase):

    def test_zero_vulns(self):
        with open(sample_path("zero_vulns.json"), encoding="utf-8") as test_file:
            parser = TruffleHog3Parser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 0)

    def test_many_vulns_legacy(self):
        with open(sample_path("many_vulns_legacy.json"), encoding="utf-8") as test_file:
            parser = TruffleHog3Parser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 7)
            # {
            #     "date": "2018-05-28 03:24:03",
            #     "path": "fixtures/users.json",
            #     "branch": "origin/master",
            #     "commit": "Update users.json",
            #     "commitHash": "3e2d1f58bf2ee974fb1195373d8526876fd6348b",
            #     "reason": "High entropy",
            #     "stringsFound": [
            #     "+      \"password\": \"md5$c77N8n6nJPb1$3b35343aac5e46740f6e673521aa53dc\",",
            #     "-      \"password\": \"md5$oAKvI66ce0Xq$a5c1836db3d6dedff5deca630a358d8b\","
            #     ]
            # }
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("fixtures/users.json", finding.file_path)
            # TODO: for now the date in Finding is type datetime.date we need to switch to datetime
            # self.assertEqual(datetime.datetime, type(finding.date))
            # self.assertEqual(datetime.datetime(2018, 2, 25, 11, 35, 52), finding.date)
            self.assertEqual(datetime.date, type(finding.date))
            self.assertEqual(7, finding.nb_occurences)

    def test_many_vulns2_legacy(self):
        with open(sample_path("many_vulns2_legacy.json"), encoding="utf-8") as test_file:
            parser = TruffleHog3Parser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 27)
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("test_all.py", finding.file_path)
            self.assertEqual(8, finding.nb_occurences)

    def test_many_vulns_current(self):
        with open(sample_path("many_vulns_current.json"), encoding="utf-8") as test_file:
            parser = TruffleHog3Parser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 3)

            finding = findings[0]
            self.assertEqual("High Entropy found in docker/Dockerfile", finding.title)
            self.assertEqual(798, finding.cwe)
            description = """**Secret:** 964a1afa20dd4a3723002560124dd96f2a9e853f7ef5b86f5c2354af336fca37
**Context:**
    3: +FROM python:3.9.7-alpine@sha256:964a1afa20dd4a3723002560124dd96f2a9e853f7ef5b86f5c2354af336fca37
**Branch:** python-ab08dd9
**Commit message:** Bump python from 3.9.7-alpine to 3.10.0-alpine
**Commit hash:** 9c3f4d641d14eba2740febccd902cde300218a8d
**Commit date:** 2021-10-08T20:14:27+02:00"""
            self.assertEqual(description, finding.description)
            self.assertEqual("High", finding.severity)
            self.assertEqual("docker/Dockerfile", finding.file_path)
            self.assertEqual(3, finding.line)
            self.assertEqual(1, finding.nb_occurences)

            finding = findings[1]
            self.assertEqual("High Entropy found in docker/Dockerfile", finding.title)
            self.assertEqual(798, finding.cwe)
            self.maxDiff = None
            self.assertIn("\n\n***\n\n", finding.description)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("docker/Dockerfile", finding.file_path)
            self.assertEqual(2, finding.line)
            self.assertEqual(2, finding.nb_occurences)

            finding = findings[2]
            self.assertEqual("High Entropy found in env-file.txt", finding.title)
            self.assertEqual(798, finding.cwe)
            description = """**Secret:** 44c45225cf94e58d0c86f0a31051eb7c52c8f78f
**Context:**
    10: DD_API_KEY=44c45225cf94e58d0c86f0a31051eb7c52c8f78f
    11: second line of context"""
            self.assertEqual(description, finding.description)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("env-file.txt", finding.file_path)
            self.assertEqual(10, finding.line)
            self.assertEqual(1, finding.nb_occurences)

    def test_issue_6999(self):
        with open(sample_path("issue_6999.json"), encoding="utf-8") as test_file:
            parser = TruffleHog3Parser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 1)
