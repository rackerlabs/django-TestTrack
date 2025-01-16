import logging
from datetime import UTC, datetime

from dateutil.tz import tzlocal, tzoffset

from dojo.models import Test
from dojo.tools.dependency_check.parser import DependencyCheckParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)


class TestFile:
    def read(self):
        return self.content

    def __init__(self, name, content):
        self.name = name
        self.content = content


class TestDependencyCheckParser(DojoTestCase):
    def test_parse_empty_file(self):
        with open(get_unit_tests_scans_path("dependency_check") / "single_dependency_with_related_no_vulnerability.xml", encoding="utf-8") as testfile:
            parser = DependencyCheckParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_single_vulnerability_has_single_finding(self):
        with open(get_unit_tests_scans_path("dependency_check") / "single_vuln.xml", encoding="utf-8") as testfile:
            parser = DependencyCheckParser()
            findings = parser.get_findings(testfile, Test())
            items = findings
            self.assertEqual(1, len(items))
            i = 0
            with self.subTest(i=i):
                self.assertEqual(items[i].title, "org.owasp:library:6.7.8 | CVE-0000-0001")
                self.assertEqual(items[i].severity, "Medium")
                self.assertEqual(items[i].component_name, "org.owasp:library")
                self.assertEqual(items[i].component_version, "6.7.8")
                self.assertEqual(
                    items[i].mitigation,
                    "Update org.owasp:library:6.7.8 to at least the version recommended in the description",
                )
                self.assertEqual(items[i].date, datetime(2016, 11, 5, 14, 52, 15, 748000, tzinfo=tzoffset(None, -14400)))

    def test_parse_file_with_single_dependency_with_related_no_vulnerability(self):
        with open(get_unit_tests_scans_path("dependency_check") / "single_dependency_with_related_no_vulnerability.xml", encoding="utf-8") as testfile:
            parser = DependencyCheckParser()
            findings = parser.get_findings(testfile, Test())
            items = findings
            self.assertEqual(0, len(items))

    def test_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        with open(get_unit_tests_scans_path("dependency_check") / "multiple_vulnerabilities_has_multiple_findings.xml", encoding="utf-8") as testfile:
            parser = DependencyCheckParser()
            findings = parser.get_findings(testfile, Test())
            items = findings
            self.assertEqual(11, len(items))
            # test also different component_name formats

            with self.subTest(i=0):
                # identifier -> package url java + 2 relateddependencies
                self.assertEqual(items[0].title, "org.dom4j:dom4j:2.1.1.redhat-00001 | CVE-0000-0001")
                self.assertEqual(items[0].component_name, "org.dom4j:dom4j")
                self.assertEqual(items[0].component_version, "2.1.1.redhat-00001")
                self.assertIn(
                    "Description of a bad vulnerability.",
                    items[0].description,
                )
                self.assertIn(
                    "/var/lib/adapter-ear1.ear/dom4j-2.1.1.jar",
                    items[0].description,
                )
                self.assertEqual(items[0].severity, "High")
                self.assertEqual(items[0].file_path, "adapter-ear1.ear: dom4j-2.1.1.jar")
                self.assertEqual(
                    items[0].mitigation,
                    "Update org.dom4j:dom4j:2.1.1.redhat-00001 to at least the version recommended in the description",
                )
                self.assertEqual(
                    items[0].date, datetime(2016, 11, 5, 14, 52, 15, 748000, tzinfo=tzoffset(None, -14400)),
                )  # 2016-11-05T14:52:15.748-0400
                self.assertEqual(1, len(items[0].unsaved_vulnerability_ids))
                self.assertEqual("CVE-0000-0001", items[0].unsaved_vulnerability_ids[0])

            with self.subTest(i=1):
                self.assertEqual(items[1].title, "org.dom4j:dom4j:2.1.1.redhat-00001 | CVE-0000-0001")
                self.assertEqual(items[1].component_name, "org.dom4j:dom4j")
                self.assertEqual(items[1].component_version, "2.1.1.redhat-00001")
                self.assertIn(
                    "Description of a bad vulnerability.",
                    items[1].description,
                )
                self.assertIn(
                    "/var/lib/adapter-ear8.ear/dom4j-2.1.1.jar",
                    items[1].description,
                )
                self.assertEqual(items[1].severity, "High")
                self.assertEqual(items[1].file_path, "adapter-ear8.ear: dom4j-2.1.1.jar")
                self.assertEqual(
                    items[1].mitigation,
                    "Update org.dom4j:dom4j:2.1.1.redhat-00001 to at least the version recommended in the description",
                )
                self.assertEqual(items[1].tags, "related")
                self.assertEqual(1, len(items[1].unsaved_vulnerability_ids))
                self.assertEqual("CVE-0000-0001", items[1].unsaved_vulnerability_ids[0])

            with self.subTest(i=2):
                self.assertEqual(items[2].title, "org.dom4j:dom4j:2.1.1.redhat-00001 | CVE-0000-0001")
                self.assertEqual(items[2].component_name, "org.dom4j:dom4j")
                self.assertEqual(items[2].component_version, "2.1.1.redhat-00001")
                self.assertIn(
                    "Description of a bad vulnerability.",
                    items[2].description,
                )
                self.assertIn(
                    "/var/lib/adapter-ear1.ear/dom4j-extensions-2.1.1.jar",
                    items[2].description,
                )
                self.assertEqual(items[2].severity, "High")
                self.assertEqual(items[2].file_path, "adapter-ear1.ear: dom4j-extensions-2.1.1.jar")
                self.assertEqual(
                    items[2].mitigation,
                    "Update org.dom4j:dom4j:2.1.1.redhat-00001 to at least the version recommended in the description",
                )
                self.assertEqual(1, len(items[2].unsaved_vulnerability_ids))
                self.assertEqual("CVE-0000-0001", items[2].unsaved_vulnerability_ids[0])

            with self.subTest(i=3):
                # identifier -> package url javascript, no vulnerabilitids, 3 vulnerabilities, relateddependencies without filename (pre v6.0.0)
                self.assertEqual(
                    items[3].title, "yargs-parser:5.0.0 | 1500",
                )
                self.assertEqual(items[3].component_name, "yargs-parser")
                self.assertEqual(items[3].component_version, "5.0.0")
                # assert fails due to special characters, not too important
                # self.assertEqual(items[1].description, "Affected versions of `yargs-parser` are vulnerable to prototype pollution. Arguments are not properly sanitized, allowing an attacker to modify the prototype of `Object`, causing the addition or modification of an existing property that will exist on all objects.Parsing the argument `--foo.__proto__.bar baz&apos;` adds a `bar` property with value `baz` to all objects. This is only exploitable if attackers have control over the arguments being passed to `yargs-parser`.")
                self.assertEqual(items[3].severity, "Low")
                self.assertEqual(items[3].file_path, "yargs-parser:5.0.0")
                self.assertEqual(
                    items[3].mitigation, "Update yargs-parser:5.0.0 to at least the version recommended in the description",
                )
                self.assertIn(
                    "**Source:** NPM",
                    items[3].description,
                )
                self.assertIsNone(items[3].unsaved_vulnerability_ids)

            with self.subTest(i=4):
                self.assertEqual(
                    items[4].title,
                    "yargs-parser:5.0.0 | CVE-2020-7608",
                )
                self.assertEqual(items[4].component_name, "yargs-parser")
                self.assertEqual(items[4].component_version, "5.0.0")
                self.assertIn(
                    'yargs-parser could be tricked into adding or modifying properties\n                        of Object.prototype using a "__proto__" payload.\n**Source:** OSSINDEX\n**Filepath:** \n                /var/lib/jenkins/workspace/nl-selfservice_-_metrics_develop/package-lock.json?yargs-parser',
                    items[4].description,
                )
                self.assertIn(
                    "/var/lib/jenkins/workspace/nl-selfservice_-_metrics_develop/package-lock.json?yargs-parser",
                    items[4].description,
                )
                self.assertEqual(items[4].severity, "High")
                self.assertEqual(items[4].file_path, "yargs-parser:5.0.0")
                self.assertEqual(
                    items[4].mitigation, "Update yargs-parser:5.0.0 to at least the version recommended in the description",
                )
                self.assertEqual(1, len(items[4].unsaved_vulnerability_ids))
                self.assertEqual("CVE-2020-7608", items[4].unsaved_vulnerability_ids[0])

            with self.subTest(i=5):
                self.assertEqual(
                    items[5].title,
                    "yargs-parser:5.0.0 | CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')",
                )
                self.assertEqual(items[5].component_name, "yargs-parser")
                self.assertEqual(items[5].component_version, "5.0.0")
                self.assertIn(
                    "The software does not properly restrict the size or amount of resources that are requested or influenced by an actor, which can be used to consume more resources than intended.",
                    items[5].description,
                )
                # check that the filepath is in the description
                self.assertIn(
                    "/var/lib/jenkins/workspace/nl-selfservice_-_metrics_develop/package-lock.json?yargs-parser",
                    items[5].description,
                )
                self.assertEqual(items[5].severity, "High")
                self.assertEqual(items[5].file_path, "yargs-parser:5.0.0")
                self.assertEqual(
                    items[5].mitigation, "Update yargs-parser:5.0.0 to at least the version recommended in the description",
                )
                self.assertIsNone(items[5].unsaved_vulnerability_ids)

            with self.subTest(i=6):
                # identifier -> cpe java
                self.assertEqual(items[6].title, "org.dom4j:dom4j:2.1.1.redhat-00001 | CVE-0000-0001")
                self.assertEqual(items[6].component_name, "org.dom4j:dom4j")
                self.assertEqual(items[6].component_version, "2.1.1.redhat-00001")
                self.assertEqual(items[6].severity, "High")
                self.assertEqual(items[6].file_path, "adapter-ear2.ear: dom4j-2.1.1.jar")
                self.assertEqual(
                    items[6].mitigation,
                    "Update org.dom4j:dom4j:2.1.1.redhat-00001 to at least the version recommended in the description",
                )
                self.assertEqual(1, len(items[6].unsaved_vulnerability_ids))
                self.assertEqual("CVE-0000-0001", items[6].unsaved_vulnerability_ids[0])

            with self.subTest(i=7):
                # identifier -> maven java
                self.assertEqual(items[7].title, "dom4j:2.1.1 | CVE-0000-0001")
                self.assertEqual(items[7].component_name, "dom4j")
                self.assertEqual(items[7].component_version, "2.1.1")
                self.assertEqual(items[7].severity, "High")
                self.assertEqual(
                    items[7].mitigation, "Update dom4j:2.1.1 to at least the version recommended in the description",
                )

            with self.subTest(i=8):
                # evidencecollected -> single product + single verison javascript
                self.assertEqual(
                    items[8].title,
                    "jquery:3.1.1 | CVE-0000-0001",
                )
                self.assertEqual(items[8].component_name, "jquery")
                self.assertEqual(items[8].component_version, "3.1.1")
                self.assertEqual(items[8].severity, "High")
                self.assertEqual(
                    items[8].mitigation, "Update jquery:3.1.1 to at least the version recommended in the description",
                )

            with self.subTest(i=9):
                # Tests for two suppressed vulnerabilities,
                # One for Suppressed with notes, the other is without.
                self.assertEqual(items[9].active, False)
                self.assertEqual(
                    items[9].mitigation,
                    "**This vulnerability is mitigated and/or suppressed:** Document on why we are suppressing this vulnerability is missing!\nUpdate jquery:3.1.1 to at least the version recommended in the description",
                )
                self.assertEqual(items[9].tags, ["suppressed", "no_suppression_document"])
                self.assertEqual(items[10].severity, "Critical")
                self.assertEqual(items[10].is_mitigated, True)

            with self.subTest(i=10):
                self.assertEqual(items[10].active, False)
                self.assertEqual(
                    items[10].mitigation,
                    "**This vulnerability is mitigated and/or suppressed:** This is our reason for not to upgrade it.\nUpdate jquery:3.1.1 to at least the version recommended in the description",
                )
                self.assertEqual(items[10].tags, "suppressed")
                self.assertEqual(items[10].severity, "Critical")
                self.assertEqual(items[10].is_mitigated, True)

    def test_parse_java_6_5_3(self):
        """Test with version 6.5.3"""
        with open(get_unit_tests_scans_path() / "dependency_check/version-6.5.3.xml", encoding="utf-8") as test_file:
            parser = DependencyCheckParser()
            findings = parser.get_findings(test_file, Test())
            items = findings
            self.assertEqual(1, len(items))

            i = 0
            with self.subTest(i=i):
                self.assertEqual(items[i].component_name, "org.apache.logging.log4j:log4j-api")
                self.assertEqual(items[i].component_version, "2.12.4")
                self.assertIn(
                    "Improper validation of certificate with host mismatch in Apache Log4j SMTP appender. This could allow an SMTPS connection to be intercepted by a man-in-the-middle attack which could leak any log messages sent through that appender.",
                    items[i].description,
                )
                self.assertEqual(items[i].severity, "Low")
                self.assertEqual(items[i].file_path, "log4j-api-2.12.4.jar")
                self.assertEqual(items[i].date, datetime(2022, 1, 15, 14, 31, 13, 42600, tzinfo=UTC))

    def test_parse_file_pr6439(self):
        with open(get_unit_tests_scans_path("dependency_check") / "PR6439.xml", encoding="utf-8") as testfile:
            parser = DependencyCheckParser()
            findings = parser.get_findings(testfile, Test())
            items = findings
            self.assertEqual(37, len(items))
            # test also different component_name formats

            with self.subTest(i=0):
                logger.debug(items[0])
                # identifier -> package url java + 2 relateddependencies
                self.assertEqual(items[0].title, "org.apache.activemq:activemq-broker:5.16.5 | CVE-2015-3208")
                self.assertEqual(items[0].component_name, "org.apache.activemq:activemq-broker")
                self.assertEqual(items[0].component_version, "5.16.5")
                self.assertIn(
                    "XML external entity (XXE) vulnerability in the XPath selector component in",
                    items[0].description,
                )
                self.assertIn(
                    "**Source:** OSSINDEX",
                    items[0].description,
                )
                self.assertEqual(items[0].severity, "Critical")
                self.assertEqual(items[0].file_path, "activemq-broker-5.16.5.jar")
                self.assertIn(
                    "**This vulnerability is mitigated and/or suppressed:** Ist eine Dependency vom CXF. Der im Finding erwähnte Bug ist seit Version 1.0",
                    items[0].mitigation,
                )
                self.assertEqual(
                    items[0].date, datetime(2022, 12, 14, 1, 35, 43, 684166, tzinfo=tzlocal()),
                )  # 2016-11-05T14:52:15.748-0400
                self.assertEqual(1, len(items[0].unsaved_vulnerability_ids))
                self.assertEqual("CVE-2015-3208", items[0].unsaved_vulnerability_ids[0])
