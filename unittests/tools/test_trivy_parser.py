import re

from dojo.models import Test
from dojo.tools.trivy.parser import TrivyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def sample_path(file_name):
    return get_unit_tests_scans_path("trivy") / file_name


class TestTrivyParser(DojoTestCase):

    def test_legacy_no_vuln(self):
        with open(sample_path("legacy_no_vuln.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            trivy_findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(trivy_findings), 0)

    def test_legacy_many_vulns(self):
        with open(sample_path("legacy_many_vulns.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 93)
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2011-3374", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(347, finding.cwe)
            self.assertEqual("apt", finding.component_name)
            self.assertEqual("1.8.2.2", finding.component_version)

    def test_scheme_2_no_vuln(self):
        with open(sample_path("scheme_2_no_vuln.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            trivy_findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(trivy_findings), 0)

    def test_scheme_2_many_vulns(self):
        with open(sample_path("scheme_2_many_vulns.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 5)
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("CVE-2020-15999 freetype 2.9.1-r2", finding.title)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2020-15999", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(787, finding.cwe)
            self.assertEqual("freetype", finding.component_name)
            self.assertEqual("app/libs/freetype-2.9.1-r2", finding.file_path)
            self.assertEqual("2.9.1-r2", finding.component_version)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.references)
            self.assertEqual("2.9.1-r3", finding.mitigation)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", finding.cvssv3)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            finding = findings[1]
            self.assertEqual("High", finding.severity)
            self.assertEqual("CVE-2020-28196 krb5-libs 1.15.5-r0", finding.title)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2020-28196", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(674, finding.cwe)
            self.assertEqual("krb5-libs", finding.component_name)
            self.assertEqual("app/libs/krb5-libs-1.15.5-r0", finding.file_path)
            self.assertEqual("1.15.5-r0", finding.component_version)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.references)
            self.assertEqual("1.15.5-r1", finding.mitigation)
            self.assertIsNone(finding.cvssv3)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_misconfigurations_and_secrets(self):
        with open(sample_path("misconfigurations_and_secrets.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 5)
            finding = findings[2]
            self.assertEqual("DS002 - Image user should not be 'root'", finding.title)
            self.assertEqual("High", finding.severity)
            description = """**Target:** Dockerfile
**Type:** Dockerfile Security Check

Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.
Specify at least 1 USER command in Dockerfile with non-root user as argument
"""
            self.assertEqual(description, finding.description)
            self.assertEqual("Add 'USER <non root user name>' line to the Dockerfile", finding.mitigation)
            references = """https://avd.aquasec.com/misconfig/ds002
https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"""
            self.assertEqual(references, finding.references)
            self.assertEqual(["config", "dockerfile"], finding.tags)
            finding = findings[3]
            self.assertEqual("Secret detected in Dockerfile - GitHub Personal Access Token", finding.title)
            self.assertEqual("Critical", finding.severity)
            description = """GitHub Personal Access Token
**Category:** GitHub
**Match:** ENV GITHUB_PAT=*****
"""
            self.assertEqual(description, finding.description)
            self.assertEqual("Dockerfile", finding.file_path)
            self.assertEqual(24, finding.line)
            self.assertEqual(["secret"], finding.tags)

    def test_kubernetes(self):
        with open(sample_path("kubernetes.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 20)
            finding = findings[0]
            self.assertEqual("CVE-2020-27350 apt 1.8.2.1", finding.title)
            self.assertEqual("Medium", finding.severity)
            description = """apt: integer overflows and underflows while parsing .deb packages
**Target:** gcr.io/google_samples/gb-redis-follower:v2 (debian 10.4)
**Type:** debian
**Fixed version:** 1.8.2.2

APT had several integer overflows and underflows while parsing .deb packages, aka GHSL-2020-168 GHSL-2020-169, in files apt-pkg/contrib/extracttar.cc, apt-pkg/deb/debfile.cc, and apt-pkg/contrib/arfile.cc. This issue affects: apt 1.2.32ubuntu0 versions prior to 1.2.32ubuntu0.2; 1.6.12ubuntu0 versions prior to 1.6.12ubuntu0.2; 2.0.2ubuntu0 versions prior to 2.0.2ubuntu0.2; 2.1.10ubuntu0 versions prior to 2.1.10ubuntu0.1;
"""
            self.assertEqual(description, finding.description)
            self.assertEqual("1.8.2.2", finding.mitigation)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2020-27350", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(["debian", "os-pkgs"], finding.tags)
            self.assertEqual("apt", finding.component_name)
            self.assertEqual("1.8.2.1", finding.component_version)
            self.assertEqual("default / Deployment / redis-follower", finding.service)
            self.assertEqual(finding.file_path, "gcr.io/google_samples/gb-redis-follower:v2 (debian 10.4)")
            finding = findings[5]
            self.assertEqual("CVE-2020-27350 apt 1.8.2.1", finding.title)
            self.assertEqual("Medium", finding.severity)
            description = """apt: integer overflows and underflows while parsing .deb packages
**Target:** docker.io/redis:6.0.5 (debian 10.4)
**Type:** debian
**Fixed version:** 1.8.2.2

APT had several integer overflows and underflows while parsing .deb packages, aka GHSL-2020-168 GHSL-2020-169, in files apt-pkg/contrib/extracttar.cc, apt-pkg/deb/debfile.cc, and apt-pkg/contrib/arfile.cc. This issue affects: apt 1.2.32ubuntu0 versions prior to 1.2.32ubuntu0.2; 1.6.12ubuntu0 versions prior to 1.6.12ubuntu0.2; 2.0.2ubuntu0 versions prior to 2.0.2ubuntu0.2; 2.1.10ubuntu0 versions prior to 2.1.10ubuntu0.1;
"""
            self.assertEqual(description, finding.description)
            self.assertEqual("1.8.2.2", finding.mitigation)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2020-27350", finding.unsaved_vulnerability_ids[0])
            self.assertEqual(["debian", "os-pkgs"], finding.tags)
            self.assertEqual("apt", finding.component_name)
            self.assertEqual("1.8.2.1", finding.component_version)
            self.assertEqual("default / Deployment / redis-leader", finding.service)
            finding = findings[10]
            self.assertEqual("KSV001 - Process can elevate its own privileges", finding.title)
            self.assertEqual("Medium", finding.severity)
            description = """**Target:** Deployment/redis-follower
**Type:** Kubernetes Security Check

A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.
Container 'follower' of Deployment 'redis-follower' should set 'securityContext.allowPrivilegeEscalation' to false
Number  Content
132                     - image: gcr.io/google_samples/gb-redis-follower:v2
133                       imagePullPolicy: IfNotPresent
134                       name: follower
135                       ports:
136                         - containerPort: 6379
137                           protocol: TCP
138                       resources:
139                         requests:
140                             cpu: 100m
141"""
            re_description = re.sub(r"\s+", " ", description)
            re_finding_description = re.sub(r"\s+", " ", finding.description)
            self.assertEqual(re_description.strip(), re_finding_description.strip())
            self.assertEqual("Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'.", finding.mitigation)
            self.assertIsNone(finding.unsaved_vulnerability_ids)
            self.assertEqual(["config", "kubernetes"], finding.tags)
            self.assertIsNone(finding.component_name)
            self.assertIsNone(finding.component_version)
            self.assertEqual("default / Deployment / redis-follower", finding.service)

    def test_license_scheme(self):
        with open(sample_path("license_scheme.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 19)
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("", finding.file_path)
            self.assertEqual(1, finding.scanner_confidence)
            self.assertEqual("", finding.url)
            description = """GPL-2.0
**Category:** restricted
**Package:** alpine-baselayout
"""
            self.assertEqual(description, finding.description)

    def test_issue_9092(self):
        with open(sample_path("issue_9092.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(finding.file_path, "requirements.txt")

    def test_issue_9170(self):
        with open(sample_path("issue_9170.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 37)
            finding = findings[0]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("KSV116 - Runs with a root primary or supplementary GID", finding.title)

    def test_issue_9263(self):
        with open(sample_path("issue_9263.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual("High", finding.severity)

    def test_issue_9333(self):
        with open(sample_path("issue_9333.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 13)
            finding = findings[0]
            self.assertEqual("Low", finding.severity)

    def test_issue_10991(self):
        with open(sample_path("issue_10991.json"), encoding="utf-8") as test_file:
            parser = TrivyParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 37)
