from dojo.models import Test
from dojo.tools.wizcli_iac.parser import WizcliIaCParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWizcliIaCParser(DojoTestCase):
    def test_no_findings(self):
        with open(get_unit_tests_scans_path("wizcli_iac") / "wizcli_iac_zero_vul.json", encoding="utf-8") as testfile:
            parser = WizcliIaCParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 0)

    def test_one_findings(self):
        with open(get_unit_tests_scans_path("wizcli_iac") / "wizcli_iac_one_vul.json", encoding="utf-8") as testfile:
            parser = WizcliIaCParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(
                "Secret: Passwords And Secrets - Password in URL (postgres://postgres:---REDACTED---@db:5432/postgres?)",
                finding.title,
            )
            self.assertEqual("High", finding.severity)
            self.assertEqual("docker-compose.yml", finding.file_path)
            self.assertEqual(58, finding.line)
            self.assertIn(
                "**Secret ID**: None\n"
                "**Description**: Passwords And Secrets - Password in URL (postgres://postgres:---REDACTED---@db:5432/postgres?)\n"
                "**File Name**: docker-compose.yml\n"
                "**Line Number**: 58\n"
                "**Match Content**: PASSWORD\n",
                finding.description,
            )

    def test_multiple_findings(self):
        with open(get_unit_tests_scans_path("wizcli_iac") / "wizcli_iac_many_vul.json", encoding="utf-8") as testfile:
            parser = WizcliIaCParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(25, len(findings))
            finding = findings[0]
            self.assertEqual(
                "Apk Add Using Local Cache Path - FROM={{registry.gitlab.com/evilorg.com/infra/images/go-lang-1.18-alpine3.17:latest as builder}}.{{RUN apk add --update make git musl-dev gcc}}",
                finding.title,
            )
            self.assertEqual("Informational", finding.severity)
            self.assertEqual("Dockerfile", finding.file_path)
            self.assertEqual(8, finding.line)
            self.assertIn(
                "**Rule ID**: 4ac84116-456f-4d60-9e12-187607266faf\n"
                "**Rule Name**: Apk Add Using Local Cache Path\n"
                "**Resource Name**: FROM={{registry.gitlab.com/evilorg.com/infra/images/go-lang-1.18-alpine3.17:latest as builder}}.{{RUN apk add --update make git musl-dev gcc}}\n"
                "**File Name**: Dockerfile\n"
                "**Line Number**: 8\n"
                "**Match Content**: RUN apk add --update make git musl-dev gcc\n"
                "**Expected**: 'RUN' should not contain 'apk add' command without '--no-cache' switch\n"
                "**Found**: 'RUN' contains 'apk add' command without '--no-cache' switch\n"
                "**File Type**: DOCKERFILE\n",
                finding.description,
            )

            finding = findings[1]
            self.assertEqual(
                "Healthcheck Instruction Missing - FROM={{registry.gitlab.com/evilorg.com/infra/images/alpine-3.9:latest}}",
                finding.title,
            )
            self.assertEqual("Low", finding.severity)
            self.assertEqual("Dockerfile", finding.file_path)
            self.assertEqual(58, finding.line)
            self.assertIn(
                "**Rule ID**: ab1043e3-1eeb-4e38-9ca9-7ec0e99fe2ba\n"
                "**Rule Name**: Healthcheck Instruction Missing\n"
                "**Resource Name**: FROM={{registry.gitlab.com/evilorg.com/infra/images/alpine-3.9:latest}}\n"
                "**File Name**: Dockerfile\n"
                "**Line Number**: 58\n"
                "**Match Content**: FROM registry.gitlab.com/evilorg.com/infra/images/alpine-3.9:latest\n"
                "**Expected**: Dockerfile should contain instruction 'HEALTHCHECK'\n"
                "**Found**: Dockerfile doesn't contain instruction 'HEALTHCHECK'\n"
                "**File Type**: DOCKERFILE\n",
                finding.description,
            )
