import os
from pathlib import Path

from django.test import tag as test_tag

from .dojo_test_case import DojoTestCase, get_unit_tests_path

basedir = get_unit_tests_path().parent


@test_tag("parser-supplement-tests")
class TestParsers(DojoTestCase):
    def test_file_existence(self):
        for parser_dir in os.scandir(Path(basedir) / "dojo" / "tools"):

            if parser_dir.is_file() or parser_dir.name == "__pycache__":
                continue  # this is not parser dir but some support file

            if parser_dir.name.startswith("api_"):
                doc_name = parser_dir.name[4:]
                category = "api"
            else:
                doc_name = parser_dir.name
                category = "file"

            if doc_name not in [
                "checkmarx_osa",  # it is documented in 'checkmarx'
                "wizcli_common_parsers",  # common class for other wizcli parsers
            ]:
                with self.subTest(parser=parser_dir.name, category="docs"):
                    doc_file = Path(basedir) / "docs" / "content" / "en" / "connecting_your_tools" / "parsers" / category / f"{doc_name}.md"
                    self.assertTrue(
                        Path(doc_file).is_file(),
                        f"Documentation file '{doc_file}' is missing or using different name",
                                    )

                    content = Path(doc_file).read_text(encoding="utf-8")
                    self.assertRegex(content, "title:",
                                    f"Documentation file '{doc_file}' does not contain a title",
                                    )
                    self.assertRegex(content, "toc_hide: true",
                                    f"Documentation file '{doc_file}' does not contain toc_hide: true",
                                    )
                    if category == "file":
                        self.assertRegex(content, "### Sample Scan Data",
                                        f"Documentation file '{doc_file}' does not contain ### Sample Scan Data",
                                        )
                        self.assertRegex(content, "https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans",
                                        f"Documentation file '{doc_file}' does not contain https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans",
                                        )

            if parser_dir.name not in [  # noqa: FURB171
                "wizcli_common_parsers",  # common class for other wizcli parsers
            ]:
                with self.subTest(parser=parser_dir.name, category="parser"):
                    parser_test_file = Path(basedir) / "unittests" / "tools" / f"test_{parser_dir.name}_parser.py"
                    self.assertTrue(
                        Path(parser_test_file).is_file(),
                        f"Unittest of parser '{parser_test_file}' is missing or using different name",
                    )

            if parser_dir.name not in [
                "vcg",  # content of the sample report is string the directly in unittest
                "wizcli_common_parsers",  # common class for other wizcli parsers
            ]:
                with self.subTest(parser=parser_dir.name, category="testfiles"):
                    scan_dir = Path(basedir) / "unittests" / "scans" / parser_dir.name
                    self.assertTrue(
                        Path(scan_dir).is_dir(),
                        f"Test files for unittest of parser '{scan_dir}' are missing or using different name",
                    )

            if category == "api":
                if parser_dir.name not in [
                    "api_blackduck",  # TODO: tests should be implemented also for this parser
                    "api_vulners",  # TODO: tests should be implemented also for this parser
                ]:
                    with self.subTest(parser=parser_dir.name, category="importer"):
                        importer_test_file = Path(basedir) / "unittests" / "tools" / f"test_{parser_dir.name}_importer.py"
                        self.assertTrue(
                            Path(importer_test_file).is_file(),
                            f"Unittest of importer '{importer_test_file}' is missing or using different name",
                        )
            for file in os.scandir(Path(basedir) / "dojo" / "tools" / parser_dir.name):
                if file.is_file() and file.name != "__pycache__" and file.name != "__init__.py":
                    f_path = Path(basedir) / "dojo" / "tools" / parser_dir.name / file.name
                    read_true = False
                    with open(f_path, encoding="utf-8") as f:
                        i = 0
                        for line in f:
                            if read_true is True:
                                if ('"utf-8"' in str(line) or "'utf-8'" in str(line) or '"utf-8-sig"' in str(line) or "'utf-8-sig'" in str(line)) and i <= 4:
                                    read_true = False
                                    i = 0
                                elif i > 4:
                                    self.assertTrue(expr=False, msg=f"In file '{f_path}' the test is failing because you don't have utf-8 after .read()")
                                    i = 0
                                    read_true = False
                                else:
                                    i += 1
                            if ".read()" in str(line):
                                read_true = True
                                i = 0

    def test_parser_existence(self):
        for docs in os.scandir(Path(basedir) / "docs" / "content" / "en" / "connecting_your_tools" / "parsers" / "file"):
            if docs.name not in [
                "_index.md", "codeql.md", "edgescan.md",
            ]:
                with self.subTest(parser=docs.name.split(".md")[0], category="parser"):
                    parser = Path(basedir) / "dojo" / "tools" / f"{docs.name.split('.md')[0]}" / "parser.py"
                    self.assertTrue(
                        Path(parser).is_file(),
                        f"Parser '{parser}' is missing or using different name",
                                    )
