import logging
from importlib import import_module
from importlib.util import find_spec
from inspect import isclass
from pathlib import Path

from dojo.models import Test, Test_Type
from dojo.tools.factory import get_parser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_path

logger = logging.getLogger(__name__)


class TestFactory(DojoTestCase):
    def test_get_parser(self):
        with self.subTest(scan_type="Acunetix Scan"):
            scan_type = "Acunetix Scan"
            testfile = open(get_unit_tests_path() / "scans" / "acunetix" / "one_finding.xml", encoding="utf-8")
            parser = get_parser(scan_type)
            parser.get_findings(testfile, Test())
            testfile.close()
        with self.subTest(scan_type="Anchore Engine Scan"):
            scan_type = "Anchore Engine Scan"
            testfile = open(get_unit_tests_path() / "scans" / "anchore_engine" / "one_vuln.json", encoding="utf-8")
            parser = get_parser(scan_type)
            parser.get_findings(testfile, Test())
            testfile.close()
        with self.subTest(scan_type="Tenable Scan"):
            scan_type = "Tenable Scan"
            testfile = open(get_unit_tests_path() / "scans" / "tenable/nessus" / "nessus_v_unknown.xml", encoding="utf-8")
            parser = get_parser(scan_type)
            parser.get_findings(testfile, Test())
            testfile.close()
        with self.subTest(scan_type="ZAP Scan"):
            scan_type = "ZAP Scan"
            testfile = open(get_unit_tests_path() / "scans" / "zap" / "some_2.9.0.xml", encoding="utf-8")
            parser = get_parser(scan_type)
            parser.get_findings(testfile, Test())
            testfile.close()

    def test_get_parser_error(self):
        with self.assertRaises(ValueError):
            scan_type = "type_that_doesn't_exist"
            get_parser(scan_type)

    def test_get_parser_test_active_in_db(self):
        """This test is designed to validate that the factory take into account the falg 'active' in DB"""
        scan_type = "ZAP Scan"
        # desactivate the parser
        Test_Type.objects.update_or_create(
            name=scan_type,
            defaults={"active": False},
        )
        with self.assertRaises(ValueError):
            get_parser(scan_type)
        # activate the parser
        _test_type, _created = Test_Type.objects.update_or_create(
            name=scan_type,
            defaults={"active": True},
        )
        parser = get_parser(scan_type)
        self.assertIsNotNone(parser)

    def test_parser_name_matches_module(self):
        """Test to ensure that parsers' class names match their module names"""
        package_dir = Path("dojo/tools")
        module_names = package_dir.iterdir()
        missing_parsers = []
        excluded_parsers = [
            "wizcli_common_parsers",  # common class for other wizcli parsers, there is not parsing here
        ]
        for module_name in module_names:
            if module_name in excluded_parsers:
                continue
            if (Path(package_dir) / module_name).is_dir():
                found = False
                if find_spec(f"dojo.tools.{module_name}.parser"):
                    module = import_module(f"dojo.tools.{module_name}.parser")
                    for attribute_name in dir(module):
                        attribute = getattr(module, attribute_name)
                        if isclass(attribute) and attribute_name.lower() == module_name.replace("_", "") + "parser":
                            found = True
                if not found and module_name != "__pycache__":
                    missing_parsers.append(module_name)
        if len(missing_parsers) > 0:
            logger.error(f"Parsers with invalid names: {missing_parsers}")
        self.assertEqual(0, len(missing_parsers))
