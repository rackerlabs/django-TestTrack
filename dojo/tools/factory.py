import logging
import os
import re
from importlib import import_module
from importlib.util import find_spec
from inspect import isclass
from pathlib import Path

from django.conf import settings

from dojo.models import Test_Type, Tool_Configuration, Tool_Type

PARSERS = {}

logger = logging.getLogger(__name__)


def register(parser_type):
    for scan_type in parser_type().get_scan_types():
        parser = parser_type()
        if scan_type.endswith("detailed"):
            parser.set_mode("detailed")
        register_parser(scan_type, parser)


def register_parser(scan_type, parser):
    logger.debug(f"register scan_type:{scan_type} with parser:{parser}")
    # check double registration or registration with an existing key
    if scan_type in PARSERS:
        msg = f"Try to register an existing parser '{scan_type}'"
        raise ValueError(msg)
    PARSERS[scan_type] = parser


def get_parser(scan_type):
    """Return a parser by the scan type"""
    if scan_type not in PARSERS:
        msg = f"Parser '{scan_type}' does not exist"
        raise ValueError(msg)
    rg = re.compile(settings.PARSER_EXCLUDE)
    if not rg.match(scan_type) or settings.PARSER_EXCLUDE.strip() == "":
        # update DB dynamically
        test_type, _ = Test_Type.objects.get_or_create(name=scan_type)
        if test_type.active:
            return PARSERS[scan_type]
    msg = f"Parser {scan_type} is not active"
    raise ValueError(msg)


def get_inactive_test_types():
    try:
        return list(Test_Type.objects.filter(active=False).values_list("name", flat=True))
    except Exception:
        # This exception is reached in the event of loading fixtures in to an empty database
        # prior to migrations runnings
        return []


def get_scan_types_sorted():
    res = []
    inactive_test_types = get_inactive_test_types()
    for key in PARSERS:
        if key not in inactive_test_types:
            res.append((key, PARSERS[key].get_description_for_scan_types(key)))
    return sorted(res, key=lambda x: x[0].lower())


def get_choices_sorted():
    res = []
    inactive_test_types = get_inactive_test_types()
    for key in PARSERS:
        if key not in inactive_test_types:
            res.append((key, key))
    return sorted(res, key=lambda x: x[1].lower())


def requires_file(scan_type):
    if scan_type not in PARSERS:
        return False
    parser = PARSERS[scan_type]
    if hasattr(parser, "requires_file"):
        return parser.requires_file(scan_type)
    # Set a sane default to require files since it is the
    # more commen scenario.
    return True


def get_api_scan_configuration_hints():
    res = []
    inactive_test_types = get_inactive_test_types()
    for name, parser in PARSERS.items():
        if name not in inactive_test_types and hasattr(parser, "api_scan_configuration_hint"):
            scan_types = parser.get_scan_types()
            for scan_type in scan_types:
                tool_type = parser.requires_tool_type(scan_type)
                res.append({
                    "name": name,
                    "id": name.lower().replace(" ", "_").replace(".", ""),
                    "tool_type_name": tool_type,
                    "tool_types": Tool_Type.objects.filter(name=tool_type),
                    "tool_configurations": Tool_Configuration.objects.filter(tool_type__name=tool_type),
                    "hint": parser.api_scan_configuration_hint(),
                })
    return sorted(res, key=lambda x: x["name"].lower())


def requires_tool_type(scan_type):
    if scan_type not in PARSERS:
        return None
    parser = PARSERS[scan_type]
    if hasattr(parser, "requires_tool_type"):
        return parser.requires_tool_type(scan_type)
    return None


# iterate through the modules in the current package
package_dir = str(Path(__file__).resolve().parent)
for module_name in os.listdir(package_dir):  # noqa: PTH208
    # check if it's dir
    if (Path(package_dir) / module_name).is_dir():
        try:
            # check if it's a Python module
            if find_spec(f"dojo.tools.{module_name}.parser"):
                # import the module and iterate through its attributes
                module = import_module(f"dojo.tools.{module_name}.parser")
                for attribute_name in dir(module):
                    attribute = getattr(module, attribute_name)
                    if isclass(attribute) and attribute_name.lower() == module_name.replace("_", "") + "parser":
                        register(attribute)
        except:
            logger.exception(f"failed to load {module_name}")
