import json

import dojo.tools.ptart.ptart_parser_tools as ptart_tools
from dojo.tools.parser_test import ParserTest
from dojo.tools.ptart.assessment_parser import PTARTAssessmentParser
from dojo.tools.ptart.retest_parser import PTARTRetestParser


class PTARTParser:

    """
    Imports JSON reports from the PTART reporting tool
    (https://github.com/certmichelin/PTART)
    """

    def get_scan_types(self):
        return ["PTART Report"]

    def get_label_for_scan_types(self, scan_type):
        return "PTART Report"

    def get_description_for_scan_types(self, scan_type):
        return "Import a PTART report file in JSON format."

    def get_tests(self, scan_type, scan):
        data = json.load(scan)

        test = ParserTest(
            name="Pen Test Report",
            parser_type="Pen Test",
            version="",
        )

        # We set both to the same value for now, setting just the name doesn't
        # seem to display when imported. This may cause issues with the UI in
        # the future, but there's not much (read no) documentation on this.
        if "name" in data:
            test.name = data["name"] + " Report"
            test.type = data["name"] + " Report"

        # Generate a description from the various fields in the report data
        description = ptart_tools.generate_test_description_from_report(data)

        # Check that the fields are filled, otherwise don't set the description
        if description:
            test.description = description

        # Setting the dates doesn't seem to want to work in reality :(
        # Perhaps in a future version of DefectDojo?
        if "start_date" in data:
            test.target_start = ptart_tools.parse_date(
                data["start_date"], "%Y-%m-%d",
            )

        if "end_date" in data:
            test.target_end = ptart_tools.parse_date(
                data["end_date"], "%Y-%m-%d",
            )

        findings = self.get_items(data)
        test.findings = findings
        return [test]

    def get_findings(self, file, test):
        data = json.load(file)
        return self.get_items(data)

    def get_items(self, data):
        # We have several main sections in the report json: Assessments and
        # Retest Campaigns. I haven't been able to create multiple tests for
        # each section, so we'll just merge them for now.
        findings = PTARTAssessmentParser().get_test_data(data)
        findings.extend(PTARTRetestParser().get_test_data(data))
        return findings

    def requires_file(self, scan_type):
        return True
