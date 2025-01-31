from dojo.models import Test
from dojo.tools.anchorectl_vulns.parser import AnchoreCTLVulnsParser
from unittests.dojo_test_case import DojoTestCase

class TestAnchoreCTLVulnsParser(DojoTestCase):

    # New test for the new JSON format
    def test_anchore_engine_parser_with_new_format(self):
        with open("unittests/scans/anchorectl_vulns/newformat.json", encoding="utf-8") as testfile:
            parser = AnchoreCTLVulnsParser()
            findings = parser.get_findings(testfile, Test())
            # If your new format returns multiple findings, update the assertion accordingly
            self.assertGreater(len(findings), 0)  # Assuming you expect more than 0 findings
            # Optionally, you can check a sample finding from the new format
            singleFinding = findings[0]
            self.assertIn("CVE-", singleFinding.title)  # Check if title has CVE, adjust as per your needs
            # Check if severity is a string and exists
            self.assertIsInstance(singleFinding.severity, str)  # Ensure severity is a string
            self.assertGreater(len(singleFinding.severity), 0)  # Ensure severity is not empty


    