from dojo.models import Engagement, Product, Test
from dojo.tools.ptart.parser import PTARTParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPTARTParser(DojoTestCase):

    def setUp(self):
        self.product = Product(name="sample product",
                               description="what a description")
        self.engagement = Engagement(name="sample engagement",
                                     product=self.product)
        self.test = Test(engagement=self.engagement)

    def test_ptart_parser_tools_parse_ptart_severity(self):
        from dojo.tools.ptart.ptart_parser_tools import parse_ptart_severity
        with self.subTest("Critical"):
            self.assertEqual("Critical", parse_ptart_severity(1))
        with self.subTest("High"):
            self.assertEqual("High", parse_ptart_severity(2))
        with self.subTest("Medium"):
            self.assertEqual("Medium", parse_ptart_severity(3))
        with self.subTest("Low"):
            self.assertEqual("Low", parse_ptart_severity(4))
        with self.subTest("Info"):
            self.assertEqual("Info", parse_ptart_severity(5))
        with self.subTest("Unknown"):
            self.assertEqual("Info", parse_ptart_severity(6))

    def test_ptart_parser_tools_parse_ptart_fix_effort(self):
        from dojo.tools.ptart.ptart_parser_tools import parse_ptart_fix_effort
        with self.subTest("High"):
            self.assertEqual("High", parse_ptart_fix_effort(1))
        with self.subTest("Medium"):
            self.assertEqual("Medium", parse_ptart_fix_effort(2))
        with self.subTest("Low"):
            self.assertEqual("Low", parse_ptart_fix_effort(3))
        with self.subTest("Unknown"):
            self.assertEqual(None, parse_ptart_fix_effort(4))

    def test_ptart_parser_tools_parse_title_from_hit(self):
        from dojo.tools.ptart.ptart_parser_tools import parse_title_from_hit
        with self.subTest("Title and ID"):
            self.assertEqual("1234: Test Title", parse_title_from_hit({"title": "Test Title", "id": "1234"}))
        with self.subTest("Title Only"):
            self.assertEqual("Test Title", parse_title_from_hit({"title": "Test Title"}))
        with self.subTest("ID Only"):
            self.assertEqual("1234", parse_title_from_hit({"id": "1234"}))
        with self.subTest("No Title or ID"):
            self.assertEqual("Unknown Hit", parse_title_from_hit({}))
        with self.subTest("Empty Title"):
            self.assertEqual("Unknown Hit", parse_title_from_hit({"title": ""}))
        with self.subTest("Empty ID"):
            self.assertEqual("Unknown Hit", parse_title_from_hit({"id": ""}))
        with self.subTest("Blank Title and Blank ID"):
            self.assertEqual("Unknown Hit", parse_title_from_hit({"title": "", "id": ""}))
        with self.subTest("Blank Title and Non-blank id"):
            self.assertEqual("1234", parse_title_from_hit({"title": "", "id": "1234"}))
        with self.subTest("Non-blank Title and Blank id"):
            self.assertEqual("Test Title", parse_title_from_hit({"title": "Test Title", "id": ""}))

    def test_ptart_parser_tools_cvss_vector_acquisition(self):
        from dojo.tools.ptart.ptart_parser_tools import parse_cvss_vector
        with self.subTest("Test CVSSv3 Vector"):
            hit = {
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            }
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", parse_cvss_vector(hit, 3))
        with self.subTest("Test CVSSv4 Vector"):
            hit = {
                "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            }
            self.assertEqual(None, parse_cvss_vector(hit, 4))
        with self.subTest("Test CVSSv3 Vector with CVSSv4 Request"):
            hit = {
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            }
            self.assertEqual(None, parse_cvss_vector(hit, 4))
        with self.subTest("Test CVSSv4 Vector with CVSSv3 Request"):
            hit = {
                "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            }
            self.assertEqual(None, parse_cvss_vector(hit, 3))
        with self.subTest("Test No CVSS Vector"):
            hit = {}
            self.assertEqual(None, parse_cvss_vector(hit, 3))
        with self.subTest("Test CVSSv2 Vector"):
            hit = {
                "cvss_vector": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
            }
            self.assertEqual(None, parse_cvss_vector(hit, 2))
        with self.subTest("Test Blank CVSS Vector"):
            hit = {
                "cvss_vector": "",
            }
            self.assertEqual(None, parse_cvss_vector(hit, 3))

    def test_ptart_parser_tools_retest_fix_status_parse(self):
        from dojo.tools.ptart.ptart_parser_tools import parse_retest_status
        with self.subTest("Fixed"):
            self.assertEqual("Fixed", parse_retest_status("F"))
        with self.subTest("Not Fixed"):
            self.assertEqual("Not Fixed", parse_retest_status("NF"))
        with self.subTest("Partially Fixed"):
            self.assertEqual("Partially Fixed", parse_retest_status("PF"))
        with self.subTest("Not Applicable"):
            self.assertEqual("Not Applicable", parse_retest_status("NA"))
        with self.subTest("Not Tested"):
            self.assertEqual("Not Tested", parse_retest_status("NT"))
        with self.subTest("Unknown"):
            self.assertEqual(None, parse_retest_status("U"))
        with self.subTest("Empty"):
            self.assertEqual(None, parse_retest_status(""))

    def test_ptart_parser_tools_parse_screenshots_from_hit(self):
        from dojo.tools.ptart.ptart_parser_tools import parse_screenshots_from_hit
        with self.subTest("No Screenshots"):
            hit = {}
            screenshots = parse_screenshots_from_hit(hit)
            self.assertEqual([], screenshots)
        with self.subTest("One Screenshot"):
            hit = {
                "screenshots": [{
                    "caption": "One",
                    "order": 0,
                    "screenshot": {
                        "filename": "screenshots/a78bebcc-6da7-4c25-86a3-441435ea68d0.png",
                        "data": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABzElEQVR42mNk",
                    },
                }],
            }
            screenshots = parse_screenshots_from_hit(hit)
            self.assertEqual(1, len(screenshots))
            screenshot = screenshots[0]
            self.assertEqual("One.png", screenshot["title"])
            self.assertTrue(screenshot["data"] == "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABzElEQVR42mNk",
                            "Invalid Screenshot Data")
        with self.subTest("Two Screenshots"):
            hit = {
                "screenshots": [{
                    "caption": "One",
                    "order": 0,
                    "screenshot": {
                        "filename": "screenshots/a78bebcc-6da7-4c25-86a3-441435ea68d0.png",
                        "data": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABzElEQVR42mNk",
                    },
                }, {
                    "caption": "Two",
                    "order": 1,
                    "screenshot": {
                        "filename": "screenshots/123e4567-e89b-12d3-a456-426614174000.png",
                        "data": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABzElEQVR42mNk",
                    },
                }],
            }
            screenshots = parse_screenshots_from_hit(hit)
            self.assertEqual(2, len(screenshots))
            first_screenshot = screenshots[0]
            self.assertEqual("One.png", first_screenshot["title"])
            self.assertTrue(first_screenshot["data"] == "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABzElEQVR42mNk",
                            "Invalid Screenshot Data")
            second_screenshot = screenshots[1]
            self.assertEqual("Two.png", second_screenshot["title"])
            self.assertTrue(second_screenshot["data"] == "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABzElEQVR42mNk",
                            "Invalid Screenshot Data")
        with self.subTest("Empty Screenshot"):
            hit = {
                "screenshots": [{
                    "caption": "Borked",
                    "order": 0,
                    "screenshot": {
                        "filename": "screenshots/a78bebcc-6da7-4c25-86a3-441435ea68d0.png",
                        "data": "",
                    },
                }],
            }
            screenshots = parse_screenshots_from_hit(hit)
            self.assertEqual(0, len(screenshots))
        with self.subTest("Screenshot with No Caption"):
            hit = {
                "screenshots": [{
                    "order": 0,
                    "screenshot": {
                        "filename": "screenshots/a78bebcc-6da7-4c25-86a3-441435ea68d0.png",
                        "data": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABzElEQVR42mNk",
                    },
                }],
            }
            screenshots = parse_screenshots_from_hit(hit)
            self.assertEqual(1, len(screenshots))
            screenshot = screenshots[0]
            self.assertEqual("screenshot.png", screenshot["title"])
            self.assertTrue(screenshot["data"] == "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABzElEQVR42mNk",
                            "Invalid Screenshot Data")
        with self.subTest("Screenshot with Blank Caption"):
            hit = {
                "screenshots": [{
                    "caption": "",
                    "order": 0,
                    "screenshot": {
                        "filename": "screenshots/a78bebcc-6da7-4c25-86a3-441435ea68d0.png",
                        "data": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABzElEQVR42mNk",
                    },
                }],
            }
            screenshots = parse_screenshots_from_hit(hit)
            self.assertEqual(1, len(screenshots))
            screenshot = screenshots[0]
            self.assertEqual("screenshot.png", screenshot["title"])
            self.assertTrue(screenshot["data"] == "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABzElEQVR42mNk",
                            "Invalid Screenshot Data")

    def test_ptart_parser_tools_parse_attachment_from_hit(self):
        from dojo.tools.ptart.ptart_parser_tools import parse_attachment_from_hit
        with self.subTest("No Attachments"):
            hit = {}
            attachments = parse_attachment_from_hit(hit)
            self.assertEqual([], attachments)
        with self.subTest("One Attachment"):
            hit = {
                "attachments": [{
                    "title": "License",
                    "data": "TUlUIExpY2Vuc2UKCkNvcHl",
                }],
            }
            attachments = parse_attachment_from_hit(hit)
            self.assertEqual(1, len(attachments))
            attachment = attachments[0]
            self.assertEqual("License", attachment["title"])
            self.assertTrue(attachment["data"] == "TUlUIExpY2Vuc2UKCkNvcHl", "Invalid Attachment Data")
        with self.subTest("Two Attachments"):
            hit = {
                "attachments": [{
                    "title": "License",
                    "data": "TUlUIExpY2Vuc2UKCkNvcHl",
                }, {
                    "title": "Readme",
                    "data": "UkVBRERtZQoK",
                }],
            }
            attachments = parse_attachment_from_hit(hit)
            self.assertEqual(2, len(attachments))
            first_attachment = attachments[0]
            self.assertEqual("License", first_attachment["title"])
            self.assertTrue(first_attachment["data"] == "TUlUIExpY2Vuc2UKCkNvcHl", "Invalid Attachment Data")
            second_attachment = attachments[1]
            self.assertEqual("Readme", second_attachment["title"])
            self.assertTrue(second_attachment["data"] == "UkVBRERtZQoK", "Invalid Attachment Data")
        with self.subTest("Empty Attachment"):
            hit = {
                "attachments": [{
                    "title": "License",
                    "data": "",
                }],
            }
            attachments = parse_attachment_from_hit(hit)
            self.assertEqual(0, len(attachments))
        with self.subTest("No Data Attachment"):
            hit = {
                "attachments": [{
                    "title": "License",
                }],
            }
            attachments = parse_attachment_from_hit(hit)
            self.assertEqual(0, len(attachments))
        with self.subTest("Attachement with no Title"):
            hit = {
                "attachments": [{
                    "data": "TUlUIExpY2Vuc2UKCkNvcHl",
                }],
            }
            attachments = parse_attachment_from_hit(hit)
            self.assertEqual(1, len(attachments))
            attachment = attachments[0]
            self.assertEqual("attachment", attachment["title"])
            self.assertTrue(attachment["data"] == "TUlUIExpY2Vuc2UKCkNvcHl", "Invalid Attachment Data")
        with self.subTest("Attachment with Blank Title"):
            hit = {
                "attachments": [{
                    "title": "",
                    "data": "TUlUIExpY2Vuc2UKCkNvcHl",
                }],
            }
            attachments = parse_attachment_from_hit(hit)
            self.assertEqual(1, len(attachments))
            attachment = attachments[0]
            self.assertEqual("attachment", attachment["title"])

            self.assertTrue(attachment["data"] == "TUlUIExpY2Vuc2UKCkNvcHl", "Invalid Attachment Data")

    def test_ptart_parser_tools_get_description_from_report_base(self):
        from dojo.tools.ptart.ptart_parser_tools import generate_test_description_from_report
        with self.subTest("No Description"):
            data = {}
            self.assertEqual(None, generate_test_description_from_report(data))
        with self.subTest("Description from Executive Summary Only"):
            data = {
                "executive_summary": "This is a summary",
            }
            self.assertEqual("This is a summary", generate_test_description_from_report(data))
        with self.subTest("Description from Engagement Overview Only"):
            data = {
                "engagement_overview": "This is an overview",
            }
            self.assertEqual("This is an overview", generate_test_description_from_report(data))
        with self.subTest("Description from Conclusion Only"):
            data = {
                "conclusion": "This is a conclusion",
            }
            self.assertEqual("This is a conclusion", generate_test_description_from_report(data))
        with self.subTest("Description from All Sections"):
            data = {
                "executive_summary": "This is a summary",
                "engagement_overview": "This is an overview",
                "conclusion": "This is a conclusion",
            }
            self.assertEqual("This is a summary\n\nThis is an overview\n\nThis is a conclusion",
                             generate_test_description_from_report(data))
        with self.subTest("Description from Executive Summary and Conclusion"):
            data = {
                "executive_summary": "This is a summary",
                "conclusion": "This is a conclusion",
            }
            self.assertEqual("This is a summary\n\nThis is a conclusion",
                             generate_test_description_from_report(data))
        with self.subTest("Description from Executive Summary and Engagement Overview"):
            data = {
                "executive_summary": "This is a summary",
                "engagement_overview": "This is an overview",
            }
            self.assertEqual("This is a summary\n\nThis is an overview",
                             generate_test_description_from_report(data))
        with self.subTest("Description from Engagement Overview and Conclusion"):
            data = {
                "engagement_overview": "This is an overview",
                "conclusion": "This is a conclusion",
            }
            self.assertEqual("This is an overview\n\nThis is a conclusion",
                             generate_test_description_from_report(data))
        with self.subTest("Description from All Sections with Empty Strings"):
            data = {
                "executive_summary": "",
                "engagement_overview": "",
                "conclusion": "",
            }
            self.assertEqual(None, generate_test_description_from_report(data))
        with self.subTest("Description with Some Blank Strings"):
            data = {
                "executive_summary": "",
                "engagement_overview": "This is an overview",
                "conclusion": "",
            }
            self.assertEqual("This is an overview", generate_test_description_from_report(data))

    def test_ptart_parser_tools_parse_references_from_hit(self):
        from dojo.tools.ptart.ptart_parser_tools import parse_references_from_hit
        with self.subTest("No References"):
            hit = {}
            self.assertEqual(None, parse_references_from_hit(hit))
        with self.subTest("One Reference"):
            hit = {
                "references": [{
                    "name": "Reference",
                    "url": "https://ref.example.com",
                }],
            }
            self.assertEqual("Reference: https://ref.example.com", parse_references_from_hit(hit))
        with self.subTest("Two References"):
            hit = {
                "references": [{
                    "name": "Reference1",
                    "url": "https://ref.example.com",
                }, {
                    "name": "Reference2",
                    "url": "https://ref2.example.com",
                }],
            }
            self.assertEqual("Reference1: https://ref.example.com\nReference2: https://ref2.example.com",
                             parse_references_from_hit(hit))
        with self.subTest("No Data Reference"):
            hit = {
                "references": [],
            }
            self.assertEqual(None, parse_references_from_hit(hit))
        with self.subTest("Reference with No Name"):
            hit = {
                "references": [{
                    "url": "https://ref.example.com",
                }],
            }
            self.assertEqual("Reference: https://ref.example.com", parse_references_from_hit(hit))
        with self.subTest("Reference with No URL"):
            hit = {
                "references": [{
                    "name": "Reference",
                }],
            }
            self.assertEqual(None, parse_references_from_hit(hit))
        with self.subTest("Mixed bag of valid and invalid references"):
            hit = {
                "references": [{
                    "name": "Reference1",
                    "url": "https://ref.example.com",
                }, {
                    "name": "Reference2",
                }, {
                    "url": "https://ref3.example.com",
                }],
            }
            self.assertEqual("Reference1: https://ref.example.com\nReference: https://ref3.example.com", parse_references_from_hit(hit))

    def test_ptart_parser_with_empty_json_throws_error(self):
        with open(get_unit_tests_scans_path("ptart") / "empty_with_error.json", encoding="utf-8") as testfile:
            parser = PTARTParser()
            findings = parser.get_findings(testfile, self.test)
            self.assertEqual(0, len(findings))

    def test_ptart_parser_with_no_assessments_has_no_findings(self):
        with open(get_unit_tests_scans_path("ptart") / "ptart_zero_vul.json", encoding="utf-8") as testfile:
            parser = PTARTParser()
            findings = parser.get_findings(testfile, self.test)
            self.assertEqual(0, len(findings))

    def test_ptart_parser_with_one_assessment_has_one_finding(self):
        with open(get_unit_tests_scans_path("ptart") / "ptart_one_vul.json", encoding="utf-8") as testfile:
            parser = PTARTParser()
            findings = parser.get_findings(testfile, self.test)
            self.assertEqual(1, len(findings))
            with self.subTest("Test Assessment: Broken Access Control"):
                finding = findings[0]
                self.assertEqual("PTART-2024-00002: Broken Access Control", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(
                    "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside of the limits of the user.",
                    finding.description)
                self.assertEqual(
                    "Access control vulnerabilities can generally be prevented by taking a defense-in-depth approach and applying the following principles:\n\n* Never rely on obfuscation alone for access control.\n* Unless a resource is intended to be publicly accessible, deny access by default.\n* Wherever possible, use a single application-wide mechanism for enforcing access controls.\n* At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.\n* Thoroughly audit and test access controls to ensure they are working as designed.",
                    finding.mitigation)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding.cvssv3)
                self.assertEqual("PTART-2024-00002", finding.unique_id_from_tool)
                self.assertEqual("PTART-2024-00002", finding.vuln_id_from_tool)
                self.assertEqual("PTART-2024-00002", finding.cve)
                self.assertEqual("Low", finding.effort_for_fixing)
                self.assertEqual("Test Assessment", finding.component_name)
                self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(2, len(finding.unsaved_tags))
                self.assertEqual([
                    "A01:2021-Broken Access Control",
                    "A04:2021-Insecure Design",
                ], finding.unsaved_tags)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "https://test.example.com")
                self.assertEqual(2, len(finding.unsaved_files))
                screenshot = finding.unsaved_files[0]
                self.assertEqual("Borked.png", screenshot["title"])
                self.assertTrue(screenshot["data"].startswith("iVBORw0KGgoAAAAN"), "Invalid Screenshot Data")
                attachment = finding.unsaved_files[1]
                self.assertEqual("License", attachment["title"])
                self.assertTrue(attachment["data"].startswith("TUlUIExpY2Vuc2UKCkNvcHl"), "Invalid Attachment Data")
                self.assertEqual("Reference: https://ref.example.com", finding.references)

    def test_ptart_parser_with_one_assessment_has_many_findings(self):
        with open(get_unit_tests_scans_path("ptart") / "ptart_many_vul.json", encoding="utf-8") as testfile:
            parser = PTARTParser()
            findings = parser.get_findings(testfile, self.test)
            self.assertEqual(2, len(findings))
            with self.subTest("Test Assessment: Broken Access Control"):
                finding = findings[0]
                self.assertEqual("PTART-2024-00002: Broken Access Control", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(
                    "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside of the limits of the user.",
                    finding.description)
                self.assertEqual(
                    "Access control vulnerabilities can generally be prevented by taking a defense-in-depth approach and applying the following principles:\n\n* Never rely on obfuscation alone for access control.\n* Unless a resource is intended to be publicly accessible, deny access by default.\n* Wherever possible, use a single application-wide mechanism for enforcing access controls.\n* At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.\n* Thoroughly audit and test access controls to ensure they are working as designed.",
                    finding.mitigation)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding.cvssv3)
                self.assertEqual("PTART-2024-00002", finding.unique_id_from_tool)
                self.assertEqual("PTART-2024-00002", finding.vuln_id_from_tool)
                self.assertEqual("PTART-2024-00002", finding.cve)
                self.assertEqual("Low", finding.effort_for_fixing)
                self.assertEqual("Test Assessment", finding.component_name)
                self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "https://test.example.com")
                self.assertEqual(2, len(finding.unsaved_files))
                screenshot = finding.unsaved_files[0]
                self.assertEqual("Borked.png", screenshot["title"])
                self.assertTrue(screenshot["data"].startswith("iVBORw0KGgoAAAAN"), "Invalid Screenshot Data")
                attachment = finding.unsaved_files[1]
                self.assertEqual("License", attachment["title"])
                self.assertTrue(attachment["data"].startswith("TUlUIExpY2Vuc2UKCkNvcHl"), "Invalid Attachment Data")
                self.assertEqual(None, finding.references)
            with self.subTest("Test Assessment: Unrated Hit"):
                finding = findings[1]
                self.assertEqual("PTART-2024-00003: Unrated Hit", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("Some hits are not rated.", finding.description)
                self.assertEqual("They can be informational or not related to a direct attack", finding.mitigation)
                self.assertEqual(None, finding.cvssv3)
                self.assertEqual("PTART-2024-00003", finding.unique_id_from_tool)
                self.assertEqual("PTART-2024-00003", finding.vuln_id_from_tool)
                self.assertEqual("PTART-2024-00003", finding.cve)
                self.assertEqual("Low", finding.effort_for_fixing)
                self.assertEqual("Test Assessment", finding.component_name)
                self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(None, finding.references)

    def test_ptart_parser_with_multiple_assessments_has_many_findings_correctly_grouped(self):
        with open(get_unit_tests_scans_path("ptart") / "ptart_vulns_with_mult_assessments.json", encoding="utf-8") as testfile:
            parser = PTARTParser()
            findings = parser.get_findings(testfile, self.test)
            self.assertEqual(3, len(findings))
            with self.subTest("Test Assessment: Broken Access Control"):
                finding = next((f for f in findings if f.unique_id_from_tool == "PTART-2024-00002"), None)
                self.assertEqual("PTART-2024-00002: Broken Access Control", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(
                    "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside of the limits of the user.",
                    finding.description)
                self.assertEqual(
                    "Access control vulnerabilities can generally be prevented by taking a defense-in-depth approach and applying the following principles:\n\n* Never rely on obfuscation alone for access control.\n* Unless a resource is intended to be publicly accessible, deny access by default.\n* Wherever possible, use a single application-wide mechanism for enforcing access controls.\n* At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.\n* Thoroughly audit and test access controls to ensure they are working as designed.",
                    finding.mitigation)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding.cvssv3)
                self.assertEqual("PTART-2024-00002", finding.unique_id_from_tool)
                self.assertEqual("PTART-2024-00002", finding.vuln_id_from_tool)
                self.assertEqual("PTART-2024-00002", finding.cve)
                self.assertEqual("Low", finding.effort_for_fixing)
                self.assertEqual("Test Assessment", finding.component_name)
                self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "https://test.example.com")
                self.assertEqual(2, len(finding.unsaved_files))
                screenshot = finding.unsaved_files[0]
                self.assertEqual("Borked.png", screenshot["title"])
                self.assertTrue(screenshot["data"].startswith("iVBORw0KGgoAAAAN"), "Invalid Screenshot Data")
                attachment = finding.unsaved_files[1]
                self.assertEqual("License", attachment["title"])
                self.assertTrue(attachment["data"].startswith("TUlUIExpY2Vuc2UKCkNvcHl"), "Invalid Attachment Data")
                self.assertEqual(None, finding.references)
            with self.subTest("Test Assessment: Unrated Hit"):
                finding = next((f for f in findings if f.unique_id_from_tool == "PTART-2024-00003"), None)
                self.assertEqual("PTART-2024-00003: Unrated Hit", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("Some hits are not rated.", finding.description)
                self.assertEqual("They can be informational or not related to a direct attack", finding.mitigation)
                self.assertEqual(None, finding.cvssv3)
                self.assertEqual("PTART-2024-00003", finding.unique_id_from_tool)
                self.assertEqual("PTART-2024-00003", finding.vuln_id_from_tool)
                self.assertEqual("PTART-2024-00003", finding.cve)
                self.assertEqual("Low", finding.effort_for_fixing)
                self.assertEqual("Test Assessment", finding.component_name)
                self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(None, finding.references)
            with self.subTest("New Api: HTML Injection"):
                finding = next((f for f in findings if f.unique_id_from_tool == "PTART-2024-00004"), None)
                self.assertEqual("PTART-2024-00004: HTML Injection", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual(
                    "HTML injection is a type of injection issue that occurs when a user is able to control an input point and is able to inject arbitrary HTML code into a vulnerable web page. This vulnerability can have many consequences, like disclosure of a user's session cookies that could be used to impersonate the victim, or, more generally, it can allow the attacker to modify the page content seen by the victims.",
                    finding.description)
                self.assertEqual(
                    "Preventing HTML injection is trivial in some cases but can be much harder depending on the complexity of the application and the ways it handles user-controllable data.\n\nIn general, effectively preventing HTML injection vulnerabilities is likely to involve a combination of the following measures:\n\n* **Filter input on arrival**. At the point where user input is received, filter as strictly as possible based on what is expected or valid input.\n* **Encode data on output**. At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding.",
                    finding.mitigation)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", finding.cvssv3)
                self.assertEqual("PTART-2024-00004", finding.unique_id_from_tool)
                self.assertEqual("PTART-2024-00004", finding.vuln_id_from_tool)
                self.assertEqual("PTART-2024-00004", finding.cve)
                self.assertEqual("Medium", finding.effort_for_fixing)
                self.assertEqual("New API", finding.component_name)
                self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(0, len(finding.unsaved_endpoints))
                self.assertEqual(0, len(finding.unsaved_files))
                self.assertEqual(None, finding.references)

    def test_ptart_parser_with_single_vuln_on_import_test(self):
        with open(get_unit_tests_scans_path("ptart") / "ptart_one_vul.json", encoding="utf-8") as testfile:
            parser = PTARTParser()
            tests = parser.get_tests("PTART Report", testfile)
            self.assertEqual(1, len(tests))
            test = tests[0]
            self.assertEqual("Test Report", test.name)
            self.assertEqual("Test Report", test.type)
            self.assertEqual("", test.version)
            self.assertEqual("Mistakes were made\n\nThings were done\n\nThings should be put right", test.description)
            self.assertEqual("2024-08-11", test.target_start.strftime("%Y-%m-%d"))
            self.assertEqual("2024-08-16", test.target_end.strftime("%Y-%m-%d"))
            self.assertEqual(1, len(test.findings))
            finding = test.findings[0]
            self.assertEqual("PTART-2024-00002: Broken Access Control", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(
                "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside of the limits of the user.",
                finding.description)
            self.assertEqual(
                "Access control vulnerabilities can generally be prevented by taking a defense-in-depth approach and applying the following principles:\n\n* Never rely on obfuscation alone for access control.\n* Unless a resource is intended to be publicly accessible, deny access by default.\n* Wherever possible, use a single application-wide mechanism for enforcing access controls.\n* At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.\n* Thoroughly audit and test access controls to ensure they are working as designed.",
                finding.mitigation)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding.cvssv3)
            self.assertEqual("PTART-2024-00002", finding.unique_id_from_tool)
            self.assertEqual("PTART-2024-00002", finding.vuln_id_from_tool)
            self.assertEqual("PTART-2024-00002", finding.cve)
            self.assertEqual("Low", finding.effort_for_fixing)
            self.assertEqual("Test Assessment", finding.component_name)
            self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
            self.assertEqual(2, len(finding.unsaved_tags))
            self.assertEqual([
                "A01:2021-Broken Access Control",
                "A04:2021-Insecure Design",
            ], finding.unsaved_tags)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(str(endpoint), "https://test.example.com")
            self.assertEqual(2, len(finding.unsaved_files))
            screenshot = finding.unsaved_files[0]
            self.assertEqual("Borked.png", screenshot["title"])
            self.assertTrue(screenshot["data"].startswith("iVBORw0KGgoAAAAN"), "Invalid Screenshot Data")
            attachment = finding.unsaved_files[1]
            self.assertEqual("License", attachment["title"])
            self.assertTrue(attachment["data"].startswith("TUlUIExpY2Vuc2UKCkNvcHl"), "Invalid Attachment Data")
            self.assertEqual("Reference: https://ref.example.com", finding.references)

    def test_ptart_parser_with_retest_campaign(self):
        with open(get_unit_tests_scans_path("ptart") / "ptart_vuln_plus_retest.json", encoding="utf-8") as testfile:
            parser = PTARTParser()
            findings = parser.get_findings(testfile, self.test)
            self.assertEqual(3, len(findings))
            with self.subTest("Test Assessment: Broken Access Control"):
                finding = next((f for f in findings if f.unique_id_from_tool == "PTART-2024-00002"), None)
                self.assertEqual("PTART-2024-00002: Broken Access Control", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(
                    "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside of the limits of the user.",
                    finding.description)
                self.assertEqual(
                    "Access control vulnerabilities can generally be prevented by taking a defense-in-depth approach and applying the following principles:\n\n* Never rely on obfuscation alone for access control.\n* Unless a resource is intended to be publicly accessible, deny access by default.\n* Wherever possible, use a single application-wide mechanism for enforcing access controls.\n* At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.\n* Thoroughly audit and test access controls to ensure they are working as designed.",
                    finding.mitigation)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding.cvssv3)
                self.assertEqual("PTART-2024-00002", finding.unique_id_from_tool)
                self.assertEqual("PTART-2024-00002", finding.vuln_id_from_tool)
                self.assertEqual("PTART-2024-00002", finding.cve)
                self.assertEqual("Low", finding.effort_for_fixing)
                self.assertEqual("Test Assessment", finding.component_name)
                self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "https://test.example.com")
                self.assertEqual(2, len(finding.unsaved_files))
                screenshot = finding.unsaved_files[0]
                self.assertEqual("Borked.png", screenshot["title"])
                self.assertTrue(screenshot["data"].startswith("iVBORw0KGgoAAAAN"), "Invalid Screenshot Data")
                attachment = finding.unsaved_files[1]
                self.assertEqual("License", attachment["title"])
                self.assertTrue(attachment["data"].startswith("TUlUIExpY2Vuc2UKCkNvcHl"), "Invalid Attachment Data")
                self.assertEqual(None, finding.references)
            with self.subTest("Test Assessment: Unrated Hit"):
                finding = next((f for f in findings if f.unique_id_from_tool == "PTART-2024-00003"), None)
                self.assertEqual("PTART-2024-00003: Unrated Hit", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("Some hits are not rated.", finding.description)
                self.assertEqual("They can be informational or not related to a direct attack", finding.mitigation)
                self.assertEqual(None, finding.cvssv3)
                self.assertEqual("PTART-2024-00003", finding.unique_id_from_tool)
                self.assertEqual("PTART-2024-00003", finding.vuln_id_from_tool)
                self.assertEqual("PTART-2024-00003", finding.cve)
                self.assertEqual("Low", finding.effort_for_fixing)
                self.assertEqual("Test Assessment", finding.component_name)
                self.assertEqual("2024-09-06", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(None, finding.references)
            with self.subTest("Retest: Broken Access Control"):
                finding = next((f for f in findings if f.unique_id_from_tool == "PTART-2024-00002-RT"), None)
                self.assertEqual("PTART-2024-00002-RT: Broken Access Control (Not Fixed)", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("Still borked", finding.description)
                self.assertEqual(
                    "Access control vulnerabilities can generally be prevented by taking a defense-in-depth approach and applying the following principles:\n\n* Never rely on obfuscation alone for access control.\n* Unless a resource is intended to be publicly accessible, deny access by default.\n* Wherever possible, use a single application-wide mechanism for enforcing access controls.\n* At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.\n* Thoroughly audit and test access controls to ensure they are working as designed.",
                    finding.mitigation)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding.cvssv3)
                self.assertEqual("PTART-2024-00002-RT", finding.unique_id_from_tool)
                self.assertEqual("PTART-2024-00002", finding.vuln_id_from_tool)
                self.assertEqual("PTART-2024-00002", finding.cve)
                self.assertEqual("Low", finding.effort_for_fixing)
                self.assertEqual("Retest: Test Retest", finding.component_name)
                self.assertEqual("2024-09-08", finding.date.strftime("%Y-%m-%d"))
                self.assertEqual(1, len(finding.unsaved_endpoints))
                endpoint = finding.unsaved_endpoints[0]
                self.assertEqual(str(endpoint), "https://test.example.com")
                self.assertEqual(1, len(finding.unsaved_files))
                screenshot = finding.unsaved_files[0]
                self.assertEqual("Yet another Screenshot.png", screenshot["title"])
                self.assertTrue(screenshot["data"].startswith("iVBORw0KGgoAAAAN"), "Invalid Screenshot Data")
