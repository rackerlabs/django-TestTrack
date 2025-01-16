# ruff: noqa: RUF001
import datetime
from unittest.mock import patch

from dojo.models import Engagement, Product, Test
from dojo.tools.checkmarx.parser import CheckmarxParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCheckmarxParser(DojoTestCase):
    # comment out to get full diff with big reports
    # maxDiff = None

    def init(self, reportFilename):
        my_file_handle = open(reportFilename, encoding="utf-8")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        return my_file_handle, product, engagement, test

    def teardown(self, my_file_handle):
        my_file_handle.close()

    # ----------------------------------------------------------------------------
    # no_finding
    # ----------------------------------------------------------------------------
    # Default checkmarx scanner, aggregated by sink file_path
    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_name_aggregated_parse_file_with_no_vulnerabilities_has_no_findings(self, mock):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "no_finding.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(0, len(findings))

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_detailed_parse_file_with_no_vulnerabilities_has_no_findings(self, mock):
        """Checkmarx detailed scanner, with all vulnerabilities from checkmarx"""
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "no_finding.xml",
        )
        parser = CheckmarxParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(0, len(findings))

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_name_aggregated_parse_file_with_single_vulnerability_has_single_finding(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "single_finding.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_single_vulnerability_has_single_finding(findings)
        # Fields that differ from detailed scanner
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual(
            "**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "<b>Source file: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java (line 39)\n"
            "<b>Source object: </b> executeQuery\n"
            "<b>Sink file: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java (line 58)\n"
            "<b>Sink object: </b> allUsersMap",
            item.description,
        )
        self.assertEqual(1, item.nb_occurences)
        mock.assert_called_with(product, "Java", files=1)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_detailed_parse_file_with_single_vulnerability_has_single_finding(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "single_finding.xml",
        )
        parser = CheckmarxParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_single_vulnerability_has_single_finding(findings)
        # Fields that differ from aggregated scanner
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual(
            "**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 59\n"
            "**Source Object:** executeQuery\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 27\n"
            "**Source Object:** results\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);\n"
            "-----\n"
            "**Line Number:** 46\n"
            "**Column:** 28\n"
            "**Source Object:** results\n"
            "**Number:** 46\n"
            "**Code:** while (results.next()) {\n"
            "-----\n"
            "**Line Number:** 47\n"
            "**Column:** 34\n"
            "**Source Object:** results\n"
            "**Number:** 47\n"
            "**Code:** int id = results.getInt(0);\n"
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 64\n"
            "**Source Object:** getString\n"
            "**Number:** 53\n"
            '**Code:** userMap.put("cookie", results.getString(5));\n'
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 36\n"
            "**Source Object:** put\n"
            "**Number:** 53\n"
            '**Code:** userMap.put("cookie", results.getString(5));\n'
            "-----\n"
            "**Line Number:** 54\n"
            "**Column:** 25\n"
            "**Source Object:** userMap\n"
            "**Number:** 54\n"
            '**Code:** userMap.put("loginCOunt",Integer.toString(results.getInt(6)));\n'
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 44\n"
            "**Source Object:** userMap\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 40\n"
            "**Source Object:** put\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 58\n"
            "**Column:** 28\n"
            "**Source Object:** allUsersMap\n"
            "**Number:** 58\n"
            "**Code:** return allUsersMap;\n"
            "-----\n",
            item.description,
        )
        self.assertEqual(int, type(item.line))
        self.assertEqual(58, item.line)
        # Added field for detailed scanner
        self.assertEqual(str, type(item.unique_id_from_tool))
        # unique_id_from_tool update from PathId to SimilarityId+PathId
        self.assertEqual("157422106028", item.unique_id_from_tool)
        self.assertEqual(str, type(item.sast_source_object))
        self.assertEqual("executeQuery", item.sast_source_object)
        self.assertEqual(str, type(item.sast_sink_object))
        self.assertEqual("allUsersMap", item.sast_sink_object)
        self.assertEqual(int, type(item.sast_source_line))
        self.assertEqual(39, item.sast_source_line)
        self.assertEqual(str, type(item.sast_source_file_path))
        self.assertEqual(
            "WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java",
            item.sast_source_file_path,
        )
        self.assertIsNone(item.nb_occurences)
        mock.assert_called_with(product, "Java", files=1)

    def check_parse_file_with_single_vulnerability_has_single_finding(self, findings):
        self.assertEqual(1, len(findings))
        # check content
        item = findings[0]
        self.assertEqual(str, type(findings[0].title))
        self.assertEqual("Stored XSS (Users.java)", item.title)
        self.assertEqual(int, type(item.cwe))
        self.assertEqual(79, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(True, item.active)
        self.assertEqual(bool, type(item.verified))
        # state 0 in checkmarx = "To verify"
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(False, item.false_p)
        self.assertEqual(str, type(item.severity))
        self.assertEqual("High", item.severity)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual(
            "WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java",
            item.file_path,
        )
        # ScanStart
        self.assertEqual(datetime.date, type(item.date))
        self.assertEqual(datetime.date(2018, 2, 25), item.date)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)

    # ----------------------------------------------------------------------------
    # single finding false positive
    # ----------------------------------------------------------------------------
    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_name_aggregated_parse_file_with_false_positive_is_false_positive(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "single_finding_false_positive.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_false_positive_is_false_positive(findings)
        mock.assert_called_with(product, "Java", files=1)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_detailed_parse_file_with_false_positive_is_false_positive(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "single_finding_false_positive.xml",
        )
        parser = CheckmarxParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_false_positive_is_false_positive(findings)
        mock.assert_called_with(product, "Java", files=1)

    def check_parse_file_with_false_positive_is_false_positive(self, findings):
        self.assertEqual(1, len(findings))
        # check content
        item = findings[0]
        self.assertEqual(bool, type(item.active))
        self.assertEqual(False, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(True, item.false_p)

    # ----------------------------------------------------------------------------
    # two findings with the same aggregate keys, but one is false positive
    # the result should be one exploitable finding, even though the first one found was false positive
    # ----------------------------------------------------------------------------

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_name_aggregated_parse_file_with_two_aggregated_findings_one_is_false_p(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "two_aggregated_findings_one_is_false_positive.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(1, len(findings))
        # check content for aggregated finding
        item = findings[0]
        # if any of the findings in the aggregate is active, the aggregated finding is active
        self.assertEqual(bool, type(item.active))
        self.assertEqual(True, item.active)
        self.assertEqual(bool, type(item.verified))
        # state 0 in checkmarx = "To verify"
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        # If at least one of the findings in the aggregate is exploitable, the defectdojo finding should not be "false positive"
        self.assertEqual(False, item.false_p)
        mock.assert_called_with(product, "Java", files=2)

    # ----------------------------------------------------------------------------
    # multiple_findings : source filename = sink filename.
    # ----------------------------------------------------------------------------

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_name_aggregated_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "multiple_findings.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        # checkmarx says 3 but we're down to 2 due to the aggregation on sink filename rather than source filename + source line number + sink filename + sink line number
        self.assertEqual(2, len(findings))
        mock.assert_called_with(product, "Java", files=3)
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("SQL Injection (Assignment5.java)", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(datetime.date(2018, 2, 25), finding.date)
            self.assertEqual(True, finding.static_finding)
            self.assertEqual("WebGoat/webgoat-lessons/challenge/src/main/java/org/owasp/webgoat/plugin/challenge5/challenge6/Assignment5.java", finding.file_path)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_detailed_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "multiple_findings.xml",
        )
        parser = CheckmarxParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(3, len(findings))
        mock.assert_called_with(product, "Java", files=3)
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("SQL Injection (Assignment5.java)", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(datetime.date(2018, 2, 25), finding.date)
            self.assertEqual(True, finding.static_finding)
            self.assertEqual("WebGoat/webgoat-lessons/challenge/src/main/java/org/owasp/webgoat/plugin/challenge5/challenge6/Assignment5.java", finding.file_path)
            self.assertEqual(50, finding.line)

    # ----------------------------------------------------------------------------
    # multiple_findings : different sourceFilename but same sinkFilename
    # ----------------------------------------------------------------------------
    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_name_aggregated_parse_file_with_different_sourceFilename_same_sinkFilename_is_aggregated(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "multiple_findings_different_sourceFilename_same_sinkFilename.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        # aggregation is on sink filename so all vuln with different source filenames are aggregated
        self.assertEqual(1, len(findings))
        # nb_occurences counts the number of aggregated vulnerabilities from tool
        self.assertEqual(2, findings[0].nb_occurences)
        mock.assert_called_with(product, "Java", files=2)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_detailed_parse_file_with_different_sourceFilename_same_sinkFilename_is_not_aggregated(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "multiple_findings_different_sourceFilename_same_sinkFilename.xml",
        )
        parser = CheckmarxParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(2, len(findings))
        self.assertIsNone(findings[0].nb_occurences)
        self.assertIsNone(findings[1].nb_occurences)
        mock.assert_called_with(product, "Java", files=2)

    # ----------------------------------------------------------------------------
    # multiple_findings : same sourceFilename but different sinkFilename
    # ----------------------------------------------------------------------------
    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_name_aggregated_parse_file_with_same_sourceFilename_different_sinkFilename_is_not_aggregated(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "multiple_findings_same_sourceFilename_different_sinkFilename.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        # aggregation is on sink filename but sink filename differ -> not aggregated
        self.assertEqual(2, len(findings))
        mock.assert_called_with(product, "Java", files=2)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_detailed_parse_file_with_same_sourceFilename_different_sinkFilename_is_not_aggregated(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "multiple_findings_same_sourceFilename_different_sinkFilename.xml",
        )
        parser = CheckmarxParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(2, len(findings))
        mock.assert_called_with(product, "Java", files=2)

    # ----------------------------------------------------------------------------
    # utf-8 replacement char in various fields of the report. check all finding elements
    # ----------------------------------------------------------------------------
    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_name_aggregated_parse_file_with_utf8_replacement_char(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "utf8_replacement_char.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_utf8_replacement_char(findings)
        # Fields that differ from detailed scanner
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual(
            "**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "<b>Source file: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java� (line 39)\n"
            "<b>Source object: </b> executeQuery�\n"
            "<b>Sink file: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java� (line 58)\n"
            "<b>Sink object: </b> allUsersMap�",
            item.description,
        )
        self.assertIsNone(item.line)
        mock.assert_called_with(product, "Java", files=1)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_detailed_parse_file_with_utf8_replacement_char(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "utf8_replacement_char.xml",
        )
        parser = CheckmarxParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_utf8_replacement_char(findings)
        # Fields that differ from aggregated scanner
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual(
            "**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 59\n"
            "**Source Object:** executeQuery�\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);//�\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 27\n"
            "**Source Object:** results\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);\n"
            "-----\n"
            "**Line Number:** 46\n"
            "**Column:** 28\n"
            "**Source Object:** results\n"
            "**Number:** 46\n"
            "**Code:** while (results.next()) {\n"
            "-----\n"
            "**Line Number:** 47\n"
            "**Column:** 34\n"
            "**Source Object:** results\n"
            "**Number:** 47\n"
            "**Code:** int id = results.getInt(0);\n"
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 64\n"
            "**Source Object:** getString\n"
            "**Number:** 53\n"
            '**Code:** userMap.put("cookie", results.getString(5));\n'
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 36\n"
            "**Source Object:** put\n"
            "**Number:** 53\n"
            '**Code:** userMap.put("cookie", results.getString(5));\n'
            "-----\n"
            "**Line Number:** 54\n"
            "**Column:** 25\n"
            "**Source Object:** userMap\n"
            "**Number:** 54\n"
            '**Code:** userMap.put("loginCOunt",Integer.toString(results.getInt(6)));\n'
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 44\n"
            "**Source Object:** userMap\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 40\n"
            "**Source Object:** put\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 58\n"
            "**Column:** 28\n"
            "**Source Object:** allUsersMap�\n"
            "**Number:** 58\n"
            "**Code:** return allUsersMap;\n"
            "-----\n",
            item.description,
        )
        self.assertEqual(int, type(item.line))
        self.assertEqual(58, item.line)
        mock.assert_called_with(product, "Java", files=1)

    def check_parse_file_with_utf8_replacement_char(self, findings):
        self.assertEqual(1, len(findings))
        # check content
        item = findings[0]
        self.assertEqual(str, type(findings[0].title))
        self.assertEqual("Stored XSS (Users.java�)", item.title)
        self.assertEqual(int, type(item.cwe))
        self.assertEqual(79, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(True, item.active)
        self.assertEqual(bool, type(item.verified))
        # state 0 in checkmarx = "To verify"
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(False, item.false_p)
        self.assertEqual(str, type(item.severity))
        self.assertEqual("High", item.severity)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual(
            "WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java�",
            item.file_path,
        )
        # ScanStart
        self.assertEqual(datetime.date, type(item.date))
        self.assertEqual(datetime.date(2018, 2, 25), item.date)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)

    # ----------------------------------------------------------------------------
    # more utf-8 non-ascii chars.
    # ----------------------------------------------------------------------------
    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_name_aggregated_parse_file_with_utf8_various_non_ascii_char(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "utf8_various_non_ascii_char.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_utf8_various_non_ascii_char(findings)
        # Fields that differ from detailed scanner
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual(
            "**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "<b>Source file: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſUsers.java (line 39)\n"
            "<b>Source object: </b> executeQuery¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ\n"
            "<b>Sink file: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſUsers.java (line 58)\n"
            "<b>Sink object: </b> allUsersMap¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ",
            item.description,
        )
        self.assertIsNone(item.line)
        mock.assert_called_with(product, "Java", files=1)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_detailed_parse_file_with_utf8_various_non_ascii_char(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "utf8_various_non_ascii_char.xml",
        )
        parser = CheckmarxParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_utf8_various_non_ascii_char(findings)
        # Fields that differ from aggregated scanner
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual(
            "**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 59\n"
            "**Source Object:** executeQuery¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 27\n"
            "**Source Object:** results\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);//all latins non ascii with extended: U+00A1   to U+017F  (ref https://www.utf8-chartable.de/unicode-utf8-table.pl): ¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ\n"
            "-----\n"
            "**Line Number:** 46\n"
            "**Column:** 28\n"
            "**Source Object:** results\n"
            "**Number:** 46\n"
            "**Code:** while (results.next()) { // other: ƒ\n"
            "-----\n"
            "**Line Number:** 47\n"
            "**Column:** 34\n"
            "**Source Object:** results\n"
            "**Number:** 47\n"
            "**Code:** int id = results.getInt(0);\n"
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 64\n"
            "**Source Object:** getString\n"
            "**Number:** 53\n"
            '**Code:** userMap.put("cookie", results.getString(5));\n'
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 36\n"
            "**Source Object:** put\n"
            "**Number:** 53\n"
            '**Code:** userMap.put("cookie", results.getString(5));\n'
            "-----\n"
            "**Line Number:** 54\n"
            "**Column:** 25\n"
            "**Source Object:** userMap\n"
            "**Number:** 54\n"
            '**Code:** userMap.put("loginCOunt",Integer.toString(results.getInt(6)));\n'
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 44\n"
            "**Source Object:** userMap\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 40\n"
            "**Source Object:** put\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 58\n"
            "**Column:** 28\n"
            "**Source Object:** allUsersMap¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ\n"
            "**Number:** 58\n"
            "**Code:** return allUsersMap;\n"
            "-----\n",
            item.description,
        )
        self.assertEqual(int, type(item.line))
        self.assertEqual(58, item.line)
        mock.assert_called_with(product, "Java", files=1)

    def check_parse_file_with_utf8_various_non_ascii_char(self, findings):
        self.assertEqual(1, len(findings))
        # check content
        item = findings[0]
        self.assertEqual(str, type(findings[0].title))
        self.assertEqual(
            "Stored XSS (¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſUsers.java)",
            item.title,
        )
        self.assertEqual(int, type(item.cwe))
        self.assertEqual(79, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(True, item.active)
        self.assertEqual(bool, type(item.verified))
        # state 0 in checkmarx = "To verify"
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(False, item.false_p)
        self.assertEqual(str, type(item.severity))
        self.assertEqual("High", item.severity)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual(
            "WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſUsers.java",
            item.file_path,
        )
        # ScanStart
        self.assertEqual(datetime.date, type(item.date))
        self.assertEqual(datetime.date(2018, 2, 25), item.date)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_with_multiple_findings_is_aggregated_with_query_id(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "multiple_findings_same_query_id.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(6, len(findings))
        mock.assert_called_with(product, "Java", files=4)
        with self.subTest(i=0):
            finding = findings[0]
            # ScanStart
            self.assertEqual("Client Potential ReDoS In Match (prettify.js)", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(datetime.date, type(finding.date))
            self.assertEqual(datetime.date(2021, 11, 17), finding.date)
            self.assertEqual(bool, type(finding.static_finding))
            self.assertEqual(True, finding.static_finding)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_with_empty_filename(self, mock):
        my_file_handle, product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "single_no_filename.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(1, len(findings))
        mock.assert_called_with(product, "PHP", files=1)
        with self.subTest(i=0):
            finding = findings[0]
            # ScanStart
            self.assertEqual("Missing HSTS Header", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(datetime.date, type(finding.date))
            self.assertEqual(datetime.date(2021, 12, 24), finding.date)
            self.assertEqual(bool, type(finding.static_finding))
            self.assertEqual(True, finding.static_finding)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_with_many_aggregated_findings(self, mock):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "many_aggregated_findings.xml",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(1, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            # ScanStart
            self.assertEqual("Insufficient Logging of Exceptions (filename3.cs)", finding.title)
            self.assertEqual("Information", finding.severity)
            self.assertEqual(185, finding.nb_occurences)
            self.assertEqual("5273", finding.vuln_id_from_tool)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_with_many_findings_json(self, mock):
        my_file_handle, _product, _engagement, _test = self.init(
            get_unit_tests_scans_path("checkmarx") / "multiple_findings.json",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, Test())
        self.teardown(my_file_handle)
        self.assertEqual(10, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(89, finding.cwe)
            self.assertEqual("/diva-android-master/app/src/main/java/jakhar/aseem/diva/SQLInjectionActivity.java", finding.file_path)
            self.assertEqual(70, finding.line)
            self.assertEqual("/oiUUpBjigtUpTb1+haL9nypVaQ=", finding.unique_id_from_tool)
        with self.subTest(i=5):
            finding = findings[4]
            self.assertEqual("CSRF", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(352, finding.cwe)
            self.assertEqual("/diva-android-master/app/src/main/java/jakhar/aseem/diva/InsecureDataStorage2Activity.java", finding.file_path)
            self.assertEqual(67, finding.line)
            self.assertEqual("IJOkZAzX5emCOIeTESXgsNulW2w=", finding.unique_id_from_tool)
        with self.subTest(i=9):
            finding = findings[9]
            self.assertEqual("Heap Inspection", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(244, finding.cwe)
            self.assertEqual("/diva-android-master/app/src/main/java/jakhar/aseem/diva/InsecureDataStorage1Activity.java", finding.file_path)
            self.assertEqual(54, finding.line)
            self.assertEqual("udB1urKobWKTYYlRQbAAub1yRAc=", finding.unique_id_from_tool)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_file_issue6956(self, mock):
        my_file_handle, _product, _engagement, _test = self.init(
            get_unit_tests_scans_path("checkmarx") / "sample_report.json",
        )
        parser = CheckmarxParser()
        findings = parser.get_findings(my_file_handle, Test())
        self.teardown(my_file_handle)
        # in this report we have 817
        # "KICS": 31,
        # "SAST": 669,
        # "SCA": 117
        self.assertEqual(817, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Reflected XSS All Clients", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/webgoat-lessons/password-reset/src/main/java/org/owasp/webgoat/password_reset/ResetLinkAssignment.java", finding.file_path)
            self.assertEqual(96, finding.line)
            self.assertEqual("-1833874157", finding.unique_id_from_tool)
        for finding in findings:
            # test for SAST
            if finding.unique_id_from_tool == "bEGSvBn40cp99etnudzTeskzJRQ=":
                with self.subTest(i="bEGSvBn40cp99etnudzTeskzJRQ="):
                    self.assertEqual("SQL Injection", finding.title)
                    self.assertEqual("High", finding.severity)
                    self.assertEqual(89, finding.cwe)
                    self.assertEqual("/webgoat-lessons/challenge/src/main/java/org/owasp/webgoat/challenges/challenge5/Assignment5.java", finding.file_path)
                    self.assertEqual(61, finding.line)
                    self.assertEqual(datetime.date(2022, 5, 6), finding.date)
            if finding.unique_id_from_tool == "SYlu22e7ZQydKJFOlC/o1EsyixQ=":
                with self.subTest(i="SYlu22e7ZQydKJFOlC/o1EsyixQ="):
                    self.assertEqual("SQL Injection", finding.title)
                    self.assertEqual("High", finding.severity)
                    self.assertEqual(89, finding.cwe)
                    self.assertEqual("/webgoat-lessons/sql-injection/src/main/java/org/owasp/webgoat/sql_injection/introduction/SqlInjectionLesson5.java", finding.file_path)
                    self.assertEqual(72, finding.line)
                    self.assertEqual(datetime.date(2022, 5, 6), finding.date)
            # test one in SCA part
            if finding.unique_id_from_tool == "GkVx1zoIKcd1EF72zqWrGzeVTmo=":
                with self.subTest(i="GkVx1zoIKcd1EF72zqWrGzeVTmo="):
                    self.assertEqual("underscore:1.10.2 | CVE-2021-23358", finding.title)
                    self.assertIn("The package underscore from 1.13.0-0 and before 1.13.0-2", finding.description)
                    self.assertEqual("High", finding.severity)
                    self.assertEqual(94, finding.cwe)
                    self.assertEqual("underscore", finding.component_name)
                    self.assertEqual("1.10.2", finding.component_version)
                    self.assertTrue(finding.active)
                    self.assertFalse(finding.verified)
                    self.assertIsNone(finding.line)
                    self.assertEqual(datetime.date(2022, 5, 6), finding.date)
            # test one in KICS part
            if finding.unique_id_from_tool == "eZrh18HAPbe2LbDAprSPrwncAC0=":
                with self.subTest(i="eZrh18HAPbe2LbDAprSPrwncAC0="):
                    self.assertEqual("Dockerfile | IncorrectValue", finding.title)
                    self.assertIn("After using apt-get install, it is needed to delete apt-get lists", finding.description)
                    self.assertEqual("Info", finding.severity)
                    self.assertTrue(finding.active)
                    self.assertFalse(finding.verified)
                    self.assertEqual("/webgoat-server/Dockerfile", finding.file_path)
                    self.assertEqual(datetime.date(2022, 5, 6), finding.date)

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_finding_date_should_be_date_xml(self, mock):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "single_finding.xml",
        )
        parser = CheckmarxParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(findings[0].date, datetime.date(2018, 2, 25))

    @patch("dojo.tools.checkmarx.parser.add_language")
    def test_finding_date_should_be_date_json(self, mock):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("checkmarx") / "multiple_findings.json",
        )
        parser = CheckmarxParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(findings[0].date, datetime.date(2022, 2, 25))
