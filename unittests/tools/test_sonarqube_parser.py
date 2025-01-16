from dojo.models import Engagement, Product, Test
from dojo.tools.sonarqube.parser import SonarQubeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSonarQubeParser(DojoTestCase):
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

    # SonarQube Scan - no finding
    def test_file_name_aggregated_parse_file_with_no_vulnerabilities_has_no_findings(
            self,
    ):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-no-finding.html",
        )
        parser = SonarQubeParser()
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(0, len(findings))
        my_file_handle.close()

    # SonarQube Scan detailed - no finding
    def test_detailed_parse_file_with_no_vulnerabilities_has_no_findings(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-no-finding.html",
        )
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(0, len(findings))
        my_file_handle.close()

    # SonarQube Scan - report with one vuln
    def test_file_name_aggregated_parse_file_with_single_vulnerability_has_single_finding(
            self,
    ):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-single-finding.html",
        )
        parser = SonarQubeParser()
        findings = parser.get_findings(my_file_handle, test)
        # common verifications
        self.assertEqual(1, len(findings))
        # specific verifications
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual(
            "Because it is easy to extract strings from a compiled application, credentials should never be hard-coded. Do so, and they're almost guaranteed to\n"
            "end up in the hands of an attacker. This is particularly true for applications that are distributed.\n"
            "Credentials should be stored outside of the code in a strongly-protected encrypted configuration file or database.\n"
            'It\'s recommended to customize the configuration of this rule with additional credential words such as "oauthToken", "secret", ...\n'
            "**Noncompliant Code Example**\n"
            "\n"
            "Connection conn = null;\n"
            "try {\n"
            '  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +\n'
            '        "user=steve&amp;password=blue"); // Noncompliant\n'
            '  String uname = "steve";\n'
            '  String password = "blue";\n'
            '  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +\n'
            '        "user=" + uname + "&amp;password=" + password); // Noncompliant\n'
            "\n"
            '  java.net.PasswordAuthentication pa = new java.net.PasswordAuthentication("userName", "1234".toCharArray());  // Noncompliant\n'
            "\n"
            "**Compliant Solution**\n"
            "\n"
            "Connection conn = null;\n"
            "try {\n"
            "  String uname = getEncryptedUser();\n"
            "  String password = getEncryptedPass();\n"
            '  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +\n'
            '        "user=" + uname + "&amp;password=" + password);\n'
            "\n"
            "-----\n"
            "Occurences:\n"
            "Line: 66",
            item.description,
        )
        self.assertIsNone(item.line)
        self.assertIsNone(item.unique_id_from_tool)
        self.assertEqual(int, type(item.nb_occurences))
        self.assertEqual(1, item.nb_occurences)
        my_file_handle.close()

    def test_detailed_parse_file_with_single_vulnerability_has_single_finding(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-single-finding.html",
        )
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        # common verifications
        self.assertEqual(1, len(findings))
        # specific verifications
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual(
            "Because it is easy to extract strings from a compiled application, credentials should never be hard-coded. Do so, and they're almost guaranteed to\n"
            "end up in the hands of an attacker. This is particularly true for applications that are distributed.\n"
            "Credentials should be stored outside of the code in a strongly-protected encrypted configuration file or database.\n"
            'It\'s recommended to customize the configuration of this rule with additional credential words such as "oauthToken", "secret", ...\n'
            "**Noncompliant Code Example**\n"
            "\n"
            "Connection conn = null;\n"
            "try {\n"
            '  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +\n'
            '        "user=steve&amp;password=blue"); // Noncompliant\n'
            '  String uname = "steve";\n'
            '  String password = "blue";\n'
            '  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +\n'
            '        "user=" + uname + "&amp;password=" + password); // Noncompliant\n'
            "\n"
            '  java.net.PasswordAuthentication pa = new java.net.PasswordAuthentication("userName", "1234".toCharArray());  // Noncompliant\n'
            "\n"
            "**Compliant Solution**\n"
            "\n"
            "Connection conn = null;\n"
            "try {\n"
            "  String uname = getEncryptedUser();\n"
            "  String password = getEncryptedPass();\n"
            '  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +\n'
            '        "user=" + uname + "&amp;password=" + password);',
            item.description,
        )
        self.assertEqual(str, type(item.line))
        self.assertEqual("66", item.line)
        self.assertEqual(str, type(item.unique_id_from_tool))
        self.assertEqual("AWK40IMu-pl6AHs22MnV", item.unique_id_from_tool)
        my_file_handle.close()

    def test_detailed_parse_file_with_multiple_vulnerabilities_has_multiple_findings(
            self,
    ):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-6-findings.html",
        )
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        # common verifications
        self.assertEqual(6, len(findings))
        my_file_handle.close()

    def test_file_name_aggregated_parse_file_with_multiple_vulnerabilities_has_multiple_findings(
            self,
    ):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-6-findings.html",
        )
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        # common verifications
        # (there is no aggregation to be done here)
        self.assertEqual(6, len(findings))
        my_file_handle.close()

    def test_detailed_parse_file_with_table_in_table(self):
        """Test parsing when the vulnerability details include a table, with tr and td that should be ignored when looking for list of rules"""
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-table-in-table.html",
        )
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(1, len(findings))

        # check content
        item = findings[0]
        self.assertEqual(str, type(findings[0].title))
        self.assertEqual('"clone" should not be overridden', item.title)
        self.assertEqual(int, type(item.cwe))
        self.assertEqual(0, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(True, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual(
            "Many consider clone and Cloneable broken in Java, largely because the rules for overriding clone are tricky\n"
            "and difficult to get right, according to Joshua Bloch:\n"
            "\n"
            "  Object's clone method is very tricky. It's based on field copies, and it's \"extra-linguistic.\" It creates an object without calling a constructor.\n"
            "  There are no guarantees that it preserves the invariants established by the constructors. There have been lots of bugs over the years, both in and\n"
            "  outside Sun, stemming from the fact that if you just call super.clone repeatedly up the chain until you have cloned an object, you have a shallow\n"
            "  copy of the object. The clone generally shares state with the object being cloned. If that state is mutable, you don't have two independent objects.\n"
            "  If you modify one, the other changes as well. And all of a sudden, you get random behavior.\n"
            "\n"
            "A copy constructor or copy factory should be used instead.\n"
            "This rule raises an issue when clone is overridden, whether or not Cloneable is implemented.\n"
            "**Noncompliant Code Example**\n"
            "\n"
            "public class MyClass {\n"
            "  // ...\n"
            "\n"
            "  public Object clone() { // Noncompliant\n"
            "    //...\n"
            "  }\n"
            "}\n"
            "\n"
            "**Compliant Solution**\n"
            "\n"
            "public class MyClass {\n"
            "  // ...\n"
            "\n"
            "  MyClass (MyClass source) {\n"
            "    //...\n"
            "  }\n"
            "}",
            item.description,
        )
        self.assertEqual(str, type(item.severity))
        self.assertEqual("Critical", item.severity)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual(
            'Remove this "clone" implementation; use a copy constructor or copy factory instead.',
            item.mitigation,
        )
        self.assertEqual(str, type(item.references))
        self.assertMultiLineEqual(
            "squid:S2975\nCopy Constructor versus Cloning\nS2157\nS1182",
            item.references,
        )
        self.assertEqual(str, type(item.file_path))
        self.assertEqual(
            "java/org/apache/catalina/util/URLEncoder.java", item.file_path,
        )
        self.assertEqual(str, type(item.line))
        self.assertEqual("190", item.line)
        self.assertEqual(str, type(item.unique_id_from_tool))
        self.assertEqual("AWK40IMu-pl6AHs22MnV", item.unique_id_from_tool)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)
        self.assertEqual(bool, type(item.dynamic_finding))
        self.assertEqual(False, item.dynamic_finding)
        my_file_handle.close()

    def test_detailed_parse_file_with_rule_undefined(self):
        """The vulnerability's rule is not in the list of rules"""
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-rule-undefined.html",
        )
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(1, len(findings))

        # check content
        item = findings[0]
        self.assertEqual(str, type(findings[0].title))
        self.assertEqual('"clone" should not be overridden', item.title)
        self.assertEqual(int, type(item.cwe))
        # no rule found -> 0
        self.assertEqual(0, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(True, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(str, type(item.description))
        self.assertEqual("No description provided", item.description)
        self.assertEqual(str, type(item.severity))
        self.assertEqual("Critical", item.severity)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual(
            'Remove this "clone" implementation; use a copy constructor or copy factory instead.',
            item.mitigation,
        )
        self.assertEqual(str, type(item.references))
        self.assertEqual("", item.references)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual(
            "java/org/apache/catalina/util/URLEncoder.java", item.file_path,
        )
        self.assertEqual(str, type(item.line))
        self.assertEqual("190", item.line)
        self.assertEqual(str, type(item.unique_id_from_tool))
        self.assertEqual("AWK40IMu-pl6AHs22MnV", item.unique_id_from_tool)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)
        self.assertEqual(bool, type(item.dynamic_finding))
        self.assertEqual(False, item.dynamic_finding)
        my_file_handle.close()

    # SonarQube Scan - report with aggregations to be made
    def test_file_name_aggregated_parse_file_with_vuln_on_same_filename(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-4-findings-3-to-aggregate.html",
        )
        parser = SonarQubeParser()
        findings = parser.get_findings(my_file_handle, test)
        # specific verifications
        self.assertEqual(2, len(findings))
        # checking both items because they aren't always in the same order
        item1 = findings[0]
        item2 = findings[1]
        if item1.nb_occurences == 3:
            aggregatedItem = item1
            # there is nothing to aggregate on the other finding
            self.assertEqual(int, type(item2.nb_occurences))
            self.assertEqual(1, item2.nb_occurences)
        elif item2.nb_occurences == 3:
            aggregatedItem = item2
            # there is nothing to aggregate on the other finding
            self.assertEqual(int, type(item1.nb_occurences))
            self.assertEqual(1, item1.nb_occurences)
        else:
            self.fail("cannot find aggregated item")
        self.assertEqual(str, type(aggregatedItem.description))
        self.assertMultiLineEqual(
            "Because it is easy to extract strings from a compiled application, credentials should never be hard-coded. Do so, and they're almost guaranteed to\n"
            "end up in the hands of an attacker. This is particularly true for applications that are distributed.\n"
            "Credentials should be stored outside of the code in a strongly-protected encrypted configuration file or database.\n"
            "**Noncompliant Code Example**\n"
            "\n"
            "Connection conn = null;\n"
            "try {\n"
            '  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +\n'
            '        "user=steve&amp;password=blue"); // Noncompliant\n'
            '  String uname = "steve";\n'
            '  String password = "blue";\n'
            '  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +\n'
            '        "user=" + uname + "&amp;password=" + password); // Noncompliant\n'
            "\n"
            '  java.net.PasswordAuthentication pa = new java.net.PasswordAuthentication("userName", "1234".toCharArray());  // Noncompliant\n'
            "\n"
            "**Compliant Solution**\n"
            "\n"
            "Connection conn = null;\n"
            "try {\n"
            "  String uname = getEncryptedUser();\n"
            "  String password = getEncryptedPass();\n"
            '  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +\n'
            '        "user=" + uname + "&amp;password=" + password);\n'
            "\n"
            "-----\n"
            "Occurences:\n"
            "Line: 12\n"
            "Line: 13\n"
            "Line: 14",
            aggregatedItem.description,
        )
        self.assertIsNone(aggregatedItem.line)
        self.assertIsNone(aggregatedItem.unique_id_from_tool)
        self.assertEqual(int, type(aggregatedItem.nb_occurences))
        my_file_handle.close()

    # SonarQube Scan detailed - report with aggregations to be made
    def test_detailed_parse_file_with_vuln_on_same_filename(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-4-findings-3-to-aggregate.html",
        )
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        # specific verifications
        self.assertEqual(4, len(findings))
        my_file_handle.close()

    def test_detailed_parse_file_with_vuln_issue_3725(self):
        """
        SonarQube Scan detailed - report that crash
        see: https://github.com/DefectDojo/django-DefectDojo/issues/3725
        """
        my_file_handle, _product, _engagement, test = self.init(get_unit_tests_scans_path("sonarqube") / "sonar.html")
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        # specific verifications
        self.assertEqual(322, len(findings))
        my_file_handle.close()

    def test_detailed_parse_file_table_has_whitespace(self):
        """
        From version 3.1.1: sonarqube-report has new template with some change.
        see: https://github.com/soprasteria/sonar-report/commit/7dab559e7ecf9ed319345e9262a8b160bd3af94f
        Data table will have some whitespaces, parser should strip it before compare or use these properties.
        """
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-table-in-table-with-whitespace.html",
        )
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(1, len(findings))

        # check content
        item = findings[0]
        self.assertEqual(str, type(findings[0].title))
        self.assertEqual('"clone" should not be overridden', item.title)
        self.assertEqual(int, type(item.cwe))
        self.assertEqual(0, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(True, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual(
            "Many consider clone and Cloneable broken in Java, largely because the rules for overriding clone are tricky\n"
            "and difficult to get right, according to Joshua Bloch:\n"
            "\n"
            "  Object's clone method is very tricky. It's based on field copies, and it's \"extra-linguistic.\" It creates an object without calling a constructor.\n"
            "  There are no guarantees that it preserves the invariants established by the constructors. There have been lots of bugs over the years, both in and\n"
            "  outside Sun, stemming from the fact that if you just call super.clone repeatedly up the chain until you have cloned an object, you have a shallow\n"
            "  copy of the object. The clone generally shares state with the object being cloned. If that state is mutable, you don't have two independent objects.\n"
            "  If you modify one, the other changes as well. And all of a sudden, you get random behavior.\n"
            "\n"
            "A copy constructor or copy factory should be used instead.\n"
            "This rule raises an issue when clone is overridden, whether or not Cloneable is implemented.\n"
            "**Noncompliant Code Example**\n"
            "\n"
            "public class MyClass {\n"
            "  // ...\n"
            "\n"
            "  public Object clone() { // Noncompliant\n"
            "    //...\n"
            "  }\n"
            "}\n"
            "\n"
            "**Compliant Solution**\n"
            "\n"
            "public class MyClass {\n"
            "  // ...\n"
            "\n"
            "  MyClass (MyClass source) {\n"
            "    //...\n"
            "  }\n"
            "}",
            item.description,
        )
        self.assertEqual(str, type(item.severity))
        self.assertEqual("Critical", item.severity)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual(
            'Remove this "clone" implementation; use a copy constructor or copy factory instead.',
            item.mitigation,
        )
        self.assertEqual(str, type(item.references))
        self.assertMultiLineEqual(
            "squid:S2975\nCopy Constructor versus Cloning\nS2157\nS1182",
            item.references,
        )
        self.assertEqual(str, type(item.file_path))
        self.assertEqual(
            "java/org/apache/catalina/util/URLEncoder.java", item.file_path,
        )
        self.assertEqual(str, type(item.line))
        self.assertEqual("190", item.line)
        self.assertEqual(str, type(item.unique_id_from_tool))
        self.assertEqual("AWK40IMu-pl6AHs22MnV", item.unique_id_from_tool)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)
        self.assertEqual(bool, type(item.dynamic_finding))
        self.assertEqual(False, item.dynamic_finding)
        my_file_handle.close()

    def test_detailed_parse_json_file_with_no_vulnerabilities_has_no_findings(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-no-finding.json",
        )
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(0, len(findings))
        my_file_handle.close()

    def test_detailed_parse_json_file_with_single_vulnerability_has_single_finding(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-single-finding.json",
        )
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        # common verifications
        self.assertEqual(1, len(findings))
        # specific verifications
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.maxDiff = None
        self.assertMultiLineEqual('A cross-site request forgery (CSRF) attack occurs when a trusted user of a web '
                                  'application can be forced, by an attacker, to perform sensitive\nactions that he '
                                  'didn&#8217;t intend, such as updating his profile or sending a message, more generally '
                                  'anything that can change the state of the\napplication.\nThe attacker can trick '
                                  'the user/victim to click on a link, corresponding to the privileged action, '
                                  'or to visit a malicious web site that embeds a\nhidden web request and as web '
                                  'browsers automatically include cookies, the actions can be authenticated and '
                                  'sensitive.\n**Ask Yourself Whether**\n\n   The web application uses cookies to '
                                  'authenticate users. \n   There exist sensitive operations in the web application '
                                  'that can be performed when the user is authenticated. \n   The state / resources '
                                  'of the web application can be modified by doing HTTP POST or HTTP DELETE requests '
                                  'for example. \n\nThere is a risk if you answered yes to any of those '
                                  'questions.\n**Recommended Secure Coding Practices**\n\n   Protection against CSRF '
                                  'attacks is strongly recommended:\n    \n       to be activated by default for all '
                                  'unsafe HTTP\n      methods. \n       implemented, for example, with an unguessable '
                                  'CSRF token \n      \n   Of course all sensitive operations should not be performed '
                                  'with safe HTTP methods like GET which are designed to be\n  used only for '
                                  'information retrieval. \n\n**Sensitive Code Example**\nFor a Django application, '
                                  'the code is sensitive when,\n\n   django.middleware.csrf.CsrfViewMiddleware is not '
                                  'used in the Django settings: \n\n\nMIDDLEWARE = [\n    '
                                  '\'django.middleware.security.SecurityMiddleware\','
                                  '\n    \'django.contrib.sessions.middleware.SessionMiddleware\','
                                  '\n    \'django.middleware.common.CommonMiddleware\','
                                  '\n    \'django.contrib.auth.middleware.AuthenticationMiddleware\','
                                  '\n    \'django.contrib.messages.middleware.MessageMiddleware\','
                                  '\n    \'django.middleware.clickjacking.XFrameOptionsMiddleware\',\n] # Sensitive: '
                                  'django.middleware.csrf.CsrfViewMiddleware is missing\n\n\n   the CSRF protection '
                                  'is disabled on a view: \n\n\n@csrf_exempt # Sensitive\ndef example(request):\n    '
                                  'return HttpResponse("default")\n\nFor a Flask application, the code is sensitive '
                                  'when,\n\n   the WTF_CSRF_ENABLED setting is set to false: \n\n\napp = Flask('
                                  '__name__)\napp.config[\'WTF_CSRF_ENABLED\'] = False # Sensitive\n\n\n   the '
                                  'application doesn&#8217;t use the CSRFProtect module: \n\n\napp = Flask(__name__) # '
                                  'Sensitive: CSRFProtect is missing\n\n@app.route(\'/\')\ndef hello_world():\n    '
                                  'return \'Hello, World!\'\n\n\n   the CSRF protection is disabled on a view: '
                                  '\n\n\napp = Flask(__name__)\ncsrf = CSRFProtect()\ncsrf.init_app('
                                  'app)\n\n@app.route(\'/example/\', methods=[\'POST\'])\n@csrf.exempt # '
                                  'Sensitive\ndef example():\n    return \'example \'\n\n\n   the CSRF protection is '
                                  'disabled on a form: \n\n\nclass unprotectedForm(FlaskForm):\n    class Meta:\n     '
                                  '   csrf = False # Sensitive\n\n    name = TextField(\'name\')\n    submit = '
                                  'SubmitField(\'submit\')\n\n**Compliant Solution**\nFor a Django application,'
                                  '\n\n   it is recommended to protect all the views with '
                                  'django.middleware.csrf.CsrfViewMiddleware: \n\n\nMIDDLEWARE = [\n    '
                                  '\'django.middleware.security.SecurityMiddleware\','
                                  '\n    \'django.contrib.sessions.middleware.SessionMiddleware\','
                                  '\n    \'django.middleware.common.CommonMiddleware\','
                                  '\n    \'django.middleware.csrf.CsrfViewMiddleware\', # Compliant\n    '
                                  '\'django.contrib.auth.middleware.AuthenticationMiddleware\','
                                  '\n    \'django.contrib.messages.middleware.MessageMiddleware\','
                                  '\n    \'django.middleware.clickjacking.XFrameOptionsMiddleware\',\n]\n\n\n   and '
                                  'to not disable the CSRF protection on specific views: \n\n\ndef example(request): '
                                  '# Compliant\n    return HttpResponse("default")\n\nFor a Flask application,'
                                  '\n\n   the CSRFProtect module should be used (and not disabled further with '
                                  'WTF_CSRF_ENABLED set to false):\n  \n\n\napp = Flask(__name__)\ncsrf = '
                                  'CSRFProtect()\ncsrf.init_app(app) # Compliant\n\n\n   and it is recommended to not '
                                  'disable the CSRF protection on specific views or forms: \n\n\n@app.route('
                                  '\'/example/\', methods=[\'POST\']) # Compliant\ndef example():\n    return '
                                  '\'example \'\n\nclass unprotectedForm(FlaskForm):\n    class Meta:\n        csrf = '
                                  'True # Compliant\n\n    name = TextField(\'name\')\n    submit = SubmitField('
                                  '\'submit\')\n\n'.strip(),
                                  item.description)
        self.assertEqual(str, type(item.line))
        self.assertEqual(8, 8)
        self.assertEqual(str, type(item.unique_id_from_tool))
        self.assertEqual("AYvNd32RyD1npIoQXyT1", item.unique_id_from_tool)
        my_file_handle.close()

    def test_detailed_parse_json_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "sonar-6-findings.json",
        )
        parser = SonarQubeParser()
        parser.set_mode("detailed")
        findings = parser.get_findings(my_file_handle, test)
        # common verifications
        # (there is no aggregation to be done here)
        self.assertEqual(6, len(findings))
        my_file_handle.close()

    def test_parse_json_file_from_api_with_multiple_findings_json(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "findings_over_api.json",
        )
        parser = SonarQubeParser()
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(5, len(findings))
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.assertEqual("OWASP:UsingComponentWithKnownVulnerability_fjioefjwoefijo", item.title)
        self.assertEqual("Medium", item.severity)
        self.assertEqual("CVE-2024-2529", item.unsaved_vulnerability_ids[0])
        self.assertEqual("120", item.cwe)
        self.assertEqual("6.4", item.cvssv3_score)
        self.assertEqual("package", item.component_name)
        self.assertEqual("1.1.2", item.component_version)
        item = findings[1]
        self.assertEqual("Web:TableWithoutCaptionCheck_asdfwfewfwefewf", item.title)
        self.assertEqual("Low", item.severity)
        self.assertEqual(0, item.cwe)
        self.assertIsNone(item.cvssv3_score)
        item = findings[2]
        self.assertEqual("typescript:S1533_fjoiewfjoweifjoihugu-", item.title)
        self.assertEqual("Low", item.severity)
        item = findings[3]
        self.assertEqual("GHSA-frr2-c345-p7c2", item.unsaved_vulnerability_ids[0])
        item = findings[4]
        self.assertEqual("CVE-2023-52428", item.unsaved_vulnerability_ids[0])
        self.assertEqual("nimbus-jose-jwt-9.24.4.jar", item.component_name)
        self.assertIsNone(item.component_version)
        my_file_handle.close()

    def test_parse_json_file_from_api_with_multiple_findings_hotspots_json(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "findings_over_api_hotspots.json",
        )
        parser = SonarQubeParser()
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(4, len(findings))
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.assertEqual("typescript:7777_fwafewef", item.title)
        self.assertEqual("High", item.severity)
        item = findings[1]
        self.assertEqual("Web:1222_cyxcvyxcvyxv", item.title)
        self.assertEqual("Low", item.severity)
        item = findings[2]
        self.assertEqual("Web:9876_werrwerwerwer", item.title)
        self.assertEqual("Low", item.severity)
        my_file_handle.close()

    def test_parse_json_file_from_api_with_empty_json(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "findings_over_api_empty.json",
        )
        parser = SonarQubeParser()
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(0, len(findings))
        my_file_handle.close()

    def test_parse_json_file_from_api_with_emppty_zip(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "empty_zip.zip",
        )
        parser = SonarQubeParser()
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(0, len(findings))
        my_file_handle.close()

    def test_parse_json_file_from_api_with_multiple_findings_zip(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "findings_over_api.zip",
        )
        parser = SonarQubeParser()
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(6, len(findings))
        item = findings[0]
        self.assertEqual(str, type(item.description))
        self.assertEqual("OWASP:UsingComponentWithKnownVulnerability_fjioefjwoefijo", item.title)
        self.assertEqual("testapplication", item.file_path)
        self.assertEqual("Medium", item.severity)
        item = findings[3]
        self.assertEqual("OWASP:UsingComponentWithKnownVulnerability_fjioefjwo1123efijo", item.title)
        self.assertEqual("Low", item.severity)
        item = findings[5]
        self.assertEqual("typescript:S112533_fjoiewfjo1235gweifjoihugu-", item.title)
        self.assertEqual("Medium", item.severity)
        my_file_handle.close()

    def test_parse_json_file_issue_10150(self):
        my_file_handle, _product, _engagement, test = self.init(
            get_unit_tests_scans_path("sonarqube") / "issue_10150.json",
        )
        parser = SonarQubeParser()
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(3, len(findings))
        item = findings[0]
        self.assertEqual("High", item.severity)
        item = findings[2]
        self.assertEqual("Medium", item.severity)
        my_file_handle.close()
