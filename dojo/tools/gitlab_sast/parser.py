import json

from dojo.models import Finding
from dojo.tools.parser_test import ParserTest


class GitlabSastParser:

    def get_scan_types(self):
        return ["GitLab SAST Report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import GitLab SAST Report vulnerabilities in JSON format."

    def get_findings(self, json_output, test):

        if json_output is None:
            return None

        tree = self.parse_json(json_output)
        if tree:
            return self.get_items(tree)
        return None

    def get_tests(self, scan_type, handle):
        tree = self.parse_json(handle)
        scan = tree.get("scan")
        if scan:
            scanner_name = scan["scanner"]["name"]
            scanner_type = scan["scanner"]["name"]
            scanner_version = scan["scanner"]["version"]
        else:
            scanner_name = scanner_type = scanner_version = None

        test = ParserTest(
            name=scanner_name,
            parser_type=scanner_type,
            version=scanner_version,
        )
        test.findings = self.get_items(tree)
        return [test]

    def parse_json(self, json_output):
        data = json_output.read()
        try:
            tree = json.loads(str(data, "utf-8"))
        except:
            tree = json.loads(data)

        return tree

    def get_items(self, tree):
        items = {}
        scanner = tree.get("scan", {}).get("scanner", {})
        for node in tree["vulnerabilities"]:
            item = self.get_item(node, scanner)
            if item:
                items[item.unique_id_from_tool] = item

        return list(items.values())

    def get_confidence_numeric(self, argument):
        switcher = {
            "Confirmed": 1,    # Certain
            "High": 3,         # Firm
            "Medium": 4,       # Firm
            "Low": 6,          # Tentative
            "Experimental": 7,  # Tentative
        }
        return switcher.get(argument)

    def get_item(self, vuln, scanner):
        unique_id_from_tool = vuln["id"] if "id" in vuln else vuln["cve"]
        title = ""
        if "name" in vuln:
            title = vuln["name"]
        elif "message" in vuln:
            title = vuln["message"]
        elif "description" in vuln:
            title = vuln["description"]
        else:
            # All other fields are optional, if none of them has a value, fall back on the unique id
            title = unique_id_from_tool

        description = f"Scanner: {scanner.get('name', 'Could not be determined')}\n"
        if "message" in vuln:
            description += f"{vuln['message']}\n"
        if "description" in vuln:
            description += f"{vuln['description']}\n"

        location = vuln["location"]
        file_path = location.get("file", None)

        line = location.get("start_line", None)

        sast_object = None
        sast_source_file_path = None
        sast_source_line = None
        if "class" in location and "method" in location:
            sast_object = f"{location['class']}#{location['method']}"
        elif "class" in location:
            sast_object = location["class"]
        elif "method" in location:
            sast_object = location["method"]

        if sast_object is not None:
            sast_source_file_path = file_path
            sast_source_line = line

        if "end_line" in location:
            line = location["end_line"]

        severity = vuln.get("severity")
        if severity is None or severity == "Undefined" or severity == "Unknown":
            # Severity can be "Undefined" or "Unknown" in SAST report
            # In that case we set it as Info and specify the initial severity in the title
            title = f"[{severity} severity] {title}"
            severity = "Info"
        scanner_confidence = self.get_confidence_numeric(vuln.get("confidence", "Unkown"))

        mitigation = vuln.get("solution", "")
        cwe = None
        vulnerability_id = None
        references = ""
        if "identifiers" in vuln:
            for identifier in vuln["identifiers"]:
                if identifier["type"].lower() == "cwe":
                    if isinstance(identifier["value"], int):
                        cwe = identifier["value"]
                    elif identifier["value"].isdigit():
                        cwe = int(identifier["value"])
                elif identifier["type"].lower() == "cve":
                    vulnerability_id = identifier["value"]
                else:
                    references += f"Identifier type: {identifier['type']}\n"
                    references += f"Name: {identifier['name']}\n"
                    references += f"Value: {identifier['value']}\n"
                    if "url" in identifier:
                        references += f"URL: {identifier['url']}\n"
                    references += "\n"

        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            scanner_confidence=scanner_confidence,
            mitigation=mitigation,
            unique_id_from_tool=unique_id_from_tool,
            references=references,
            file_path=file_path,
            line=line,
            sast_source_object=sast_object,
            sast_sink_object=sast_object,
            sast_source_file_path=sast_source_file_path,
            sast_source_line=sast_source_line,
            cwe=cwe,
            static_finding=True,
            dynamic_finding=False)
        if vulnerability_id:
            finding.unsaved_vulnerability_ids = [vulnerability_id]

        return finding
