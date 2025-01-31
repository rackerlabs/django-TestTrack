from xml.dom import NamespaceErr

from defusedxml import ElementTree as ET

from dojo.models import Endpoint, Finding


class HCLAppScanParser:
    def get_scan_types(self):
        return ["HCLAppScan XML"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import XML output of HCL AppScan."

    def xmltreehelper(self, xml_input):
        if xml_input.text is None:
            output = None
        elif "\n" in xml_input.text:
            output = ""
            for i in xml_input:
                output = output + " " + i.text
        else:
            output = " " + xml_input.text
        return output

    def get_findings(self, file, test):
        findings = []
        tree = ET.parse(file)
        root = tree.getroot()
        if "xml-report" not in root.tag:
            msg = "This doesn't seem to be a valid HCLAppScan xml file."
            raise NamespaceErr(msg)
        report = root.find("issue-group")
        if report is not None:
            for finding in report:
                title = ""
                description = ""
                for item in finding:
                    match item.tag:
                        case "severity":
                            output = self.xmltreehelper(item)
                            severity = "Info" if output is None else output.strip(" ").capitalize()
                        case "cwe":
                            cwe = int(self.xmltreehelper(item))
                        case "remediation":
                            remediation = self.xmltreehelper(item)
                        case "advisory":
                            advisory = self.xmltreehelper(item)
                        case "issue-type":
                            title = self.xmltreehelper(item).strip()
                            description = description + "Issue-Type:" + title + "\n"
                        case "issue-type-name":
                            title = self.xmltreehelper(item).strip()
                            description = description + "Issue-Type-Name:" + title + "\n"
                        case "location":
                            location = self.xmltreehelper(item)
                            description = description + "Location:" + location + "\n"
                        case "domain":
                            domain = self.xmltreehelper(item)
                            title += "_" + domain.strip()
                            description = description + "Domain:" + domain + "\n"
                        case "threat-class":
                            threatclass = self.xmltreehelper(item)
                            description = description + "Threat-Class:" + threatclass + "\n"
                        case "entity":
                            entity = self.xmltreehelper(item)
                            title += "_" + entity.strip()
                            description = description + "Entity:" + entity + "\n"
                        case "security-risks":
                            security_risks = self.xmltreehelper(item)
                            description = description + "Security-Risks:" + security_risks + "\n"
                        case "cause-id":
                            causeid = self.xmltreehelper(item)
                            title += "_" + causeid.strip()
                            description = description + "Cause-Id:" + causeid + "\n"
                        case "url-name":
                            urlname = self.xmltreehelper(item)
                            title += "_" + urlname.strip()
                            description = description + "Url-Name:" + urlname + "\n"
                        case "element":
                            element = self.xmltreehelper(item)
                            description = description + "Element:" + element + "\n"
                        case "element-type":
                            elementtype = self.xmltreehelper(item)
                            description = description + "ElementType:" + elementtype + "\n"
                        case "path":
                            path = self.xmltreehelper(item)
                            title += "_" + path.strip()
                            description = description + "Path:" + path + "\n"
                        case "scheme":
                            scheme = self.xmltreehelper(item)
                            description = description + "Scheme:" + scheme + "\n"
                        case "host":
                            host = self.xmltreehelper(item)
                            description = description + "Host:" + host + "\n"
                        case "port":
                            port = self.xmltreehelper(item)
                            description = description + "Port:" + port + "\n"
                prepared_finding = Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    cwe=cwe,
                    mitigation="Remediation:" + remediation + "\nAdvisory:" + advisory,
                    dynamic_finding=True,
                    static_finding=False,
                )
                findings.append(prepared_finding)
                try:
                    prepared_finding.unsaved_endpoints = []
                    endpoint = Endpoint(host=host, port=port)
                    prepared_finding.unsaved_endpoints.append(endpoint)
                except UnboundLocalError:
                    pass
            return findings
        return findings
