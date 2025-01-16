from xml.dom import NamespaceErr

from defusedxml import ElementTree as ET

from dojo.models import Finding


class HCLASoCSASTParser:
    def get_scan_types(self):
        return ["HCL AppScan on Cloud SAST XML"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import XML output of HCL AppScan on Cloud SAST"

    def xmltreehelper(self, input):
        if input.text is None:
            output = None
        elif "\n" in input.text:
            output = ""
            for i in input:
                output = output + " " + i.text
        else:
            output = " " + input.text
        return output

    def get_findings(self, file, test):
        findings = []
        tree = ET.parse(file)
        root = tree.getroot()
        if "xml-report" not in root.tag:
            msg = "This doesn't seem to be a valid HCL ASoC SAST xml file."
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
                        case "issue-type":
                            title = self.xmltreehelper(item).strip()
                            description = description + "**Issue-Type:** " + title + "\n"
                        case "issue-type-name":
                            title = self.xmltreehelper(item).strip()
                            description = description + "**Issue-Type-Name:** " + title + "\n"
                        case "source-file":
                            location = self.xmltreehelper(item).strip()
                            description = description + "**Location:** " + location + "\n"
                        case "line":
                            line = int(self.xmltreehelper(item).strip())
                            description = description + "***Line:" + str(line) + "\n"
                        case "threat-class":
                            threatclass = self.xmltreehelper(item)
                            description = description + "***Threat-Class:" + threatclass + "\n"
                        case "entity":
                            entity = self.xmltreehelper(item)
                            title += "_" + entity.strip()
                            description = description + "***Entity:" + entity + "\n"
                        case "security-risks":
                            security_risks = self.xmltreehelper(item)
                            description = description + "***Security-Risks:" + security_risks + "\n"
                        case "cause-id":
                            causeid = self.xmltreehelper(item)
                            title += "_" + causeid.strip()
                            description = description + "***Cause-Id:" + causeid + "\n"
                        case "element":
                            element = self.xmltreehelper(item)
                            description = description + "***Element:" + element + "\n"
                        case "element-type":
                            elementtype = self.xmltreehelper(item)
                            description = description + "***ElementType:" + elementtype + "\n"
                        case "variant-group":
                            variantgroup = item.iter()
                            description = description + "***Call Trace:" + "\n"
                            for vitem in variantgroup:
                                if vitem.tag == "issue-information":
                                    issueinformation = vitem.iter()
                                    for iitem in issueinformation:
                                        if iitem.tag == "context":
                                            description = description + self.xmltreehelper(iitem) + "\n"

                        case "fix":
                            recommendations = ""
                            externalreferences = ""
                            issuetypename = ""
                            remediation = ""
                            fix = item.iter()
                            for fitem in fix:
                                if fitem.tag == "types":
                                    type = fitem.iter()
                                    for titem in type:
                                        if titem.tag == "name":
                                            issuetypename = self.xmltreehelper(titem)
                                if fitem.tag == "remediation":
                                    remediation = self.xmltreehelper(fitem)

                articlegroup = root.find("article-group")
                if articlegroup is not None:
                    for articles in articlegroup:
                        if articles.attrib["id"] == issuetypename.strip() and articles.attrib["api"] == remediation.strip():
                            articledetails = articles.iter()
                            for aitem in articledetails:
                                if aitem.tag == "cause":
                                    description = description + "***Cause:" + "\n"
                                    for causeitem in aitem:
                                        if causeitem.attrib["type"] == "string" and causeitem.text is not None:
                                            description = description + causeitem.text + "\n"
                                if aitem.tag == "recommendations":
                                    for recitem in aitem:
                                        if recitem.attrib["type"] == "string" and recitem.text is not None:
                                            recommendations = recommendations + recitem.text + "\n"
                                        elif recitem.attrib["type"] == "object":
                                            codeblock = recitem.iter()
                                            for codeitem in codeblock:
                                                if codeitem.tag == "item" and codeitem.attrib["type"] == "string":
                                                    if codeitem.text is None:
                                                        recommendations = recommendations + "\n"
                                                    else:
                                                        recommendations = recommendations + self.xmltreehelper(codeitem) + "\n"

                                if aitem.tag == "externalReferences":
                                    ref = aitem.iter()
                                    for ritem in ref:
                                        if ritem.tag == "title":
                                            externalreferences = externalreferences + self.xmltreehelper(ritem).strip() + "\n"
                                        if ritem.tag == "url":
                                            externalreferences = externalreferences + self.xmltreehelper(ritem).strip() + "\n"

                prepared_finding = Finding(
                    title=title,
                    description=description,
                    file_path=location,
                    line=line,
                    severity=severity,
                    cwe=cwe,
                    mitigation=recommendations,
                    references=externalreferences,
                    dynamic_finding=False,
                    static_finding=True,
                )
                findings.append(prepared_finding)
            return findings
        return findings
