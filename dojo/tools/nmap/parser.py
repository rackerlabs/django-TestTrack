import contextlib
import datetime

from cpe import CPE
from defusedxml.ElementTree import parse

from dojo.models import Endpoint, Finding


class NmapParser:
    def get_scan_types(self):
        return ["Nmap Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "XML output (use -oX)"

    def get_findings(self, file, test):
        tree = parse(file)
        root = tree.getroot()
        dupes = {}
        if "nmaprun" not in root.tag:
            msg = "This doesn't seem to be a valid Nmap xml file."
            raise ValueError(msg)

        report_date = None
        with contextlib.suppress(ValueError):
            report_date = datetime.datetime.fromtimestamp(
                int(root.attrib["start"]),
            )

        for host in root.findall("host"):
            host_info = "### Host\n\n"

            ip = host.find("address[@addrtype='ipv4']").attrib["addr"]
            if ip is not None:
                host_info += f"**IP Address:** {ip}\n"

            fqdn = (
                host.find("hostnames/hostname[@type='PTR']").attrib["name"]
                if host.find("hostnames/hostname[@type='PTR']") is not None
                else None
            )
            if fqdn is not None:
                host_info += f"**FQDN:** {fqdn}\n"

            host_info += "\n\n"

            for os in host.iter("os"):
                for os_match in os.iter("osmatch"):
                    if "name" in os_match.attrib:
                        host_info += (
                            "**Host OS:** {}\n".format(os_match.attrib["name"])
                        )
                    if "accuracy" in os_match.attrib:
                        host_info += "**Accuracy:** {}%\n".format(
                            os_match.attrib["accuracy"],
                        )

                host_info += "\n\n"

            for port_element in host.findall("ports/port"):
                protocol = port_element.attrib["protocol"]
                endpoint = Endpoint(
                    host=fqdn or ip, protocol=protocol,
                )
                if (
                    "portid" in port_element.attrib
                    and port_element.attrib["portid"].isdigit()
                ):
                    endpoint.port = int(port_element.attrib["portid"])

                # filter on open ports
                if port_element.find("state").attrib.get("state") != "open":
                    continue
                title = f"Open port: {endpoint.port}/{endpoint.protocol}"
                description = host_info
                description += f"**Port/Protocol:** {endpoint.port}/{endpoint.protocol}\n"

                service_info = "\n\n"
                if port_element.find("service") is not None:
                    if "product" in port_element.find("service").attrib:
                        service_info += (
                            "**Product:** {}\n".format(port_element.find("service").attrib["product"])
                        )

                    if "version" in port_element.find("service").attrib:
                        service_info += (
                            "**Version:** {}\n".format(port_element.find("service").attrib["version"])
                        )

                    if "extrainfo" in port_element.find("service").attrib:
                        service_info += (
                            "**Extra Info:** {}\n".format(port_element.find("service").attrib["extrainfo"])
                        )
                    description += service_info
                script_id = None
                if script := port_element.find("script"):
                    if script_id := script.attrib.get("id"):
                        description += f"**Script ID:** {script_id}\n"
                    if script_output := script.attrib.get("output"):
                        description += f"**Script Output:** {script_output}\n"
                description += "\n\n"

                # manage some script like
                # https://github.com/vulnersCom/nmap-vulners
                for script_element in port_element.findall(
                    'script[@id="vulners"]',
                ):
                    self.manage_vulner_script(
                        test, dupes, script_element, endpoint, report_date,
                    )

                severity = "Info"
                dupe_key = "nmap:" + str(endpoint.port)
                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if description is not None:
                        find.description += description
                else:
                    find = Finding(
                        title=title,
                        test=test,
                        description=description,
                        severity=severity,
                        mitigation="N/A",
                        impact="No impact provided",
                        vuln_id_from_tool=script_id,
                    )
                    find.unsaved_endpoints = []
                    dupes[dupe_key] = find
                    if report_date:
                        find.date = report_date

                find.unsaved_endpoints.append(endpoint)
        return list(dupes.values())

    def convert_cvss_score(self, raw_value):
        """
        According to CVSS official numbers https://nvd.nist.gov/vuln-metrics/cvss
                        None 	0.0
        Low 	0.0-3.9 	Low 	0.1-3.9
        Medium 	4.0-6.9 	Medium 	4.0-6.9
        High 	7.0-10.0 	High 	7.0-8.9
        Critical 	9.0-10.0
        """
        val = float(raw_value)
        if val == 0.0:
            return "Info"
        if val < 4.0:
            return "Low"
        if val < 7.0:
            return "Medium"
        if val < 9.0:
            return "High"
        return "Critical"

    def manage_vulner_script(
        self, test, dupes, script_element, endpoint, report_date=None,
    ):
        for component_element in script_element.findall("table"):
            component_cpe = CPE(component_element.attrib["key"])
            for vuln in component_element.findall("table"):
                # convert elements in dict
                vuln_attributes = {}
                for elem in vuln.findall("elem"):
                    vuln_attributes[elem.attrib["key"].lower()] = elem.text

                vuln_id = vuln_attributes["id"]
                description = "### Vulnerability\n\n"
                description += "**ID**: `" + str(vuln_id) + "`\n"
                description += "**CPE**: " + str(component_cpe) + "\n"
                for attribute in vuln_attributes:
                    description += (
                        "**"
                        + attribute
                        + "**: `"
                        + vuln_attributes[attribute]
                        + "`\n"
                    )
                severity = self.convert_cvss_score(vuln_attributes["cvss"])

                finding = Finding(
                    title=vuln_id,
                    test=test,
                    description=description,
                    severity=severity,
                    component_name=component_cpe.get_product()[0]
                    if len(component_cpe.get_product()) > 0
                    else "",
                    component_version=component_cpe.get_version()[0]
                    if len(component_cpe.get_version()) > 0
                    else "",
                    vuln_id_from_tool=vuln_id,
                    nb_occurences=1,
                )
                finding.unsaved_endpoints = [endpoint]

                # manage if CVE is in metadata
                if (
                    "type" in vuln_attributes
                    and vuln_attributes["type"] == "cve"
                ):
                    finding.unsaved_vulnerability_ids = [vuln_attributes["id"]]

                if report_date:
                    finding.date = report_date

                dupe_key = finding.vuln_id_from_tool
                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if description is not None:
                        find.description += (
                            "\n-----\n\n" + finding.description
                        )  # fives '-' produces an horizontal line
                    find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                    find.nb_occurences += finding.nb_occurences
                else:
                    dupes[dupe_key] = finding
