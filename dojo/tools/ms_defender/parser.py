import json
import zipfile

from dojo.models import Endpoint, Finding


class MSDefenderParser:

    """Import from MSDefender findings"""

    def __init__(self):
        self.findings = []

    def get_scan_types(self):
        return ["MSDefender Parser"]

    def get_label_for_scan_types(self, scan_type):
        return "MSDefender Parser"

    def get_description_for_scan_types(self, scan_type):
        return ("MSDefender findings can be retrieved using the REST API")

    def get_findings(self, file, test):
        if str(file.name).endswith(".json"):
            vulnerabilityfile = json.load(file)
            vulnerabilitydata = vulnerabilityfile["value"]
            for vulnerability in vulnerabilitydata:
                self.process_json(vulnerability)
        elif str(file.name).endswith(".zip"):
            if str(file.__class__) == "<class '_io.TextIOWrapper'>":
                input_zip = zipfile.ZipFile(file.name, "r")
            else:
                input_zip = zipfile.ZipFile(file, "r")
            zipdata = {name: input_zip.read(name) for name in input_zip.namelist()}
            if zipdata.get("machines/") is None or zipdata.get("vulnerabilities/") is None:
                return []
            vulnerabilityfiles = []
            machinefiles = []
            for content in list(zipdata):
                if "vulnerabilities/" in content and content != "vulnerabilities/":
                    vulnerabilityfiles.append(content)
                if "machines/" in content and content != "machines/":
                    machinefiles.append(content)
            vulnerabilities = []
            machines = {}
            for vulnerabilityfile in vulnerabilityfiles:
                output = json.loads(zipdata[vulnerabilityfile].decode("ascii"))["value"]
                for data in output:
                    vulnerabilities.append(data)
            for machinefile in machinefiles:
                output = json.loads(zipdata[machinefile].decode("ascii"))["value"]
                for data in output:
                    machines[data.get("id")] = data
            for vulnerability in vulnerabilities:
                try:
                    self.process_zip(vulnerability, machines[vulnerability["machineId"]])
                except (IndexError, KeyError):
                    self.process_json(vulnerability)
        else:
            return []
        return self.findings

    def process_json(self, vulnerability):
        description = ""
        description += "cveId: " + str(vulnerability["cveId"]) + "\n"
        description += "machineId: " + str(vulnerability["machineId"]) + "\n"
        description += "fixingKbId: " + str(vulnerability["fixingKbId"]) + "\n"
        description += "productName: " + str(vulnerability["productName"]) + "\n"
        description += "productVendor: " + str(vulnerability["productVendor"]) + "\n"
        description += "productVersion: " + str(vulnerability["productVersion"]) + "\n"
        title = str(vulnerability["cveId"])
        finding = Finding(
            title=title + "_" + vulnerability["machineId"],
            severity=self.severity_check(vulnerability["severity"]),
            description=description,
            static_finding=False,
            dynamic_finding=True,
        )
        if vulnerability["fixingKbId"] is not None:
            finding.mitigation = vulnerability["fixingKbId"]
        if vulnerability["cveId"] is not None:
            finding.unsaved_vulnerability_ids = []
            finding.unsaved_vulnerability_ids.append(vulnerability["cveId"])
        self.findings.append(finding)
        finding.unsaved_endpoints = []

    def process_zip(self, vulnerability, machine):
        description = ""
        description += "cveId: " + str(vulnerability["cveId"]) + "\n"
        description += "machineId: " + str(vulnerability["machineId"]) + "\n"
        description += "fixingKbId: " + str(vulnerability["fixingKbId"]) + "\n"
        description += "productName: " + str(vulnerability["productName"]) + "\n"
        description += "productVendor: " + str(vulnerability["productVendor"]) + "\n"
        description += "productVersion: " + str(vulnerability["productVersion"]) + "\n"
        description += "machine Info: id: " + str(machine["id"]) + "\n"
        description += "machine Info: osPlatform: " + str(machine["osPlatform"]) + "\n"
        description += "machine Info: osVersion: " + str(machine["osVersion"]) + "\n"
        description += "machine Info: osProcessor: " + str(machine["osProcessor"]) + "\n"
        description += "machine Info: version: " + str(machine["version"]) + "\n"
        description += "machine Info: agentVersion: " + str(machine["agentVersion"]) + "\n"
        description += "machine Info: osBuild: " + str(machine["osBuild"]) + "\n"
        description += "machine Info: healthStatus: " + str(machine["healthStatus"]) + "\n"
        description += "machine Info: deviceValue: " + str(machine["deviceValue"]) + "\n"
        description += "machine Info: rbacGroupId: " + str(machine["rbacGroupId"]) + "\n"
        description += "machine Info: rbacGroupName: " + str(machine["rbacGroupName"]) + "\n"
        description += "machine Info: riskScore: " + str(machine["riskScore"]) + "\n"
        description += "machine Info: exposureLevel: " + str(machine["exposureLevel"]) + "\n"
        description += "machine Info: isAadJoined: " + str(machine["isAadJoined"]) + "\n"
        description += "machine Info: aadDeviceId: " + str(machine["aadDeviceId"]) + "\n"
        description += "machine Info: defenderAvStatus: " + str(machine["defenderAvStatus"]) + "\n"
        description += "machine Info: onboardingStatus: " + str(machine["onboardingStatus"]) + "\n"
        description += "machine Info: osArchitecture: " + str(machine["osArchitecture"]) + "\n"
        description += "machine Info: managedBy: " + str(machine["managedBy"]) + "\n"
        title = str(vulnerability["cveId"])
        if str(machine["computerDnsName"]) != "null":
            title = title + "_" + str(machine["computerDnsName"])
        if str(machine["osPlatform"]) != "null":
            title = title + "_" + str(machine["osPlatform"])
        finding = Finding(
            title=title + "_" + vulnerability["machineId"],
            severity=self.severity_check(vulnerability["severity"]),
            description=description,
            static_finding=False,
            dynamic_finding=True,
        )
        if vulnerability["fixingKbId"] is not None:
            finding.mitigation = vulnerability["fixingKbId"]
        if vulnerability["cveId"] is not None:
            finding.unsaved_vulnerability_ids = []
            finding.unsaved_vulnerability_ids.append(vulnerability["cveId"])
        self.findings.append(finding)
        finding.unsaved_endpoints = []
        if machine["computerDnsName"] is not None:
            finding.unsaved_endpoints.append(Endpoint(host=str(machine["computerDnsName"]).replace(" ", "").replace("(", "_").replace(")", "_")))
        if machine["lastIpAddress"] is not None:
            finding.unsaved_endpoints.append(Endpoint(host=str(machine["lastIpAddress"])))
        if machine["lastExternalIpAddress"] is not None:
            finding.unsaved_endpoints.append(Endpoint(host=str(machine["lastExternalIpAddress"])))

    def severity_check(self, severity_input):
        if severity_input in ["Informational", "Low", "Medium", "High", "Critical"]:
            return severity_input
        return "Informational"
