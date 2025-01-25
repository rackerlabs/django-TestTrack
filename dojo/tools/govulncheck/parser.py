import json
import logging
from itertools import groupby, islice

from dojo.models import Finding

logger = logging.getLogger(__name__)

SEVERITY = "Info"


class GovulncheckParser:
    def get_scan_types(self):
        return ["Govulncheck Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Govulncheck Scanner findings in JSON format."

    @staticmethod
    def get_location(data, node):
        while (
            data["Calls"]["Functions"][str(node)]["CallSites"][0]["Parent"]
            != 1
        ):
            node = data["Calls"]["Functions"][str(node)]["CallSites"][0][
                "Parent"
            ]
        return [
            f"{x['Pos']['Filename']}:{x['Pos']['Line']}:{x['Pos']['Column']}"
            for x in data["Calls"]["Functions"][str(node)]["CallSites"]
        ]

    @staticmethod
    def get_version(data, node):
        return data["Requires"]["Modules"][str(node)]["Version"]

    def get_finding_trace_info(self, data, osv_id):
        # Browse the findings to look for matching OSV-id. If the OSV-id is matching, extract traces.
        trace_info_strs = []
        for elem in data:
            if "finding" in elem:
                finding = elem["finding"]
                if finding.get("osv") == osv_id:
                    trace_info = finding.get("trace", [])
                    for trace in trace_info:
                        module = trace.get("module", "Unknown module")
                        version = trace.get("version", "Unknown version")
                        package = trace.get("module", "Unknown package")
                        function = trace.get("function", "Unknown function")
                        filename = filename = trace.get("position", {}).get("filename", "Unknown filename")
                        line = trace.get("position", {}).get("line", "Unknown line")
                        trace_info_str = f"\tModule: {module}, Version: {version}, Package: {package}, Function: {function}, File: {filename}, Line: {line}"
                        trace_info_strs.append(trace_info_str)
        return "\n".join(trace_info_strs)

    def get_affected_version(self, data, osv_id):
        # Browse the findings to look for matching OSV-id. If the OSV-id is matching, extract the first affected version.
        for elem in data:
            if "finding" in elem:
                finding = elem["finding"]
                if finding.get("osv") == osv_id:
                    trace_info = finding.get("trace", [])
                    for trace in trace_info:
                        if "version" in trace:
                            return trace.get("version")
        return ""

    def get_findings(self, scan_file, test):
        findings = []
        try:
            data = json.load(scan_file)
        except Exception:
            msg = "Invalid JSON format"
            raise ValueError(msg)
        else:
            if isinstance(data, dict):
                if data["Vulns"]:
                    # Parsing for old govulncheck output format
                    list_vulns = data["Vulns"]
                    for cve, elems in groupby(
                        list_vulns, key=lambda vuln: vuln["OSV"]["aliases"][0],
                    ):
                        first_elem = list(islice(elems, 1))
                        d = {
                            "cve": cve,
                            "severity": SEVERITY,
                            "title": first_elem[0]["OSV"]["id"],
                            "component_name": first_elem[0]["OSV"]["affected"][0][
                                "package"
                            ]["name"],
                            "component_version": self.get_version(
                                data, first_elem[0]["RequireSink"],
                            ),
                        }
                        d["references"] = first_elem[0]["OSV"]["references"][0][
                            "url"
                        ]
                        d["url"] = first_elem[0]["OSV"]["affected"][0][
                            "database_specific"
                        ]["url"]
                        d["unique_id_from_tool"] = first_elem[0]["OSV"]["id"]
                        vuln_methods = set(
                            first_elem[0]["OSV"]["affected"][0][
                                "ecosystem_specific"
                            ]["imports"][0]["symbols"],
                        )
                        impact = set(
                            self.get_location(data, first_elem[0]["CallSink"]),
                        )
                        for elem in elems:
                            impact.update(
                                self.get_location(data, elem["CallSink"]),
                            )
                            vuln_methods.update(
                                elem["OSV"]["affected"][0]["ecosystem_specific"][
                                    "imports"
                                ][0]["symbols"],
                            )
                        d["impact"] = "; ".join(impact) if impact else None
                        d[
                            "description"
                        ] = f"Vulnerable functions: {'; '.join(vuln_methods)}"
                        findings.append(Finding(**d))
            elif isinstance(data, list):
                # Parsing for new govulncheck output format
                for elem in data:
                    if "osv" in elem:
                        cve = elem["osv"]["aliases"][0]
                        osv_data = elem["osv"]
                        affected_package = osv_data["affected"][0]["package"]
                        affected_ranges = osv_data["affected"][0]["ranges"]
                        affected_ecosystem = affected_package.get("ecosystem", "Unknown")
                        impact = osv_data.get("details", "Unknown")
                        formatted_ranges = []
                        summary = osv_data.get("summary", "Unknown")
                        component_name = affected_package["name"]
                        osv_id = osv_data["id"]

                        for r in affected_ranges:
                            events = r["events"]
                            event_pairs = []
                            for i in range(0, len(events), 2):
                                # Events come in pairs: introduced, then fixed
                                introduced = events[i].get("introduced", "Unknown")
                                fixed = events[i + 1].get("fixed", "Unknown") if i + 1 < len(events) else "Unknown"
                                event_pairs.append(f"\n\t\tIntroduced in {introduced}, fixed in {fixed}")
                            formatted_ranges.append(f"type {r['type']}: {'. '.join(event_pairs)}")
                        range_info = "\n ".join(formatted_ranges)

                        vuln_functions = ", ".join(
                            set(osv_data["affected"][0]["ecosystem_specific"]["imports"][0].get("symbols", [])),
                        )

                        description = (
                            f"**Summary:** {summary}\n"
                            f"**Vulnerable functions:** {vuln_functions}\n"
                            f"**Affected Ecosystem:** {affected_ecosystem}\n"
                            f"**Affected Versions:** {range_info}\n"
                            f"**Vulnerable Package:** {affected_package['name']}\n"
                            f"**Traces found :**\n{self.get_finding_trace_info(data, osv_data['id'])}"
                        )

                        references = [f"{ref['type']}: {ref['url']}" for ref in osv_data["references"]]
                        db_specific_url = osv_data["database_specific"].get("url", "Unknown")
                        if db_specific_url:
                            references.append(f"Database: {db_specific_url}")
                        references = "\n".join(references)

                        ecosystem_specific = osv_data["affected"][0].get("ecosystem_specific", {})
                        imports = ecosystem_specific.get("imports", [{}])
                        path = imports[0].get("path", "") if imports else ""
                        if path:
                            title = f"{osv_data['id']} - {affected_package['name']} - {path}"
                        else:
                            title = f"{osv_data['id']} - {affected_package['name']}"

                        affected_version = self.get_affected_version(data, osv_data["id"])

                        severity = elem["osv"].get("severity", SEVERITY)

                        d = {
                            "cve": cve,
                            "severity": severity,
                            "title": title,
                            "component_name": component_name,
                            "component_version": affected_version,
                            "description": description,
                            "impact": impact,
                            "references": references,
                            "file_path": path,
                            "url": db_specific_url,
                            "unique_id_from_tool": osv_id,
                        }

                        findings.append(Finding(**d))
            return findings
