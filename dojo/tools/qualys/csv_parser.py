import csv
import io
import logging
import re
from datetime import datetime

from dateutil import parser
from django.conf import settings

from dojo.models import Endpoint, Finding

_logger = logging.getLogger(__name__)


def parse_csv(csv_file) -> [Finding]:
    """
    Parses Qualys Report in CSV format
    Args:
        csv_file:
    Returns:
    """
    content = csv_file.read()
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    csv_reader = csv.DictReader(
        io.StringIO(content), delimiter=",", quotechar='"',
    )

    report_findings = get_report_findings(csv_reader)
    return build_findings_from_dict(report_findings)


def get_report_findings(csv_reader) -> [dict]:
    """
    Filters out the unneeded information at the beginning of the Qualys CSV report.

    Args:
        csv_reader:

    """
    report_findings = []

    for row in csv_reader:
        if (row.get("Title") and row["Title"] != "Title") or row.get("VULN TITLE"):
            report_findings.append(row)
    return report_findings


def _extract_cvss_vectors(cvss_base, cvss_temporal):
    """
    Parses the CVSS3 Vectors from the CVSS3 Base and CVSS3 Temporal fields and returns as a single string.

    This is done because the raw values come with additional characters that cannot be parsed with the cvss library.
        Example: 6.7 (AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)

    Args:
        cvss_base:
        cvss_temporal:
    Returns:
        A CVSS3 Vector including both Base and Temporal if available

    """
    vector_pattern = r"^\d{1,2}.\d \((.*)\)"
    cvss_vector = "CVSS:3.0/"

    if cvss_base:
        try:
            cvss_vector += re.search(vector_pattern, cvss_base).group(1)
        except IndexError:
            _logger.error(f"CVSS3 Base Vector not found in {cvss_base}")
        except AttributeError:
            _logger.error(f"CVSS3 Base Vector not found in {cvss_base}")
        if cvss_temporal:
            try:
                cvss_temporal_vector = re.search(
                    vector_pattern, cvss_temporal,
                ).group(1)
                cvss_vector += "/"
                cvss_vector += cvss_temporal_vector
            except IndexError:
                _logger.error(
                    f"CVSS3 Temporal Vector not found in {cvss_base}",
                )
            except AttributeError:
                _logger.error(
                    f"CVSS3 Temporal Vector not found in {cvss_base}",
                )

        return cvss_vector
    return None


def _clean_cve_data(cve_string: str) -> list:
    # Determine if a CVE was even provided
    if len(cve_string) == 0:
        return []
    # Determine if there is more than one CVE
    cve_list = []
    if "," in cve_string:
        # Split everything up
        cve_list = [single_cve.strip() for single_cve in cve_string.split(",")]
    else:
        # There is just one CVE here, but we must return a list
        cve_list = [cve_string.strip()]

    return cve_list


def get_severity(value: str) -> str:
    legacy_severity_lookup = {
        "1": "Info",
        "2": "Low",
        "3": "Medium",
        "4": "High",
        "5": "Critical",
    }
    # Severity mapping taken from
    # https://qualysguard.qg2.apps.qualys.com/portal-help/en/malware/knowledgebase/severity_levels.htm
    qualys_severity_lookup = {
        "1": "Low",
        "2": "Low",
        "3": "Medium",
        "4": "High",
        "5": "High",
    }

    if settings.USE_QUALYS_LEGACY_SEVERITY_PARSING:
        return legacy_severity_lookup.get(value, "Info")
    return qualys_severity_lookup.get(value, "Info")


def build_findings_from_dict(report_findings: [dict]) -> [Finding]:
    """
    Takes a list of Dictionaries built from CSV and creates a Finding object
    Args:
        report_findings:
    Returns:

    """
    dojo_findings = []
    for report_finding in report_findings:
        # Get endpoint meta
        if report_finding.get("FQDN"):
            endpoint = Endpoint.from_uri(report_finding.get("FQDN"))
        elif report_finding.get("DNS"):
            endpoint = Endpoint(host=report_finding.get("DNS"))
        else:
            endpoint = Endpoint(host=report_finding["IP"])

        # Get CVE meta
        cve_data = report_finding.get("CVE ID", report_finding.get("CVEID", ""))
        # Clean up the CVE data appropriately
        cve_list = _clean_cve_data(cve_data)

        if "CVSS3 Base" in report_finding:
            cvssv3 = _extract_cvss_vectors(
                        report_finding["CVSS3 Base"], report_finding["CVSS3 Temporal"],
                    )
        elif "CVSS3.1 Base" in report_finding:
            cvssv3 = _extract_cvss_vectors(
                        report_finding["CVSS3.1 Base"], report_finding["CVSS3.1 Temporal"],
                    )
        # Get the date based on the first_seen setting
        try:
            if settings.USE_FIRST_SEEN:
                if date := report_finding.get("First Detected"):
                    date = datetime.strptime(date, "%m/%d/%Y %H:%M:%S").date()
            else:
                if date := report_finding.get("Last Detected"):
                    date = datetime.strptime(date, "%m/%d/%Y %H:%M:%S").date()
        except Exception:
            date = None

        finding_with_id = next((obj for obj in dojo_findings if obj.vuln_id_from_tool == report_finding["QID"]), None)
        if finding_with_id:
            finding = finding_with_id
        else:
            if report_finding.get("Title"):
                finding = Finding(
                    title=f"QID-{report_finding['QID']} | {report_finding['Title']}",
                    mitigation=report_finding["Solution"],
                    description=f"{report_finding['Threat']}\nResult Evidence: \n{report_finding.get('Threat', 'Not available')}",
                    severity=get_severity(report_finding["Severity"]),
                    impact=report_finding["Impact"],
                    date=date,
                    vuln_id_from_tool=report_finding["QID"],
                    cvssv3=cvssv3,
                )
                # Qualys reports regression findings as active, but with a Date Last
                # Fixed.
                if report_finding["Date Last Fixed"]:
                    finding.mitigated = datetime.strptime(
                        report_finding["Date Last Fixed"], "%m/%d/%Y %H:%M:%S",
                    )
                    finding.is_mitigated = True
                else:
                    finding.is_mitigated = False

                finding.active = report_finding["Vuln Status"] in (
                    "Active",
                    "Re-Opened",
                    "New",
                )

                if finding.active:
                    finding.mitigated = None
                    finding.is_mitigated = False
            elif report_finding.get("VULN TITLE"):
                # Get the date based on the first_seen setting
                try:
                    if settings.USE_FIRST_SEEN:
                        if date := report_finding.get("LAST SCAN"):
                            date = parser.parse(date.replace("Z", ""))
                    else:
                        if date := report_finding.get("LAST SCAN"):
                            date = parser.parse(date.replace("Z", ""))
                except Exception:
                    date = None

                finding = Finding(
                    title=f"QID-{report_finding['QID']} | {report_finding['VULN TITLE']}",
                    mitigation=report_finding["SOLUTION"],
                    description=f"{report_finding['THREAT']}\nResult Evidence: \n{report_finding.get('THREAT', 'Not available')}",
                    severity=report_finding["SEVERITY"],
                    impact=report_finding["IMPACT"],
                    date=date,
                    vuln_id_from_tool=report_finding["QID"],
                )
        # Make sure we have something to append to
        if isinstance(finding.unsaved_vulnerability_ids, list):
            # Append CVEs if there is a chance for duplicates
            finding.unsaved_vulnerability_ids += cve_list
        else:
            # Set the initial cve list for new findings
            finding.unsaved_vulnerability_ids = cve_list
        finding.verified = True
        finding.unsaved_endpoints.append(endpoint)
        if not finding_with_id:
            dojo_findings.append(finding)
    return dojo_findings
