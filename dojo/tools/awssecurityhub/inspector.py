import datetime

from dojo.models import Endpoint, Finding


class Inspector:
    def get_item(self, finding: dict, test):
        finding_id = finding.get("Id", "")
        title = finding.get("Title", "")
        severity = finding.get("Severity", {}).get("Label", "INFORMATIONAL").title()
        mitigation = ""
        impact = []
        references = []
        unsaved_vulnerability_ids = []
        epss_score = finding.get("EpssScore")
        description = f"This is an Inspector Finding\n{finding.get('Description', '')}" + "\n"
        description += f"**AWS Finding ARN:** {finding_id}\n"
        description += f"**AwsAccountId:** {finding.get('AwsAccountId', '')}\n"
        description += f"**Region:** {finding.get('Region', '')}\n"
        vulnerabilities = finding.get("Vulnerabilities", [])
        for vulnerability in vulnerabilities:
            # Save the CVE if it is present
            if cve := vulnerability.get("Id"):
                unsaved_vulnerability_ids.append(cve)
            for alias in vulnerability.get("RelatedVulnerabilities", []):
                if alias != cve:
                    unsaved_vulnerability_ids.append(alias)
            # Add information about the vulnerable packages to the description and mitigation
            vulnerable_packages = vulnerability.get("VulnerablePackages", [])
            for package in vulnerable_packages:
                mitigation += f"- Update {package.get('Name', '')}-{package.get('Version', '')}\n"
                if remediation := package.get("Remediation"):
                    mitigation += f"\t- {remediation}\n"
            if vendor := vulnerability.get("Vendor"):
                if vendor_url := vendor.get("Url"):
                    references.append(vendor_url)
            if vulnerability.get("EpssScore") is not None:
                epss_score = vulnerability.get("EpssScore")
        if finding.get("ProductFields", {}).get("aws/inspector/FindingStatus", "ACTIVE") == "ACTIVE":
            mitigated = None
            is_Mitigated = False
            active = True
        else:
            is_Mitigated = True
            active = False
            if finding.get("LastObservedAt"):
                try:
                    mitigated = datetime.datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%S.%fZ")
                except Exception:
                    mitigated = datetime.datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%fZ")
            else:
                mitigated = datetime.datetime.now(datetime.UTC)
        title_suffix = ""
        hosts = []
        for resource in finding.get("Resources", []):
            component_name = resource.get("Type")
            hosts.append(Endpoint(host=f"{component_name}_{resource.get('Id')}".replace(":", "_").replace("/", "_")))
            if component_name == "AwsEcrContainerImage":
                details = resource.get("Details", {}).get("AwsEcrContainerImage")
                arn = resource.get("Id")
                if details:
                    impact.extend((
                        f"Image ARN: {arn}",
                        f"Registry: {details.get('RegistryId')}",
                        f"Repository: {details.get('RepositoryName')}",
                        f"Image digest: {details.get('ImageDigest')}",
                        f"Image tags: {','.join(details.get('ImageTags', []))}",
                    ))
                title_suffix = f" - Image: {arn.split('/', 1)[1]}"  # repo-name/sha256:digest
            else:  # generic implementation
                resource_id = resource["Id"].split(":")[-1]
                impact.append(f"Resource: {resource_id}")
                title_suffix = f" - Resource: {resource_id}"
        if remediation_rec_url := finding.get("Remediation", {}).get("Recommendation", {}).get("Url"):
            references.append(remediation_rec_url)
        false_p = False
        result = Finding(
            title=f"{title}{title_suffix}",
            test=test,
            description=description,
            mitigation=mitigation,
            references="\n".join(references),
            severity=severity,
            impact="\n".join(impact),
            active=active,
            verified=False,
            false_p=false_p,
            unique_id_from_tool=finding_id,
            mitigated=mitigated,
            is_mitigated=is_Mitigated,
            static_finding=True,
            dynamic_finding=False,
            component_name=component_name,
        )
        result.unsaved_endpoints = []
        result.unsaved_endpoints.extend(hosts)
        if epss_score is not None:
            result.epss_score = epss_score
        # Add the unsaved vulnerability ids
        result.unsaved_vulnerability_ids = unsaved_vulnerability_ids
        return result
