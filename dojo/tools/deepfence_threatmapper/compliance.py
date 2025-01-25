from dojo.models import Finding


class DeepfenceThreatmapperCompliance:
    def get_findings(self, row, headers, test):
        description = ""
        compliance_check_type = row[headers["compliance_check_type"]]
        count = row[headers["count"]]
        doc_id = row[headers["doc_id"]]
        host_name = row[headers["host_name"]]
        cloud_account_id = row[headers["cloud_account_id"]]
        masked = row[headers["masked"]]
        node_id = row[headers["node_id"]]
        node_name = row[headers["node_name"]]
        node_type = row[headers["node_type"]]
        status = row[headers["status"]]
        test_category = row[headers["test_category"]]
        test_desc = row[headers["test_desc"]]
        test_info = row[headers["test_info"]]
        test_number = row[headers["test_number"]]
        description += "**compliance_check_type:** " + str(compliance_check_type) + "\n"
        description += "**host_name:** " + str(host_name) + "\n"
        description += "**cloud_account_id:** " + str(cloud_account_id) + "\n"
        description += "**masked:** " + str(masked) + "\n"
        description += "**node_id:** " + str(node_id) + "\n"
        description += "**node_name:** " + str(node_name) + "\n"
        description += "**node_type:** " + str(node_type) + "\n"
        description += "**status:** " + str(status) + "\n"
        description += "**test_category:** " + str(test_category) + "\n"
        description += "**test_desc:** " + str(test_desc) + "\n"
        description += "**test_info:** " + str(test_info) + "\n"
        description += "**test_number:** " + str(test_number) + "\n"
        description += "**count:** " + str(count) + "\n"
        description += "**doc_id:** " + str(doc_id) + "\n"
        return Finding(
            title="Threatmapper_Compliance_Report-" + test_number,
            description=description,
            severity=self.compliance_severity(status),
            static_finding=False,
            dynamic_finding=True,
            test=test,
        )

    def compliance_severity(self, severity_input):
        if severity_input == "pass" or severity_input == "info":
            output = "Info"
        elif severity_input == "warn":
            output = "Medium"
        else:
            output = "Info"
        return output
