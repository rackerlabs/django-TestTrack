from dojo.models import Finding


class DeepfenceThreatmapperSecret:
    def get_findings(self, row, headers, test):
        description = ""
        Filename = row[headers["Filename"]]
        Content = row[headers["Content"]]
        Name = row[headers["Name"]]
        Rule = row[headers["Rule"]]
        Severity = row[headers["Severity"]]
        Node_Name = row[headers["Node Name"]]
        Container_Name = row[headers["Container Name"]]
        Kubernetes_Cluster_Name = row[headers["Kubernetes Cluster Name"]]
        Signature = row[headers["Signature"]]
        description += "**Filename:** " + str(Filename) + "\n"
        description += "**Name:** " + str(Name) + "\n"
        description += "**Rule:** " + str(Rule) + "\n"
        description += "**Node Name:** " + str(Node_Name) + "\n"
        description += "**Container Name:** " + str(Container_Name) + "\n"
        description += "**Kubernetes Cluster Name:** " + str(Kubernetes_Cluster_Name) + "\n"
        description += "**Content:** " + str(Content) + "\n"
        description += "**Signature:** " + str(Signature) + "\n"
        if Name is not None and Severity is not None:
            finding = Finding(
                    title=str(Name),
                    description=description,
                    file_path=Filename,
                    severity=self.severity(Severity),
                    static_finding=False,
                    dynamic_finding=True,
                    test=test,
            )
        else:
            finding = None
        return finding

    def severity(self, severity_input):
        if severity_input is None:
            return "Info"
        return severity_input.capitalize()
