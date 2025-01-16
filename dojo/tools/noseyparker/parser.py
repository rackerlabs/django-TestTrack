import hashlib
import json
from datetime import datetime

from dojo.models import Finding


class NoseyParkerParser:

    """Scanning secrets from repos"""

    def get_scan_types(self):
        return ["Nosey Parker Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Nosey Parker Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Nosey Parker report file can be imported in JSON Lines format (option --jsonl). " \
               "Supports v0.16.0 and v0.22.0 of https://github.com/praetorian-inc/noseyparker"

    def get_findings(self, file, test):
        """
        Returns findings from jsonlines file and uses filter
        to skip findings and determine severity
        """
        self.dupes = {}
        # Turn JSONL file into DataFrame
        if file is None:
            return None
        if file.name.lower().endswith(".jsonl"):
            # Process JSON lines into Dict
            data = [json.loads(line) for line in file]
            # Check for empty file
            if len(data[0]) == 0:
                return []
            # Parse through each secret in each JSON line
            for line in data:
                # Set rule to the current secret type (e.g. AWS S3 Bucket)
                if line.get("rule_name") is not None and line.get("match_content") is not None:
                    self.version_0_16_0(line, test)
                elif line.get("rule_name") is not None and line.get("finding_id") is not None:
                    self.version_0_22_0(line, test)
                else:
                    msg = "Invalid Nosey Parker data, make sure to use Nosey Parker v0.16.0"
                    raise ValueError(msg)
        else:
            msg = "JSON lines format not recognized (.jsonl file extension). Make sure to use Nosey Parker v0.16.0"
            raise ValueError(msg)

        return list(self.dupes.values())

    def version_0_16_0(self, line, test):
        rule_name = line["rule_name"]
        secret = line["match_content"]
        for match in line["matches"]:
            # The following path is to account for the variability in the JSON lines output
            num_elements = len(match["provenance"]) - 1
            json_path = match["provenance"][num_elements]

            title = f"Secret(s) Found in Repository with Commit ID {json_path['commit_provenance']['commit_metadata']['commit_id']}"
            filepath = json_path["commit_provenance"]["blob_path"]
            line_num = match["location"]["source_span"]["start"]["line"]
            description = f"Secret found of type:   {rule_name} \n" \
                            f"SECRET starts with:  '{secret[:3]}' \n" \
                            f"Committer Name: {json_path['commit_provenance']['commit_metadata']['committer_name']}  \n" \
                            f"Committer Email: {json_path['commit_provenance']['commit_metadata']['committer_email']} \n" \
                            f"Commit ID: {json_path['commit_provenance']['commit_metadata']['commit_id']}  \n" \
                            f"Location: {filepath} line #{line_num} \n" \
                            f"Line #{line_num} \n"

            # Internal de-duplication
            key = hashlib.md5((filepath + "|" + secret + "|" + str(line_num)).encode("utf-8")).hexdigest()

            # If secret already exists with the same filepath/secret/linenum
            if key in self.dupes:
                finding = self.dupes[key]
                finding.nb_occurences += 1
                self.dupes[key] = finding
            else:
                self.dupes[key] = True
                # Create Finding object
                finding = Finding(
                    test=test,
                    cwe=798,
                    title=title,
                    description=description,
                    severity="High",
                    mitigation="Reset the account/token and remove from source code. Store secrets/tokens/passwords in secret managers or secure vaults.",
                    date=datetime.today().strftime("%Y-%m-%d"),
                    verified=False,
                    active=True,
                    is_mitigated=False,
                    file_path=filepath,
                    line=line_num,
                    static_finding=True,
                    nb_occurences=1,
                    dynamic_finding=False,

                )
                self.dupes[key] = finding

    def version_0_22_0(self, line, test):
        rule_name = line["rule_name"]
        rule_text_id = line["rule_text_id"]
        for match in line["matches"]:
            # The following path is to account for the variability in the JSON lines output
            num_elements = len(match["provenance"]) - 1
            json_path = match["provenance"][num_elements]

            title = f"Secret(s) Found in Repository with Commit ID {json_path['first_commit']['commit_metadata']['commit_id']}"
            filepath = json_path["first_commit"]["blob_path"]
            line_num = match["location"]["source_span"]["start"]["line"]
            description = f"Secret found of type:   {rule_name} \n" \
                            f"SECRET starts with:  '{rule_text_id[:3]}' \n" \
                            f"Committer Name: {json_path['first_commit']['commit_metadata']['committer_name']}  \n" \
                            f"Committer Email: {json_path['first_commit']['commit_metadata']['committer_email']} \n" \
                            f"Commit ID: {json_path['first_commit']['commit_metadata']['commit_id']}  \n" \
                            f"Location: {filepath} line #{line_num} \n" \
                            f"Line #{line_num} \n"

            # Internal de-duplication
            key = hashlib.md5((filepath + "|" + rule_text_id + "|" + str(line_num)).encode("utf-8")).hexdigest()

            # If secret already exists with the same filepath/secret/linenum
            if key in self.dupes:
                finding = self.dupes[key]
                finding.nb_occurences += 1
                self.dupes[key] = finding
            else:
                self.dupes[key] = True
                # Create Finding object
                finding = Finding(
                    test=test,
                    cwe=798,
                    title=title,
                    description=description,
                    severity="High",
                    mitigation="Reset the account/token and remove from source code. Store secrets/tokens/passwords in secret managers or secure vaults.",
                    date=datetime.today().strftime("%Y-%m-%d"),
                    verified=False,
                    active=True,
                    is_mitigated=False,
                    file_path=filepath,
                    line=line_num,
                    static_finding=True,
                    nb_occurences=1,
                    dynamic_finding=False,
                )
                self.dupes[key] = finding
