import hashlib
import json

from dojo.models import Finding
from dojo.utils import first_elem


class TruffleHogParser:
    def get_scan_types(self):
        return ["Trufflehog Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Trufflehog Scan"

    def get_description_for_scan_types(self, scan_type):
        return "JSON Output of Trufflehog. Supports version 2 and 3 of https://github.com/trufflesecurity/trufflehog"

    def get_findings(self, filename, test):
        data = filename.read()
        dict_strs = data.splitlines()
        if len(dict_strs) == 0:
            return []
        try:
            json_data = json.loads(str(dict_strs[0], "utf-8"))
        except Exception:
            json_data = json.loads(dict_strs[0])

        if "SourceMetadata" in json_data:
            return self.get_findings_v3(dict_strs, test)
        if "path" in json_data:
            return self.get_findings_v2(dict_strs, test)
        return []

    def get_findings_v2(self, data, test):
        dupes = {}
        for line in data:
            try:
                json_data = json.loads(str(line, "utf-8"))
            except Exception:
                json_data = json.loads(line)

            file = json_data.get("path")
            reason = json_data.get("reason")
            titleText = f"Hard Coded {reason} in: {file}"
            commit = json_data.get("commit")
            description = "**Commit:** " + str(commit).split("\n")[0] + "\n"
            description += (
                "```\n" + str(commit).replace("```", "\\`\\`\\`") + "\n```\n"
            )
            description += (
                "**Commit Hash:** " + json_data.get("commitHash") + "\n"
            )
            description += "**Commit Date:** " + json_data.get("date") + "\n"
            description += "**Branch:** " + json_data.get("branch") + "\n"
            description += "**Reason:** " + json_data.get("reason") + "\n"
            description += f"**Path:** {file}" + "\n"

            severity = "High"
            if reason == "High Entropy":
                severity = "Info"
            elif "Oauth" in reason or "AWS" in reason or "Heroku" in reason:
                severity = "Critical"
            elif reason == "Generic Secret":
                severity = "Medium"

            strings_found = "".join(
                string + "\n" for string in json_data.get("stringsFound")
            )
            dupe_key = hashlib.md5((file + reason).encode("utf-8")).hexdigest()
            description += (
                "\n**Strings Found:**\n```" + strings_found + "```\n"
            )

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                finding.description += description
                finding.nb_occurences += 1
                dupes[dupe_key] = finding
            else:
                dupes[dupe_key] = True

                finding = Finding(
                    title=titleText,
                    test=test,
                    cwe=798,
                    description=description,
                    severity=severity,
                    mitigation="Secrets and passwords should be stored in a secure vault and/or secure storage.",
                    impact="This weakness can lead to the exposure of resources or functionality to unintended actors, possibly providing attackers with sensitive information or even execute arbitrary code.",
                    references="N/A",
                    file_path=file,
                    line=0,  # setting it to a fake value to activate deduplication
                    url="N/A",
                    dynamic_finding=False,
                    static_finding=True,
                    nb_occurences=1,
                )

                dupes[dupe_key] = finding

        return list(dupes.values())

    def get_findings_v3(self, data, test):
        dupes = {}
        for line in data:
            try:
                json_data = json.loads(str(line, "utf-8"))
            except Exception:
                json_data = json.loads(line)

            metadata = json_data.get("SourceMetadata", {}).get("Data", {})
            # Get the source of the data
            source = {}
            source_data = {}
            if metadata:
                source = first_elem(metadata.keys())
                source_data = metadata.get(source)

            file = source_data.get("file", "")
            email = source_data.get("email", "")
            commit = source_data.get("commit", "")
            detector_name = json_data.get("DetectorName", "")
            date = source_data.get("timestamp", "")
            line_number = source_data.get("line", 0)
            repository = source_data.get("repository", "")
            link = source_data.get("link", "")
            redacted_info = json_data.get("Redacted", "")
            structured_data = json_data.get("StructuredData", {})
            extra_data = json_data.get("ExtraData", {})
            verified = json_data.get("Verified", "")
            raw = json_data.get("Raw", "")
            rawV2 = json_data.get("RawV2", "")

            titleText = f"Hard Coded {detector_name} secret in: {file}"

            mitigation = "Secrets and passwords should be stored in a secure vault and/or secure storage."
            if link:
                mitigation = f"{mitigation}\nSee the commit here: {link}"

            description = f"**Repository:** {repository}\n"
            description += f"**Link:** {link}\n"
            description += f"**Commit Hash:** {commit}\n"
            description += f"**Commit Date:** {date}\n"
            description += f"**Committer:** {email}\n"
            description += f"**Reason:** {detector_name}\n"
            description += f"**Path:** {file}\n"
            description += f"**Contents:** {redacted_info}\n"

            if structured_data:
                description += f"**Structured Data:**\n{self.walk_dict(structured_data)}\n"

            if extra_data:
                description += (
                    f"**Extra Data:**\n{self.walk_dict(extra_data)}\n"
                )

            severity = "Critical"
            if not verified:
                if (
                    "Oauth" in detector_name
                    or "AWS" in detector_name
                    or "Heroku" in detector_name
                ):
                    severity = "Critical"
                elif detector_name == "PrivateKey":
                    severity = "High"
                elif detector_name == "Generic Secret":
                    severity = "Medium"

            dupe_key = hashlib.md5(
                (file + detector_name + str(line_number) + commit + (raw + rawV2)).encode("utf-8"),
            ).hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                finding.description += description
                finding.nb_occurences += 1
                dupes[dupe_key] = finding
            else:
                dupes[dupe_key] = True

                finding = Finding(
                    title=titleText,
                    test=test,
                    cwe=798,
                    description=description,
                    severity=severity,
                    mitigation=mitigation,
                    impact="This weakness can lead to the exposure of resources or functionality to unintended actors, possibly providing attackers with sensitive information or even execute arbitrary code.",
                    references="N/A",
                    file_path=file,
                    line=line_number,  # setting it to a fake value to activate deduplication
                    url="N/A",
                    dynamic_finding=False,
                    static_finding=True,
                    nb_occurences=1,
                )
                dupes[dupe_key] = finding

        return list(dupes.values())

    def walk_dict(self, obj, tab_count=1):
        return_string = ""
        if obj:
            tab_string = tab_count * "\t"
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if isinstance(value, dict):
                        return_string += self.walk_dict(
                            value, tab_count=(tab_count + 1),
                        )
                        continue
                    return_string += f"{tab_string}{key}: {value}\n"
        return return_string
