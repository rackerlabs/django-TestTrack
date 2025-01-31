from urllib.parse import urlencode

import requests
from django.conf import settings


class BugcrowdAPI:

    """A simple client for the bugcrowd.io API"""

    bugcrowd_api_url = "https://api.bugcrowd.com"
    default_headers = {
        "Accept": "application/vnd.bugcrowd+json",
        "User-Agent": "DefectDojo",
        "Bugcrowd-Version": "2021-10-28",
    }

    def __init__(self, tool_config):
        self.session = requests.Session()
        if tool_config.authentication_type == "API":
            self.api_token = tool_config.api_key
            self.session.headers.update(
                {"Authorization": f"Token {self.api_token}"},
            )
            self.session.headers.update(self.default_headers)
        else:
            msg = f"bugcrowd Authentication type {tool_config.authentication_type} not supported"
            raise Exception(msg)

    def get_findings(self, program, target):
        """
        Returns the findings in a paginated iterator for a given bugcrowd program and target, if target is *,
        everything is returned
        :param program:
        :param target:
        :return:
        """
        params_default = {
            "filter[duplicate]": "false",
            "filter[program]": program,
            "page[limit]": 100,
            "page[offset]": 0,
            "include": "monetary_rewards,target,program,external_issues",
            "sort": "submitted-desc",
        }

        if target:
            params = params_default
            params["filter[target]"] = target
            params_encoded = urlencode(params)
        else:
            params_encoded = urlencode(params_default)

        next_page = f"{self.bugcrowd_api_url}/submissions?{params_encoded}"
        while next_page != "":
            response = self.session.get(
                url=next_page,
                timeout=settings.REQUESTS_TIMEOUT,
            )
            response.raise_for_status()
            if response.ok:
                data = response.json()
                if len(data["data"]) != 0:
                    yield data["data"]

                # When we hit the end of the submissions, break out
                if len(data["data"]) == 0:
                    next_page = ""
                    break

                # Otherwise, keep updating next link
                next_page = "{}{}".format(
                    self.bugcrowd_api_url, data["links"]["next"],
                )
            else:
                next_page = "over"

    def test_connection(self):
        # Request programs
        response_programs = self.session.get(
            url=f"{self.bugcrowd_api_url}/programs",
            timeout=settings.REQUESTS_TIMEOUT,
        )
        response_programs.raise_for_status()

        # Request submissions to validate the org token
        response_subs = self.session.get(
            url=f"{self.bugcrowd_api_url}/submissions",
            timeout=settings.REQUESTS_TIMEOUT,
        )
        response_subs.raise_for_status()
        if response_programs.ok and response_subs.ok:
            data = response_programs.json().get("data")
            data_subs = response_subs.json().get("meta")
            total_subs = str(data_subs["total_hits"])

            progs = list(filter(lambda prog: prog["type"] == "program", data))
            program_names = ", ".join(
                [p["attributes"]["code"] for p in progs],
            )
            # Request targets to validate the org token
            response_targets = self.session.get(
                url=f"{self.bugcrowd_api_url}/targets",
                timeout=settings.REQUESTS_TIMEOUT,
            )
            response_targets.raise_for_status()
            if response_targets.ok:
                data_targets = response_targets.json().get("data")
                targets = list(
                    filter(lambda prog: prog["type"] == "target", data_targets),
                )
                target_names = ", ".join(
                    [p["attributes"]["name"] for p in targets],
                )
                return (
                    f'With {total_subs} submissions, you have access to the "{program_names}" '
                    f"programs, "
                    f"you can use these as Service key 1 for filtering submissions "
                    f'You also have targets "{target_names}" that can be used in Service key 2'
                )
            msg = (
                "Bugcrowd API test not successful, no targets were defined in Bugcrowd which is used for "
                f"filtering, check your configuration, HTTP response was: {response_targets.text}"
            )
            raise Exception(msg)
        msg = (
            "Bugcrowd API test not successful, could not retrieve the programs or submissions, check your "
            f"configuration, HTTP response for programs was: {response_programs.text}, HTTP response for submissions was: {response_subs.text}"
        )
        raise Exception(msg)

    def test_product_connection(self, api_scan_configuration):
        submissions = []
        submission_gen = self.get_findings(
            api_scan_configuration.service_key_1,
            api_scan_configuration.service_key_2,
        )
        for page in submission_gen:
            submissions = submissions + page
        submission_number = len(submissions)
        return (
            f'You have access to "{submission_number}" submissions (no duplicates)'
            f'in Bugcrowd in the Program code "{api_scan_configuration.service_key_1}"'
            f'and Target "{api_scan_configuration.service_key_2}" '
            f"(leave service key 2 empty to get all submissions in "
            f"program)"
        )
