---
title: "DefectDojo API v2"
description: "DefectDojo's API lets you automate tasks, e.g. uploading scan reports in CI/CD pipelines."
draft: false
weight: 2
---

DefectDojo\'s API is created using [Django Rest
Framework](http://www.django-rest-framework.org/). The documentation of
each endpoint is available within each DefectDojo installation at
[`/api/v2/oa3/swagger-ui`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/)) and can be accessed by choosing the API v2
Docs link on the user drop down menu in the header. 

![image](../../images/api_v2_1.png)

The documentation is generated using [drf-spectacular](https://drf-spectacular.readthedocs.io/) at [`/api/v2/oa3/swagger-ui/`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/), and is
interactive. On the top of API v2 docs is a link that generates an OpenAPI v3 spec.

To interact with the documentation, a valid Authorization header value
is needed. Visit the `/api/key-v2` view to generate your
API Key (`Token <api_key>`) and copy the header value provided.

![image](../../images/api_v2_2.png)

Each section allows you to make calls to the API and view the Request
URL, Response Body, Response Code and Response Headers.

![image](../../images/api_v2_3.png)

If you're logged in to the Defect Dojo web UI, you do not need to provide the authorization token.

## Authentication

The API uses header authentication with API key. The format of the
header should be: :

    Authorization: Token <api.key>

For example: :

    Authorization: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

### Alternative authentication method

If you use [an alternative authentication method](../archived_docs/integrations/social-authentication/) for users, you may want to disable DefectDojo API tokens because it could bypass your authentication concept. \
Using of DefectDojo API tokens can be disabled by specifying the environment variable `DD_API_TOKENS_ENABLED` to `False`.
Or only `api/v2/api-token-auth/` endpoint can be disabled by setting `DD_API_TOKEN_AUTH_ENDPOINT_ENABLED` to `False`.

## Sample Code

Here are some simple python examples and their results produced against
the `/users` endpoint: :

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

This code will return the list of all the users defined in DefectDojo.
The json object result looks like : :

{{< highlight json >}}
    [
        {
          "first_name": "Tyagi",
          "id": 22,
          "last_login": "2019-06-18T08:05:51.925743",
          "last_name": "Paz",
          "username": "dev7958"
        },
        {
          "first_name": "saurabh",
          "id": 31,
          "last_login": "2019-06-06T11:44:32.533035",
          "last_name": "",
          "username": "saurabh.paz"
        }
    ]
{{< /highlight >}}

Here is another example against the `/users` endpoint, this
time we will filter the results to include only the users whose user
name includes `jay`:

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users/?username__contains=jay'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

The json object result is: :

{{< highlight json >}}
[
    {
        "first_name": "Jay",
        "id": 22,
        "last_login": "2015-10-28T08:05:51.925743",
        "last_name": "Paz",
        "username": "jay7958"
    },
    {
        "first_name": "",
        "id": 31,
        "last_login": "2015-10-13T11:44:32.533035",
        "last_name": "",
        "username": "jay.paz"
    }
]
{{< /highlight >}}

See [Django Rest Framework\'s documentation on interacting with an
API](https://www.django-rest-framework.org/) for
additional examples and tips.

## Manually calling the API

Tools like Postman can be used for testing the API.

Example for importing a scan result:

-   Verb: POST
-   URI: <http://localhost:8080/api/v2/import-scan/>
-   Headers tab:

    add the authentication header
    :   -   Key: Authorization
        -   Value: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

-   Body tab

    -   select \"form-data\", click \"bulk edit\". Example for a ZAP scan:

<!-- -->

    engagement:3
    verified:true
    active:true
    lead:1
    tags:test
    scan_type:ZAP Scan
    minimum_severity:Info
    skip_duplicates:true
    close_old_findings:false

-   Body tab

       -   Click \"Key-value\" edit
       -   Add a \"file\" parameter of type \"file\". This will trigger
            multi-part form data for sending the file content
       -   Browse for the file to upload

-   Click send

## Clients / API Wrappers

| Wrapper                      | Status                   | Notes |
| -----------------------------| ------------------------| ------------------------|
| [Specific python wrapper](https://github.com/DefectDojo/defectdojo_api)      | working (2021-01-21)    | API Wrapper including scripts for continous CI/CD uploading. Is lagging behind a bit on latest API features as we plan to revamp the API wrapper |
| [Openapi python wrapper](https://github.com/alles-klar/defectdojo-api-v2-client)       | | proof of concept only where we found out the the OpenAPI spec is not perfect yet |
| [Java library](https://github.com/secureCodeBox/defectdojo-client-java)                 | working (2021-08-30)    | Created by the kind people of [SecureCodeBox](https://github.com/secureCodeBox/secureCodeBox) |
| [Image using the Java library](https://github.com/SDA-SE/defectdojo-client) | working (2021-08-30)    | |
| [.Net/C# library](https://www.nuget.org/packages/DefectDojo.Api/)              | working (2021-06-08)    | |
| [dd-import](https://github.com/MaibornWolff/dd-import)                    | working (2021-08-24)    | dd-import is not directly an API wrapper. It offers some convenience functions to make it easier to import findings and language data from CI/CD pipelines. |

Some of the api wrappers contain quite a bit of logic to ease scanning and importing in CI/CD environments. We are in the process of simplifying this by making the DefectDojo API smarter (so api wrappers / script can be dumber).