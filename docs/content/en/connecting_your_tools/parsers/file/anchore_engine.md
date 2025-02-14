---
title: "Anchore-Engine"
toc_hide: true
---

### File Types
DefectDojo parser accepts a .json file.

Using the [Anchore CLI](https://docs.anchore.com/current/docs/using/cli_usage/images/inspecting_image_content/) is the most reliable way to generate an Anchore report which DefectDojo can parse. When generating a report with the Anchore CLI, please use the following command to ensure complete data: `anchore-cli --json image vuln <image:tag> all`

### Acceptable JSON Format
All properties are strings and are required by the parser.

~~~

{
    "metadata":{
        "registry":"docker.io",
        "repository":"myimage",
        "tag":"new",
        "imageDigest":
        "sha256:100ec0d69914788c491567bccaea0ab9aa50f0ddd00584db7afb264718c010d6",
        "timestamp":"2025-01-13T10:09:59.971Z"
        },
    "securityEvaluation":[
        {
            "vulnerabilityId":"CVE-2024-50379",
            "cves":"CVE-2024-50379",
            "severity":"Critical",
            "detectedAt":"2025-01-10T15:09:00Z",
            "packageType":"Java",
            "path":"/aci/base/lib/tomcat-annotations-api-9.0.97.jar",
            "package":"tomcat-annotations-api-9.0.97",
            "fixAvailable":"10.1.34,11.0.2,9.0.98",
            "fixObservedAt":"2025-01-10T15:09:00Z",
            "link":"https://nvd.nist.gov/vuln/detail/CVE-2024-50379",
            "nvdCvssBaseScore":9.8
        },
        {
            "vulnerabilityId":"CVE-2024-56337",
            ...
            ...
            "nvdCvssBaseScore":9.8}
        ...
    ]
}
~~~

### Sample Scan Data
Sample Anchore-Engine scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/anchore_engine).