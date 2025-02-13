---
title: "Contribute to Parsers"
description: "How to contribute to parsers"
draft: false
weight: 1
---

All commands assume that you're located at the root of the django-DefectDojo cloned repo.

## Pre-requisites

- You have forked https://github.com/DefectDojo/django-DefectDojo and cloned locally.
- Checkout `dev` and make sure you're up to date with the latest changes.
- It's advised that you create a dedicated branch for your development, such as `git checkout -b parser-name`.

It is easiest to use the docker compose deployment as it has hot-reload capbility for uWSGI.
Set up your environment to use the dev environment:

`$ docker/setEnv.sh dev`

Please have a look at [DOCKER.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) for more details.

### Docker images

You will want to build your docker images locally, and eventually pass in your local user's `uid` to be able to write to the image (handy for database migration files). Assuming your user's `uid` is `1000`, then:

{{< highlight bash >}}
$ docker compose build --build-arg uid=1000
{{< /highlight >}}

## Which files do you need to modify?

| File                                          | Purpose
|-------                                        |--------
|`dojo/tools/<parser_dir>/__init__.py`          | Empty file for class initialization
|`dojo/tools/<parser_dir>/parser.py`            | The meat. This is where you write your actual parser. The class name must be the Python module name without underscores plus `Parser`. **Example:** When the name of the Python module is `dependency_check`, the class name shall be `DependencyCheckParser`
|`unittests/scans/<parser_dir>/{many_vulns,no_vuln,one_vuln}.json` | Sample files containing meaningful data for unit tests. The minimal set.
|`unittests/tools/test_<parser_name>_parser.py` | Unit tests of the parser.
|`dojo/settings/settings.dist.py`               | If you want to use a modern hashcode based deduplication algorithm
|`doc/content/en/integrations/parsers/<file/api>/<parser_file>.md` | Documentation, what kind of file format is required and how it should be obtained 

## Factory contract

Parsers are loaded dynamicaly with a factory pattern. To have your parser loaded and works correctly, you need to implement the contract.

1. your parser **MUST** be in a sub-module of module `dojo.tools`
   - ex: `dojo.tools.my_tool.parser` module
2. your parser **MUST** be a class in this sub-module.
   - ex: `dojo.tools.my_tool.parser.MyToolParser`
3. The name of this class **MUST** be the Python module name without underscores and with `Parser` suffix.
   - ex: `dojo.tools.my_tool.parser.MyToolParser`
4. This class **MUST** have an empty constructor or no constructor
5. This class **MUST** implement 3 methods:
   1. `def get_scan_types(self)` This function return a list of all the *scan_type* supported by your parser. This identifiers are used internally. Your parser can support more than one *scan_type*. For example some parsers use different identifier to modify the behavior of the parser (aggregate, filter, etc...)
   2. `def get_label_for_scan_types(self, scan_type):` This function return a string used to provide some text in the UI (short label)
   3. `def get_description_for_scan_types(self, scan_type):` This function return a string used to provide some text in the UI (long description)
   4. `def get_findings(self, file, test)` This function return a list of findings
6. If your parser have more than 1 scan_type (for detailled mode) you **MUST** implement `def set_mode(self, mode)` method

Example:

```Python

class MyToolParser(object):
    def get_scan_types(self):
        return ["My Tool Scan", "My Tool Scan detailed"]

    def get_label_for_scan_types(self, scan_type):
        if scan_type == "My Tool Scan":
            return "My Tool XML Scan aggregated by ..."
        else:
            return "My Tool XML Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Aggregates findings per cwe, title, description, file_path. SonarQube output file can be imported in HTML format. Generate with https://github.com/soprasteria/sonar-report version >= 1.1.0"

    def requires_file(self, scan_type):
        return False

    # mode:
    # None (default): aggregates vulnerabilites per sink filename (legacy behavior)
    # 'detailed' : No aggregation
    mode = None

    def set_mode(self, mode):
        self.mode = mode

    def get_findings(self, file, test):
        <...>

```

## API Parsers

DefectDojo has a limited number of API parsers. While we won't remove these connectors, adding API connectors has been problematic and thus we cannot accept new API parsers / connectors from the community at this time for supportability reasonsing. To maintain a high quality API connector, it is necessary to have a license to the tool. To get that license requires partnership with the author or vendor. We're close to announcing a new program to help address this and bring API connectors to DefectDojo.

## Template Generator

Use the [template](https://github.com/DefectDojo/cookiecutter-scanner-parser)  parser to quickly generate the files required. To get started you will need to install [cookiecutter](https://github.com/cookiecutter/cookiecutter).

{{< highlight bash >}}
$ pip install cookiecutter
{{< /highlight >}}

Then generate your scanner parser from the root of django-DefectDojo:

{{< highlight bash >}}
$ cookiecutter https://github.com/DefectDojo/cookiecutter-scanner-parser
{{< /highlight >}}

Read [more](https://github.com/DefectDojo/cookiecutter-scanner-parser) on the template configuration variables.

## Things to pay attention to

Here is a list of considerations that will make the parser robust for both common cases and edge cases.

### Do not parse URLs by hand

We use 2 modules to handle endpoints:
 - `hyperlink`
 - `dojo.models` with a specific class to handle processing around URLs to create endpoints `Endpoint`.

All the existing parser use the same code to parse URL and create endpoints.
Using `Endpoint.from_uri()` is the best way to create endpoints.
If you really need to parse an URL, use `hyperlink` module.

Good example:

```python
    if "url" in item:
        endpoint = Endpoint.from_uri(item["url"])
        finding.unsaved_endpoints = [endpoint]
```

Very bad example:

```python
    u = urlparse(item["url"])
    endpoint = Endpoint(host=u.host)
    finding.unsaved_endpoints = [endpoint]
```

### Use the right libraries to parse information
Various file formats are handled through libraries. In order to keep DefectDojo slim and also don't extend the attack surface, keep the number of libraries used minimal and take other parsers as an example.

#### defusedXML in favour of lxml
As xml is by default an unsecure format, the information parsed from various xml output has to be parsed in a secure way. Within an evaluation, we determined that defusedXML is the library which we will use in the future to parse xml files in parsers as this library is rated more secure. Thus, we will only accept PRs with the defusedxml library. 

### Not all attributes are mandatory

Parsers may have many fields, out of which many of them may be optional.
It better to not set attribute if you don't have data instead of filling with values like `NA`, `No data` etc...

Check class `dojo.models.Finding`

### Data could be missing in the source report

Always make sure you include checks to avoid potential `KeyError` errors (e.g. field does not exist), for those fields you are not absolutely certain will always be in file that will get uploaded. These translate to 500 error, and do not look good.

Good example:

```python
   if "mykey" in data:
       finding.cwe = data["mykey"]
```

### Do not parse CVSS by hand (vector, score or severity)

Data can have `CVSS` vectors or scores. Don't write your own CVSS score algorithm.
For parser, we rely on module `cvss`.

It's easy to use and will make the parser aligned with the rest of the code.

Example of use:

```python
from cvss.cvss3 import CVSS3
import cvss.parser
vectors = cvss.parser.parse_cvss_from_text("CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X")
if len(vectors) > 0 and type(vectors[0]) == CVSS3:
    print(vectors[0].severities())  # this is the 3 severities

    cvssv3 = vectors[0].clean_vector()
    severity = vectors[0].severities()[0]
    vectors[0].compute_base_score()
    cvssv3_score = vectors[0].scores()[0]
    print(severity)
    print(cvssv3_score)
```

Good example:

```python
vectors = cvss.parser.parse_cvss_from_text(item['cvss_vect'])
if len(vectors) > 0 and type(vectors[0]) == CVSS3:
    finding.cvss = vectors[0].clean_vector()
    finding.severity = vectors[0].severities()[0]  # if your tool does generate severity
```

Bad example (DIY):

```python
    def get_severity(self, cvss, cvss_version="2.0"):
        cvss = float(cvss)
        cvss_version = float(cvss_version[:1])
        # If CVSS Version 3 and above
        if cvss_version >= 3:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss < 9:
                return "High"
            elif cvss >= 9:
                return "Critical"
            else:
                return "Informational"
        # If CVSS Version prior to 3
        else:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss <= 10:
                return "High"
            else:
                return "Informational"
```

## Deduplication algorithm

By default a new parser uses the 'legacy' deduplication algorithm documented at https://documentation.defectdojo.com/usage/features/#deduplication-algorithms

Please use a pre-defined deduplication algorithm where applicable.

## Unit tests

Each parser must have unit tests, at least to test for 0 vuln, 1 vuln and many vulns. You can take a look at how other parsers have them for starters. The more quality tests, the better.

It's important to add checks on attributes of findings.
For ex:

```python
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("test title", finding.title)
            self.assertEqual(True, finding.active)
            self.assertEqual(True, finding.verified)
            self.assertEqual(False, finding.duplicate)
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("CVE-2020-36234", finding.vulnerability_ids[0])
            self.assertEqual(261, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)
            self.assertIn("security", finding.tags)
            self.assertIn("network", finding.tags)
            self.assertEqual("3287f2d0-554f-491b-8516-3c349ead8ee5", finding.unique_id_from_tool)
            self.assertEqual("TEST1", finding.vuln_id_from_tool)
```

### Use with to open example files

In order to make certain that file handles are closed properly, please use the with pattern to open files.
Instead of:
```python
    testfile = open("path_to_file.json")
    ...
    testfile.close()
```

use:
```python
    with open("path_to_file.json") as testfile:
        ...
```

This ensures the file is closed at the end of the with statement, even if an exception occurs somewhere in the block.

### Test database

To test your unit tests locally, you first need to grant some rights. Get your MySQL root password from the docker compose logs, login as root and issue the following commands:

{{< highlight mysql >}}
MYSQL> grant all privileges on test_defectdojo.* to defectdojo@'%';
MYSQL> flush privileges;
{{< /highlight >}}

### Run your tests

This local command will launch the unit test for your new parser

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.<your_unittest_py_file>.<main_class_name> -v2'
{{< /highlight >}}

or like this:

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.<your_unittest_py_file>.<main_class_name>
{{< /highlight >}}

Example for the blackduck hub parser:

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.test_blackduck_csv_parser.TestBlackduckHubParser -v2'
{{< /highlight >}}

or like this:

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.test_blackduck_csv_parser.TestBlackduckHubParser
{{< /highlight >}}

If you want to run all unit tests, simply run `$ docker-compose exec uwsgi bash -c 'python manage.py test unittests -v2'`

### Endpoint validation

Some types of parsers create a list of endpoints that are vulnerable (they are stored in `finding.unsaved_endpoints`). DefectDojo requires storing endpoints in a specific format (which follow RFCs). Endpoints that do not follow this format can be stored but they will be marked as broken (red flag 🚩in UI). To be sure your parse store endpoints in the correct format run the `.clean()` function for all endpoints in unit tests

```python
findings = parser.get_findings(testfile, Test())
for finding in findings:
    for endpoint in finding.unsaved_endpoints:
        endpoint.clean()
```

### Tests API Parsers

Not only parser but also importer should be tested.
`patch` method from `unittest.mock` is usualy usefull for simulating API responses.
It is highly recommeded to use it.

## Other files that could be involved

### Change to the model

In the event where you'd have to change the model, e.g. to increase a database column size to accomodate a longer string of data to be saved
* Change what you need in `dojo/models.py`
* Create a new migration file in dojo/db_migrations by running and including as part of your PR

    {{< highlight bash >}}
    $ docker compose exec uwsgi bash -c 'python manage.py makemigrations -v2'
    {{< /highlight >}}

### Accept a different type of file to upload

If you want to be able to accept a new type of file for your parser, take a look at `dojo/forms.py` around line 436 (at the time of this writing) or locate the 2 places (for import and re-import) where you find the string `attrs={"accept":`.

Formats currently accepted: .xml, .csv, .nessus, .json, .html, .js, .zip.

### A need for more than just the parser.py

Of course, nothing prevents you from having more files than the `parser.py` file. It's python :-)

## Pull request examples

If you want to take a look at previous parsers that are now part of DefectDojo, take a look at https://github.com/DefectDojo/django-DefectDojo/pulls?q=is%3Apr+sort%3Aupdated-desc+label%3A%22Import+Scans%22+is%3Aclosed

## Update the import page documentation

Please add a new .md file in [`docs/content/en/integrations/parsers`] with the details of your new parser.  Include the following content headings:

* Acceptable File Type(s) - please include how to generate this type of file from the related tool, as some tools have multiple methods or require specific commands.
* An example unit test block, if applicable.
* A link to the relevant unit tests folder so that users can quickly navigate there from Documentation.
* A link to the scanner itself - (e.g. GitHub or vendor link)

Here is an example of a completed Parser documentation page: [https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/en/connecting_your_tools/parsers/file/acunetix.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/en/connecting_your_tools/parsers/file/acunetix.md)

