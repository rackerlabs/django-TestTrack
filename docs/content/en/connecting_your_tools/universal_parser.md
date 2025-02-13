---
title: "🌐 Universal Parser"
description: ""
draft: "false"
weight: 4
pro-feature: true
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note: The Universal Parser is only available in DefectDojo Pro.</span>

The Universal Parser is currently in Beta.  See our [announcement presentation](https://community.defectdojo.com/universalparser) for more information.

**The Universal Parser is:**

* A quick way to support file formats for which we do not have Community parsers, such as reports produced by internal tools
* A tool to help you ingest data even if a Community parser is out-of-date or doesn't structure findings the way you would like
* An alternative to custom scripting that transforms tool reports into the CSV/JSON format expected by the "Generic Findings Import" scan type
* Designed to be easy to use for anyone, with no coding and minimal configuration required

**The Universal Parser is not:**

* A comprehensive replacement for open source parsers, Connectors, or carefully-massaged "Generic Findings Import" reports
* Capable of handling nuanced, branching logic to structure findings
* Universal Parser configuration is only available in the beta UI, though you can still import scans using a Universal Parser via the old UI or API

## Step 1: Creating a new Universal Parser

You can create a new Universal Parser by clicking the "New Universal Parser" button in the navigation bar under the "Import" section, or from the link on the "Add Findings" page.

![image](images/universal_parser.png)

The first screen will ask you for a scan file and a parser name.

![image](images/universal_parser_2.png)

The file should:

* Have a recognized extension (see supported file extensions below)
* Contain enough finding-like objects to be representative of real reports - i.e., one that includes values in all optional fields
* Not be larger than about 1-2MB - beyond this point it will generally just take longer to parse the file, without any benefit

The parser name will be used when creating the Test_Type for this new parser. You'll find your newly-created Universal Parser in the scan types drop-down on the "Add Findings" page with a name like "Universal Parser - MyCustomParser". Parser names must be unique to prevent confusion when selecting a scan type for imports.

## Step 2: Mapping your Finding fields

![image](images/universal_parser_3.png)

After uploading an example scan file, selecting a parser name, and clicking "Next", the following page will let you configure the way this Universal Parser will populate finding fields when using this configuration to perform imports. On the right, you will find a selection of DefectDojo finding fields (output fields). Drop-down menus to the left of each output field allow you to select which item(s) (input fields) from your scan file's structure should be used to populate them.

Example:

If you've uploaded a scan file in JSON format that looks like this:

```
{
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345",
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "LOW",
            "CVE": "CVE-2025-54321",
            ...
        },
        ...

    ]
}
```

You'll see a hierarchical representation of the unique fields we detected based on the structure of the input file, with icons indicating the type of each field (if we can determine this). You can then select the "title" input field in the drop-down menu that populates the "Title" output field, the "description" input field can go with the "Description" output field, and so on. 

Input field names don't have to match the names of output fields, and your scan file may not have an equivalent to all DefectDojo output fields.

### Required fields
The following output fields require an input field mapping:

* Title
* Severity
* Description

### About severities
A Universal Parser will accept any case variation of the DefectDojo severities - "CRITICAL", "Critical", "cRiTiCaL", etc. - and apply it to your findings. Any value that doesn't match a DefectDojo severity will be replaced with "Info". This mirrors how parsers and Connectors work today: unknown values are generally mapped to "Info".

### Multi-select fields
Some output fields will accept multiple input fields. If you decide to select more than one input field, we will provide that field's value under a header with that input field's name.

Example

`description`

This was pulled from a field called "description" in the input file

`detailed_description`

This was pulled from a field called "detailed_description" in the input file

## Step 3: Previewing your Findings

Once you've selected your mappings from input fields to output fields, you can click the "Next" button to see a preview of what the Findings from your input file will look like once they are imported to DefectDojo with your chosen configuration. Some fields will have an "expand" button next to them to allow you to see the full, rendered MarkDown of what that field will look like. We will only render previews of the first 25 Findings from your input file, but you can also see how many findings were detected in the whole scan file.

If the previews don't look like you expected, you can hit the "Back" button to tweak the mappings. Once you are satisfied with your configuration, click the "Submit" button to create your new Universal Parser. This will not perform an import automatically.

Once your Universal Parser is created, you'll be redirected to the "Add Findings" page where you can upload and import a scan file matching the structure of the example file you provided in Step 1.

## Additional notes about Universal Parser configuration

### Choosing the right input fields

Each vendor may produce very different scan report formats, some of which will map more closely to DefectDojo's finding model than others. We allow for significant flexibility in what we will accept, but we must impose some structure to ensure that findings don't get garbled in the translation from input to output. While we can accommodate optional input fields, we don't accept "global" fields, or fields that occur a different number of times than the number of finding objects.

#### Example

```
{
    "scan_type": "MyToolScan", // <- There is only one instance of this field, which doesn't match the number of findings
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345", // <- This optional field only appears in Finding 1 - that's okay!
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "CRITICAL",
            ...  // <- While there is no "CVE" field here, we can still query for it and simply default to a null value
        },
        ... 5 more findings ...
    ],
    "global_details": [
        {
            "nested_detail": "Global detail 1"
        },
        {
            "nested_detail": "Global detail 2" // <- The number of "global_details" objects (2) does not match the number of individual finding objects (7)
        }

    ]
}
```

## After saving a Universal Parser

You can edit the Test_Type associated with your Universal Parser to change:
* Whether it is "active" or not. If not, it will not appear as an option in the "Scan Type" drop-down on the "Add Findings" page
* Whether its findings should be marked "static" or "dynamic"
* You can tweak the same-tool and cross-tool deduplication hash codes, as well as the reimport hash codes, for your Universal Parser under "Enterprise Settings". By default, only same-tool deduplication and reimport hash codes are populated, with the required values Title, Severity, and Description.