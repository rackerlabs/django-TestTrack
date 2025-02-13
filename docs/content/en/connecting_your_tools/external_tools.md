---
title: "External Tools: Universal Importer & DefectDojo-CLI"
description: "Import files to DefectDojo from the command line"
draft: false
weight: 2
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note: The following external tools are DefectDojo Pro-only features. These binaries will not work unless they are connected to an instance with a DefectDojo Pro license.</span>

## About External Tools

`defectdojo-cli` and `universal-importer` are command-line tools designed to seamlessly upload scan results into DefectDojo. They streamline both the import and re-import processes of findings and associated objects. These tools are flexible and supports importing and re-importing scan results, making it ideal for users who need robust interaction with the DefectDojo API.

DefectDojo-CLI has the same functionality as Universal Importer, but also includes the ability to export Findings from DefectDojo to JSON or CSV.

## Installation

1. Use the DefectDojo UI to download the appropriate binary for your operating system from the platform.

2. Locate “External Tools” from your User Profile menu:

![image](images/external-tools.png)

3. Extract the downloaded archive within a directory of your choice.
Optional: Add the directory containing the extracted binary to your system's $PATH for repeat access.

**Note that Macintosh users may be blocked from running DefectDojo-CLI or Universal Importer as they are apps from an unidentified developer.  See [Apple Support](https://support.apple.com/en-ca/guide/mac-help/mh40616/mac) for instructions on how to override the block from Apple.**  

**Windows Users: If you receive the "Couldn't download - virus detected" error, disabling Smartscreen may work. Otherwise, use a different browser to download the tool from the Cloud portal.**

## Configuration

Universal Importer & DefectDojo-CLI can be configured using flags, environment variables, or a configuration file. The most important configuration is the API token, which must be set as an environment variable:

1. Add your API key to your environment variables. 
You can retrieve your API key from: `https://YOUR_INSTANCE.cloud.defectdojo.com/api/key-v2`

or 

Via the DefectDojo user interface 
in the user dropdown in the top-right corner:

![image](images/api-token.png)

2. Set your environment variable for the API token.

**For DefectDojo-CLI:**
	`export DD_CLI_API_TOKEN=YOUR_API_KEY`

**For Universal Importer:**
	`export DD_IMPORTER_DOJO_API_TOKEN=YOUR_API_KEY`


Note: On Windows, use `set` instead of `export`.

### Windows: Using PowerShell
1. Open PowerShell (Windows Key, then search for "PowerShell").
2. Set the environment variables:
   - **Temporary:**
     ```powershell
     $env:DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     $env:DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Permanent:**
     ```powershell
     [Environment]::SetEnvironmentVariable("DD_IMPORTER_DOJO_API_TOKEN", "[VALUE_FROM_DEFECTDOJO_API]", "Machine")
     ```
3. Restart your PowerShell session.
4. Verify the setting:
   ```powershell
   echo $env:DD_IMPORTER_DOJO_API_TOKEN
   echo $env:DD_IMPORTER_DEFECTDOJO_URL
   ```

### Windows: Using Command Prompt (Administrative Accounts)
1. Open Command Prompt (Windows Key, then search for "Command Prompt").
2. Set the environment variables:
   - **Temporary:**
     ```cmd
     set DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     set DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Permanent:**
     ```cmd
     setx DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     setx DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```

### Using Windows Settings (Non-Administrative Accounts)
1. Press `Win + I` to open the system settings dialog.
2. In the search box, type "environment".
3. Choose "Edit Environment variables for your account".
4. Under "User variables for [username]", click the "New…" button.
5. Set the variable:
   - **Variable name:** `DD_IMPORTER_DOJO_API_TOKEN`
   - **Variable value:** `[VALUE_FROM_DEFECTDOJO_API]`
6. Click "OK".
7. Repeat steps 4 through 6 for the DD_IMPORTER_DEFECTDOJO_URL variable
8. Restart any open command windows.
9. Verify the settings:
   ```cmd
   echo %DD_IMPORTER_DOJO_API_TOKEN%
   echo %DD_IMPORTER_DEFECTDOJO_URL%
   ```

## DefectDojo-CLI

`defectdojo-cli` seamlessly integrates scan results into DefectDojo, streamlining the import and reimport processes of Findings and associated objects. Designed for ease of use, the tool supports various endpoints, catering to both initial imports and subsequent reimports — ideal for users requiring robust and flexible interaction with the DefectDojo API. DefectDojo-CLI can perform the same functions as `universal-importer`, and adds export functionality for Findings.

### Commands

- [`import`](./#import)       Imports findings into DefectDojo.
- [`reimport`](./#reimport)     Reimports findings into DefectDojo.
- [`export`](./#export)	Exports findings from DefectDojo.
- [`interactive`](./#interactive)   Starts an interactive mode to configure the import and reimport process, step by 

### Global Options

`--help, -h`     
* show help

`--version, -v`
* print the version

#### CLI Formatting

`--no-color`
* Disable color output. (default: false) `[$DD_CLI_NO_COLOR]`
`--no-emojis, --no-emoji`

* Disable emojis in the output. (default: false) `[$DD_CLI_NO_EMOJIS]`

* `--verbose`
Enable verbose output. (default: false) `[$DD_CLI_VERBOSE]`

### Import

Use the import command to import new findings into DefectDojo.

#### Usage

```
defectdojo-cli [global options] import <required flags> [optional flags]
	or: defectdojo-cli [global options] import  --config ./config-file-path
	or: defectdojo-cli import [-h | --help]
	or: defectdojo-cli import example [subcommand options]
	or: defectdojo-cli import example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

`import` can import Findings in two ways:

**By ID:**
* Create a Product (or use an existing product)
* Create an Engagement inside the product
* Provide the id of the Engagement in the engagement parameter

In this scenario a new Test will be created inside the Engagement.

**By Name:**
* Create a Product (or use an existing product)
* Create an Engagement inside the product
* Provide product-name
* Provide engagement-name
* Optionally provide product-type-name

In this scenario DefectDojo will look up the Engagement by the provided details.

When using names you can let the importer automatically create Engagements, Products and Product-types by using `auto-create-context=true`.
You can use `deduplication-on-engagement` to restrict deduplication for imported Findings to the newly created Engagement.


**Import Basic syntax:**
```
defectdojo-cli import [options]
```

#### **Import Example:**
```
defectdojo-cli import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### Commands
`example, x`
* Shows an example of required and optional flags for import operation

#### Options

`--active, -a` 
* Dictates whether findings should be active on import. (default: true) `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`
* The ID of the API Scan Configuration object to use when importing or reimporting. (default: 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* If set to true, the tags (from the option --tag) will be applied to the endpoints (default: false) 
`[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* If set to true, the tags (from the option --tag) will be applied to the findings (default: false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* If set to true, the importer automatically creates Engagements, Products, and Product_Types (default: false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--deduplication-on-engagement, --doe`
* If set to true, the importer restricts deduplication for imported findings to the newly created Engagement. (default: false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* The ID of the Engagement to import findings into. (default: 0) `[$DD_CLI_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* The name of the Engagement to import findings into. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Dictates the lowest level severity that should be imported. Valid values are: Critical, High, Medium, Low, Info. (default: "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* The name of the Product to import findings into. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* The name of the Product Type to import findings into. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* The path to the report to import. (required). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`
* The scan type of the tool (required). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Any tags to be applied to the Test object `[$DD_CLI_TAGS]`

`--test-name value, --tn value`
* The name of the Test to import findings into - Defaults to the name of the scan type. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`
* The version of the test. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`
* Dictates whether findings should be verified on import. (default: false) `[$DD_CLI_VERIFIED]`

**Settings:**

`--config value, -c value`          
* The path to the TOML configuration file is used to set values for the options. If the option is set in the configuration file and the CLI, the option will take the value set from the CLI. `[$DD_CLI_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* The URL of the DefectDojo instance to import findings into. (required). `[$DD_CLI_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          ignore TLS validation errors when connecting to the provided DefectDojo instance. Most users should not enable this flag. (default: false) `[$DD_CLI_INSECURE_TLS]`

### Reimport

Use the `reimport` command to extend an existing Test with Findings from a new report in one of two ways:

By ID:
- Create a Product (or use an existing product)
- Create an Engagement inside the product
- Import a scan report and find the id of the Test
- Provide this in the test-id parameter

By Names:
- Create a Product (or use an existing product)
- Create an Engagement inside the product
- Import a report which will create a Test
- Provide product-name
- Provide engagement-name
- Optional: Provide test-name

In this scenario DefectDojo will look up the Test by the provided details. If no test-name is provided, the latest test inside the engagement will be chosen based on scan-type.

When using names you can let the importer automatically create Engagements, Products and Product-types by using `auto-create-context=true`.
You can use `deduplication-on-engagement` to restrict deduplication for imported Findings to the newly created Engagement.

#### Usage

```
defectdojo-cli [global options] reimport <required flags> [optional flags]
   or: defectdojo-cli [global options] reimport  --config ./config-file-path
   or: defectdojo-cli reimport [-h | --help]
   or: defectdojo-cli reimport example [subcommand options]
   or: defectdojo-cli reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

#### **Reimport Example:**

```
defectdojo-cli reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### Commands

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Options

`--active, -a`                                    
* Dictates whether findings should be active on import. (default: true) `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`

* The ID of the API Scan Configuration object to use when importing or reimporting. (default: 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* If set to true, the tags (from the option --tag) will be applied to the endpoints (default: false) `[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* If set to true, the tags (from the option --tag) will be applied to the findings (default: false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* If set to true, the importer automatically creates Engagements, Products, and Product_Types (default: false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--deduplication-on-engagement, --doe`          
* If set to true, the importer restricts deduplication for imported findings to the newly created Engagement. (default: false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* The name of the Engagement to import findings into. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Dictates the lowest level severity that should be imported. Valid values are: Critical, High, Medium, Low, Info. (default: "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* The name of the Product to import findings into. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* The name of the Product Type to import findings into. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* The path to the report to import. (required). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`                      
* The scan type of the tool (required). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Any tags to be applied to the Test object `[$DD_CLI_TAGS]`

`--test-id value, --ti value`                      
* The ID of the Test to reimport findings into. (default: 0) `[$DD_CLI_TEST_ID]`

`--test-name value, --tn value`                    
* The name of the Test to import findings into - Defaults to the name of the scan type. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`                   
* The version of the test. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`                                   
* Dictates whether findings should be set to Verified on import. (default: false) `[$DD_CLI_VERIFIED]`

**Settings:**

`--config value, -c value`
* The path to the TOML configuration file is used to set values for the options. If the option is set in the configuration file and the CLI, the option will take the value set from the CLI. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* The URL of the DefectDojo instance to import findings into. (required). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* ignore TLS validation errors when connecting to the provided DefectDojo instance. Most users should not enable this flag. (default: false) `[$DD_CLI_INSECURE_TLS]`

### Export

#### Usage

```
defectdojo-cli export <required options> [optional options]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --config ./config-file-path
	or: defectdojo-cli [global options] export --config ./config-file-path --json ./output_file_path.json
	or: defectdojo-cli [global options] export --config ./config-file-path --csv ./output_file_path.csv
	or: defectdojo-cli export [-h | --help]
	or: defectdojo-cli export example [subcommand options]
	or: defectdojo-cli export example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

To export Findings from DefectDojo-CLI, you will need to supply a configuration file which contains details explaining which Findings you wish to export.  This is similar to the GET Findings method via the API.

For assistance use `defectdojo-cli export --help`.

#### **Export Example**

This example specifies the URL, export format and a few filter parameters to create a list of Findings.

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
--json "./path/to/findings.json" \
--active "true" \
--created "Past 90 days"
```

#### Commands

`example, x`
* Shows an example of required and optional flags for export operation

`help, h`
* Shows a list of commands or help for one command

#### Options

**Findings Filters:**

`--active true|false, -a true|false`
* Findings by active status. `[$DD_CLI_FINDINGS_FILTERS_ACTIVE]`

`--created value`
* Findings by created date. Supported values: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_CREATED]`

`--cvssv3-score value`
* Findings by CVSS v3 score. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_CVSSV3_SCORE]`

`--cwe value` 
* Findings by CWE ID. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_CWE]`

`--date value`
* Findings by date. Supported values: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_DATE]`

`--discovered-after value`
* Findings by discovered after the specified date. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_AFTER]`

`--discovered-before value`
* Findings by discovered before the specified date. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_BEFORE]`

`--discovered-on value`
* Findings by discovered date. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_ON]`

`--duplicate true|false`
* Findings by duplicated status. `[$DD_CLI_FINDINGS_FILTERS_DUPLICATE]`

`--engagement-ids value [ --engagement-ids value ]`
* Findings by engagement IDs. This flag can be used multiple times or as a comma-separated list. `[$DD_CLI_FINDINGS_FILTERS_ENGAGEMENT]`

`--epss-percentile value`
* Findings by EPSS percentile. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_EPSS_PERCENTILE]`

`--epss-score value`
* Findings by EPSS score. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_EPSS_SCORE]`

`--false-positive true|false`
* Findings by false positive status. `[$DD_CLI_FINDINGS_FILTERS_FALSE_POSITIVE]`

`--is-mitigated true|false`
* Findings by mitigation status. `[$DD_CLI_FINDINGS_FILTERS_IS_MITIGATED]`

`--mitigated value`
* Findings by the date range in which they were marked mitigated Supported values: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_MITIGATED]`

`--mitigated-after value`
* Findings by mitigation after the specified date. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_AFTER]`

`--mitigated-before value`
* Findings by mitigation before the specified date. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BEFORE]`

`--mitigated-by-ids value [ --mitigated-by-ids value ]`
* Findings by mitigated_by user IDs. This flag can be used multiple times or as a comma-separated list. Could be combined with --mitigated-by-names. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_IDS]`

`--mitigated-by-names value [ --mitigated-by-names value ]`
* Findings by mitigated_by user names. This flag can be used multiple times or as a comma-separated list. Could be combined with --mitigated-by-ids. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_NAMES]`

`--mitigated-on value`
* Findings by mitigation date. Format: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_ON]`

`--not-tags value [ --not-tags value ]`
* Findings by tags that should not be present. This flag can be used multiple times or as a comma-separated list. `[$DD_CLI_FINDINGS_FILTERS_NOT_TAGS]`

`--out-of-scope true|false`
* Findings by out of scope or in scope status. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SCOPE]`

`--out-of-sla true|false`
* Findings by outside or inside SLA status. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SLA]`

`--product-name value`
* Findings by product name. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME]`

`--product-name-contains value`
* Findings by product name contains. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME_CONTAINS]`

`--product-type-ids value [ --product-type-ids value ]`
* Findings by product type IDs. This flag can be used multiple times or as a comma-separated list. Could be combined with --product-type-names `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_IDS]`

`--product-type-names value [ --product-type-names value ]`
* Findings by product type names. This flag can be used multiple times or as a comma-separated list. Could be combined with --product-type-ids `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_NAMES]`

`--risk-accepted true|false`
* Findings by risk accepted status. `[$DD_CLI_FINDINGS_FILTERS_RISK_ACCEPTED]`

`--severity value [ --severity value ]`
* Findings by severity. Valid values are: Critical, High, Medium, Low, Info. This flag can be used multiple times or as a comma-separated list. `[$DD_CLI_FINDINGS_FILTERS_SEVERITY]`

`--tags value [ --tags value ]`
* Findings by tags that should be present. This flag can be used multiple times or as a comma-separated list. `[$DD_CLI_FINDINGS_FILTERS_TAGS]`

`--test-id value`
* Findings by test ID. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_TEST_ID]`

`--title-contains value`
* Findings by containing the given string in their title. `[$DD_CLI_FINDINGS_FILTERS_TITLE_CONTAINS]`

`--under-review true|false`
* Findings by under review status. `[$DD_CLI_FINDINGS_FILTERS_UNDER_REVIEW]`

`--verified true|false`
* Findings by verified status. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_VERIFIED]`

`--vulnerability-id value [ --vulnerability-id value ]`
* Findings by vulnerability ID. This flag can be used multiple times or as a comma-separated list. `[$DD_CLI_FINDINGS_FILTERS_VULNERABILITY_ID]`

**Findings Output**

`--csv value`
* Path of the file where the CSV file of the findings will be written. `[$DD_CLI_FINDINGS_OUTPUT_CSV_PATH_FILE]`

`--json value`  Path of the file where the JSON file of the findings will be written. `[$DD_CLI_FINDINGS_OUTPUT_JSON_PATH_FILE]`

**Settings**

`--config value, -c value`
The path to the TOML configuration file is used to set values for the options. If the option is set in the configuration file and the CLI, the option will take the value set from the CLI. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`
The URL of the DefectDojo instance to import findings into. (required). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
ignore TLS validation errors when connecting to the provided DefectDojo instance. Most users should not enable this flag. (default: false) `[$DD_CLI_INSECURE_TLS]`

#### Export Example:

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
```

### Interactive

Interactive mode allows you to configure import and reimport process, step-by-step.

#### Usage

```
defectdojo-cli interactive
	or: defectdojo-cli interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: defectdojo-cli interactive [-h | --help]
```

#### Options

`--skip-intro `    
* Skip the intro screen (default: false)

`--no-full-screen`
* Disable full screen mode (default: false)

`--log-path value`
* Path to the log file

`--help, -h`
* show help

## Universal Importer

`universal-importer` seamlessly integrates scan results into DefectDojo, streamlining both the import and reimport processes of findings and associated objects. Designed for ease of use, the tool supports various endpoints, catering to both initial imports and subsequent reimports — ideal for users requiring robust and flexible interaction with the DefectDojo API.

Usage of Universal Importer is similar to DefectDojo-CLI, however Universal Importer does not have the Export functionality, and environment variables are encoded differently.

### Commands

- [`import`](./#import-1)       Imports findings into DefectDojo.
- [`reimport`](./#reimport-1)     Reimports findings into DefectDojo.
- [`interactive`](./#interactive-1)   Starts an interactive mode to configure the import and reimport process, step by 

### Global Options

`--help, -h`     
* show help

`--version, -v`
* print the version

#### CLI Formatting

`--no-color`
* Disable color output. (default: false) `[$DD_IMPORTER_NO_COLOR]`

`--no-emojis, --no-emoji`
* Disable emojis in the output. (default: false) `[$DD_IMPORTER_NO_EMOJIS]`

`--verbose`
* Enable verbose output. (default: false) `[$DD_IMPORTER_VERBOSE]`

### Import

Use the import command to import new findings into DefectDojo.

#### Usage

```
defectdojo-cli [global options] import <required flags> [optional flags]
	or: defectdojo-cli [global options] import  --config ./config-file-path
	or: defectdojo-cli import [-h | --help]
	or: defectdojo-cli import example [subcommand options]
	or: defectdojo-cli import example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

`import` can import Findings in two ways:

**By ID:**
* Create a Product (or use an existing product)
* Create an Engagement inside the product
* Provide the id of the Engagement in the engagement parameter

In this scenario a new Test will be created inside the Engagement.

**By Name:**
* Create a Product (or use an existing product)
* Create an Engagement inside the product
* Provide product-name
* Provide engagement-name
* Optionally provide product-type-name

In this scenario DefectDojo will look up the Engagement by the provided details.

When using names you can let the importer automatically create Engagements, Products and Product-types by using `auto-create-context=true`.
You can use `deduplication-on-engagement` to restrict deduplication for imported Findings to the newly created Engagement.


**Import Basic syntax:**

```
defectdojo-cli import [options]
```

#### **Import Example:**

```
defectdojo-cli import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### Commands

`example, x`
* Shows an example of required and optional flags for import operation

#### Options

`--active, -a` 
* Dictates whether findings should be active on import. (default: true) `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* The ID of the API Scan Configuration object to use when importing or reimporting. (default: 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* If set to true, the tags (from the option --tag) will be applied to the endpoints (default: false) 
`[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* If set to true, the tags (from the option --tag) will be applied to the findings (default: false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* If set to true, the importer automatically creates Engagements, Products, and Product_Types (default: false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--deduplication-on-engagement, --doe`
* If set to true, the importer restricts deduplication for imported findings to the newly created Engagement. (default: false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* The ID of the Engagement to import findings into. (default: 0) `[$DD_IMPORTER_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* The name of the Engagement to import findings into. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Dictates the lowest level severity that should be imported. Valid values are: Critical, High, Medium, Low, Info. (default: "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* The name of the Product to import findings into. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* The name of the Product Type to import findings into. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* The path to the report to import. (required). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`
* The scan type of the tool (required). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Any tags to be applied to the Test object `[$DD_IMPORTER_TAGS]`

`--test-name value, --tn value`
* The name of the Test to import findings into - Defaults to the name of the scan type. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`
* The version of the test. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`
* Dictates whether findings should be verified on import. (default: false) `[$DD_IMPORTER_VERIFIED]`

**Settings:**

`--config value, -c value`          
* The path to the TOML configuration file is used to set values for the options. If the option is set in the configuration file and the CLI, the option will take the value set from the CLI. `[$DD_IMPORTER_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* The URL of the DefectDojo instance to import findings into. (required). `[$DD_IMPORTER_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          ignore TLS validation errors when connecting to the provided DefectDojo instance. Most users should not enable this flag. (default: false) `[$DD_IMPORTER_INSECURE_TLS]`

### Reimport

Use the `reimport` command to extend an existing Test with Findings from a new report in one of two ways:

By ID:
- Create a Product (or use an existing product)
- Create an Engagement inside the product
- Import a scan report and find the id of the Test
- Provide this in the test-id parameter

By Names:
- Create a Product (or use an existing product)
- Create an Engagement inside the product
- Import a report which will create a Test
- Provide product-name
- Provide engagement-name
- Optional: Provide test-name

In this scenario DefectDojo will look up the Test by the provided details. If no test-name is provided, the latest test inside the engagement will be chosen based on scan-type.

When using names you can let the importer automatically create Engagements, Products and Product-types by using `auto-create-context=true`.
You can use `deduplication-on-engagement` to restrict deduplication for imported Findings to the newly created Engagement.

#### Usage

```
defectdojo-cli [global options] reimport <required flags> [optional flags]
   or: defectdojo-cli [global options] reimport  --config ./config-file-path
   or: defectdojo-cli reimport [-h | --help]
   or: defectdojo-cli reimport example [subcommand options]
   or: defectdojo-cli reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

#### **Reimport Example:**

```
defectdojo-cli reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### Commands

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Options

`--active, -a`                                    
* Dictates whether findings should be active on import. (default: true) `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* The ID of the API Scan Configuration object to use when importing or reimporting. (default: 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* If set to true, the tags (from the option --tag) will be applied to the endpoints (default: false) `[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* If set to true, the tags (from the option --tag) will be applied to the findings (default: false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* If set to true, the importer automatically creates Engagements, Products, and Product_Types (default: false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--deduplication-on-engagement, --doe`          
* If set to true, the importer restricts deduplication for imported findings to the newly created Engagement. (default: false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* The name of the Engagement to import findings into. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Dictates the lowest level severity that should be imported. Valid values are: Critical, High, Medium, Low, Info. (default: "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* The name of the Product to import findings into. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* The name of the Product Type to import findings into. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* The path to the report to import. (required). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`                      
* The scan type of the tool (required). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Any tags to be applied to the Test object `[$DD_IMPORTER_TAGS]`

`--test-id value, --ti value`                      
* The ID of the Test to reimport findings into. (default: 0) `[$DD_IMPORTER_TEST_ID]`

`--test-name value, --tn value`                    
* The name of the Test to import findings into - Defaults to the name of the scan type. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`                   
* The version of the test. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`                                   
* Dictates whether findings should be set to Verified on import. (default: false) `[$DD_IMPORTER_VERIFIED]`

**Settings:**

`--config value, -c value`
* The path to the TOML configuration file is used to set values for the options. If the option is set in the configuration file and the CLI, the option will take the value set from the CLI. `[$DD_IMPORTER_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* The URL of the DefectDojo instance to import findings into. (required). `[$DD_IMPORTER_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* ignore TLS validation errors when connecting to the provided DefectDojo instance. Most users should not enable this flag. (default: false) `[$DD_IMPORTER_INSECURE_TLS]`

### Interactive
Interactive mode allows you to configure import and reimport process, step-by-step.

#### Usage

```
defectdojo-cli interactive
	or: defectdojo-cli interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: defectdojo-cli interactive [-h | --help]
```

#### Options

`--skip-intro `    
* Skip the intro screen (default: false)

`--no-full-screen`
* Disable full screen mode (default: false)
`--log-path value`
* Path to the log file
`--help, -h`
* show help


## Troubleshooting

If you encounter any issues with these tools, please check the following:
- Ensure you're using the correct binary for your operating system and CPU architecture.
- Verify that the API key is set correctly in your environment variables.
- Check that the DefectDojo URL is correct and accessible.
- When importing, confirm that the report file exists and is in the supported format for the specified scan type.  You can review the supported scanners for DefectDojo on our [supported tools list](../parsers). 
