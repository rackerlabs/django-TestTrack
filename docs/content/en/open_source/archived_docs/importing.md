---
title: "Importing"
description: "How DefectDojo imports and reimports security tool reports."
draft: false
weight: 1
exclude_search: true
---

## Import

The importers analyze each report and create new Findings for each item
reported. DefectDojo collapses duplicate Findings by capturing the
individual hosts vulnerable.

![Import Form](images/imp_1.png)

This approach will create a new Test for each upload. This can result in a lot of findings. If deduplication is enabled, new Findings that are identical to existing Findings get marked as a duplicate.

## Reimport

Additionally, DefectDojo allows for re-imports of previously uploaded
reports. This greatly reduces the amount of findings as no duplicates are created for findings that already exist.

![Reimport menu](images/reupload_menu1.png)

DefectDojo will attempt to capture the deltas between the
original and new import and automatically add or mitigate findings as
appropriate.

![Re-Import Form](images/imp_2.png)

This behaviour can be controled via the `closed_old_findings` parameter on the reupload form.

The history of a test will be shown with the delta's for each reimported scan report.
![Import History](images/import_history1.png)

Clicking on a reimport changset will show the affected findings, as well as a status history per finding.
![Import History details](images/import_history_details1.png)

### Triage-less scanners
Some scanners might not include triage information in their reports (e.g. tfsec). They simply scan code or dependencies, flag issues, and return everything. Removing some findings requires you to add comments in your code perhaps, but there is no simple way to filter out findings from the reports.

That is why DefectDojo also includes a "Do not reactivate" checkbox in uploading reports (also in the reimport API), so you can persist the triages that have been done in Defectdojo without reactivating Findings on every upload.

For context, see [#6892](https://github.com/DefectDojo/django-DefectDojo/issues/6892)

# API
This section focuses on Import and Reimport via the API. Please see the [full documentation details of all API Endpoints](../api-v2-docs/) for more details.
Reimport is actually the easiest way to get started as it will create any entities on the fly if needed and it will automatically detect if it is a first time upload or a re-upload.

## Import
Importing via the API is performed via the [import-scan](https://demo.defectdojo.org/api/v2/doc/) endpoint.

As described in the [Core Data Classes](../../usage/models/), a test gets created inside an Engagement, inside a Product, inside a Product Type.

An import can be performed by specifying the names of these entities in the API request:


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
}
```

When `auto_create_context` is `True`, the product, engagement, and environment will be created if needed. Make sure your user has sufficient [permissions](../usage/permissions) to do this.

A classic way of importing a scan is by specifying the ID of the engagement instead:

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "engagement": 123,
}
```


## Reimport
ReImporting via the API is performed via the [reimport-scan](https://demo.defectdojo.org/api/v2/doc/) endpoint.

A reimport can be performed by specifying the names of these entities in the API request:


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
    "do_not_reactivate": False,
}
```

When `auto_create_context` is `True`, the product and engagement will be created if needed. Make sure your user has sufficient [permissions](../usage/permissions) to do this.

When `do_not_reactivate` is `True`, the importing/reimporting will ignore uploaded active findings and not reactivate previously closed findings, while still creating new findings if there are new ones. You will get a note on the finding to explain that it was not reactivated for that reason.

A reimport will automatically select the latest test inside the provided engagement that satisifes the provided `scan_type` and (optionally) provided `test_title`.

If no existing Test is found, the reimport endpoint will use the import function to import the provided report into a new Test. This means a (CI/CD) script using the API doesn't need to know if a Test already exists, or if it is a first time upload for this Product / Engagement.

A classic way of reimporting a scan is by specifying the ID of the test instead:

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test": 123,
}
```

## Using the Scan Completion Date (API: `scan_date`) field

DefectDojo offers a plethora of supported scanner reports, but not all of them contain the
information most important to a user. The `scan_date` field is a flexible smart feature that
allows users to set the completion date of the a given scan report, and have it propagate
down to all the findings imported. This field is **not** mandatory, but the default value for
this field is the date of import (whenever the request is processed and a successful response is returned).

Here are the following use cases for using this field:

1. The report **does not** set the date, and `scan_date` is **not** set at import
    - Finding date will be the default value of `scan_date`
2. The report **sets** the date, and the `scan_date` is **not** set at import
    - Finding date will be whatever the report sets
3. The report **does not** set the date, and the `scan_date` is **set** at import
    - Finding date will be whatever the user set for `scan_date`
4. The report **sets** the date, and the `scan_date` is **set** at import
    - Finding date will be whatever the user set for `scan_date`
