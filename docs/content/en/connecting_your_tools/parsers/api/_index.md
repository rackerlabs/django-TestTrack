---
title: "API Pull"
description: "Report pulled to DefectDojo via API exposed by scanning service"
weight: 3
chapter: true
sidebar:
  collapsed: true
exclude_search: true
---
All parsers that use API pull have common basic configuration steps, but with different values.

Follow these steps to set up API importing:

1.  Configure the API authentication details by navigating to
    `Configuration -> Tool Configuration -> Add Tool Configuration`. Enter a `Name`,
    selecting the related `Tool Type` and `Authentication Type` "API Key". Paste your credentials
    to the proper fields based on definitions below.

2.  In the `Product` settings select `Add API Scan Configuration` and select the
    previously added `Tool Configuration`. Provide values based on definitions below.

3.  After this is done, you can import the findings on the `Product` page through
    `Findings -> Import Scan Results`. As the `Scan type`, select the related type,
    the API scan configuration from the last step, and click `Import`.
