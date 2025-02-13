---
title: "Introduction to Findings"
description: "The main workflow and vulnerability tracking system of DefectDojo"
weight: 1
---

Findings are the main way that DefectDojo standardizes and guides the reporting and remediation process of your security tools. Regardless of whether a vulnerability was reported in SonarQube, Acunetix, or your team’s custom tool, Findings give you the ability to manage each vulnerability in the same way.

## What are Findings?

Findings in DefectDojo are made up of the following components: 

* The reported vulnerability data in question
* The ‘status’ of the Finding, used to track remediation, risk acceptance or other decisions made around the vulnerability
* Other metadata related to the Finding. For example, this could include the location of a Finding in your network, a tool’s suggestions for remediation, or links to an associated CWE or EPSS score.

In addition to storing the vulnerability data and providing a remediation framework, DefectDojo also enhances your Findings in the following ways:

* Automatically adding related EPSS scores to a Finding to describe exploitability
* Automatically translating a security tool’s severity metric into a Severity score for each Finding, which confers an SLA onto the Finding according to your Product’s SLA Configuration.

Overall, DefectDojo Findings are designed to work with the Product Hierarchy to standardize your efforts, and apply a consistent method to each Product.

## A Finding Page

The Finding Page contains various components. Each will be populated by the Import process when the Finding is created.

![image](images/Introduction_to_Findings.png)

1. **The Title of the Finding:** Usually this is a descriptive shorthand which identifies the vulnerability or issue detected. This section is also where user\-created Tags are displayed if they exist.  
​
2. **Finding Overview:** This section contains five separate pages of relevant information for the Finding: Description, Mitigation, Impact, References and Notes. These fields can be populated automatically based on the incoming vulnerability data, or they can be edited by a DefectDojo user to provide additional context.  
​  
​**\- Description** is a more detailed summary and explanation of the Finding in question.  
​**\- Mitigation** is a suggested method for mitigating the Finding so that it is no longer present in your system.  
​**\- Impact** describes the impact of the vulnerability on your security posture. This page might hold descriptive text, or it may include a [CVSS Vector String](https://qualysguard.qualys.com/qwebhelp/fo_portal/setup/cvss_vector_strings.htm), which is a shorthand way to communicate the vulnerability’s overall exploitability and with the consequences of an exploitation to your organization. Impact is closely related to a Finding’s Severity field.  
​**\- References** will list any links or additional information relevant to this Finding if included.  
​**\- Notes** is a page where you can record any other relevant information to this Finding. Notes are ‘DefectDojo\-only’ metadata, and they are not created at the time of import. Use this field to track your mitigation progress or to add more specific detail to the Finding.  
​
3. **Additional Details:** This section lists other details related to this Finding, if relevant:


	* Request/Response Pairs associated with the vulnerability
	* Steps To Reproduce the vulnerability
	* Severity Justification where you can record a more detailed explanation of the severity or impact of the Finding.  
	​  
	​
4. **Metadata: This section contains filterable metadata related to the Finding:**


	* **ID:** the ID value of the Finding in DefectDojo
	* **Severity:** the Severity value of the Finding. Can be Info, Low, Medium, High or Critical. Finding Severities are directly related to the Finding’s calculated SLA, based on the Product the Finding is stored in.
	* **Status:** the status of the Finding. Can be either Active or Inactive. In addition to these, Findings can also have a Status of Duplicate, Mitigated, False Positive, Out Of Scope, Risk Accepted or Under Defect Review. These Statuses explain the State of the Finding in more detail.
	* **Type:** this field describes how the Finding was found, either via a Static (SAST) evaluation of the source code, or through a Dynamic (DAST) evaluation of the Product as it was running. This field is defined by the tool type.
	* **Location:** this field describes the related File Path to your vulnerability, if relevant.
	* **Line:** this field describes the line of code containing the vulnerability, if relevant.
	* **Date Discovered:** this field shows either the date the Finding was imported to DefectDojo, or the date the Finding was discovered by the Tool.
	* **Age:** this calculated field shows the number of days the Finding has been active.
	* **Reporter:** this is the username of the DefectDojo account who created this Finding.
	* **CWE:** this field is a link to the external CWE (Common Weakness Enumeration) definition which applies to this Finding.
	* **Vulnerability ID:** if there is a particular ID value for this vulnerability within the tool itself, it will be tracked here.
	* **EPSS Score / Percentile:** if the source data has a CWE value, DefectDojo will automatically pull an [EPSS Score](https://www.first.org/epss/) and Percentile (Exploit Prediction Scoring System). EPSS represents the likelihood that a software vulnerability can be exploited, based on real\-world exploit data. EPSS scores are updated on an ongoing basis, using the latest exploitation data from First.
	* **Found By:** This will list the scanner used to find this vulnerability.  
	​

## Example Finding Workflows

How you work with Findings in DefectDojo depends on your team’s responsibilities within your organization. Here are some examples of these processes, and how DefectDojo can help:

### Discover and Report vulnerabilities

If you’re in charge of security reporting for many different contexts, software Products or teams, DefectDojo can report on those vulnerabilities uncovered. Using the Product Hierarchy, you can organize your Finding data into the appropriate context. For example:

* Each Product in DefectDojo can have a different SLA configuration, so that you can instantly flag Findings that are discovered in Production or other highly sensitive environments.
* You can create a report directly from a **Product Type, Product, Engagement or Test** to ‘zoom in and out’ of your security context. **Tests** contain results from a single tool, **Engagements** can combine multiple Tests, **Products** can contain multiple Engagements, **Product Types** can contain multiple Products.

For more information on creating a Report, see our guides to **[Custom Reporting](/en/pro_reports/using_the_report_builder/)**.

### Triage Vulnerabilities using Finding Status

If your team needs to validate the Findings discovered, you can do so by manually applying the **Verified** status to Findings as you review them. You can also apply other statuses, such as:

* **False Positive:** A tool detected the threat, but the threat is not active in the environment.
* **Out Of Scope:** Active, but irrelevant to the current testing effort.
* **Risk Accepted:** Active, but determined not to be a priority to address until the Risk Acceptance expires.
* **Under Review:** may or may not be Active \- your team is still investigating.
* **Mitigated:** This issue has been resolved since the Finding was created.

If a tool reports a previously triaged Finding on a subsequent import, DefectDojo will remember the Finding’s previous status and update accordingly. Findings with **False Positive**, **Out Of Scope, Risk Accepted and Under Review** statuses will remain as they are, but any Finding that has been **Mitigated** will be **reactivated** to let you know that the Finding has returned to the Test environment.

### Ensure Team\-wide Consensus and Accountability with Risk Acceptances

Part of a security team’s responsibility is to collaborate with developers to prioritize and deprioritize security issue remediation. This is where Risk Acceptances come in. Adding a Risk Acceptance to a Finding allows you to:

* Store records and ‘artifact’ files on DefectDojo \- these could be emails from colleagues acknowledging the Risk Acceptance, meeting notes, or simply a written justification for accepting the risk from your own security team.
* Add an expiration date to the Risk Acceptance, so that the vulnerability can be re\-examined after a given period of time.

Any Appsec team member understands that issue mitigation can’t be prioritized exclusively by developer teams, so Risk Acceptances help you log those sensitive decisions when they are made.

### Monitor current vulnerabilities using CVEs and EPSS scores (Pro Feature)

Sometimes, the exploitability and threat posed by a known vulnerability can change based on new data. To keep your work up to date, DefectDojo Pro has partnered with First.org to maintain a database of the latest EPSS scores related to Findings. Any Findings in DefectDojo Pro will be kept up to date automatically according to their EPSS, which is directly based on the CVE of the Finding.

If a Finding’s EPSS score changes (i.e. the related Finding becomes more exploitable or less exploitable), the Severity of the Finding will adjust accordingly.

# Next Steps:

* Learn how to add or adjust data on your Findings: **[Editing Findings](../findings_workflows/editing_findings)**.
* Learn how to apply **[Risk Acceptances](../findings_workflows/risk_acceptances/)** to Findings which create a record of sensitive decisions made surrounding risk\-accepted vulnerabilities.
