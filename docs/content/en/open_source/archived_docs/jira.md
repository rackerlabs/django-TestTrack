---
title: "JIRA integration"
description: "Bidirectional integration of DefectDojo findings with Jira issues."
draft: false
weight: 4
exclude_search: true
---

DefectDojo\'s JIRA integration is bidirectional. You may push findings
to JIRA and share comments. If an issue is closed in JIRA it will
automatically be closed in Dojo.

**NOTE:** These steps will configure the necessary webhook in JIRA and add JIRA integration into DefectDojo. This isn\'t sufficient by itself, you will need to configure products and findings to push to JIRA. On a product\'s settings page you will need to define a:

-   Project Key (and this project must exist in JIRA)
-   JIRA Configuration (select the JIRA configuration that you
        create in the steps below)
-   Component (can be left blank)

Then elect (via tickbox) whether you want to \'Push all issues\',
\'Enable engagement epic mapping\' and/or \'Push notes\'. Then click on
\'Submit\'.

If creating a Finding, ensure to tick \'Push to jira\' if desired.

Enabling the Webhook
--------------------

1.  Visit <https://>\<**YOUR JIRA URL**\>/plugins/servlet/webhooks
2.  Click \'Create a Webhook\'
3.  For the field labeled \'URL\' enter: <https://>\<**YOUR DOJO
    DOMAIN**\>/jira/webhook/<**YOUR GENERATED WEBHOOK SECRET**>
    This value can be found under Defect Dojo System settings
4.  Under \'Comments\' enable \'Created\'. Under Issue enable
    \'Updated\'.

Configurations in Dojo
----------------------

1.  Navigate to the System Settings from the menu on the left side
    or by directly visiting \<your url\>/system\_settings.
2.  Enable \'Enable JIRA integration\' and click submit.
3.  For the webhook created in Enabling the Webhook, enable
    \'Enable JIRA web hook\' and click submit.

Adding JIRA to Dojo
-------------------

1.  Click \'JIRA\' from the left hand menu.
2.  Select \'Add Configuration\' from the drop-down.
3.  For JIRA Server: 
    
    Enter the _Username_ & _Password_. A _Username_ and JIRA _Personal Access Token_ will not necessarily work.
    
    For JIRA Cloud:
    
    Enter _Email Address_ & [API token for Jira](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)
4.  To obtain the \'open status key\' and \'closed status key\'
    visit <https://>\<**YOUR JIRA
    URL**\>/rest/api/latest/issue/\<**ANY VALID ISSUE
    KEY**\>/transitions?expand=transitions.fields
5.  The \'id\' for \'Todo\' should be filled in as the \'open status
    key\'
6.  The \'id\' for \'Done\' should be filled in as the \'closed
    status key\'

To obtain \'epic name id\': If you have admin access to JIRA:

1.  visit: <https://>\<**YOUR JIRA
    URL**\>/secure/admin/ViewCustomFields.jspa
2.  Click on the cog next to \'Epic Name\' and select view.
3.  The numeric value for \'epic name id\' will be displayed in the
    URL
4.  **Note**: dojojira uses the same celery functionality as
    reports. Make sure the celery runner is setup correctly as
    described:
    <https://documentation.defectdojo.com/basics/features/#reports>

Or

1.  login to JIRA
2.  visit <https://yourjiraurl/rest/api/2/field> and use control+F
    or grep to search for \'Epic Name\' it should look something
    like this:

{
    "id":"customfield_122",
    "key":"customfield_122",
    "name":"Epic Name",
    "custom":true,
    "orderable":true,
    "navigable":true,
    "searchable":true,
    "clauseNames":"cf[122]",
    "Epic Name"\],
    "schema":{"type":"string","custom":"com.pyxis.greenhopper.jira:gh-epic-label","customId":122}
}

**In the above example 122 is the number needed**

## Customize JIRA issue description

By default Defect Dojo uses the `dojo/templates/issue-trackers/jira_full/jira-description.tpl` template to render the description of the 'to be' created JIRA issue.
This file can be modified to your needs, rebuild all containers afterwards. There's also a more limited template available, which can be chosen when
configuring a JIRA Instance or JIRA Project for a Product or Engagement:

![image](images/jira_issue_templates.png)

Any folder added to  `dojo/templates/issue-trackers/` will be added to the dropdown (after rebuilding/restarting the containers).

## Engagement Epic Mapping

If creating an Engagement, ensure to tick 'Enable engagement epic mapping' if desired. This can also be done after engagement creation on the edit engagement page.
This will create an 'Epic' type issue within Jira. All findings in the engagement pushed to Jira will have a link to this Epic issue.
If Epic Mapping was enabled after associated findings have already been pushed to Jira, simply pushing them again will link the Jira issue to the Epic issue.

## Pushing findings

Findings can be pushed to Jira in a number of ways:

1. When importing scanner reports, select 'Push to JIRA' to push every single finding in the report to Jira
2. When creating a new finding, select 'Push to JIRA' and submit. This will create the finding in DefectDojo and Jira simultaneously
3. If a finding already exist, visit the edit finding page and find the 'Push to JIRA' tick box at the bottom
4. When viewing a list of findings, select each relevant tick boxes to the left of the finding, and click the 'Bulk Edit' button at the top. find 'Push to JIRA' at the bottom of the menu

## Status Sync

DefectDojo will try to keep the status in sync with the status in JIRA
using the Close and Reopen transition IDs configured for each JIRA instance. This
will only work if your workflow in JIRA allows the Close transition to be
performed from every status a JIRA issue can be in.

## Known Issues

The Risk Acceptance feature
in DefectDojo will (for that reason) not (yet) try to sync statuses. A
comment will be pushed to JIRA if a finding is risk accepted or
unaccepted. Contributions are welcome to enhance the integration.

## Status reconciliation

Sometimes JIRA is down, or Defect Dojo is down, or there was bug in a webhook. In this case
JIRA can become out of sync with Defect Dojo. If this is the case for lots of issues, manual reconciliation
might not be feasible. For this scenario there is the management command 'jira_status_reconciliation'.

{{< highlight bash >}}
usage: manage.py jira_status_reconciliation [-h] [--mode MODE] [--product PRODUCT] [--engagement ENGAGEMENT] [--dryrun] [--version] [-v {0,1,2,3}]

Reconcile finding status with JIRA issue status, stdout will contain semicolon seperated CSV results.
Risk Accepted findings are skipped. Findings created before 1.14.0 are skipped.

optional arguments:
  -h, --help            show this help message and exit
  --mode MODE           - reconcile: (default)reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change
                        timestamp in both systems to determine which one is the correct status
                        - push_status_to_jira: update JIRA status for all JIRA issues
                        connected to a Defect Dojo finding (will not push summary/description, only status)
                        - import_status_from_jira: update Defect Dojo
                        finding status from JIRA
  --product PRODUCT     Only process findings in this product (name)
  --engagement ENGAGEMENT
                        Only process findings in this product (name)
  --dryrun              Only print actions to be performed, but make no modifications.
  -v {0,1,2,3}, --verbosity {0,1,2,3}
                        Verbosity level; 0=minimal output, 1=normal output, 2=verbose output, 3=very verbose output
{{< /highlight >}}

This can be executed from the uwsgi docker container using:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation'
{{< /highlight >}}

DEBUG output can be obtains via `-v 3`, but only after increasing the logging to DEBUG level in your settings.dist.py or local_settings.py file

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation -v 3'
{{< /highlight >}}

At the end of the command a semicolon seperated CSV summary will be printed. This can be captured by redirecting stdout to a file:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation > jira_reconciliation.csv'
{{< /highlight >}}


## Troubleshooting JIRA integration

JIRA actions are typically performed in the celery background process.
Errors are logged as alerts/notifications to be seen on the top right of
the DefectDojo UI and in stdout of the celery workers.
