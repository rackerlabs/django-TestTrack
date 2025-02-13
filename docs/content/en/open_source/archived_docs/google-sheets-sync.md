---
title: "Google Sheets synchronisation"
description: "Export finding details to Google Sheets and upload changes from Google Sheets."
draft: false
weight: 8
exclude_search: true
---

**Please note - the Google Sheets feature has been deprecated as of DefectDojo version 2.21.0 - these documents are for reference only.**

With the Google Sheets sync feature, DefectDojo allow the users to
export all the finding details of each test into a separate Google
Spreadsheet. Users can review and edit finding details via Google
Spreadsheets. Also, they can add new notes to findings and edit existing
notes using the Google Spreadsheet. After reviewing and updating the
finding details in the Google Spreadsheet, the user can import (sync)
all the changes done via the Google Spreadsheet into DefectDojo
database.

### Configuration

Creating a project and a Service Account

1.  Go to the [Service Accounts
    page](https://console.developers.google.com/iam-admin/serviceaccounts/).
2.  Create a new project for DefectDojo and select it.
3.  Click **+CREATE SERVICE ACCOUNT**, enter a name and description
    for the service account. You can use the default service account
    ID, or choose a different, unique one. When done click Create.
4.  The **Service account permissions (optional)** section that
    follows is not required. Click **Continue**.
5.  On the **Grant users access to this service account** screen,
    scroll down to the **Create key** section. Click **+Create
    key**.
6.  In the side panel that appears, select the format for your key
    as **JSON**
7.  Click **Create**. Your new public/private key pair is generated
    and downloaded to your machine.

Enabling the required APIs

1.  Go to the [Google API
    Console](https://console.developers.google.com//).
2.  From the projects list, select the project created for
    DefectDojo.
3.  If the APIs & services page isn\'t already open, open the
    console left side menu and select **APIs & services**, and then
    select **Library**.
4.  **Google Sheets API** and **Google Drive API** should be
    enabled. Click the API you want to enable. If you need help
    finding the API, use the search field.
5.  Click **ENABLE**.

Configurations in DefectDojo

1.  Click \'Configuration\' from the left hand menu.
2.  Click \'Google Sheets Sync\'.
3.  Fill the form.

    ![Google Sheets Sync Configuration Page](images/google_sheets_sync_1.png)

    * Upload the downloaded json file into the **Upload
      Credentials file** field.

    * Drive Folder Id:

        * Create a folder inside the Google drive of the same
          Gmail account used to create the service account.
        * Get the **client\_email** from the downloaded json file
          and share the created drive folder with client\_email
          giving **edit access**.
        * Extract the folder id from the URL and insert it as the
          **Drive Folder Id**:

          ![Extracting Drive Folder ID](images/google_sheets_sync_2.png)

    * Tick the **Enable Service** check box. (**Optional** as this
      has no impact on the configuration, but you must set it to
      true inorder to use the feature. Service can be enabled or
      disabled at any point after the configuration using this
      check box)

    * For each field in the finding table there are two related
      entries in the form:

        * In the drop down, select Hide if the column needs to be
          hidden in the Google Sheet, else select any other option
          based on the length of the entry that goes under the
          column.
        * If the column needs to be protected in the Google Sheet,
          tick the check box. Otherwise leave it unchecked.

4.  Click \'Submit\'.

Admin has the privilege to revoke the access given to DefectDojo to
access Google Sheets and Google Drive data by simply clicking the
**Revoke Access** button.

### Using Google Sheets Sync Feature

Before a user can export a test to a Google Spreadsheet, admin must
Configure Google Sheets Sync and **Enable** sync feature.Depending on
whether a Google Spreadsheet exists for the test or not, the User
interface displayed will be different.

If a Google Spreadsheet does not exist for the Test:

![Create Google Sheet Button](images/google_sheets_sync_3.png)

If a Google Spreadsheet is already created for the Test:

![Sync Google Sheet Button](images/google_sheets_sync_4.png)

After creating a Google Spreadsheet, users can review and edit Finding
details using the Google Sheet. If any change is done in the Google
Sheet users can click the **Sync Google Sheet** button to get those
changes into DefectDojo.
