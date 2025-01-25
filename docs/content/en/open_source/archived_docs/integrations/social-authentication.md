---
title: "Authentication via OAuth2/SAML2"
description: "OAuth2/SAML2 let users authenticate against enterprise directories."
draft: false
weight: 3
exclude_search: true
---

## Auth0

In the same way as with other identity providers, it's now possible to
leverage Auth0 to authenticate users on DefectDojo.

1.  Inside your Auth0 dashboard create a new application (Applications /
    Create Application / Single Page Web Application).
2.  On the new application set the following fields:
    -   Name: "Defectdojo"
    -   Allowed Callback URLs:
        **https://the_hostname_you_have_dojo_deployed:your_server_port/complete/auth0/**
3.  Copy the following info from the application:
    -   Domain
    -   Client ID
    -   Client Secret
4.  Now, edit the settings (see [Configuration](../../open_source/installation/configuration)) with the following
    information:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED=True
    DD_SOCIAL_AUTH_AUTH0_KEY=(str, '**YOUR_CLIENT_ID_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_AUTH0_SECRET=(str,'**YOUR_CLIENT_SECRET_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_AUTH0_DOMAIN=(str, '**YOUR_AUTH0_DOMAIN_FROM_STEP_ABOVE**'),
    {{< /highlight >}}

5.  Restart DefectDojo, and you should now see a **Login with Auth0**
    button on the login page.

## Google

New to DefectDojo, a Google account can now be used for Authentication,
Authorization, and a DefectDojo user. Upon login with a Google account,
a new user will be created if one does not already exist. The criteria
for determining whether a user exists is based on the users username. In
the event a new user is created, the username is that of the Google
address without the domain. Once created, the user creation process will
not happen again as the user is recalled by its username, and logged in.
In order to make the magic happen, a Google authentication server needs
to be created. Closely follow the steps below to guarantee success.

1.  Navigate to the following address and either create a new account,
    or login with an existing one: [Google Developers
    Console](https://console.developers.google.com)
2.  Once logged in, find the key shaped button labeled **Credentials**
    on the left side of the screen. Click **Create Credentials**, and
    choose **OAuth Client ID**:

    ![image](images/google_1.png)

3.  Select **Web Applications**, and provide a descriptive name for the
    client.

    ![image](images/google_2.png)

4.  Add the pictured URLs in the **Authorized Redirect URLs** section.
    This part is very important. If there are any mistakes here, the
    authentication client will not authorize the request, and deny
    access.
5.  Once all URLs are added, finish by clicking **Create**

6. Now with the authentication client created, the **Client ID** and
   **Client Secret Key** need to be copied over to the settings.
   Click the newly created client and copy the values:

   ![image](images/google_3.png)

7. Edit the settings (see [Configuration](../../open_source/installation/configuration) with the following
   information:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_ENABLED=True,
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_KEY=(str, '**YOUR_CLIENT_ID_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET=(str, '**YOUR_CLIENT_SECRET_FROM_STEP_ABOVE**'),
    {{< /highlight >}}

   To authorize users you will need to set the following:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS = ['example.com', 'example.org']
    {{< /highlight >}}

    As an environment variable:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS = example.com,example.org
    {{< /highlight >}}

    or

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS = ['<email@example.com>']
    {{< /highlight >}}

    As an environment variable:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS = email@example.com,email2@example.com
    {{< /highlight >}}

## OKTA

In a similar fashion to that of Google, using OKTA as a OAuth2 provider
carries the same attributes and a similar procedure. Follow along below.

1.  Navigate to the following address and either create a new account,
    or login with an existing one: [OKTA Account
    Creation](https://www.okta.com/developer/signup/)
2.  Once logged in, enter the **Applications** and click **Add
    Application**:

    ![image](images/okta_1.png)

3.  Select **Web Applications**.

    ![image](images/okta_2.png)

4.  Add the pictured URLs in the **Login Redirect URLs** section. This
    part is very important. If there are any mistakes here, the
    authentication client will not authorize the request, and deny
    access. Check the **Implicit** box as well.

    ![image](images/okta_3.png)

5.  Once all URLs are added, finish by clicking **Done**.

6.  Return to the **Dashboard** to find the **Org-URL**. Note this value
    as it will be important in the settings file.

    ![image](images/okta_4.png)

7.  Now, with the authentication client created, the **Client ID** and
    **Client Secret** Key need to be copied over to the settings.
    Click the newly created client and copy the values:

    ![image](images/okta_5.png)

8. Edit the settings (see [Configuration](../../open_source/installation/configuration)) with the following
   information:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_OKTA_OAUTH2_ENABLED=True,
    DD_SOCIAL_AUTH_OKTA_OAUTH2_KEY=(str, '**YOUR_CLIENT_ID_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_SECRET=(str, '**YOUR_CLIENT_SECRET_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_API_URL=(str, 'https://{your-org-url}/oauth2'),
    {{< /highlight >}}

If during the login process you get the following error: *The
'redirect_uri' parameter must be an absolute URI that is whitelisted
in the client app settings.* and the `redirect_uri` HTTP
GET parameter starts with `http://` instead of
`https://` you need to add
`SOCIAL_AUTH_REDIRECT_IS_HTTPS = True` in the settings.

## Azure Active Directory
### Azure AD Configuration
You can now use your corporate Azure Active Directory to authenticate
users to Defect Dojo. Users will be using your corporate Azure AD
account (A.K.A. Office 365 identity) to authenticate via OAuth, and all
the conditional access rules and benefits from Azure Active Directory
will also apply to the Defect Dojo Authentication. Once the user signs
in, it will try to match the UPN of the user to an existing e-mail from
a user in Defect Dojo, and if no match is found, a new user will be
created in Defect Dojo, associated with the unique id/value of the user
provided by your Azure AD tenant. Then, you can assign roles to this
user, such as 'superuser'.

1.  Navigate to the following address and follow instructions to create
    a new app registration

    -   <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app>

2.  Once you register an app, take note of the following information:

    -   **Application (client) ID**
    -   **Directory (tenant) ID**
    -   Under Certificates & Secrets, create a new **Client Secret**

3.  Under Authentication > Redirect URIs, add a *WEB* type of uri where
    the redirect points to

    -   <http://localhost:8080/complete/azuread-tenant-oauth2/>
    -   **OR**
    -   **https://the_hostname_you_have_dojo_deployed:your_server_port/complete/azuread-tenant-oauth2/**

4.  Edit the settings (see [Configuration](../../open_source/installation/configuration)) with the following
    information:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY=(str, 'YOUR_APPLICATION_ID_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET=(str, 'YOUR_CLIENT_SECRET_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID=(str, 'YOUR_DIRECTORY_ID_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_ENABLED = True
    {{< /highlight >}}

5.  Restart your Dojo, and you should now see a **Login with Azure AD**
    button on the login page which should *magically* work

### Automatic Import of User-Groups
To import groups from Azure AD users, the following environment variable needs to be set:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GET_GROUPS=True
    {{< /highlight >}}

This will ensure the user is added to all the groups found in the Azure AD Token. Any missing groups will be created in DefectDojo (unless filtered). This group synchronization allows for product access via groups to limit the products a user can interact with.

The Azure AD token returned by Azure will also need to be configured to include group IDs. Without this step, the
token will not contain any notion of a group, and the mapping process will report that the current user is not a member of any
groups. To update the format of the token, add a group claim that applies to whatever group type you are using.
If unsure of what type that is, select `All Groups`. Do not activate `Emit groups as role claims` within the Azure AD
"Token configuration" page.

Application API permissions need to be updated with the `Group.Read.All` permission so that groups can be read on behalf
of the user that has successfully signed in.

To limit the amount of groups imported from Azure AD, a regular expression can be used as the following:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GROUPS_FILTER='^team-.*' # or 'teamA|teamB|groupC'
    {{< /highlight >}}

### Automatic Cleanup of User-Groups

To prevent authorization creep, old Azure AD groups a user is not having anymore can be deleted with the following environment parameter:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS=True
    {{< /highlight >}}

When a user is removed from a given group in Azure AD, they will also be removed from the corresponding group in DefectDojo.
If there is a group in DefectDojo, that no longer has any members, it will be left as is for record purposes.

## Gitlab

In a similar fashion to that of Google and OKTA, using Gitlab as a
OAuth2 provider carries the same attributes and a similar procedure.
Follow along below.

1. Navigate to your Gitlab settings page and got to the Applications
    section

    -   <https://gitlab.com/profile/applications>
    -   **OR**
    -   **https://the_hostname_you_have_gitlab_deployed:your_gitlab_port/profile/applications**

2. Choose a name for your application
3. For the Redirect URI, enter the DefectDojo URL with the following
    format

    -   **https://the_hostname_you_have_dojo_deployed:your_server_port/complete/gitlab/**

4. Edit the settings (see [Configuration](../../open_source/installation/configuration)) with the following
    information:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GITLAB_KEY=(str, 'YOUR_APPLICATION_ID_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_GITLAB_SECRET=(str, 'YOUR_SECRET_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_GITLAB_API_URL=(str, 'https://gitlab.com'),
    DD_SOCIAL_AUTH_GITLAB_OAUTH2_ENABLED = True
    {{< /highlight >}}

    Additionally, if you want to import your Gitlab projects as DefectDojo
    products, add the following line to your settings:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GITLAB_PROJECT_AUTO_IMPORT = True
    {{< /highlight >}}

    **Important:** if you enable this setting on already working instance with gitlab integrations, it will require new grant "read_repository" by user

5. Restart DefectDojo, and you should now see a **Login with Gitlab**
    button on the login page.

## Keycloak
There is also an option to use Keycloak as OAuth2 provider in order to authenticate users to Defect Dojo, also by using
the social-auth plugin.

Here are suggestion on how to configure Keycloak and DefectDojo:

### Configure Keycloak
(assuming you already have an existing realm, otherwise create one)
1. Navigate to your keycloak realm and add a new client of type openid-connect. Choose a name for the client id and use this value below for DD_SOCIAL_AUTH_KEYCLOAK_KEY).
2. In the client settings:
   * Set `access type` to `confidential`
   * Under `valid Redirect URIs`, add the URI to your defect dojo installation, e.g. 'https://<YOUR_DD_HOST>/*'
   * Under `web origins`, add the same (or '+')
   * Under `Fine grained openID connect configuration` -> `user info signed response algorithm`: set to `RS256`
   * Under `Fine grained openID connect configuration` -> `request object signature algorithm`: set to `RS256`
   * -> save these settings in keycloak (hit save button)
3. Under `Scope` -> `Full Scope Allowed` set to `off`
4. Under `mappers` -> add a custom mapper here:
   * Name: `aud`
   * Mapper type: `audience`
   * Included audience: select your client/client-id here
   * Add ID to token: `off`
   * Add access to token: `on`
5. Under `credentials`: copy the secret (and use as DD_SOCIAL_AUTH_KEYCLOAK_SECRET below)
6. In your realm settings -> keys: copy the "Public key" (signing key) (use for DD_SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY below)
7. In your realm settings -> general -> endpoints: look into openId endpoint configuration
   and look up your authorization and token endpoint (use them below)

### Configure Defect Dojo
Edit the settings (see [Configuration](../../open_source/installation/configuration)) with the following
   information:

   {{< highlight python >}}
   DD_SESSION_COOKIE_SECURE=True,
   DD_CSRF_COOKIE_SECURE=True,
   DD_SECURE_SSL_REDIRECT=True,
   DD_SOCIAL_AUTH_KEYCLOAK_OAUTH2_ENABLED=True,
   DD_SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY=(str, '<your realm public key>'),
   DD_SOCIAL_AUTH_KEYCLOAK_KEY=(str, '<your client id>'),
   DD_SOCIAL_AUTH_KEYCLOAK_SECRET=(str, '<your keycloak client credentials secret>'),
   DD_SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL=(str, '<your authorization endpoint>'),
   DD_SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL=(str, '<your token endpoint>')
   {{< /highlight >}}

or, alternatively, for helm configuration, add this to the `extraConfig` section:

```yaml
DD_SESSION_COOKIE_SECURE: 'True'
DD_CSRF_COOKIE_SECURE: 'True'
DD_SECURE_SSL_REDIRECT: 'True'
DD_SOCIAL_AUTH_KEYCLOAK_OAUTH2_ENABLED: 'True'
DD_SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY: '<your realm public key>'
DD_SOCIAL_AUTH_KEYCLOAK_KEY: '<your client id>'
DD_SOCIAL_AUTH_KEYCLOAK_SECRET: '<your keycloak client credentials secret>'
DD_SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL: '<your authorization endpoint>'
DD_SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL: '<your token endpoint>'
```

Optionally, you *can* set `DD_SOCIAL_AUTH_KEYCLOAK_LOGIN_BUTTON_TEXT` in order to customize the login button's text caption.

## GitHub Enterprise
1.  Navigate to your GitHub Enterprise Server and follow instructions to create a new OAuth App [https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app)
2. Choose a name for your application
3. For the Redirect URI, enter the DefectDojo URL with the following
    format
    -   **https://the_hostname_you_have_dojo_deployed:your_server_port/complete/github-enterprise/**
4. Edit the settings (see [Configuration](../../open_source/installation/configuration)) with the following
    information:
    {{< highlight python >}}
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_KEY=(str, 'GitHub Enterprise OAuth App Client ID'),
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_SECRET=(str, 'GitHub Enterprise OAuth App Client Secret'),
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_URL=(str, 'https://github.<your_company>.com/'),
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_API_URL=(str, 'https://github.<your_company>.com/api/v3/'),
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_OAUTH2_ENABLED = True,
    {{< /highlight >}}
5. Restart DefectDojo, and you should now see a **Login with GitHub Enterprise**
    button on the login page.

## SAML 2.0
In a similar direction to OAuth, this SAML addition provides a more secure
perogative to SSO. For definitions of terms used and more information,
see the plugin [plugin homepage](https://github.com/IdentityPython/djangosaml2).

1.  Navigate to your SAML IdP and find your metadata
2.  Edit the settings (see [Configuration](../../open_source/installation/configuration)) with the following
    information:

    {{< highlight python >}}
    DD_SAML2_ENABLED=(bool, **True**),
    # SAML Login Button Text
    DD_SAML2_LOGIN_BUTTON_TEXT=(str, 'Login with SAML'),
    # If the metadata can be accessed from a url, try the
    DD_SAML2_METADATA_AUTO_CONF_URL=(str, '<https://your_IdP.com/metadata.xml>'),
    # Otherwise, downlaod a copy of the metadata into an xml file, and
    # list the path in DD_SAML2_METADATA_LOCAL_FILE_PATH
    DD_SAML2_METADATA_LOCAL_FILE_PATH=(str, '/path/to/your/metadata.xml'),
    # Fill in DD_SAML2_ATTRIBUTES_MAP to corresponding SAML2 userprofile attributes provided by your IdP
    DD_SAML2_ATTRIBUTES_MAP=(dict, {
        # format: SAML attrib:django_user_model
        'Email': 'email',
        'UserName': 'username',
        'Firstname': 'first_name',
        'Lastname': 'last_name'
    }),
    # May configure the optional fields
    {{< /highlight >}}

NOTE: *DD_SAML2_ATTRIBUTES_MAP* in k8s can be referenced as extraConfig (e.g. `DD_SAML2_ATTRIBUTES_MAP: 'Email'='email', 'Username'='username'...`)

NOTE: *DD_SITE_URL* might also need to be set depending on the choices you make with the metadata.xml provider. (File versus URL).

4.  Checkout the SAML section in dojo/`dojo/settings/settings_dist.py` and verfiy if it fits your requirement. If you need help, take a look at the [plugin
documentation](https://djangosaml2.readthedocs.io/contents/setup.html#configuration).

5.  Restart DefectDojo, and you should now see a **Login with SAML** button (default setting of DD_SAML2_LOGIN_BUTTON_TEXT) on the login page.

NOTE: In the case when IDP is configured to use self signed (private) certificate,
than CA needs to be specified by define environments variable
REQUESTS_CA_BUNDLE that points to the path of private CA certificate.

### Advanced Configuration
The [https://github.com/IdentityPython/djangosaml2](djangosaml2) plugin has a lot of options. For details take a look at the [plugin
documentation](https://djangosaml2.readthedocs.io/contents/setup.html#configuration). All default options in DefectDojo can overwritten in the local_settings.py. If you want to change the organization name, you can add the following lines:

{{< highlight python >}}
if SAML2_ENABLED:
    SAML_CONFIG['contact_person'] = [{
        'given_name': 'Extra',
        'sur_name': 'Example',
        'company': 'DefectDojo',
        'email_address': 'dummy@defectdojo.com',
        'contact_type': 'technical'
    }]
    SAML_CONFIG['organization'] = {
        'name': [('DefectDojo', 'en')],
        'display_name': [('DefectDojo', 'en')],
    },
{{< /highlight >}}

### Migration from django-saml2-auth
Up to relase 1.15.0 the SAML integration was based on [https://github.com/fangli/django-saml2-auth](django-saml2-auth). Which the switch to djangosaml2 some parameters has changed:

* DD_SAML2_ASSERTION_URL: not necessary any more - automatically generated
* DD_SAML2_DEFAULT_NEXT_URL: not necessary any more - default forwarding from defectdojo is used
* DD_SAML2_NEW_USER_PROFILE: not possible any more - default profile is used, see User Permissions
* DD_SAML2_ATTRIBUTES_MAP: Syntax has changed
* DD_SAML2_CREATE_USER: Default value changed to False, to avoid security breaches

## RemoteUser

This implementation is suitable if the DefectDojo instance is placed behind HTTP Authentication Proxy.
Dojo expects that the proxy will perform authentication and pass HTTP requests to the Dojo instance with filled HTTP headers.
The proxy should check if an attacker is not trying to add a malicious HTTP header and bypass authentication.

Values which need to be set:

* `DD_AUTH_REMOTEUSER_ENABLED` - Needs to be set to `True`
* `DD_AUTH_REMOTEUSER_USERNAME_HEADER` - Name of the header which contains the username
* `DD_AUTH_REMOTEUSER_EMAIL_HEADER`(optional) - Name of the header which contains the email
* `DD_AUTH_REMOTEUSER_FIRSTNAME_HEADER`(optional) - Name of the header which contains the first name
* `DD_AUTH_REMOTEUSER_LASTNAME_HEADER`(optional) - Name of the header which contains the last name
* `DD_AUTH_REMOTEUSER_GROUPS_HEADER`(optional) - Name of the header which contains the comma-separated list of groups; user will be assigned to these groups (missing groups will be created)
* `DD_AUTH_REMOTEUSER_GROUPS_CLEANUP`(optional) - Same as [#automatic-import-of-user-groups](AzureAD implementation)
* `DD_AUTH_REMOTEUSER_TRUSTED_PROXY` - Comma separated list of proxies; Simple IP and CIDR formats are supported
* `DD_AUTH_REMOTEUSER_LOGIN_ONLY`(optional) - Check [Django documentation](https://docs.djangoproject.com/en/3.2/howto/auth-remote-user/#using-remote-user-on-login-pages-only)

*WARNING:* There is possible spoofing of headers (for all `DD_AUTH_REMOTEUSER_xxx_HEADER` values). Read Warning in [Django documentation](https://docs.djangoproject.com/en/3.2/howto/auth-remote-user/#configuration)

## User Permissions

When a new user is created via the social-auth, only the default permissions are active. This means that the newly created user does not have access to add, edit, nor delete anything within DefectDojo. There are two parameters in the System Settings to influence the permissions for newly created users:

### Default group

When both the parameters `Default group` and `Default group role` are set, the new user will be a member of the given group with the given role, which will give him the respective permissions.

### Groups from Identity Providers

Some Identity Providers are able to send list of groups to which should user belongs. This functionality is implemented only for Identity Providers mentioned below. For all others, we will be more than happy for contribution (hint: functions `assign_user_to_groups` and `cleanup_old_groups_for_user` from [`dojo/pipeline.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/pipeline.py) might be useful).

- [Azure](#automatic-import-of-user-groups): Check `DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GET_GROUPS` and `DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS`
- [RemoteUser](#remoteuser): Check `DD_AUTH_REMOTEUSER_GROUPS_HEADER` and `DD_AUTH_REMOTEUSER_GROUPS_CLEANUP`

## Login speed-up

You can bypass the login form if you are only using SSO/Social authentication for login in by enabling these two environment variables:

```yaml
DD_SOCIAL_LOGIN_AUTO_REDIRECT: "true"
DD_SOCIAL_AUTH_SHOW_LOGIN_FORM: "false"
```

### Login form fallback

If you are using "login speed-up", it can be useful to be able to login by the standard way, for example when an admin
user needs to log in because of a change of some settings or permissions. This feature is accessible by a visiting the URL
`<DD_HOST>/login?force_login_form`.


## Other Providers

In an effort to accommodate as much generality as possible, it was
decided to implement OAuth2 with the
[social-auth](https://github.com/python-social-auth/social-core/tree/master/social_core/backends)
ecosystem as it has a library of compatible providers with documentation
of implementation. Conveniently, each provider has an identical
procedure of managing the authenticated responses and authorizing access
within a given application. The only difficulty is creating a new
authentication client with a given OAuth2 provider.
