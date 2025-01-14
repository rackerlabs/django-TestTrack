---
title: "Authentication via LDAP"
description: "Authenticate users using LDAP"
draft: false
weight: 4
---

## LDAP Authentication

Out of the box Defect Dojo does not support LDAP authentication.

*However*, since Defect Dojo is built using Django, it isn't too difficult to add support for LDAP.
So long as you don't mind building your own Docker images...

We will need to modify a grand total of 4-5 files, depending on how you want to pass Dojo your LDAP secrets.

 - Dockerfile.django-*
 - Dockerfile.nginx-*
 - requirements.txt
 - local_settings.py
 - docker-compose.yml *(Optional)*


#### Dockerfile modifications

In both Dockerfile.django and Dockerfile.nginx, you want to add the following lines to the apt-get install layers:

```bash
libldap2-dev \
libsasl2-dev \
ldap-utils \
```


#### requirements.txt

Please check for the latest version of these requirements at the time of implementation on pypi.org and use those if you can.

- [python-ldap](https://pypi.org/project/python-ldap/)
- [django-auth-ldap](https://pypi.org/project/django-auth-ldap/)

Otherwise add the following to requirements.txt:

```python
python-ldap==3.4.2
django-auth-ldap==4.1.0
```


#### local_settings.py

Find the settings file (hint: check in `/dojo/settings/settings.py` for instructions for how to use `/dojo/settings/local_settings.py`, if the file does not already exist) and add the following:

At the top of the file:
```python
import ldap
from django_auth_ldap.config import LDAPSearch, GroupOfNamesType
```

Then further down add LDAP settings to the env dict:
```python
# LDAP
DD_LDAP_SERVER_URI=(str, 'ldap://ldap.example.com'),
DD_LDAP_BIND_DN=(str, ''),
DD_LDAP_BIND_PASSWORD=(str, ''),
```

Then under the env dict add:
```python
AUTH_LDAP_SERVER_URI = env('DD_LDAP_SERVER_URI')
AUTH_LDAP_BIND_DN = env('DD_LDAP_BIND_DN')
AUTH_LDAP_BIND_PASSWORD = env('DD_LDAP_BIND_PASSWORD')
AUTH_LDAP_USER_SEARCH = LDAPSearch(
    "ou=Groups,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=%(user)s)"
)

AUTH_LDAP_USER_ATTR_MAP = {
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail",
}
```
Please make sure to customise all of the LDAP search variables to match your company's configuration.


For additional group controls you can add:
```python
# Set up the basic group parameters.
AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
    "dc=example,dc=com",
    ldap.SCOPE_SUBTREE,
    "(objectClass=groupOfNames)",
)
AUTH_LDAP_GROUP_TYPE = GroupOfNamesType(name_attr="cn")

# Simple group restrictions
AUTH_LDAP_REQUIRE_GROUP = "cn=DD_USER_ACTIVE,ou=Groups,dc=example,dc=com"

AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    "is_active": "cn=DD_USER_ACTIVE,ou=Groups,dc=example,dc=com",
    "is_staff": "cn=DD_USER_STAFF,ou=Groups,dc=example,dc=com",
    "is_superuser": "cn=DD_USER_ADMIN,ou=Groups,dc=example,dc=com",
}
```

Then also add `'django_auth_ldap.backend.LDAPBackend'` to the `AUTHENTICATION_BACKENDS` variable, for example:
```python
AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.RemoteUserBackend',
    'django.contrib.auth.backends.ModelBackend',
)
```

Read the docs for Django Authentication with LDAP here: https://django-auth-ldap.readthedocs.io/en/latest/

#### docker-compose.yml

In order to pass the variables to the local_settings.py file via docker, it's a good idea to add these to the docker compose file.

You can do this by adding the following variables to the environment section for the uwsgi image:
```yaml
DD_LDAP_SERVER_URI: "${DD_LDAP_SERVER_URI:-ldap://ldap.example.com}"
DD_LDAP_BIND_DN: "${DD_LDAP_BIND_DN:-}"
DD_LDAP_BIND_PASSWORD: "${DD_LDAP_BIND_PASSWORD:-}"
```

Alternatively you can set these values in a local_settings.py file.
