---
title: "Configuration (Open Source)"
description: "DefectDojo is highly configurable."
draft: false
weight: 3
---

## dojo/settings/settings.dist.py

The main settings are stored in [`dojo/settings/settings.dist.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py). It is great to use this file as a reference for what can be configured, but it shouldn\'t be edited directly, because changes will be overwritten when updating DefectDojo. There are several methods to change the default settings:

### Environment variables

Most parameters can be set by environment variables. 

When you deploy DefectDojo via **Docker Compose**, you can set environment variables in [`docker-compose.yml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/docker-compose.yml). Be aware you have to set the variables for three services: `uwsgi`, `celerybeat` and `celeryworker`.

When you deploy DefectDojo in a **Kubernetes** cluster, you can set environment variables as `extraConfigs` and `extraSecrets` in [`helm/defectdojo/values.yaml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/helm/defectdojo/values.yaml).

### Environment file (not with Docker Compose or Kubernetes)

`settings.dist.py` reads environment variables from a file whose name is specified in the environment variable `DD_ENV_PATH`. If this variable is not set, the default `.env.prod` is used. The file must be located in the `dojo/settings` directory.

An example can be found in [`template_env`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-env).

### local_settings.py

`local_settings.py` can contain more complex customizations such as adding MIDDLEWARE or INSTALLED_APP entries.
This file is processed *after* settings.dist.py is processed, so you can modify settings delivered by DefectDojo out of the box.
 The file must be located in the `dojo/settings` directory. Environment variables in this file must not have the `DD_` prefix.
If the file is missing feel free to create it. Do not edit `settings.dist.py` directly.

An example can be found in [`dojo/settings/template-local_settings`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-local_settings).

In Docker Compose release mode, files in `docker/extra_settings/` (relative to the file `docker-compose.yml`) will be copied into `dojo/settings/` in the docker container on startup.

`local_settings.py` can be used in Kubernetes as well. Variable `localsettingspy` will be stored as ConfigMap and mounted to responsible location of containers.

## Configuration in the UI

Users with the superuser status can configure more options via the UI under `Configuration` / `System Settings`. 
