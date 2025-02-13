---
title: "Running in Production (Open Source)"
description: "For use in Production environments, performance tweaks and backups are recommended."
draft: false
weight: 4
---

## Production use with docker compose

The docker-compose.yml file in this repository is fully functional to evaluate DefectDojo in your local environment.

Although Docker Compose is one of the supported installation methods to deploy a containerized DefectDojo in a production environment, the docker-compose.yml file is not intended for production use without first customizing it to your particular situation.

See [Running with Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) for more information how to run DefectDojo with Docker Compose.

### Database performance and backup

It is recommended to use a dedicated database server and not the preconfigured PostgreSQL database. This will improve the performance of DefectDojo.

In both cases (dedicated DB or containerized), if you are self-hosting, it is recommended that you implement and create periodic backups of your data.

### Backup of Media files

Media files for uploaded files, including threat models and risk acceptance, are stored in a docker volume. This volume needs to be backed up regularly.

### Instance size

Please read the paragraphs below about key processes tweaks.


With a separate database, the minimum recommendations
are:

-   2 vCPUs
-   8 GB of RAM
-   10 GB of disk space (remember, your database is not here \-- so
     what you have for your O/S should do). You could allocate
    a different disk than your OS\'s for potential performance
    improvements.

#### uWSGI

By default (except in `ptvsd` mode for debug purposes), uWSGI will
handle 4 concurrent connections.

Based on your resource settings, you can tweak:

-   `DD_UWSGI_NUM_OF_PROCESSES` for the number of spawned processes.
    (default 2)
-   `DD_UWSGI_NUM_OF_THREADS` for the number of threads in these
    processes. (default 2)

For example, you may have 4 processes with 6 threads each, yielding 24
concurrent connections.

#### Celery worker

By default, a single mono-process celery worker is spawned. When storing a large amount of findings, leveraging async functions (like deduplication), or both. Eventually, it is important to adjust these parameters to prevent resource starvation. 


The following variables can be changed to increase worker performance, while keeping a single celery container.

-   `DD_CELERY_WORKER_POOL_TYPE` will let you switch to `prefork`.
    (default `solo`)

When you enable `prefork`, the variables below have
to be used. see the
Dockerfile.django-* for in-file references.

-   `DD_CELERY_WORKER_AUTOSCALE_MIN` defaults to 2.
-   `DD_CELERY_WORKER_AUTOSCALE_MAX` defaults to 8.
-   `DD_CELERY_WORKER_CONCURRENCY` defaults to 8.
-   `DD_CELERY_WORKER_PREFETCH_MULTIPLIER` defaults to 128.

You can execute the following command to see the configuration:

`docker compose exec celerybeat bash -c "celery -A dojo inspect stats"`
and see what is in effect.

#### Asynchronous Import

**Please note: Asynchronous Import is currently an experimental feature.  Please exercise caution with this method as results may be inconsistent.**

Import and Re-Import can also be configured to handle uploads asynchronously to aid in 
processing especially large scans. It works by batching Findings and Endpoints by a 
configurable amount. Each batch will be be processed in separate celery tasks.

The following variables impact async imports.

-   `DD_ASYNC_FINDING_IMPORT` defaults to False
-   `DD_ASYNC_FINDING_IMPORT_CHUNK_SIZE` defaults to 100

When using asynchronous imports with dynamic scanners, Endpoints will continue to "trickle" in
even after the import has returned a successful response. This is because processing continues 
to occur after the Findings have already been imported.

To determine if an import has been fully completed, please see the progress bar in the appropriate test.

