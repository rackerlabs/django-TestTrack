A local_settings.py file can be placed here to override/extend the settings bundled with DefectDojo.
This folders is ignore by git and docker.

If a file if placed here, it will be copied on startup to `dojo/settings/local_settings.py`.

For an example, see [template-local_settings](../../dojo/settings/template-local_settings)

Please note this copy action could fail if you have mounted the full `dojo/` folder, but that is owned by a different user/group.
That's why this copy action only happens in docker compose release mode, and not in dev/debug/unit_tests/integration_tests modes.

For advanced usage you can also place a `settings_dist.py` or `settings.py` file. These will also be copied on startup to dojo/settings.

The files in this `docker/extra_settings` folder are *not* used by the nginx container, as this container needs the settings at build time.
