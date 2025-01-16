{% load display_tags %}
---
description: "{{ description | default_if_none:'' }}"
title: "{{ title | default_if_none:'' }}"
user: {{ user | default_if_none:'' }}
{% if url %}
url_ui:  {{ url|full_url }}
{% endif %}
{% if url_api %}
url_api:  {{ url_api|full_url }}
{% endif %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
disclaimer:  {{ system_settings.disclaimer_notifications }}
{% endif %}
