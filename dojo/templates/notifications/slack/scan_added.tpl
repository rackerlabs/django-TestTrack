{% load i18n %}
{% load display_tags %}
{{ description }}
{% if url is not None %}
    
  {% blocktranslate trimmed with scan_url=url|full_url %}
    {{ test }} results have been uploaded.
    They can be viewed here: {{ scan_url }}
  {% endblocktranslate %}
{% endif %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer_notifications }}
{% endif %}
