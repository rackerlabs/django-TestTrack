{% load i18n %}
{% load display_tags %}
{% blocktranslate trimmed with name=report.name report_url=url|full_url %}
Your report "{{ name }}" is ready. It can be downloaded here: {{ report_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer_notifications }}
{% endif %}
