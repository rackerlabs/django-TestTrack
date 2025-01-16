{% load i18n %}{% blocktranslate trimmed %}
User {{ user }} jotted a note on {{ section }}:

{{ note }}

Full details of the note can be reviewed at {{ url }}
{% endblocktranslate %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer_notifications }}
{% endif %}
