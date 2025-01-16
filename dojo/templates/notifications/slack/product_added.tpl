{% load i18n %}
{% load display_tags %}
{% blocktranslate trimmed with prod_url=url|full_url %}
The new product "{{ title }}" has been added. It can be viewed here: {{ prod_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer_notifications }}
{% endif %}
