{% load i18n %}
{% load display_tags %}
{% blocktranslate trimmed with name=engagement.name eng_product=engagement.product eng_url=url|full_url %}
The engagement "{{ name }}" has been created in the product "{{ eng_product }}". It can be viewed here: {{ eng_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer_notifications }}
{% endif %}
