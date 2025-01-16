{% load i18n %}
{% load display_tags %}
{{ description|safe }}
{% if url is not None %}
{% blocktranslate trimmed with event_url=url|full_url %}
    More information on this event can be found here: {{ event_url }}
{% endblocktranslate %}
{% endif %}
{% if system_settings.disclaimer_notifications|length %}

    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer_notifications }}
{% endif %}
