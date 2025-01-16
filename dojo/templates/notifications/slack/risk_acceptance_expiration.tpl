{% load i18n %}
{% load display_tags %}
{{ description }}

{% if risk_acceptance.is_expired %}
    {% trans "Risk Acceptance Expired" %}
{% else %}
    {% trans "Risk Acceptance Will Expire Soon" %}
{% endif %}

{% blocktranslate trimmed with risk_url=risk_acceptance_url|full_url %}
Risk Acceptance can be viewed here: {{ risk_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer_notifications }}
{% endif %}
