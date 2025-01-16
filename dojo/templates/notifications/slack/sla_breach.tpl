{% load i18n %}
{% load display_tags %}
{% blocktranslate trimmed with id=finding.id product_name=finding.test.engagement.product title=finding.title severity=finding.severity sla_url=url|full_url %}
SLA breach alert for finding {{ id }} in product {{ product_name }}. Relative days count to SLA due date: {{sla_age}}.
Title: {{title}}
Severity: {{severity}}
You can find details here: {{ sla_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer_notifications }}
{% endif %}
