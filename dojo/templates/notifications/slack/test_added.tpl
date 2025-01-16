{% load i18n %}
{% load display_tags %}
{% blocktranslate trimmed with eng_name=engagement.name eng_product=engagement.product title=test.title test_type=test.test_type test_url=url|full_url %}
New test added for engagement {{eng_name }} in product {{ eng_product}}.
Title: {{title}}
Type: {{ test_type }}
You can find details here: {{ test_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer_notifications }}
{% endif %}
