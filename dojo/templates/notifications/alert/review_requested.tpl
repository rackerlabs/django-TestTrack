{% load i18n %}
{% load display_tags %}
{% blocktranslate trimmed %}
    User {{ requested_by }} has requested that the following users review the finding "{{ finding }}" for accuracy:
{% endblocktranslate %}

{% for user in reviewers %}
    - {{ user.get_full_name }}    
{% endfor %}

{% blocktranslate trimmed %}
    {{ note }}
{% endblocktranslate %}

{% trans "Full details of the finding can be reviewed at" %} {{ url|full_url }}

{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}    
    {% trans "Disclaimer:" %}
    {{ system_settings.disclaimer_notifications }}
{% endif %}