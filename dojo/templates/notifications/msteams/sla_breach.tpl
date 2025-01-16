{% load i18n %}
{% load display_tags %}
{% url 'view_finding' finding.id as finding_url %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "title": "{% trans "SLA breached" %}",
        "summary": "{% trans "SLA breached" %}",
        "sections": [
            {
                "activityTitle": "DefectDojo",
                "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
                "text": "{% trans "A SLA for a finding has been breached" %}.",
                "facts": [
                    {
                        "name": "{% trans "Product" %}:",
                        "value": "{{ finding.test.engagement.product.name }}"
                    },
                    {
                        "name": "{% trans "Engagement" %}:",
                        "value": "{{ finding.test.engagement.name }}"
                    },
                    {
                        "name": "{% trans "Finding" %}:",
                        "value": "{{ finding.title }}"
                    },
                    {
                        "name": "{% trans "Severity" %}:",
                        "value": "{{ finding.severity }}"
                    },
                    {
                        "name": "{% trans "SLA age" %}:",
                        "value": "{{ sla_age }}"
                    }
            ]
        }
        {% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
            ,{
                "activityTitle": "{% trans "Disclaimer" %}",
                "text": "{{ system_settings.disclaimer_notifications }}"
            }
        {% endif %}
    ],
    "potentialAction": [
        {
            "@type": "OpenUri",
            "name": "{% trans "View" %}",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
