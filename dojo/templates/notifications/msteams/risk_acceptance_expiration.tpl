{% load i18n %}
{% load display_tags %}
{% url 'view_test' test.id as test_url %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    {% if risk_acceptance.is_expired %}
        "title": "{% trans "Risk Acceptance Expired" %}",
        "summary": "{% trans "Risk Acceptance Expired" %}",
    {% else %}
        "title": "{% trans "Risk Acceptance Will Expire Soon" %}",
        "summary": "{% trans "Risk Acceptance Will Expire Soon" %}",
    {% endif %}
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            {% if risk_acceptance.is_expired %}
                "text": "{% blocktranslate with accepted_findings=risk_acceptance.accepted_findings.all|length exp_date=risk_acceptance.expiration_date_handled|date %}Risk acceptance {{ risk_acceptance }} with {{ accepted_findings }} has expired {{ exp_date }}{% endblocktranslate %}",
            {% else %}
                "text": "{% blocktranslate with accepted_findings=risk_acceptance.accepted_findings.all|length exp_date=risk_acceptance.expiration_date|date %}Risk acceptance {{ risk_acceptance }} with {{ accepted_findings }} will expire {{ exp_date }}{% endblocktranslate %}",
            {% endif %}
            "facts": [
                {
                    "name": "{% trans "Product" %}:",
                    "value": "{{ risk_acceptance.engagement.product.name }}"
                },
                {
                    "name": "{% trans "Engagement" %}:",
                    "value": "{{ risk_acceptance.engagement.name }}"
                },
                {
                    "name": "{% trans "Risk Acceptance" %}:",
                    "value": "{{ risk_acceptance }}"
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
            "name": "{% trans "View Risk Acceptance" %}",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
