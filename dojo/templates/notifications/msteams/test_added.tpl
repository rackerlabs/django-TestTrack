{% load i18n %}
{% load display_tags %}
{% url 'view_test' test.id as test_url %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "{% trans "Test added" %}",
    "summary": "{% trans "Test added" %}",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "{% trans "A new test has been added" %}.",
            "facts": [
                {
                    "name": "{% trans "Product" %}:",
                    "value": "{{ engagement.product.name }}"
                },
                {
                    "name": "{% trans "Engagement" %}:",
                    "value": "{{ engagement.name }}"
                },
                {
                    "name": "{% trans "Test" %}:",
                    "value": "{{ test }}"
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
            "name": "{% trans "View Test" %}",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
