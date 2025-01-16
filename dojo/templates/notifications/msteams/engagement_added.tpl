{% load i18n %}
{% load display_tags %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "{% trans "Engagement added" %}",
    "summary": "{% trans "Engagement added" %}",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "{% trans "A new engagement has been added" %}.",
            "facts": [
                {
                    "name": "{% trans "Product" %}:",
                    "value": "{{ engagement.product.name }}"
                },
                {
                    "name": "{% trans "Engagement" %}:",
                    "value": "{{ engagement.name }}"
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
            "name": "{% trans "View Engagement" %}",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
