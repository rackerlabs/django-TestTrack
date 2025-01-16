{% load i18n %}
{% load display_tags %}
{% url 'view_engagement' engagement.id as engagement_url %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "{% trans "Engagement is starting" %}",
    "summary": "{% trans "Engagement is starting" %}",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "{% trans "An Engagement is starting" %}.",
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
                    "name": "{% trans "Start date" %}:",
                    "value": "{{ engagement.target_start }}"
                },
                {
                    "name": "{% trans "End date" %}:",
                    "value": "{{ engagement.target_end }}"
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
