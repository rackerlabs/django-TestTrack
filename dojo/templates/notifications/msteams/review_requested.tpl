{% load i18n %}
{% load display_tags %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "{% trans "Review Requested" %}",
    "summary": "{% trans "Review Requested" %}",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "{% trans "A user has requested that the following users review the finding below for accuracy" %}.",
            "facts": [
                {
                    "name": "{% trans "Requested By" %}:",
                    "value": "{{ requested_by }}"
                },
                {
                    "name": "{% trans "Finding" %}:",
                    "value": "{{ finding }}"
                },
                {
                    "name": "{% trans "Reviewers" %}:",
                    "value": "{{ reviewers }}"
                },
                {
                    "name": "{% trans "note" %}:",
                    "value": "{{ note }}"
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
