{% load i18n %}
{% load display_tags %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "{% trans "Report created" %}",
    "summary": "{% trans "Report created" %}",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "{% trans "Report is ready for download" %}.",
            "facts": [
                {
                    "name": "{% trans "Report" %}:",
                    "value": "{{ report.name }}"
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
            "name": "{% trans "Download" %}",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
