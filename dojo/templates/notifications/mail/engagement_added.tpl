{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
{% url 'view_product' engagement.product.id as product_url %}
{% url 'view_engagement' engagement.id as engagement_url %}
<html>
    <body>
        {% autoescape on %}
            <p>
                {% trans "Hello" %},
            </p>
            <p>
              {% blocktranslate trimmed with engagement_name=engagement.name engagement_product=engagement.product prod_url=product_url|full_url eng_url=engagement_url|full_url%}
                The engagement "{{ engagement_name }}" has been created in the product "{{ engagement_product }}". It can be viewed here: <a href="{{prod_url}}">{{product}}</a> / <a href="{{eng_url}}">{{ engagement_name }}</a>
              {% endblocktranslate %}
            </p>
            <br/>
            <br/>
                {% trans "Kind regards" %},<br/>
            <br/>
                {% if system_settings.team_name %}
                    {{ system_settings.team_name }}
                {% else %}
                    Defect Dojo
                {% endif %}
            <br/>
            <br/>
            <p>
                {% url 'notifications' as notification_url %}
                {% trans "You can manage your notification settings here" %}: <a href="{{ notification_url|full_url }}">{{ notification_url|full_url }}</a>
            </p>
            {% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
                <br/>
                <div style="background-color:#DADCE2; border:1px #003333; padding:.8em; ">
                    <span style="font-size:16pt;  font-family: 'Cambria','times new roman','garamond',serif; color:#ff0000;">{% trans "Disclaimer" %}</span><br/>
                    <p style="font-size:11pt; line-height:10pt; font-family: 'Cambria','times roman',serif;">{{ system_settings.disclaimer_notifications }}</p>
                </div>
            {% endif %}
        {% endautoescape %}
    </body>
</html>
