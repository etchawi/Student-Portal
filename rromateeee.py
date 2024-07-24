{% extends "base.html" %}

{% block content %}
<div class="container">
    <h1>Find Your Roommate</h1>
    <form method="post">
        {{ form.hidden_tag() }}
        <div class="form-group">
            <label for="move_in_date">Move-in Date:</label>
            {{ form.move_in_date(class="form-control") }}
        </div>
        <div class="form-group">
            <label for="gender_preference">Gender Preference:</label>
            {{ form.gender_preference(class="form-control") }}
        </div>
        <div class="form-group">
            <label for="max_price">Maximum Price:</label>
            {{ form.max_price(class="form-control") }}
        </div>
        <div class="form-group">
            {{ form.submit(class="btn btn-primary") }}
        </div>
    </form>

    {% if search_attempted %}
        {% if matches %}
            <h2>Potential Roommates</h2>
            <div class="list-group mt-4">
                {% for match in matches %}
                    <a href="{{ url_for('view_profile', user_id=match.user.id) }}" class="list-group-item list-group-item-action">
                        <h5 class="mb-1">{{ match.user.first_name }} {{ match.user.last_name }}</h5>
                        <p>Gender Preference: {{ match.gender_preference }}</p>
                        <small>Maximum Price: ${{ match.max_price }}</small>
                        <small>Move-in Date: {{ match.move_in_date.strftime('%Y-%m-%d') }}</small>
                    </a>
                {% endfor %}
            </div>
        {% else %}
            <p>No matches found.</p>
        {% endif %}
    {% endif %}
</div>
{% endblock %}
