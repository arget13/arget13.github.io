---
permalink: /
---
<link rel="stylesheet" href="/style.css">

# Posts

* * *

<ul style="list-style-type: none;">
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url | remove: '.html' }}">
          <div style="background-image: url('{{ post.item_image }}');" class="entry">
              <p>{{ post.title }}</p>
          </div>
      </a>
    </li>
  {% endfor %}
</ul>
