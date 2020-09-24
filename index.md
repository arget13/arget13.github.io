---
permalink: /
---
<link rel="stylesheet" href="/style.css">

# Posts

* * *

<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url | remove: '.html' }}">
          <div style="background-image: url('{{ post.item_image }}');" class="entry">
              <svg height="60" width="320">
                  <rect class="shape" height="60" width="320" />
                  <p class="title">{{ post.title }}</p>
              </svg>
          </div>
      </a>
    </li>
  {% endfor %}
</ul>
