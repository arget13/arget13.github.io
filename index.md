---
title: Home
permalink: /
---
<link rel="stylesheet" href="style.css">

## Posts

* * *

<ul>
  {% for post in site.posts %}
    <li>
      <h3><a href="{{ post.url }}">{{ post.title }}</a></h3>
      <img src="{{ post.item_image }}" width="512" height="256">
      <p></p>
    </li>
  {% endfor %}
</ul>
