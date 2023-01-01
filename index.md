---
permalink: /
---
<link rel="stylesheet" href="/style.css">

# Posts

* * *

<ul class="entries">
    {% for post in site.posts %}
        <li>
            <a href="{{ post.url | remove: '.html' }}" draggable="false">
                <div style="background-image: url('{{ post.item_image }}');" class="entry">
                    <svg height="4rem" width="26rem">
                        <rect class="shape" height="4rem" width="26rem" />
                    </svg>
                    <p class="title">{{ post.title }}</p>
                </div>
            </a>
        </li>
    {% endfor %}
</ul>
