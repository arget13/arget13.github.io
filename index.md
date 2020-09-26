---
permalink: /
---
<link rel="stylesheet" href="/style.css">

# Posts

* * *

<ul>
    {% for post in site.posts %}
        <li>
            <a href="{{ post.url | remove: '.html' }}" draggable="false">
                <div style="background-image: url('{{ post.item_image }}');" class="entry">
                    <svg height="60" width="320">
                        <rect class="shape" height="60" width="320" />
                    </svg>
                    <p class="title">{{ post.title }}</p>
                </div>
            </a>
            <aside>
                <p>tag1 tag2 tag3</p>
            </aside>
        </li>
    {% endfor %}
</ul>
