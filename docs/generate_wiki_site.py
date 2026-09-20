#!/usr/bin/env python3
"""Regenerates docs/wiki-site/*.html from docs/wiki/*.md.

Run this after editing any file in docs/wiki/ to keep the rendered HTML
site in sync:

    python3 docs/generate_wiki_site.py

This is a small, purpose-built converter for the specific markdown subset
docs/wiki/*.md actually uses (headers, paragraphs, **bold**, *italic*,
`code`, fenced code blocks, bullet/numbered lists, links, simple pipe
tables) -- not a general-purpose markdown parser. If you add a new kind of
markdown formatting to a wiki page, extend `convert()`/`inline()` below to
handle it, or it will show up unconverted in the rendered HTML.

If you add a new wiki page, add it to TOPICS below too (both the sidebar
and the generated file depend on that list).
"""
import html
import os
import re

WIKI_DIR = "docs/wiki"
SITE_DIR = "docs/wiki-site"

TOPICS = [
    ("00-START-HERE", "Start Here"),
    ("01-process-model-and-ipc", "Process Model & IPC"),
    ("02-dom-html-css-layout-render", "DOM, CSS, Layout & Render"),
    ("03-javascript-engine", "JavaScript Engine"),
    ("04-network-and-privacy", "Network & Privacy"),
    ("05-account-storage-sync", "Account, Storage & Sync"),
    ("06-app-ui-and-window", "App UI & Window"),
    ("07-sandboxing", "Sandboxing"),
    ("08-rust-patterns-glossary", "Rust Patterns Glossary"),
    ("09-troubleshooting", "Troubleshooting"),
]


def esc(s):
    return html.escape(s, quote=False)


def rewrite_href(url):
    # Internal cross-references in the markdown source point at sibling
    # .md files (correct for reading them on GitHub/in an editor) -- the
    # rendered site needs the matching .html file instead, and
    # 00-START-HERE.md is served as index.html, not 00-START-HERE.html.
    m = re.match(r"^(\d{2}-[a-z-]+)\.md$", url)
    if not m:
        return url
    slug = m.group(1)
    return "index.html" if slug == "00-START-HERE" else f"{slug}.html"


def inline(text):
    text = esc(text)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: f'<a href="{rewrite_href(m.group(2))}">{m.group(1)}</a>',
        text,
    )
    # Bold/italic BEFORE code spans: this content sometimes bolds a phrase
    # that itself contains inline code (e.g. "**the `foo` method**"), and
    # splitting on code spans first would separate the ** markers onto
    # different sides of that split, so neither half ever sees a matching
    # pair. None of this content puts a literal * inside `code`, so doing
    # bold/italic first and code spans last is safe here.
    text = re.sub(r"\*\*([^*]+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*\n]+?)\*(?!\*)", r"<em>\1</em>", text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    return text


def convert(md_text):
    lines = md_text.split("\n")
    html_out = []
    i = 0
    n = len(lines)
    in_list = None  # 'ul' or 'ol'

    def close_list():
        nonlocal in_list
        if in_list:
            html_out.append(f"</{in_list}>")
            in_list = None

    while i < n:
        line = lines[i]

        if line.startswith("```"):
            close_list()
            lang = line[3:].strip()
            i += 1
            code_lines = []
            while i < n and not lines[i].startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1  # skip closing fence
            cls = f' class="lang-{lang}"' if lang else ""
            html_out.append(f"<pre{cls}><code>{esc(chr(10).join(code_lines))}</code></pre>")
            continue

        if line.startswith("|") and i + 1 < n and re.match(r"^\|[\s:-]+\|", lines[i + 1]):
            close_list()
            header_cells = [c.strip() for c in line.strip().strip("|").split("|")]
            i += 2  # skip header + separator
            rows = []
            while i < n and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            html_out.append('<div class="table-wrap"><table>')
            html_out.append("<tr>" + "".join(f"<th>{inline(c)}</th>" for c in header_cells) + "</tr>")
            for r in rows:
                html_out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>")
            html_out.append("</table></div>")
            continue

        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            close_list()
            # The page template already renders the doc's own leading `#`
            # title as a real <h1> (and that line is stripped before this
            # function ever sees it -- see main()), so markdown ## -> <h2>,
            # ### -> <h3>, with no offset needed.
            level = len(m.group(1))
            text = m.group(2).strip()
            slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
            html_out.append(f'<h{level} id="{slug}">{inline(text)}</h{level}>')
            i += 1
            continue

        m = re.match(r"^- (.*)$", line)
        if m:
            if in_list != "ul":
                close_list()
                html_out.append("<ul>")
                in_list = "ul"
            item_text = m.group(1)
            i += 1
            while i < n and lines[i].startswith("  ") and lines[i].strip() and not re.match(r"^\s*(-|\d+\.)\s", lines[i]):
                item_text += " " + lines[i].strip()
                i += 1
            html_out.append(f"<li>{inline(item_text)}</li>")
            continue

        m = re.match(r"^\d+\.\s+(.*)$", line)
        if m:
            if in_list != "ol":
                close_list()
                html_out.append("<ol>")
                in_list = "ol"
            item_text = m.group(1)
            i += 1
            while i < n and lines[i].startswith("   ") and lines[i].strip() and not re.match(r"^\s*(-|\d+\.)\s", lines[i]):
                item_text += " " + lines[i].strip()
                i += 1
            html_out.append(f"<li>{inline(item_text)}</li>")
            continue

        if line.strip() == "":
            close_list()
            i += 1
            continue

        close_list()
        para_lines = [line]
        i += 1
        while i < n and lines[i].strip() != "" and not re.match(r"^(#{1,3}\s|```|- |\d+\.\s|\|)", lines[i]):
            para_lines.append(lines[i])
            i += 1
        html_out.append(f"<p>{inline(' '.join(para_lines))}</p>")

    close_list()
    return "\n".join(html_out)


def sidebar_html(current_slug):
    items = []
    for slug, title in TOPICS:
        cls = ' class="active"' if slug == current_slug else ""
        href = "index.html" if slug == "00-START-HERE" else f"{slug}.html"
        items.append(f'<li{cls}><a href="{href}" data-title="{title.lower()}">{esc(title)}</a></li>')
    return "\n      ".join(items)


PAGE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<title>{page_title} - Abyssal Browser Wiki</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="topbar">
  <span class="brand">Abyssal Browser Wiki</span>
  <span class="subtitle">a personal study guide, not official documentation</span>
</div>
<div class="layout">
  <div class="sidebar">
    <input type="text" id="filterBox" placeholder="Filter topics...">
    <ul id="topicList">
      {sidebar}
    </ul>
  </div>
  <div class="content">
    <h1>{page_title}</h1>
    {body}
  </div>
</div>
<script>
var box = document.getElementById('filterBox');
box.addEventListener('input', function () {{
  var q = box.value.toLowerCase();
  var items = document.getElementById('topicList');
  var links = items.querySelectorAll('a');
  for (var i = 0; i < links.length; i++) {{
    var link = links[i];
    var title = link.getAttribute('data-title');
    if (q === '' || title.indexOf(q) !== -1) {{
      link.classList.remove('hidden');
    }} else {{
      link.classList.add('hidden');
    }}
  }}
}});
</script>
</body>
</html>
"""


def main():
    os.makedirs(SITE_DIR, exist_ok=True)
    for slug, title in TOPICS:
        md_path = os.path.join(WIKI_DIR, slug + ".md")
        with open(md_path, "r", encoding="utf-8") as f:
            text = f.read()
        text = re.sub(r"^#\s+.*\n", "", text, count=1)
        body_html = convert(text)
        sidebar = sidebar_html(slug)
        page = PAGE_TEMPLATE.format(page_title=esc(title), sidebar=sidebar, body=body_html)
        out_name = "index.html" if slug == "00-START-HERE" else slug + ".html"
        out_path = os.path.join(SITE_DIR, out_name)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(page)
        print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
