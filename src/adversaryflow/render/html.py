from __future__ import annotations

from html import escape
from re import fullmatch, sub

from adversaryflow.models import ScenarioPack
from adversaryflow.render.markdown import render_markdown


def _inline(text: str) -> str:
    """Escape report text and preserve the renderer's small inline-markdown subset."""
    value = escape(text)
    value = sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", value)
    return value


def _markdown_body(markdown: str) -> str:
    """Convert AdversaryFlow's generated Markdown subset to safe semantic HTML."""
    output: list[str] = []
    in_list = False
    in_table = False
    table_header = True

    def close_blocks() -> None:
        nonlocal in_list, in_table, table_header
        if in_list:
            output.append("</ul>")
            in_list = False
        if in_table:
            output.append("</tbody></table>")
            in_table = False
            table_header = True

    lines = markdown.splitlines()
    for index, line in enumerate(lines):
        if not line:
            if not in_table:
                close_blocks()
            continue
        heading = fullmatch(r"(#{1,3}) (.+)", line)
        if heading:
            close_blocks()
            level = len(heading.group(1))
            output.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
            continue
        if line.startswith("- ") or line.startswith("  - "):
            if in_table:
                close_blocks()
            if not in_list:
                output.append("<ul>")
                in_list = True
            output.append(f"<li>{_inline(line.lstrip()[2:])}</li>")
            continue
        if line.startswith("|") and line.endswith("|"):
            if in_list:
                close_blocks()
            cells = [item.strip() for item in line.strip("|").split("|")]
            if all(fullmatch(r":?-{3,}:?", cell) for cell in cells):
                table_header = False
                output.append("</thead><tbody>")
                continue
            if not in_table:
                output.append("<table><thead>")
                in_table = True
            tag = "th" if table_header else "td"
            output.append(
                "<tr>" + "".join(f"<{tag}>{_inline(cell)}</{tag}>" for cell in cells) + "</tr>"
            )
            continue
        close_blocks()
        output.append(f"<p>{_inline(line)}</p>")

    close_blocks()
    return "\n".join(output)


def render_html(pack: ScenarioPack) -> str:
    """Render a self-contained, printable HTML scenario report."""
    body = _markdown_body(render_markdown(pack))
    title = escape(pack.title)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{ color-scheme: light dark; --accent: #5fb3b3; --border: #718096; }}
    body {{ margin: 0; font: 16px/1.55 system-ui, sans-serif; background: #111827; color: #e5e7eb; }}
    main {{ max-width: 1080px; margin: auto; padding: 3rem 1.5rem 6rem; }}
    h1 {{ font-size: clamp(2rem, 5vw, 3.5rem); line-height: 1.05; }}
    h2 {{ margin-top: 3rem; padding-bottom: .35rem; border-bottom: 1px solid var(--border); }}
    h3 {{ margin-top: 2rem; color: var(--accent); }}
    p, li {{ max-width: 85ch; }}
    table {{ width: 100%; border-collapse: collapse; display: block; overflow-x: auto; }}
    th, td {{ padding: .65rem; border: 1px solid var(--border); text-align: left; vertical-align: top; }}
    th {{ background: #1f2937; }}
    @media print {{ body {{ background: white; color: black; }} main {{ max-width: none; padding: 0; }} }}
  </style>
</head>
<body><main>{body}</main></body>
</html>
"""
