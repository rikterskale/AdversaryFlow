from adversaryflow.render.html import _markdown_body


def test_html_conversion_escapes_report_content() -> None:
    body = _markdown_body("# Report\n\n<script>alert('unsafe')</script>\n\n- **Status:** PASS")

    assert "<script>" not in body
    assert "&lt;script&gt;" in body
    assert "<strong>Status:</strong>" in body
