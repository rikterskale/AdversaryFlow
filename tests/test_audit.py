from adversaryflow.audit import redact


def test_redact_handles_nested_lists_without_retaining_sensitive_values():
    payload = redact([{"api_key": "secret-value", "nested": [{"token": "hidden"}]}])
    assert payload == [{"api_key": "[REDACTED]", "nested": [{"token": "[REDACTED]"}]}]
