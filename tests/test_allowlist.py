from adversaryflow.retrieval.allowlist import host_is_allowed, url_is_allowlisted


def test_subdomain_allowlist() -> None:
    allowed = {"mitre.org"}
    assert host_is_allowed("attack.mitre.org", allowed)
    assert not host_is_allowed("mitre.org.evil.example", allowed)


def test_https_required() -> None:
    allowed = {"attack.mitre.org"}
    assert url_is_allowlisted("https://attack.mitre.org/groups/", allowed)
    assert not url_is_allowlisted("http://attack.mitre.org/groups/", allowed)
