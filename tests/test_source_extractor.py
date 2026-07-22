from adversaryflow.models import SourceRecord, SourceTier
from adversaryflow.retrieval.source_extractor import SourceExtractor
from adversaryflow.retrieval.url_validator import FetchResult


class FakeValidator:
    def __init__(self) -> None:
        self.fetch_count = 0
        self.allowed_domains = {"attack.mitre.org"}

    async def fetch(self, record: SourceRecord) -> FetchResult:
        self.fetch_count += 1
        html = b"""
        <html><head><title>Test</title><meta property="article:published_time" content="2023-08-04T12:00:00Z"><script>ignore me</script></head>
        <body><h1>APT29</h1><p>Uses T1059.001 PowerShell.</p></body></html>
        """
        updated = SourceRecord.model_validate(
            {
                **record.model_dump(mode="json"),
                "validated": True,
                "final_url": str(record.url),
                "status_code": 200,
                "content_type": "text/html",
                "content_sha256": "a" * 64,
            }
        )
        return FetchResult(record=updated, body=html)


async def test_html_source_extraction_and_chunking() -> None:
    extractor = SourceExtractor(validator=FakeValidator())  # type: ignore[arg-type]
    record = SourceRecord(
        url="https://attack.mitre.org/groups/G0016/",
        title="APT29",
        domain="attack.mitre.org",
        tier=SourceTier.AUTHORITATIVE,
    )
    document, updated = await extractor.extract(record)
    assert updated.validated
    assert document is not None
    assert "Uses T1059.001 PowerShell" in document.text
    assert "ignore me" not in document.text
    assert document.chunks
    assert str(updated.published_at) == "2023-08-04"


async def test_source_extractor_reuses_cached_document(tmp_path) -> None:
    from adversaryflow.storage.cache import SourceCache

    validator = FakeValidator()
    cache = SourceCache(tmp_path)
    extractor = SourceExtractor(validator=validator, cache=cache)  # type: ignore[arg-type]
    record = SourceRecord(
        url="https://attack.mitre.org/groups/G0016/",
        title="APT29",
        domain="attack.mitre.org",
        tier=SourceTier.AUTHORITATIVE,
    )

    first, _ = await extractor.extract(record)
    second, _ = await extractor.extract(record)

    assert first == second
    assert validator.fetch_count == 1
    assert cache.stats.hits == 1
