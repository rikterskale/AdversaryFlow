import pytest

from adversaryflow.loopback import LoopbackSink


def test_loopback_sink_accepts_only_local_synthetic_marker():
    with LoopbackSink() as sink:
        sink.send_marker("run-test")
        assert sink.url.startswith("http://127.0.0.1:")
        assert sink.received[0]["path"] == "/beacon"
        assert "ADVERSARYFLOW_SYNTHETIC" in sink.received[0]["body"]


def test_loopback_sink_refuses_a_non_success_response(monkeypatch):
    class Response:
        status = 500
        def __enter__(self): return self
        def __exit__(self, *_args): return False

    monkeypatch.setattr("adversaryflow.loopback.urlopen", lambda *_args, **_kwargs: Response())
    with LoopbackSink() as sink:
        with pytest.raises(RuntimeError, match="rejected synthetic marker"):
            sink.send_marker("run-test")

