from adversaryflow.loopback import LoopbackSink


def test_loopback_sink_accepts_only_local_synthetic_marker():
    with LoopbackSink() as sink:
        sink.send_marker("run-test")
        assert sink.url.startswith("http://127.0.0.1:")
        assert sink.received[0]["path"] == "/beacon"
        assert "ADVERSARYFLOW_SYNTHETIC" in sink.received[0]["body"]

