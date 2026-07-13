from netdnsmonitor.anthropic_escalator import build_prompt, make_escalator


class FakeMessages:
    def __init__(self, text="likely a captive portal intercepting DNS"):
        self.text = text
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return type(
            "Resp",
            (),
            {"content": [type("Block", (), {"text": self.text})()]},
        )()


class FakeClient:
    def __init__(self, text="likely a captive portal intercepting DNS"):
        self.messages = FakeMessages(text)


class RaisingMessages:
    def create(self, **kwargs):
        raise RuntimeError("network unreachable")


class RaisingClient:
    def __init__(self):
        self.messages = RaisingMessages()


def _bundle(classification="dns"):
    return {
        "classification": classification,
        "probe_results": {"external_reachable": True, "dns_ok": False},
        "log_excerpts": ["mDNSResponder: query timed out"],
        "ladder_results": [{"name": "flush_dns_cache", "outcome": "ok"}],
    }


def test_build_prompt_includes_classification_and_log_excerpts():
    prompt = build_prompt(_bundle())
    assert "dns" in prompt.lower()
    assert "query timed out" in prompt


def test_uses_default_model_for_classified_incidents():
    client = FakeClient()
    escalator = make_escalator(client=client, default_model="claude-haiku-4-5-20251001", fallback_model="claude-sonnet-5")
    escalator(_bundle(classification="dns"))
    assert client.messages.calls[0]["model"] == "claude-haiku-4-5-20251001"


def test_uses_fallback_model_for_unclassified_incidents():
    client = FakeClient()
    escalator = make_escalator(client=client, default_model="claude-haiku-4-5-20251001", fallback_model="claude-sonnet-5")
    escalator(_bundle(classification="unclassified"))
    assert client.messages.calls[0]["model"] == "claude-sonnet-5"


def test_returns_analysis_text_from_response():
    client = FakeClient(text="likely a captive portal intercepting DNS")
    escalator = make_escalator(client=client)
    result = escalator(_bundle())
    assert result["analysis"] == "likely a captive portal intercepting DNS"
    assert "model" in result


def test_client_error_returns_error_dict_instead_of_raising():
    escalator = make_escalator(client=RaisingClient())
    result = escalator(_bundle())
    assert "error" in result
    assert "network unreachable" in result["error"]
