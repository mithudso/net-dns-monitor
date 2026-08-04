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


class EmptyContentMessages:
    """A response carrying no text block at all.

    The real SDK can return this; the happy-path fake above cannot express it,
    which is why the crash it causes went unnoticed.
    """

    def create(self, **kwargs):
        return type("Resp", (), {"content": []})()


class EmptyContentClient:
    def __init__(self):
        self.messages = EmptyContentMessages()


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
    # NOT `"dns" in prompt.lower()`: the fixed preamble already says "macOS
    # network/DNS incident", so that assertion holds even when the
    # classification is never interpolated at all. Pin the interpolated value.
    assert "Classification from local triage: dns" in prompt
    assert "query timed out" in prompt


def test_build_prompt_carries_a_classification_the_preamble_cannot_supply():
    prompt = build_prompt(_bundle(classification="unclassified"))
    assert "unclassified" in prompt


def test_build_prompt_includes_probe_results_and_ladder_results():
    """Deleting either interpolation leaves the prompt looking plausible while
    stripping the evidence the model is supposed to reason over.
    """
    prompt = build_prompt(_bundle())
    assert "external_reachable" in prompt
    assert "flush_dns_cache" in prompt


def test_uses_default_model_for_classified_incidents():
    client = FakeClient()
    escalator = make_escalator(
        client=client, default_model="claude-haiku-4-5-20251001", fallback_model="claude-sonnet-5"
    )
    escalator(_bundle(classification="dns"))
    assert client.messages.calls[0]["model"] == "claude-haiku-4-5-20251001"


def test_uses_fallback_model_for_unclassified_incidents():
    client = FakeClient()
    escalator = make_escalator(
        client=client, default_model="claude-haiku-4-5-20251001", fallback_model="claude-sonnet-5"
    )
    escalator(_bundle(classification="unclassified"))
    assert client.messages.calls[0]["model"] == "claude-sonnet-5"


def test_returns_analysis_text_from_response():
    client = FakeClient(text="likely a captive portal intercepting DNS")
    escalator = make_escalator(client=client)
    result = escalator(_bundle())
    assert result["analysis"] == "likely a captive portal intercepting DNS"
    # `"model" in result` is vacuous -- any value passes, including the wrong
    # one. This dict is embedded verbatim in the report handed to IT, so the
    # model it names has to be the model that actually answered.
    assert result["model"] == "claude-haiku-4-5-20251001"


def test_result_reports_the_model_that_actually_answered():
    client = FakeClient()
    escalator = make_escalator(
        client=client,
        default_model="claude-haiku-4-5-20251001",
        fallback_model="claude-sonnet-5",
    )
    result = escalator(_bundle(classification="unclassified"))
    assert result["model"] == "claude-sonnet-5"


def test_client_error_returns_error_dict_instead_of_raising():
    escalator = make_escalator(client=RaisingClient())
    result = escalator(_bundle())
    assert "error" in result
    assert "network unreachable" in result["error"]


def test_response_without_a_text_block_returns_error_dict_instead_of_raising():
    """`response.content[0].text` used to sit outside the try, so an empty
    content list raised IndexError straight through state_machine (which has no
    per-step guard) and aborted the tick -- no incident report written at all,
    which is the opposite of this module's stated contract.
    """
    escalator = make_escalator(client=EmptyContentClient())
    result = escalator(_bundle())
    assert "error" in result
    assert "analysis" not in result


def test_api_call_is_bounded_by_a_timeout():
    """This runs on the rumps run loop, so an unbounded request freezes the
    menu bar. The SDK's own default is minutes.
    """
    client = FakeClient()
    escalator = make_escalator(client=client, timeout=12.5)
    escalator(_bundle())
    assert client.messages.calls[0]["timeout"] == 12.5
