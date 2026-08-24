"""The human-name guard is the point: a person named Claude, Devin, or
Goose must never classify as software; the same tokens with a bot marker
or vendor domain must."""

from campanile.agent_identity import classify, classify_identity
from campanile.lines import render_agent_report


def test_guarded_names_stay_human_without_markers():
    assert classify("Claude Monet") is None
    assert classify("Devin Smith") is None
    assert classify("Goose Gossage") is None
    assert classify("Gemini Blake") is None


def test_guarded_names_classify_with_marker_or_domain():
    assert classify("claude[bot]") == "generative"
    assert classify("Claude", "noreply@anthropic.com") == "generative"
    assert classify("devin-ai-integration[bot]") == "generative"
    assert classify("Goose Agent") == "generative"


def test_unambiguous_agents_and_mechanical():
    assert classify("GitHub Copilot") == "generative"
    assert classify("dependabot[bot]") == "mechanical"
    assert classify("some-tool[bot]") == "mechanical"
    assert classify("Ada Lovelace") is None


def test_generative_precedence_and_email_fold():
    # copilot needle beats the [bot] mechanical fallback
    assert classify("copilot-swe-agent[bot]") == "generative"
    # name alone is human; a vendor email in the identity set flips it
    assert classify_identity("Devin", ()) is None
    assert classify_identity("Devin", ("d@cognition.ai",)) == "generative"


def test_render_agent_report_speaks_shares_never_names():
    agent = {"overall": {"total": 1000, "gen": 10, "mech": 100},
             "per_class": {"tests": {"total": 200, "gen": 10, "mech": 0}}}
    out = render_agent_report(agent)
    assert "generative 1.00%" in out
    assert "automation 10.00%" in out
    assert "tests" in out
    assert "identity strings only" in out
    zero = render_agent_report({"overall":
                                {"total": 50, "gen": 0, "mech": 0},
                                "per_class": {}})
    assert "none" in zero
