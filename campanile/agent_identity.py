"""agent_identity — classify an author identity as agent, bot, or neither.

Answers one question from identity strings alone: does this author
identity present itself as an AI coding agent (GENERATIVE), as
non-generative automation (MECHANICAL), or as neither (presumed human)?

Rules:

- Matching is case-insensitive substring over the author name plus the
  email when one is available. Only identity strings are read — never
  commit content.
- GENERATIVE takes precedence over MECHANICAL when both match.
- Some agent names collide with human names ("claude", "gemini",
  "devin", "goose"). Those needles count as GENERATIVE only when the
  identity also carries a bot/agent marker or a vendor email domain.
  A person named Claude is never classified as software by this module.
- A "[bot]" suffix with no generative needle is MECHANICAL.
- Author strings are repo-recorded personas, spoofable by anyone with
  push access; classification is a reading of the record, never an
  identity claim.
"""

GUARDED_GENERATIVE = ("claude", "gemini", "devin", "goose")

MARKERS = ("[bot]", "bot", "-ai", " ai", "agent", "code", "anthropic",
           "google", "cognition", "openai")

VENDOR_DOMAINS = ("anthropic.com", "openai.com", "cognition.ai",
                  "cognition-labs.com", "cursor.com", "cursor.sh",
                  "google.com", "github.com", "sweep.dev", "qodo.ai",
                  "coderabbit.ai", "factory.ai", "all-hands.dev")

GENERATIVE = (
    "claude-code", "claude code", "claude[bot]",
    "copilot",
    "codex",
    "cursor-agent", "cursoragent", "cursor agent",
    "aider",
    "openhands", "open hands", "allhands", "all-hands",
    "sweep-ai", "sweepai", "sweep[bot]",
    "jules",
    "amazon-q", "amazonq",
    "qodo", "codiumai",
    "coderabbit",
    "codegen-sh", "codegen[bot]",
    "factory-droid", "droid[bot]",
    "devin-ai", "devin[bot]",
    "gemini-code", "gemini code", "google-labs",
    "windsurf",
    "replit-agent", "replit agent",
)

MECHANICAL = (
    "dependabot", "renovate", "greenkeeper", "github-actions",
    "pre-commit-ci", "pyup", "snyk", "whitesource", "mend[bot]",
    "allcontributors", "imgbot", "codecov", "stale[bot]",
    "mergify", "semantic-release", "release-please", "netlify[bot]",
    "vercel[bot]", "travis", "appveyor", "circleci", "azure-pipelines",
    "scala-steward", "pypi-bot", "readthedocs",
)


def _norm(s):
    return (s or "").lower()


def classify(name, email=None):
    """Return 'generative', 'mechanical', or None for one identity."""
    hay_email = _norm(email)
    hay = _norm(name) + " " + hay_email

    for needle in GENERATIVE:
        if needle in hay:
            return "generative"

    has_marker = any(m in hay for m in MARKERS)
    has_domain = any(d in hay_email for d in VENDOR_DOMAINS)
    for needle in GUARDED_GENERATIVE:
        if needle in hay and (has_marker or has_domain):
            return "generative"

    for needle in MECHANICAL:
        if needle in hay:
            return "mechanical"

    if "[bot]" in hay:
        return "mechanical"

    return None


def classify_identity(name, emails=()):
    """Strongest classification across a name and every known email."""
    best = classify(name)
    if best == "generative":
        return best
    for e in emails:
        c = classify(name, e)
        if c == "generative":
            return "generative"
        if c == "mechanical" and best is None:
            best = c
    return best
