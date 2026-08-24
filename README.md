# campanile

campanile replays a repository's git history and reports its line-custody structure — which author strings held which file classes, and when that structure shifted.

Only diff STRUCTURE is read: hunk arithmetic, paths, author strings. Content lines are consumed by count and never inspected — custody is pure arithmetic over the recorded diffs.

## The calibration case

```bash
uvx campanile replay xz
```

In the xz repository (CVE-2024-3094), custody of the tests file class inverted at first-parent chain index 1746 — 2023-03-13 — while overall custody never inverted. The payload that later shipped was carried in that same file class. This tool dates the structural shift; it makes no claim about intent, identity, or wrongdoing.

Calibration (2026Q3, the first 55-repo fleet): class-level custody inversions are ordinary (46 of 55 repos have them). Any class inverting while overall custody never does: 2 of 55. The tests class specifically — the xz signature — 0 of 55. The wider fleet below measures the same signature at production scale; a rate always travels with its denominator and its epoch.

## Base rates

Measured on the sealed 406-repo top-PyPI fleet (2026Q4-wide), predictions staked before cloning. Three predicates, three separate questions. The bare xz shape in ANY file class — one class changes hands while the project overall never does: 64 of 406 healthy repositories. The same any-class shape with a 150-day recent-arrival condition on the ascending author: 36 of 406. The tests-class signature — the class that carried the xz payload, with no recent-arrival condition: 17 of 406, about 1 in 24. The earlier 55-repo calibration above measured this same tests-class signature at 0 of 55: a small fleet's zero and a wide fleet's 1-in-24 are the same physics at different denominators, and both publish. At these rates the pattern alone accuses the innocent; that is the measurement, and it is why a match is a question, never a finding.

## The sealed October envelope

Predictions for the next quarterly sweep over the same fleet are already sealed: claims sha256 851d268b69b9e89ecaa1ebdd2c4d88e2720328e9469044db4a4e320d013c5fee, RFC 3161-witnessed 2026-08-24, unsealed October 2026. Whatever unseals either matches this hash or it does not; nobody — this project included — can edit it.

Verification is offline. The shipped xz fixture replays 3,054 commits with no network, no clone, and no model. `--from-clone PATH` recomputes the same result from a live
git clone at the pinned commit and refuses any other commit — proving the
fixture against the upstream history itself.

## Your own repository

```bash
uvx campanile scan .
```

Reports the repository's custody vector: per-class custody shares
(integer-scaled), principal roles (the recorded author strings live in the
JSON vector and print only with `--personas`), and any inversion events.
Every inversion event carries its meaning in-schema:

- what this is: the date one author string's line custody in one file class first exceeded another's
- what this is not: not an accusation, not a compromise indicator, not an identity claim; author strings are repo-recorded personas

Every scan ends with the agent-held custody readout: the share of surviving lines held by identities presenting as AI coding agents versus non-generative automation — shares only, no names. Classification reads the record; it never makes an identity claim, and a person named Claude or Devin never classifies as software.

## If someone files campanile output against your project

A campanile match is a structural measurement with a published base rate, never evidence of wrongdoing. The same shape appears in healthy, famous projects at the rates above; the usual cause is ordinary succession — someone takes over the tests while the founder keeps the whole. Reports speak in roles, and this project never publishes a named per-repository result — aggregates and sealed receipts only; whether a repository tells its own custody story is its maintainer's choice. If this section was linked at you, the number being cited asks a question about succession; it does not answer one about intent.

## Verify

```bash
uvx campanile verify PATH
```

Dispatches on the file: a signed receipt (needs
`pip install 'campanile[verify]'`), a custody vector, or the fixture
manifest. All verification is offline.

## What ships in the sdist

The full test suite and the structural fixture — `pip download campanile
--no-binary :all:` gives a stranger everything needed to reproduce every
xz calibration number in this README, offline. The fleet numbers are
receipt-bound, not recomputable: the fleet bank is private under the
consent law, and the sealed receipt published beside the aggregate is what
a stranger verifies. The fixture contains git STRUCTURE only (shas, author
strings, paths, hunk arithmetic): no source code of the scanned repository
is redistributed.

Licensed Apache-2.0.
