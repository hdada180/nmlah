# Contributing to Nemla

Thanks for considering it. This is a small, single-maintainer open-source project — keep that in mind for
response times, and see below for what makes a contribution easy to review and merge.

Found a security bug rather than a regular one? See [SECURITY.md](SECURITY.md) instead — please do not open a
public issue or PR for an unpatched vulnerability.

## Before you start

For anything beyond a small, obvious fix, open an issue first to talk through the approach. It saves you writing
code that will not be merged, and the maintainer time to say so.

Scope: Nemla is a **reconnaissance and defensive-monitoring** tool. See
[Responsible use](README.md#responsible-use) and [Guard mode](README.md#guard-mode-defensive) for what that means
in practice. Pull requests that add active exploitation, credential attacks, stealth/evasion, or anything else
that turns Nemla into an offensive tool will not be accepted, whatever the framing.

## Setting up

```bash
git clone https://github.com/hdada180/nmlah.git
cd nmlah
pip install ".[dev]"        # pytest, pyflakes, ruff, mypy, coverage
```

No compiled parts, no required third-party dependencies for the tool itself (Scapy is optional, for raw ARP and
SYN fingerprinting; see [docs/privileges.md](docs/privileges.md)).

## Making a change

1. **Branch from `main`.** Never commit straight to it.
2. **Read [docs/architecture.md](docs/architecture.md)** if you are touching the scanning pipeline, adding a
   service detector, or adding a finding — it documents the shape those pieces are expected to have.
3. **Match the existing style.** Comments explain *why*, not *what*; module and function docstrings read like
   prose, not a list of flags. English is canonical for code, comments and commit messages, even where the
   feature is about Arabic or Hebrew. If in doubt, read a neighbouring file before writing new code — consistency
   with what is already there matters more than a personal preference.
4. **Add a test.** Every fix gets a regression test; every feature gets tests that exercise the real code path,
   not just a mocked-out stand-in for it (see the tests added for `nemla/discovery/arp.py` and
   `nemla_ui/server.py` for the kind of thing this project means by that — several existing tests had
   monkeypatched a function's *caller* so thoroughly that the function itself never actually ran).
5. **New strings need all three languages.** A finding, a CLI message or a UI string added in English needs an
   Arabic and a Hebrew translation in the same PR (`nemla/_strings_base.py` or `nemla/strings_extra.py`, and
   `nemla_ui/web/i18n.js` for interface-only strings). `tests/test_translations.py` checks the three languages
   stay in lockstep; run it before you open the PR, not after CI catches it. If you are not a native Arabic or
   Hebrew speaker (most contributors, including the maintainer, are not native in both), say so in the PR —
   flagged-but-imperfect translations are welcome, silent ones are not.

## Running the checks

```bash
python -m pytest -q                                                     # the suite (~1,300 tests, a few minutes)
python -m ruff check .                                                  # lint
python -m pyflakes nemla nemla_ui nemla.py
python -m mypy                                                          # type check
python -m coverage run -m pytest -q && python -m coverage report -m     # which lines your change did not test
```

A few tests are gated behind an environment they need and are skipped elsewhere, with the reason printed:
`integration` (a real Samba/xrdp lab via Docker, see [tests/integration/README.md](tests/integration/README.md)),
`privileged` (root and Scapy), `browser` (a real Chrome/Chromium for the 3D interface's layout tests). CI runs all
of them; you do not need Docker or root to contribute.

## Opening the PR

- Keep it focused — one change, one PR. A drive-by fix noticed along the way belongs in its own PR.
- Describe what changed and, if it is not obvious, why. Link the issue it addresses.
- CI must be green (lint, type-check, the full Linux/Windows matrix). If a check fails for a reason unrelated to
  your change, say so in the PR rather than silently working around it.
- Do not weaken an existing test or suppress a warning to make CI pass; fix what it is actually telling you, or
  explain in the PR why the check does not apply here.

## Code of conduct

This project follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
