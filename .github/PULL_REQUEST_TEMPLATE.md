<!--
Thanks for the PR. See CONTRIBUTING.md if you have not already - in particular:
- one focused change per PR
- a test for the fix or feature (exercising the real code path, not a mocked-out stand-in for it)
- a new string added in English needs an Arabic and a Hebrew translation in the same PR
-->

## What this changes and why

<!-- What changed, and why - link the issue this addresses if there is one. -->

## How it was tested

<!-- Which tests you ran/added. For a fix: a regression test that fails without your change. -->

## Checklist

- [ ] `python -m pytest -q` passes locally
- [ ] `python -m ruff check .` and `python -m pyflakes nemla nemla_ui nemla.py` are clean
- [ ] `python -m mypy` is clean
- [ ] New or changed strings are translated in all three languages (`nemla/_strings_base.py` /
      `nemla/strings_extra.py`, or `nemla_ui/web/i18n.js`), or this PR has no user-facing strings
- [ ] This stays within [Nemla's scope](../README.md#responsible-use) (reconnaissance and defensive monitoring)
