# Translation review (English, Arabic, Hebrew)

What was checked, what was changed, and what a machine cannot judge.

## Checked automatically (tests/test_translations.py, on every push)

* the Python tables (CLI, reports, findings) and the browser table (`nemla_ui/web/i18n.js`) have the same keys in all three languages;
* every placeholder (`{port}`, `{count}`, `{sec:.1f}`) is identical in all languages and none is half-written;
* nothing is empty, a bare key, left in English, or in the wrong script (Hebrew letters in Arabic text and the reverse);
* no key is defined twice in `i18n.js` (three older, less careful duplicates were silently overridden and are removed);
* one word per concept, per language (the glossary below), in both tables and in both READMEs;
* wording about ARP changes stays hedged ("can be ARP spoofing, but..."), in every language;
* HTML reports set `lang` and `dir`, keep addresses and banners in their own direction (`<bdi>`), and text from the network can not
  smuggle direction controls (RLO, LRI...) into any report format;
* no invisible direction character sits in a source file: they are written as `\u200f`-style escapes so a reader can see them.

## Glossary (one word each)

| Concept | Arabic | Hebrew |
|---|---|---|
| banner | لافتة | באנר |
| decoy (Guard) | طُعم | פיתיון |
| router | راوتر | ראוטר |
| gateway | بوابة | שער |
| port | منفذ | פורט |
| certificate | شهادة | תעודה |
| confidence | ثقة | ביטחון |
| spoofing | انتحال | התחזות |
| fingerprint | بصمة | טביעת אצבע (the Hebrew tagline says "זיהוי" on purpose) |
| password | كلمة المرور (reports, CLI) / كلمة السر (web page, Levantine) | סיסמה |

The Arabic web page is written in the Levantine dialect and the CLI and reports in standard Arabic; that is deliberate, and it is why
"password" has one word per register.

## Fixed in this review

* Arabic and Hebrew report column "Banner" was left in English; Hebrew used "שלט" (sign) for banner in the strings and "באנר" in the
  README, and "נתב" and "ראוטר" for router: unified.
* The Arabic tagline translated "Fingerprint" as "تخمين" (estimation); the README called the Guard's decoy ports "منافذ فخّ".
* The web page called a gateway change "a classic sign of ARP spoofing"; the (older) key was dead, the live one is hedged, and the
  dead copies are gone.
* New strings (capability notes, Guard notices) follow the same glossary.

## What this cannot tell you

That every sentence sounds natural to a native speaker. The texts were written and reviewed against the glossary and the tests above,
not by a native reviewer; treat them as good working translations, not as proofread ones. If you are a native speaker, corrections are
welcome: edit `nemla/_strings_base.py`, `nemla/strings_extra.py` or `nemla_ui/web/i18n.js` and run `python -m pytest tests/test_translations.py`.
