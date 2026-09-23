"""English, Arabic and Hebrew stay in step: same keys, same placeholders, nothing empty or left in English,
one word per concept, hedged wording where the tool cannot be sure, and no invisible direction controls in source.

There are two tables: the Python one (CLI, reports, findings: nemla/_strings_base.py + strings_extra.py)
and the browser one (nemla_ui/web/i18n.js). The tests read both. What they cannot judge is whether a sentence
sounds natural to a native speaker: that needs a native reviewer (see docs/translation-review.md).
"""
import re
from pathlib import Path

import pytest

import nemla
from nemla.i18n import STRINGS as PY

ROOT = Path(__file__).resolve().parent.parent
LANGS = ("en", "ar", "he")
ARABIC = re.compile(r"[\u0600-\u06ff]")
HEBREW = re.compile(r"[\u0590-\u05ff]")
BIDI = re.compile("[\u200e\u200f\u202a-\u202e\u2066-\u2069]")
PLACEHOLDER = re.compile(r"\{(\w+)(?::[^{}]*)?\}")            # {name} or {name:.1f}
JS_ENTRY = re.compile(r"""^\s*'((?:[^'\\]|\\.)*)'\s*:\s*'((?:[^'\\]|\\.)*)'\s*,?\s*$""")


def parse_js():
    """{lang: [(key, value, line)]} from i18n.js, in file order (the browser lets a later entry win)."""
    entries = {lang: [] for lang in LANGS}
    current = None
    for number, line in enumerate((ROOT / "nemla_ui" / "web" / "i18n.js").read_text(encoding="utf-8").splitlines(), 1):
        opened = re.match(r"^    (en|ar|he): \{\s*$", line) or re.match(r"^\s*Object\.assign\(STRINGS\.(en|ar|he), \{\s*$", line)
        if opened:
            current = opened.group(1)
        elif current and re.match(r"^\s*\}\)?;?,?\s*$", line):
            current = None
        elif current:
            m = JS_ENTRY.match(line)
            if m:
                unescape = lambda text: re.sub(r"\\(.)", lambda g: {"n": "\n", "t": "\t"}.get(g.group(1), g.group(1)), text)  # noqa: E731
                entries[current].append((unescape(m.group(1)), unescape(m.group(2)), number))
    return entries


JS_ENTRIES = parse_js()
JS = {lang: {key: value for key, value, _ in JS_ENTRIES[lang]} for lang in LANGS}
TABLES = {"python": PY, "browser": JS}

# Values that are the same in every language on purpose (a brand, an example address, a bare counter)
SAME_ON_PURPOSE = {"brand_local", "brand.local", "scan.target.ph", "hosts.more"}


def placeholders(text):
    return sorted(PLACEHOLDER.findall(text))


# ---------------------------------------------------------------------------------------------- structure

@pytest.mark.parametrize("name", TABLES)
def test_every_key_exists_in_every_language(name):
    table = TABLES[name]
    assert set(table["en"]) == set(table["ar"]) == set(table["he"]), (
        sorted(set(table["en"]) ^ set(table["ar"])), sorted(set(table["en"]) ^ set(table["he"])))
    assert len(table["en"]) > 150                                        # the tables were really read


@pytest.mark.parametrize("name", TABLES)
def test_placeholders_match_in_every_language(name):
    table = TABLES[name]
    bad = {key: [placeholders(table[lang][key]) for lang in LANGS]
           for key in table["en"] if len({tuple(placeholders(table[lang][key])) for lang in LANGS}) != 1}
    assert bad == {}


@pytest.mark.parametrize("name", TABLES)
def test_placeholders_are_well_formed(name):
    for lang in LANGS:
        for key, text in TABLES[name][lang].items():
            stripped = PLACEHOLDER.sub("", text)
            assert "{" not in stripped and "}" not in stripped, (name, lang, key, text)   # a broken or half-written placeholder
            assert "%s" not in text and "{}" not in text and "{0}" not in text, (name, lang, key)


@pytest.mark.parametrize("name", TABLES)
def test_no_translation_is_empty_or_a_bare_key(name):
    for lang in LANGS:
        for key, text in TABLES[name][lang].items():
            assert text.strip(), (name, lang, key)
            assert text != key, (name, lang, key)


@pytest.mark.parametrize("name", TABLES)
def test_nothing_is_left_untranslated(name):
    """An Arabic or Hebrew string must contain letters of its own script; English must contain neither."""
    table = TABLES[name]
    for key, text in table["ar"].items():
        assert ARABIC.search(text) or key in SAME_ON_PURPOSE, (name, "ar", key, text)
        assert not HEBREW.search(text), (name, "ar", key, "Hebrew letters in the Arabic text")
    for key, text in table["he"].items():
        assert HEBREW.search(text) or key in SAME_ON_PURPOSE, (name, "he", key, text)
        assert not ARABIC.search(text), (name, "he", key, "Arabic letters in the Hebrew text")
    for key, text in table["en"].items():
        assert not (ARABIC.search(text) or HEBREW.search(text)) or key in SAME_ON_PURPOSE, (name, "en", key)
    for key in table["en"]:
        if key not in SAME_ON_PURPOSE:
            assert table["ar"][key] != table["en"][key] and table["he"][key] != table["en"][key], key


def test_the_browser_table_defines_every_key_once():
    """i18n.js used to define three keys twice, and the older, less careful wording was silently overridden."""
    for lang in LANGS:
        keys = [key for key, _, _ in JS_ENTRIES[lang]]
        assert len(keys) > 150 and len(keys) == len(set(keys)), sorted({k for k in keys if keys.count(k) > 1})


def test_the_source_files_hold_no_invisible_direction_controls():
    """Direction controls in source are invisible to a reader and to review tools (Trojan Source): they are
    written as escapes, so the person reading the file can see them."""
    for path in [ROOT / "nemla" / "_strings_base.py", ROOT / "nemla" / "strings_extra.py", ROOT / "nemla_ui" / "web" / "i18n.js",
                 ROOT / "nemla_ui" / "web" / "app.js", ROOT / "README.ar.md", ROOT / "README.he.md"]:
        assert not BIDI.search(path.read_text(encoding="utf-8")), path.name


# ---------------------------------------------------------------------------------------------- one word per concept

# concept -> {language: (words that must appear when the English uses the concept, words that must not appear anywhere)}
# The Arabic web page is written in the Levantine dialect and the CLI/reports in standard Arabic: for a few concepts
# each register has its own word (password), listed per table.
GLOSSARY = {
    "banner": {"en": r"\bbanners?\b", "ar": (r"لافتة|اللافتة|اللافتات|لافتات", r"بانر|Banner"), "he": (r"באנר", r"שלט")},
    "decoy": {"en": r"\bdecoys?\b", "ar": (r"طُعم|الطُّعم|الطعم", r"فخ|مصيدة"), "he": (r"פיתיון", r"מלכודת")},
    "router": {"en": r"\brouters?\b", "ar": (r"راوتر", r"روتر|موجّه"), "he": (r"ראוטר", r"נתב")},
    "gateway": {"en": r"\bgateway\b", "ar": (r"بوابة|البوابة", r"غيتواي"), "he": (r"שער", r"גייטוויי")},
    "certificate": {"en": r"\bcertificates?\b", "ar": (r"شهادة|الشهادة", r"شهادات\b" r"(?!x)"), "he": (r"תעודה|תעודת", r"אישור SSL")},
    "confidence": {"en": r"\bconfidence\b", "ar": (r"ثقة", r"يقين|موثوقية"), "he": (r"ביטחון", r"אמינות|וודאות")},
    "spoofing": {"en": r"\bspoofing\b", "ar": (r"انتحال", r"خداع"), "he": (r"התחזות", r"זיוף ARP|הונאה")},
    "fingerprint": {"en": r"\bfingerprint", "ar": (r"بصمة", r"تبصيم"), "he": (r"טביעת", r"בוליות")},
    "port": {"en": r"\bports?\b", "ar": (r"منفذ|المنفذ|منافذ|المنافذ", r"بورت|ميناء"), "he": (r"פורט", r"נמל\b|יציאות")},
}


@pytest.mark.parametrize("name", TABLES)
@pytest.mark.parametrize("concept", GLOSSARY)
def test_a_concept_has_one_word_in_each_language(name, concept):
    table, spec = TABLES[name], GLOSSARY[concept]
    for lang in ("ar", "he"):
        forbidden = spec[lang][1]
        for key, text in table[lang].items():
            assert not re.search(forbidden, text), (name, lang, key, f"uses a different word for '{concept}'", text)
    for key, text in table["en"].items():
        if re.search(spec["en"], PLACEHOLDER.sub("", text), re.I):          # the word itself, not a {ports} placeholder
            for lang in ("ar", "he"):
                if (lang, key) not in GLOSSARY_EXCEPTIONS.get(concept, ()):
                    assert re.search(spec[lang][0], table[lang][key]), (
                        name, lang, key, f"'{concept}' is not translated with the usual word", table[lang][key])


# (language, key) pairs where the usual word is deliberately not used: the Hebrew tagline says "identification"
# (זיהוי), which is what fingerprinting a service means to a Hebrew reader, in a list of four short nouns
GLOSSARY_EXCEPTIONS = {
    "fingerprint": {("he", "app.tagline")},
}


def test_the_readmes_use_the_words_the_program_uses():
    ar = (ROOT / "README.ar.md").read_text(encoding="utf-8")
    he = (ROOT / "README.he.md").read_text(encoding="utf-8")
    assert "منافذ فخّ" not in ar and "منافذ طُعم" in ar          # decoy ports
    assert "שלט" not in he and "באנר" in he                       # banners


PASSWORD = {"python": {"ar": (r"كلمة المرور|كلمات المرور|كلمة مرور|كلمات مرور", r"كلمة سر|كلمات السر")},
            "browser": {"ar": (r"كلمة السر|كلمات السر|كلمة سر", r"كلمة المرور|كلمات المرور")}}


@pytest.mark.parametrize("name", TABLES)
def test_password_has_one_word_per_register(name):
    wanted, forbidden = PASSWORD[name]["ar"]
    for key, text in TABLES[name]["ar"].items():
        assert not re.search(forbidden, text), (name, key, text)
    for key, text in TABLES[name]["en"].items():
        if re.search(r"\bpasswords?\b", text, re.I) and not re.search(r"wi-?fi", text, re.I):
            assert re.search(wanted, TABLES[name]["ar"][key]), (name, key, TABLES[name]["ar"][key])


# ---------------------------------------------------------------------------------------------- claims stay hedged

HEDGE = {"en": r"can be|possible|may|might|could|also", "ar": r"قد يكون|محتمل|ممكن|أيضاً|كمان", "he": r"עשוי|אפשרי|ייתכן|גם"}


@pytest.mark.parametrize("name", TABLES)
def test_a_changed_hardware_address_is_never_called_spoofing_outright(name):
    table = TABLES[name]
    keys = [k for k in table["en"] if re.search(r"(^g_arp_|^guard\.t\.arp_)", k)]
    assert len(keys) >= 3
    for key in keys:
        for lang in LANGS:
            text = table[lang][key]
            assert re.search(HEDGE[lang], text), (name, lang, key, "states ARP trouble as fact", text)
            assert not re.search(r"classic sign|is ARP spoofing|confirmed|definitely|علامة كلاسيكية|סימן קלאסי", text), (name, lang, key)


# ---------------------------------------------------------------------------------------------- right-to-left output

def sample_scan():
    hosts = [{"ip": "10.0.0.5", "mac": None, "discovery": "ARP", "os_guess": "Linux", "ttl": 64, "os": {}, "vendor": None,
              "open_ports": [{"port": 80, "proto": "tcp", "state": "open", "service": "HTTP", "banner": "Server: nginx \u202e\u2066evil\u2069",
                              "product": "nginx", "version": "1.24", "confidence": 0.9, "heuristic": False}],
              "findings": [], "scanned": {"tcp": "80", "udp": ""}, "udp_unconfirmed": []}]
    meta = {"target": "10.0.0.0/24", "scan_time": "2026-09-21 10:00:00", "duration": 1.2, "ports_scanned": 1, "discovered": 1,
            "cancelled": False, "findings": {"high": 0, "medium": 0, "low": 0, "info": 0}, "warnings": [], "capabilities": {}}
    return meta, hosts


@pytest.mark.parametrize("lang, direction", [("en", "ltr"), ("ar", "rtl"), ("he", "rtl")])
def test_html_reports_set_language_and_direction(lang, direction):
    page = nemla.render_html(*sample_scan(), lang)
    assert f'lang="{lang}"' in page and f'dir="{direction}"' in page


@pytest.mark.parametrize("lang", ["ar", "he"])
def test_rtl_reports_keep_network_text_in_its_own_direction(lang):
    page = nemla.render_html(*sample_scan(), lang)
    hostile = "".join(chr(c) for c in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069))
    assert not any(ch in page for ch in hostile), "hostile direction controls reached the report"
    assert "<bdi>" in page                                               # addresses and banners are isolated from the sentence
    assert "evil" in page and "nginx" in page                            # the rest of the banner is still shown


def test_markdown_and_csv_reports_are_utf8_clean_in_every_language():
    for lang in LANGS:
        meta, hosts = sample_scan()
        for text in (nemla.markdown_text(meta, hosts, lang), nemla.csv_text(hosts, lang), nemla.json_text(meta, hosts, lang)):
            assert isinstance(text, str) and chr(0x202E) not in text and chr(0x2066) not in text
            assert "evil" in text

def test_a_text_asked_for_the_wrong_placeholders_comes_back_as_written():
    """A caller that forgets a placeholder must get readable text, not a KeyError in the middle of a scan."""
    assert "{count}" in nemla.t("g_notice_sweep_empty", wrong=1)
