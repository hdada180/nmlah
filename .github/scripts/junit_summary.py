"""Turn a pytest JUnit XML file into a short summary, and fail if the tests did not really run.

    python .github/scripts/junit_summary.py junit.xml "Linux / Python 3.12" [--min-tests N] [--max-skipped N]

The summary goes to the console and, on GitHub, to the job summary page. The point is to make
"CI is green" mean "the tests ran": an empty or mostly-skipped run is a failure, not a pass.
"""
import argparse
import os
import sys
import xml.etree.ElementTree as ET


def annotation(title: str, message: str) -> str:
    """A GitHub Actions error annotation: failing tests show up in the run's check annotations, readable without the logs."""
    def escape(text: str, prop: bool = False) -> str:
        text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        return text.replace(":", "%3A").replace(",", "%2C") if prop else text

    return f"::error title={escape(title, True)}::{escape(message)}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("xml")
    parser.add_argument("title")
    parser.add_argument("--min-tests", type=int, default=1)
    parser.add_argument("--max-skipped", type=int, default=10**9)
    args = parser.parse_args()

    root = ET.parse(args.xml).getroot()  # noqa: S314
    suites = [root] if root.tag == "testsuite" else list(root)
    total = sum(int(s.get("tests", 0)) for s in suites)
    failures = sum(int(s.get("failures", 0)) for s in suites)
    errors = sum(int(s.get("errors", 0)) for s in suites)
    skipped = sum(int(s.get("skipped", 0)) for s in suites)
    ran = total - skipped
    seconds = sum(float(s.get("time", 0)) for s in suites)

    skips = {}
    for case in root.iter("testcase"):
        for skip in case.findall("skipped"):
            reason = (skip.get("message") or "").strip()[:120] or "(no reason)"
            skips[reason] = skips.get(reason, 0) + 1

    lines = [f"### {args.title}", "",
             "| collected | executed | passed | failed | errors | skipped | time |",
             "|---|---|---|---|---|---|---|",
             f"| {total} | {ran} | {ran - failures - errors} | {failures} | {errors} | {skipped} | {seconds:.0f}s |", ""]
    if skips:
        lines += ["Skipped, by reason:", ""] + [f"* {n} x {reason}" for reason, n in sorted(skips.items())] + [""]
    text = "\n".join(lines)
    print(text)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")

    shown = 0
    for case in root.iter("testcase"):
        for bad in [*case.findall("failure"), *case.findall("error")]:
            if shown < 9:                                      # GitHub keeps ten errors per step: leave room for the total below
                text = " ".join((bad.get("message") or bad.text or "").split())[:400]
                print(annotation(f"{case.get('classname', '')}.{case.get('name', '')}"[-140:], text))
            shown += 1
    problems = []
    if ran < args.min_tests:
        problems.append(f"only {ran} tests executed, at least {args.min_tests} expected")
    if skipped > args.max_skipped:
        problems.append(f"{skipped} tests skipped, at most {args.max_skipped} expected")
    if failures or errors:
        problems.append(f"{failures} failures and {errors} errors")
    for problem in problems:
        print(f"::error::{args.title}: {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
