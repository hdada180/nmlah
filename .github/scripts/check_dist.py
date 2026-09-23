"""Check a built wheel and sdist against the source tree: nothing missing, nothing extra, one version.

    python .github/scripts/check_dist.py DIST_DIR

Every file under nemla/ and nemla_ui/ (the packages, including the web page's assets) must be in the wheel, and the
wheel must hold nothing else besides its own metadata. The version in the metadata, the console script and the
licence are checked too. The sdist must be enough to read the docs and run the tests, and must carry no caches.
Standard library only, so it runs in a bare CI step.
"""
import re
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ("nemla", "nemla_ui")
SDIST_REQUIRED = ("pyproject.toml", "LICENSE", "README.md", "CHANGELOG.md", "nemla.py", "nemla/config.py",
                  "nemla_ui/web/index.html", "tests/conftest.py", "docs/architecture.md", "MANIFEST.in")
SDIST_FORBIDDEN = ("__pycache__", ".pyc", ".coverage", ".git/", "/dist/", "/build/", "nemla_report.html")


def source_version() -> str:
    text = (ROOT / "nemla" / "config.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', text, re.M)
    if not match:
        sys.exit("cannot find __version__ in nemla/config.py")
    return match.group(1)


def source_files() -> set:
    found = set()
    for package in PACKAGES:
        for path in (ROOT / package).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                found.add(path.relative_to(ROOT).as_posix())
    return found


def check_wheel(path: Path, version: str) -> list:
    problems = []
    with zipfile.ZipFile(path) as wheel:
        names = set(wheel.namelist())
        dist_info = f"nemla-{version}.dist-info/"
        content = {n for n in names if not n.startswith(dist_info)}
        expected = source_files()
        for missing in sorted(expected - content):
            problems.append(f"wheel lacks {missing}")
        for extra in sorted(content - expected):
            problems.append(f"wheel has a file the source tree does not: {extra}")
        if not any(n.startswith(dist_info) for n in names):
            problems.append(f"no {dist_info} folder: the wheel's metadata says another version")
            return problems
        metadata = wheel.read(dist_info + "METADATA").decode("utf-8")
        match = re.search(r"^Version: (.+)$", metadata, re.M)
        if not match or match.group(1).strip() != version:
            problems.append(f"metadata version {match and match.group(1)!r} differs from nemla/config.py {version!r}")
        if "License-Expression: MIT" not in metadata:
            problems.append("metadata does not declare the MIT licence")
        if "nemla = nemla.main:main" not in wheel.read(dist_info + "entry_points.txt").decode("utf-8"):
            problems.append("console script `nemla = nemla.main:main` is missing")
        if not any(n.startswith(dist_info + "licenses/") and n.endswith("LICENSE") for n in names):
            problems.append("the LICENSE file is not in the wheel's metadata")
    return problems


def check_sdist(path: Path, version: str) -> list:
    problems = []
    prefix = f"nemla-{version}/"
    with tarfile.open(path) as archive:
        names = {m.name for m in archive.getmembers()}
    if not all(n == prefix.rstrip("/") or n.startswith(prefix) for n in names):
        problems.append(f"sdist entries are not all under {prefix}")
    for required in SDIST_REQUIRED:
        if prefix + required not in names:
            problems.append(f"sdist lacks {required}")
    for name in sorted(names):
        if any(bad in name for bad in SDIST_FORBIDDEN):
            problems.append(f"sdist carries a file that should not ship: {name}")
    return problems


def main(argv) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    dist = Path(argv[1])
    version = source_version()
    wheels, sdists = sorted(dist.glob("*.whl")), sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        print(f"expected exactly one wheel and one sdist in {dist}, found {len(wheels)} and {len(sdists)}")
        return 1
    problems = check_wheel(wheels[0], version) + check_sdist(sdists[0], version)
    for problem in problems:
        print("PROBLEM:", problem)
    if problems:
        return 1
    print(f"ok: {wheels[0].name} and {sdists[0].name} match the source tree (version {version}, "
          f"{len(source_files())} package files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
