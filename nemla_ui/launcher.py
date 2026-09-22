"""Add Nemla to a Linux desktop's applications menu (no root needed).

`nemla --install-launcher` writes, under your home directory only:

  ~/.local/share/applications/nemla.desktop   the menu entry
  ~/.local/share/icons/hicolor/scalable/apps/nemla.svg   its icon
  ~/.local/bin/nemla                          a `nemla` command, only when `pip install` did not already
                                               give you one and only if none exists yet

The menu entry runs whichever of these actually works: the `nemla` command already on PATH (a normal `pip
install`, including `pip install -e .`), or `python3 nemla.py` next to a plain git checkout. A checkout with
no console script and no `nemla.py` next to it (found by neither) is the only case `install()` refuses.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ICON_SOURCE = Path(__file__).resolve().parent / "web" / "brand" / "nemla-icon.svg"
SCRIPT = Path(__file__).resolve().parent.parent / "nemla.py"
DESKTOP_NAME = "nemla.desktop"
WRAPPER_MARK = "# nemla-launcher"


def data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")


def bin_home() -> Path:
    return Path.home() / ".local" / "bin"


def _quote(arg: str) -> str:
    """Quote one argument for the Exec= line of a .desktop file."""
    if arg and all(ch.isalnum() or ch in "-_./:=+" for ch in arg):
        return arg
    escaped = (arg.replace("\\", "\\\\").replace('"', '\\"')
               .replace("`", "\\`").replace("$", "\\$").replace("%", "%%"))
    return f'"{escaped}"'


def desktop_entry(command: list) -> str:
    exec_line = " ".join(_quote(part) for part in command)
    return "\n".join([
        "[Desktop Entry]",
        "Type=Application",
        "Version=1.0",
        "Name=Nemla",
        "Name[ar]=نملة",
        "Name[he]=נמלה",
        "GenericName=Network Recon",
        "GenericName[ar]=استطلاع الشبكات",
        "GenericName[he]=סיור ברשת",
        "Comment=Discover, scan, fingerprint and report - in a 3D colony view",
        "Comment[ar]=اكتشاف وفحص وتقرير للشبكة بواجهة ثلاثية الأبعاد",
        "Comment[he]=גילוי, סריקה ודיווח על הרשת בתצוגת מושבה תלת־ממדית",
        f"Exec={exec_line}",
        "Icon=nemla",
        "Terminal=false",
        "StartupNotify=true",
        "StartupWMClass=Nemla",
        "Categories=Network;Security;",
        "Keywords=nmap;scan;ports;network;recon;nemla;نملة;נמלה;",
        "",
    ])


def _refresh_caches(applications: Path, icons_root: Path) -> None:
    for command in (["update-desktop-database", str(applications)],
                    ["gtk-update-icon-cache", "-f", "-t", str(icons_root)]):
        if shutil.which(command[0]):
            try:
                # a fixed tool name (found with shutil.which) and paths this module just created; no shell
                subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,  # noqa: S603
                               timeout=20, check=False)
            except (OSError, subprocess.SubprocessError):
                pass


def install(data=None, bin_dir=None, python=None, script=None, which=shutil.which) -> int:
    data = Path(data) if data else data_home()
    bin_dir = Path(bin_dir) if bin_dir else bin_home()
    python = python or sys.executable or "python3"
    script = Path(script) if script else SCRIPT
    installed = which("nemla")     # a pip install (including `pip install -e .`) already gives you this command
    if installed:
        command = [installed]
    elif script.is_file():
        command = [python, str(script)]
    else:
        print(f"Cannot find an installed `nemla` command, and no nemla.py at {script}")
        return 1
    if not ICON_SOURCE.is_file():
        print(f"Cannot find the icon at {ICON_SOURCE}")
        return 1

    applications = data / "applications"
    icons_root = data / "icons" / "hicolor"
    icon_dir = icons_root / "scalable" / "apps"
    for folder in (applications, icon_dir, bin_dir):
        folder.mkdir(parents=True, exist_ok=True)

    (applications / DESKTOP_NAME).write_text(
        desktop_entry([*command, "--ui"]), encoding="utf-8")
    shutil.copyfile(ICON_SOURCE, icon_dir / "nemla.svg")

    wrapper = bin_dir / "nemla"
    wrote_wrapper = False
    # `nemla` already works from anywhere once pip has installed it: nothing to add under ~/.local/bin
    if not installed and (not wrapper.exists() or WRAPPER_MARK in wrapper.read_text(encoding="utf-8", errors="ignore")):
        wrapper.write_text(
            f'#!/bin/sh\n{WRAPPER_MARK}\nexec {_shell_quote(python)} {_shell_quote(str(script))} "$@"\n',
            encoding="utf-8")
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        wrote_wrapper = True
    _refresh_caches(applications, icons_root)

    print("Nemla is now in your applications menu.")
    print(f"  menu entry : {applications / DESKTOP_NAME}")
    print(f"  icon       : {icon_dir / 'nemla.svg'}")
    if wrote_wrapper:
        print(f"  command    : {wrapper}   (type `nemla` to open the 3D interface)")
        if str(bin_dir) not in os.environ.get("PATH", "").split(os.pathsep):
            print(f"  note       : add {bin_dir} to your PATH to use the `nemla` command")
    return 0


def uninstall(data=None, bin_dir=None) -> int:
    data = Path(data) if data else data_home()
    bin_dir = Path(bin_dir) if bin_dir else bin_home()
    targets = [data / "applications" / DESKTOP_NAME,
               data / "icons" / "hicolor" / "scalable" / "apps" / "nemla.svg"]
    wrapper = bin_dir / "nemla"
    if wrapper.is_file() and WRAPPER_MARK in wrapper.read_text(encoding="utf-8", errors="ignore"):
        targets.append(wrapper)
    removed = 0
    for path in targets:
        if path.exists():
            path.unlink()
            removed += 1
            print(f"removed {path}")
    _refresh_caches(data / "applications", data / "icons" / "hicolor")
    if not removed:
        print("Nothing to remove: Nemla was not installed in the applications menu.")
    return 0


def _shell_quote(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"
