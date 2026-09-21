#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nemla (نملة) launcher: `python3 nemla.py ...` runs the `nemla` package that sits next to this file.

Examples:
    python3 nemla.py                        # open the 3D interface
    sudo python3 nemla.py -t 192.168.1.0/24
    python3 nemla.py -t 192.168.1.10 --top-ports --udp --lang ar
    python3 nemla.py -t scanme.example.org -p 22,80,443 --json out.json --sarif out.sarif

Only scan systems and networks you own or have explicit permission to test.
"""
import sys

from nemla.main import main

if __name__ == "__main__":
    sys.exit(main())
