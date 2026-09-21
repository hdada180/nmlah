#!/usr/bin/env python3
"""Nemla (نملة) launcher: `python3 nemla.py ...` runs the `nemla` package that sits next to this file.

Examples:
    python3 nemla.py                              # open the 3D interface
    python3 nemla.py 192.168.1.10                 # scan one host
    sudo python3 nemla.py 192.168.1.0/24          # a whole network (root: real ARP discovery)
    python3 nemla.py 192.168.1.10 -p all --udp    # every TCP port plus the common UDP ports
    python3 nemla.py scanme.example.org -p 22,80,443 --json out.json --sarif out.sarif
    python3 nemla.py watch 192.168.1.0/24 15m     # again every 15 minutes, say what changed
    python3 nemla.py diff old.json new.json       # what changed between two saved scans
    python3 nemla.py guard                        # defensive monitoring
    python3 nemla.py --help                       # every option (`-t TARGET` still works too)

Only scan systems and networks you own or have explicit permission to test.
"""
import sys

from nemla.main import main

if __name__ == "__main__":
    sys.exit(main())
