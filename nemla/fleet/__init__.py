"""Fleet mode: one controller, several enrolled agents, each watching a network its owner authorized.

An agent runs on (or next to) the network it watches, is enrolled there by someone with access to that machine, and
carries a local scope that no controller can widen. The controller queues structured scan jobs for it and collects
the results; it never scans, and there is no way to send it anything but data. See docs/fleet.md for the threat model.

    protocol   the messages (a job, a result), their limits, secrets and certificate pins
    scope      the addresses an agent may scan
    registry   who is enrolled, who is revoked
    audit      the append-only record of everything that happened
"""
