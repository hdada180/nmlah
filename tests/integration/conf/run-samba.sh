#!/bin/sh
# Start smbd in the foreground with the given configuration file (no accounts are created).
# smbd refuses to start without its runtime directories ("Failed to create pipe directory /run/samba/ncalrpc").
set -e
mkdir -p /tmp/smb /srv/share /run/samba/ncalrpc /var/lib/samba/private /var/cache/samba /var/log/samba
exec smbd --foreground --no-process-group --debug-stdout --configfile="$1"
