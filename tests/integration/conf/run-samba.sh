#!/bin/sh
# Start smbd in the foreground with the given configuration file (no accounts are created).
set -e
mkdir -p /tmp/smb /srv/share
exec smbd --foreground --no-process-group --debug-stdout --configfile="$1"
