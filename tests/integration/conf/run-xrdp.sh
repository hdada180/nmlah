#!/bin/sh
# Start xrdp in the foreground with the given security layer: negotiate, tls or rdp (standard RDP security).
# xrdp answers the X.224 negotiation itself, so no desktop session, account or password is involved.
set -e
layer="${1:-negotiate}"
sed "s/^security_layer=.*/security_layer=${layer}/" /etc/xrdp/xrdp.ini > /tmp/xrdp.ini
grep -q "^security_layer=${layer}" /tmp/xrdp.ini
exec xrdp --nodaemon --config /tmp/xrdp.ini
