# The integration lab image: a real Samba and a real xrdp, nothing else.
# No accounts, no passwords, no secrets: Samba serves a read-only guest share, xrdp only negotiates connections.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends samba xrdp openssl \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /srv/share /tmp/smb \
 && echo "the lab share" > /srv/share/README.txt

COPY conf /lab
RUN chmod +x /lab/*.sh
